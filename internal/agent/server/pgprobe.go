package server

// ADR-0325: real wire-protocol workload-liveness probes replacing the byte-or-EOF stub.
// Hand-rolled minimal wire messages — no new DB driver dependency (consistent with the
// existing subprocess/no-heavy-dependency posture at server.go:6746-6749).

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"time"
)

// ADR-0325 round-3 (sprint46B9): SUSTAINED workload-liveness parameters. The original probe
// proved only that "a backend answered a login prompt for one instant" and was checked ONCE —
// so a crash-looping backend that happened to be up during that single instant flipped
// WorkloadLivenessVerified=True and let its source pod be deleted. sustainedProbe closes that
// gap: it requires N CONSECUTIVE passes spaced over a real interval, so a later attempt lands
// on connection-refused (or an ErrorResponse) while the backend is between crash cycles.
//
// Parameter reasoning (defaults):
//   - passes = 4, interval = 3s → a ~9s observation window (3 gaps × 3s) plus per-probe I/O.
//     A backend must stay genuinely serviceable across the whole window, not for one instant.
//   - A flapping/crash-looping backend answers the handshake, then dies; the next attempt 3s
//     later hits ECONNREFUSED (kubelet has torn the container down / CrashLoopBackOff), so the
//     window fails closed. Even a backend that answers 2–3 times inside a brief healthy sliver
//     is caught, because the window outlasts a typical post-accept crash.
//   - Budget: worst case for the SQL path is passes×perProbeTimeout + (passes-1)×interval =
//     4×5s + 3×3s = 29s, comfortably inside the 240s completion budget even if re-run across a
//     few controller requeues. The common (healthy) case is ~9s — each probe returns in ms.
//   - fail-fast: the FIRST failing attempt short-circuits the window (no reason to keep probing
//     a backend already proven not-sustained), so an unhealthy destination is rejected quickly.
const (
	defaultLivenessSustainPasses   = 4
	defaultLivenessSustainInterval = 3 * time.Second
)

// sustainedProbe runs probeOnce up to `passes` times, sleeping `interval` between attempts, and
// returns nil ONLY if EVERY attempt passes. Any single failure short-circuits and is returned.
// probeOnce must be self-contained (its own dial + per-probe timeout) so each attempt observes
// the backend's CURRENT state, not a cached connection. This is the credential-free hardening
// for the auth-challenge case (see pgProbe): we still cannot run a real query against a
// password-protected server without credentials, so instead of one instantaneous "a backend
// answered" we demand the backend keep answering across the window — a crash-loop cannot.
func sustainedProbe(ctx context.Context, passes int, interval time.Duration, probeOnce func(context.Context) error) error {
	if passes < 1 {
		passes = 1
	}
	for i := 0; i < passes; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("sustainedProbe: context done before pass %d/%d: %w", i+1, passes, ctx.Err())
			case <-time.After(interval):
			}
		}
		if err := probeOnce(ctx); err != nil {
			return fmt.Errorf("sustainedProbe: pass %d/%d failed (liveness not sustained across the window): %w", i+1, passes, err)
		}
	}
	return nil
}

// httpGet2xx performs an HTTP GET to path (default "/" when empty) at address and requires
// a genuine [200,300) status code. CheckRedirect refuses to follow redirects — a 3xx is a
// FAILURE, not silently resolved. No auth header is attached (ADR-0325).
func httpGet2xx(ctx context.Context, address, path string, timeout time.Duration) error {
	if path == "" {
		path = "/"
	}
	url := fmt.Sprintf("http://%s%s", address, path)
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("httpGet2xx: building request failed: %w", err)
	}
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("httpGet2xx: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("httpGet2xx: got status %d, want [200,300)", resp.StatusCode)
	}
	return nil
}

// pgProbe performs a minimal PostgreSQL wire-protocol v3 handshake (StartupMessage, no
// password — MUST NOT send credentials) and confirms the process behind the socket is a
// live, protocol-correct Postgres. Two success shapes:
//
//   - Trust / no-auth server: replies AuthenticationOk (type 'R', authtype 0); the probe
//     then issues a query (default "SELECT 1", or the req AppProbeQuery override) and
//     requires a genuine RowDescription + >=1 DataRow + CommandComplete + ReadyForQuery.
//   - Password-protected server: replies with a genuine authentication CHALLENGE
//     (AuthenticationCleartextPassword/MD5Password/SASL/... — type 'R', authtype != 0). A
//     wire-correct challenge can only be produced by a live postmaster that has passed its
//     own canAcceptConnections gate and a real backend speaking protocol v3, so the
//     challenge is itself proof of liveness; the probe stops there WITHOUT authenticating
//     (it holds no credentials by design). See the auth switch below for why this does NOT
//     weaken the dead-but-echo-alive guard ADR-0325 exists to enforce.
//
// An ErrorResponse ('E') — including "the database system is starting up" (57P03), which a
// crash-recovering server sends BEFORE any auth challenge — is a FAILURE. A malformed 'R', a
// continuation/unknown auth subtype as the first reply, or any other message type is a
// FAILURE. The probe NEVER sends credential material.
func pgProbe(ctx context.Context, conn net.Conn, query string, timeout time.Duration) error {
	if query == "" {
		query = "SELECT 1"
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// StartupMessage: int32 len, int32 protocol version (3.0), "user\0<val>\0\0"
	user := "podmotion_probe"
	params := []byte("user\x00" + user + "\x00\x00")
	msgLen := 4 + 4 + len(params)
	startup := make([]byte, 0, msgLen)
	startup = binary.BigEndian.AppendUint32(startup, uint32(msgLen))
	startup = binary.BigEndian.AppendUint32(startup, 0x00030000) // protocol 3.0
	startup = append(startup, params...)
	if _, err := conn.Write(startup); err != nil {
		return fmt.Errorf("pgProbe: StartupMessage write failed: %w", err)
	}

	// Read the server's first reply to our StartupMessage and classify liveness.
	msgType, body, err := readPgMessage(conn)
	if err != nil {
		return fmt.Errorf("pgProbe: reading auth response failed: %w", err)
	}
	switch msgType {
	case 'R':
		if len(body) < 4 {
			return fmt.Errorf("pgProbe: malformed Authentication message (%d body bytes, need >= 4)", len(body))
		}
		switch authType := binary.BigEndian.Uint32(body); authType {
		case 0:
			// AuthenticationOk — trust / no-auth server. Fall through to the SELECT-1
			// query proof below (the strongest liveness signal: a backend that reaches
			// the query loop has attached to shared memory and completed startup).
		case 2, 3, 5, 6, 7, 9, 10:
			// AuthenticationKerberosV5(2)/CleartextPassword(3)/MD5Password(5)/
			// SCMCredential(6)/GSS(7)/SSPI(9)/SASL(10): a genuine first-message auth
			// CHALLENGE. A wire-correct challenge is only ever emitted by a live postmaster
			// past canAcceptConnections (a starting-up/crash-recovering server rejects with
			// ErrorResponse 'E' 57P03 BEFORE authentication) and a forked backend speaking
			// protocol v3 — i.e. the process behind the socket is a live, healthy Postgres
			// answering its real protocol, exactly what ADR-0325 gates on. The
			// dead-but-echo-alive class (bare TCP acceptor, lingering socket, port-forwarder)
			// cannot frame this message. We hold no credentials BY DESIGN (no
			// credential-exfiltration surface), so we cannot answer — recognizing the
			// challenge as liveness is the correct, credential-free way to gate a
			// password-protected Postgres (the common real-world case), and mirrors
			// pg_isready/PQping, whose PQPING_OK includes the auth-required server.
			return nil
		default:
			// Continuation subtypes (8 GSSContinue, 11 SASLContinue, 12 SASLFinal) cannot
			// legitimately be the FIRST reply, and any unknown code is unrecognized — fail
			// closed rather than guess a live server.
			return fmt.Errorf("pgProbe: unrecognized/unexpected Authentication subtype %d as first reply", authType)
		}
	case 'E':
		return fmt.Errorf("pgProbe: ErrorResponse during startup: %s", string(body))
	default:
		return fmt.Errorf("pgProbe: unexpected message type %q during startup", msgType)
	}

	// Drain BackendKeyData/ParameterStatus/ReadyForQuery until first ReadyForQuery.
	if err := drainUntilReady(conn); err != nil {
		return fmt.Errorf("pgProbe: draining startup messages failed: %w", err)
	}

	// Simple Query message: 'Q' + int32 len + query\0
	qBody := append([]byte(query), 0)
	qMsg := make([]byte, 0, 5+len(qBody))
	qMsg = append(qMsg, 'Q')
	qMsg = binary.BigEndian.AppendUint32(qMsg, uint32(4+len(qBody)))
	qMsg = append(qMsg, qBody...)
	if _, err := conn.Write(qMsg); err != nil {
		return fmt.Errorf("pgProbe: Query write failed: %w", err)
	}

	sawRowDescription := false
	sawDataRow := false
	sawCommandComplete := false
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("pgProbe: context done while awaiting query response: %w", ctx.Err())
		default:
		}
		mt, mb, err := readPgMessage(conn)
		if err != nil {
			return fmt.Errorf("pgProbe: reading query response failed: %w", err)
		}
		switch mt {
		case 'T':
			sawRowDescription = true
		case 'D':
			sawDataRow = true
		case 'C':
			sawCommandComplete = true
		case 'E':
			return fmt.Errorf("pgProbe: ErrorResponse during query: %s", string(mb))
		case 'Z':
			if sawRowDescription && sawDataRow && sawCommandComplete {
				return nil
			}
			return fmt.Errorf("pgProbe: ReadyForQuery reached without full RowDescription+DataRow+CommandComplete sequence (rd=%v dr=%v cc=%v)", sawRowDescription, sawDataRow, sawCommandComplete)
		}
	}
}

// readPgMessage reads one length-prefixed Postgres backend message: 1-byte type, int32 len
// (including itself), followed by (len-4) bytes of body.
func readPgMessage(conn net.Conn) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := readFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	mtype := hdr[0]
	mlen := binary.BigEndian.Uint32(hdr[1:5])
	if mlen < 4 {
		return 0, nil, fmt.Errorf("invalid message length %d", mlen)
	}
	body := make([]byte, mlen-4)
	if len(body) > 0 {
		if _, err := readFull(conn, body); err != nil {
			return 0, nil, err
		}
	}
	return mtype, body, nil
}

func drainUntilReady(conn net.Conn) error {
	for {
		mt, mb, err := readPgMessage(conn)
		if err != nil {
			return err
		}
		switch mt {
		case 'Z':
			return nil
		case 'E':
			return fmt.Errorf("ErrorResponse: %s", string(mb))
		default:
			// BackendKeyData, ParameterStatus, NoticeResponse — ignore and continue.
		}
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// respPing sends a RESP-encoded PING and requires the literal "+PONG\r\n" reply. No AUTH is
// ever issued.
func respPing(conn net.Conn, timeout time.Duration) error {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		return fmt.Errorf("respPing: write failed: %w", err)
	}
	buf := make([]byte, 7)
	n, err := readFull(conn, buf)
	if err != nil && n < 7 {
		return fmt.Errorf("respPing: read failed: %w", err)
	}
	if string(buf) != "+PONG\r\n" {
		return fmt.Errorf("respPing: unexpected reply %q, want %q", string(buf), "+PONG\r\n")
	}
	return nil
}
