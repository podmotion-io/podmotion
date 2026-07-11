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
// password — MUST NOT send credentials) and issues a query (default "SELECT 1", or
// req query override via the AppProbeQuery overload field), requiring a genuine
// RowDescription + at least one DataRow + CommandComplete + ReadyForQuery sequence.
// Any AuthenticationXXX message other than AuthenticationOk (type 'R', authtype 0) is a
// FAILURE (AuthRequired) — this probe never authenticates. An ErrorResponse ('E') is a
// FAILURE.
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

	// Read AuthenticationOk (or fail on any other auth request / error response).
	msgType, body, err := readPgMessage(conn)
	if err != nil {
		return fmt.Errorf("pgProbe: reading auth response failed: %w", err)
	}
	switch msgType {
	case 'R':
		if len(body) < 4 || binary.BigEndian.Uint32(body) != 0 {
			return fmt.Errorf("pgProbe: AuthRequired — server requested non-trivial authentication; probe never authenticates")
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
