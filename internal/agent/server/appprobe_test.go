/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- pgProbe: real Postgres wire-protocol v3 handshake + simple query ---

// fakePgServer drives one side of a net.Pipe as a minimal Postgres backend: it replies
// AuthenticationOk, then ReadyForQuery, then on receiving a Simple Query message replies
// RowDescription + DataRow + CommandComplete + ReadyForQuery.
func fakePgServer(t *testing.T, conn net.Conn, fail bool) {
	t.Helper()
	// Read StartupMessage (don't bother parsing contents).
	hdr := make([]byte, 4)
	if _, err := readFullTest(conn, hdr); err != nil {
		return
	}
	mlen := binary.BigEndian.Uint32(hdr)
	body := make([]byte, mlen-4)
	_, _ = readFullTest(conn, body)

	writeMsg := func(mtype byte, payload []byte) {
		buf := make([]byte, 0, 5+len(payload))
		buf = append(buf, mtype)
		buf = binary.BigEndian.AppendUint32(buf, uint32(4+len(payload)))
		buf = append(buf, payload...)
		_, _ = conn.Write(buf)
	}

	if fail {
		writeMsg('E', []byte("simulated auth failure"))
		return
	}

	// AuthenticationOk: type 'R', int32 authtype=0
	authOk := make([]byte, 4)
	binary.BigEndian.PutUint32(authOk, 0)
	writeMsg('R', authOk)
	// ReadyForQuery: type 'Z', 1 status byte
	writeMsg('Z', []byte{'I'})

	// Read the Simple Query message ('Q').
	qhdr := make([]byte, 5)
	if _, err := readFullTest(conn, qhdr); err != nil {
		return
	}
	qlen := binary.BigEndian.Uint32(qhdr[1:5])
	qbody := make([]byte, qlen-4)
	_, _ = readFullTest(conn, qbody)

	writeMsg('T', []byte{}) // RowDescription (empty is fine — probe only checks presence)
	writeMsg('D', []byte{}) // DataRow
	writeMsg('C', []byte("SELECT 1"))
	writeMsg('Z', []byte{'I'}) // ReadyForQuery
}

func readFullTest(conn net.Conn, buf []byte) (int, error) {
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

func TestPgProbe_SuccessfulHandshakeAndQuery(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		fakePgServer(t, server, false)
		close(done)
	}()

	err := pgProbe(context.Background(), client, "", 2*time.Second)
	<-done
	if err != nil {
		t.Fatalf("pgProbe: expected success, got error: %v", err)
	}
}

func TestPgProbe_ErrorResponseIsFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		fakePgServer(t, server, true)
		close(done)
	}()

	err := pgProbe(context.Background(), client, "", 2*time.Second)
	<-done
	if err == nil {
		t.Fatalf("pgProbe: expected failure on ErrorResponse during startup, got nil error")
	}
}

func TestPgProbe_AuthRequiredIsFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		hdr := make([]byte, 4)
		if _, err := readFullTest(server, hdr); err != nil {
			return
		}
		mlen := binary.BigEndian.Uint32(hdr)
		body := make([]byte, mlen-4)
		_, _ = readFullTest(server, body)

		// AuthenticationCleartextPassword: type 'R', authtype=3 (non-zero => must fail).
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, 3)
		buf := make([]byte, 0, 9)
		buf = append(buf, 'R')
		buf = binary.BigEndian.AppendUint32(buf, uint32(4+len(payload)))
		buf = append(buf, payload...)
		_, _ = server.Write(buf)
	}()

	err := pgProbe(context.Background(), client, "", 2*time.Second)
	<-done
	if err == nil {
		t.Fatalf("pgProbe: expected AuthRequired failure (probe must never authenticate), got nil error")
	}
}

// --- respPing: RESP-encoded PING requiring the literal +PONG\r\n reply ---

func TestRespPing_Success(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, len("*1\r\n$4\r\nPING\r\n"))
		_, _ = readFullTest(server, buf)
		_, _ = server.Write([]byte("+PONG\r\n"))
	}()

	err := respPing(client, 2*time.Second)
	<-done
	if err != nil {
		t.Fatalf("respPing: expected success, got error: %v", err)
	}
}

func TestRespPing_WrongReplyIsFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, len("*1\r\n$4\r\nPING\r\n"))
		_, _ = readFullTest(server, buf)
		// respPing only ever reads exactly 7 bytes (len("+PONG\r\n")), so write exactly 7
		// bytes here too — net.Pipe is synchronous/unbuffered, and writing more than the
		// reader ever consumes would block this goroutine forever waiting for a read that
		// never comes.
		_, _ = server.Write([]byte("-ERR un"))
	}()

	err := respPing(client, 2*time.Second)
	<-done
	if err == nil {
		t.Fatalf("respPing: expected failure on non-PONG reply, got nil error")
	}
}

// --- httpGet2xx: requires genuine [200,300), refuses to follow redirects ---

func TestHttpGet2xx_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	addr := ts.Listener.Addr().String()
	if err := httpGet2xx(context.Background(), addr, "/", 2*time.Second); err != nil {
		t.Fatalf("httpGet2xx: expected success, got error: %v", err)
	}
}

func TestHttpGet2xx_RedirectIsFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer ts.Close()

	addr := ts.Listener.Addr().String()
	if err := httpGet2xx(context.Background(), addr, "/", 2*time.Second); err == nil {
		t.Fatalf("httpGet2xx: expected failure on 3xx redirect (CheckRedirect must refuse to follow), got nil error")
	}
}

func TestHttpGet2xx_5xxIsFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	addr := ts.Listener.Addr().String()
	if err := httpGet2xx(context.Background(), addr, "/", 2*time.Second); err == nil {
		t.Fatalf("httpGet2xx: expected failure on 500, got nil error")
	}
}

// --- dialAllowed: fail-closed SSRF pod-CIDR allowlist ---

// TestDialAllowed_FailsClosedWithNoK8sClient asserts the documented fail-closed contract at
// server.go (podCIDRAllowlist comment: "an unpopulated/empty allowlist makes dialAllowed fail
// CLOSED (refuse), never open"). An AgentServer with no k8sClient wired can never populate a
// pod-CIDR allowlist, so every dial — including one that targets a syntactically valid pod
// IP — must be refused.
func TestDialAllowed_FailsClosedWithNoK8sClient(t *testing.T) {
	s := &AgentServer{}
	err := s.dialAllowed(context.Background(), "10.244.1.5:5432")
	if err == nil {
		t.Fatalf("dialAllowed: expected fail-closed refusal with no k8sClient/allowlist wired, got nil error (SSRF containment would be bypassed)")
	}
}

// --- SSRF allowlist source-of-truth: Cilium IPAM podCIDRs, not Node.Spec.PodCIDRs ---

// TestParseCIDRAllowlist_AdmitsRealCiliumPodIPRefusesEverythingElse grounds the sprint46B7
// Validation cycle-2 security-lens fix in LIVE cluster state (read 2026-07-14 from the standing
// KVM cluster): Node.Spec.PodCIDRs and CiliumNode.spec.ipam.podCIDRs are PERMUTED on this Cilium
// cluster-pool substrate — pm-w2's Node.Spec.PodCIDRs=10.244.2.0/24, but pm-w2's pods are actually
// allocated from Cilium's 10.244.1.0/24 (the restored redis pod in the failing live proof held
// 10.244.1.203). nodePodCIDRAllowlist now keys on the Cilium block, so parseCIDRAllowlist of that
// block MUST admit the real pod IP and refuse both the wrong Node.Spec /24 and any non-pod IP
// (SSRF containment preserved). Derived from real cluster state, not an injected equality.
func TestParseCIDRAllowlist_AdmitsRealCiliumPodIPRefusesEverythingElse(t *testing.T) {
	// pm-w2's AUTHORITATIVE Cilium cluster-pool block (CiliumNode.spec.ipam.podCIDRs).
	allow := parseCIDRAllowlist([]string{"10.244.1.0/24"})
	if len(allow) != 1 {
		t.Fatalf("parseCIDRAllowlist: expected 1 parsed CIDR, got %d", len(allow))
	}
	contains := func(ip string) bool {
		parsed := net.ParseIP(ip)
		for _, n := range allow {
			if n.Contains(parsed) {
				return true
			}
		}
		return false
	}
	// The real restored-pod IP from the live proof — refused before this fix, must be admitted now.
	if !contains("10.244.1.203") {
		t.Fatalf("SSRF allowlist keyed on Cilium podCIDRs must ADMIT the real pm-w2 pod IP 10.244.1.203")
	}
	// The WRONG /24 Node.Spec.PodCIDRs named for pm-w2 — holds no real pods, must NOT be admitted.
	if contains("10.244.2.203") {
		t.Fatalf("SSRF allowlist must NOT admit 10.244.2.203 (pm-w2 Node.Spec /24 holds no Cilium-allocated pods)")
	}
	// Off-cluster / SSRF target — containment must hold.
	if contains("8.8.8.8") {
		t.Fatalf("SSRF allowlist must NEVER admit an off-cluster IP (containment bypass)")
	}
}

// TestParseCIDRAllowlist_FailsClosedOnEmptyOrGarbage asserts the fail-CLOSED contract at the parse
// layer: a nil/empty/unparsable podCIDRs list (absent or unreadable CiliumNode) yields an empty
// allowlist so dialAllowed refuses every dial — never a Node.Spec.PodCIDRs fallback (invariant #10).
func TestParseCIDRAllowlist_FailsClosedOnEmptyOrGarbage(t *testing.T) {
	for _, in := range [][]string{nil, {}, {"not-a-cidr"}, {"10.244.1.5"}} {
		if got := parseCIDRAllowlist(in); len(got) != 0 {
			t.Fatalf("parseCIDRAllowlist(%v): expected empty (fail-closed) allowlist, got %d entries", in, len(got))
		}
	}
}

func TestDialAllowed_RejectsNonIPHost(t *testing.T) {
	s := &AgentServer{}
	err := s.dialAllowed(context.Background(), "not-an-ip:5432")
	if err == nil {
		t.Fatalf("dialAllowed: expected refusal for a non-IP host, got nil error")
	}
}

// --- dialAllowedForServiceContinuity (ADR-0352 D1.2): scoped SSRF-allowlist variant ---

// TestDialAllowedForServiceContinuity_PermitsExactExpectedClusterIP asserts the ADR-0352 D1.2
// scoped-allowlist exception: an address outside the pod-CIDR allowlist (a Service ClusterIP,
// e.g. 10.96.0.0/12) is permitted ONLY when it matches expectedClusterIP exactly.
func TestDialAllowedForServiceContinuity_PermitsExactExpectedClusterIP(t *testing.T) {
	s := &AgentServer{}
	err := s.dialAllowedForServiceContinuity(context.Background(), "10.96.0.10:6379", "10.96.0.10")
	if err != nil {
		t.Fatalf("dialAllowedForServiceContinuity: expected the exact expected ClusterIP to be permitted, got: %v", err)
	}
}

// TestDialAllowedForServiceContinuity_RefusesMismatchedAddress proves this is NOT a CIDR-range
// widening: an address that does not equal expectedClusterIP (even a different Service CIDR IP)
// is refused. The ADR-0325 SSRF containment property must survive for every non-exact address.
func TestDialAllowedForServiceContinuity_RefusesMismatchedAddress(t *testing.T) {
	s := &AgentServer{}
	err := s.dialAllowedForServiceContinuity(context.Background(), "10.96.0.99:6379", "10.96.0.10")
	if err == nil {
		t.Fatalf("dialAllowedForServiceContinuity: expected refusal — address does not match expectedClusterIP (no CIDR-range widening permitted)")
	}
}

// TestDialAllowedForServiceContinuity_RefusesWhenExpectedClusterIPEmpty proves the guard does
// not silently degrade to "any address is fine" when the caller forgets to supply
// expectedClusterIP — it must fail closed exactly like plain dialAllowed.
func TestDialAllowedForServiceContinuity_RefusesWhenExpectedClusterIPEmpty(t *testing.T) {
	s := &AgentServer{}
	err := s.dialAllowedForServiceContinuity(context.Background(), "10.96.0.10:6379", "")
	if err == nil {
		t.Fatalf("dialAllowedForServiceContinuity: expected refusal when expectedClusterIP is empty (fail closed, no silent bypass)")
	}
}
