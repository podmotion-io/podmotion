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

func TestDialAllowed_RejectsNonIPHost(t *testing.T) {
	s := &AgentServer{}
	err := s.dialAllowed(context.Background(), "not-an-ip:5432")
	if err == nil {
		t.Fatalf("dialAllowed: expected refusal for a non-IP host, got nil error")
	}
}
