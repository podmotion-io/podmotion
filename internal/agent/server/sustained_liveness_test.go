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
	"sync/atomic"
	"testing"
	"time"
)

// ADR-0325 round-3 (sprint46B9) regression coverage for the SUSTAINED workload-liveness
// primitive. These tests prove the property the earlier single-shot gate lacked: a backend that
// answers the PostgreSQL auth CHALLENGE once (or for one brief window) and then crashes/refuses
// connections MUST NOT be reported live. The harness's own pg_isready check caught this
// crash-loop; the operator's single-shot gate did not. sustainedProbe is the fix.
//
// The regression uses a REAL net.Listener (not net.Pipe) so each sustainedProbe attempt performs
// an independent dial — exactly modelling how a flapping backend presents to the network probe:
// the first connection is accepted and answered, later connections hit a closed/refused socket.

// writePgAuthChallenge writes a wire-correct AuthenticationCleartextPassword challenge ('R',
// authtype=3) — the same "a live postmaster answered the handshake" signal a password-protected
// Postgres emits, which pgProbe (correctly, by design) treats as liveness for ONE instant.
func writePgAuthChallenge(conn net.Conn) {
	// Drain the client's StartupMessage first (length-prefixed, no type byte).
	hdr := make([]byte, 4)
	if _, err := readFullTest(conn, hdr); err != nil {
		return
	}
	mlen := binary.BigEndian.Uint32(hdr)
	if mlen >= 4 {
		body := make([]byte, mlen-4)
		_, _ = readFullTest(conn, body)
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, 3) // AuthenticationCleartextPassword
	buf := make([]byte, 0, 5+len(payload))
	buf = append(buf, 'R')
	buf = binary.BigEndian.AppendUint32(buf, uint32(4+len(payload)))
	buf = append(buf, payload...)
	_, _ = conn.Write(buf)
}

// TestSustainedProbe_FlappingBackendRejected is the core regression: a listener that answers the
// Postgres auth challenge on the FIRST connection then stops accepting (closed listener → dials
// refused) must NOT pass the sustained probe. A single-shot probe would have returned success on
// that first answer and flipped WorkloadLivenessVerified=True, deleting the source pod over a
// crash-looping destination.
func TestSustainedProbe_FlappingBackendRejected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	var accepted int32
	go func() {
		// Accept exactly one connection, answer the challenge, then CLOSE the listener so every
		// subsequent dial is refused — the network signature of a backend that answered once and
		// then crashed / went into CrashLoopBackOff.
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		atomic.AddInt32(&accepted, 1)
		writePgAuthChallenge(conn)
		_ = conn.Close()
		_ = ln.Close()
	}()

	probeOnce := func(ctx context.Context) error {
		conn, derr := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if derr != nil {
			return derr // ECONNREFUSED once the flapping backend is down
		}
		defer conn.Close()
		return pgProbe(ctx, conn, "", 2*time.Second)
	}

	// Small interval keeps the test fast while still exercising the multi-attempt window.
	err = sustainedProbe(context.Background(), 3, 50*time.Millisecond, probeOnce)
	if err == nil {
		t.Fatalf("sustainedProbe: a backend that answered the auth challenge ONCE then refused connections must NOT be reported live (single-shot regression)")
	}
	if got := atomic.LoadInt32(&accepted); got < 1 {
		t.Fatalf("sustainedProbe: expected the first attempt to reach the backend; accepted=%d", got)
	}
}

// TestSustainedProbe_HealthyBackendPasses is the positive control: a listener that keeps
// answering the auth challenge on EVERY connection across the whole window passes — the fix does
// not reject a genuinely-sustained backend.
func TestSustainedProbe_HealthyBackendPasses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	stop := make(chan struct{})
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			writePgAuthChallenge(conn)
			_ = conn.Close()
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	defer close(stop)

	probeOnce := func(ctx context.Context) error {
		conn, derr := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if derr != nil {
			return derr
		}
		defer conn.Close()
		return pgProbe(ctx, conn, "", 2*time.Second)
	}

	if err := sustainedProbe(context.Background(), 3, 50*time.Millisecond, probeOnce); err != nil {
		t.Fatalf("sustainedProbe: a backend that keeps answering across the window must PASS, got: %v", err)
	}
}

// TestSustainedProbe_FailFastOnFirstAttempt proves the fail-fast contract: if the very first
// attempt fails, the window short-circuits immediately without waiting out the remaining
// intervals (an unhealthy destination is rejected fast, not after the full window).
func TestSustainedProbe_FailFastOnFirstAttempt(t *testing.T) {
	var attempts int32
	probeOnce := func(context.Context) error {
		atomic.AddInt32(&attempts, 1)
		return errFakeProbe
	}
	start := time.Now()
	err := sustainedProbe(context.Background(), 4, 500*time.Millisecond, probeOnce)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("sustainedProbe: expected failure when the first attempt fails")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("sustainedProbe: fail-fast must stop after the first failing attempt, got %d attempts", got)
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("sustainedProbe: fail-fast must not wait out the inter-attempt interval, elapsed=%s", elapsed)
	}
}

// TestSustainedProbe_LaterAttemptFailureRejected proves the middle-of-window case: a backend that
// passes the first attempt but fails a LATER one (the crash-loop lands mid-window) is rejected.
func TestSustainedProbe_LaterAttemptFailureRejected(t *testing.T) {
	var attempts int32
	probeOnce := func(context.Context) error {
		if atomic.AddInt32(&attempts, 1) >= 3 {
			return errFakeProbe
		}
		return nil
	}
	if err := sustainedProbe(context.Background(), 4, 10*time.Millisecond, probeOnce); err == nil {
		t.Fatalf("sustainedProbe: a backend that fails a later attempt (crash mid-window) must be rejected")
	}
}

var errFakeProbe = &fakeProbeError{}

type fakeProbeError struct{}

func (*fakeProbeError) Error() string { return "fake probe failure" }
