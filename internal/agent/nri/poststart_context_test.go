/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package nri

import (
	"context"
	"testing"
	"time"
)

// TestHandlePostStartContainer_DecouplesFromInboundContext is the live-bug regression for the
// 2026-07-10 redis restore hang.
//
// Live failure: HandlePostStartContainer ran the 50s holder-quiescent barrier and the CRIU
// restore on containerd's PER-EVENT context, which is bounded by plugin_request_timeout = 2s.
// The barrier's select hit ctx.Done() at ~2s every time, the handler returned a hard error,
// containerd dropped the plugin connection, and the migration was forced onto the raw-CRIU
// fallback. The fix runs the barrier + restore on an INDEPENDENT context and returns nil to
// containerd promptly.
//
// This test passes an ALREADY-CANCELLED inbound context (the worst case of the 2s budget) and
// asserts:
//  1. the handler returns nil promptly (does not block, does not propagate the cancellation as
//     an error to containerd), and
//  2. OnStartContainer still runs asynchronously on a LIVE (non-cancelled) context — proving the
//     restore is no longer governed by the inbound event context.
func TestHandlePostStartContainer_DecouplesFromInboundContext(t *testing.T) {
	const ref = "redis-live-migration"

	// The provenance sentinel gate runs (inside the async goroutine) before OnStartContainer.
	// Stub it to pass so the async restore reaches OnStartContainer without a writable
	// /run/podmotion tree. Restored after the test.
	origSentinel := verifyCheckpointProvenanceSentinel
	verifyCheckpointProvenanceSentinel = func(string) error { return nil }
	defer func() { verifyCheckpointProvenanceSentinel = origSentinel }()

	restoreRan := make(chan error, 1)
	p := &Plugin{
		OnStartContainer: func(ctx context.Context, _ ContainerEvent, _ string) error {
			// Record whether the restore's context is live (not the cancelled inbound one).
			restoreRan <- ctx.Err()
			return nil
		},
	}

	event := ContainerEvent{
		ID:   "container-abc",
		Name: "redis",
		Annotations: map[string]string{
			"podmotion.io/checkpoint-ref": ref,
			// No "original-command-overridden=true" → waitForHolderQuiescent returns immediately
			// via the "annotation absent — skipping barrier" fast path, so the async restore
			// proceeds to OnStartContainer without needing a real holder.
			"podmotion.io/restore-target-containers": "redis",
		},
	}

	// Inbound context: already cancelled — the worst case of the 2s plugin_request_timeout.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := p.HandlePostStartContainer(cancelledCtx, event)
	if err != nil {
		t.Fatalf("HandlePostStartContainer returned error on cancelled inbound ctx (must return nil, not propagate cancellation): %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("HandlePostStartContainer blocked %v — it must return promptly and run restore async", elapsed)
	}

	select {
	case restoreCtxErr := <-restoreRan:
		if restoreCtxErr != nil {
			t.Errorf("OnStartContainer ran on a cancelled context (err=%v) — restore is still governed by the inbound 2s event context", restoreCtxErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnStartContainer did not run asynchronously within 5s")
	}
}
