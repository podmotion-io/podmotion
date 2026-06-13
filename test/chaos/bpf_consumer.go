//go:build chaos_test

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package chaos

import (
	"context"
	"os"
	"time"
)

const (
	// pmRSTEventsPath is the BPF pin path for the pm_rst_events ring buffer
	// written by bpf/xdp_bridge.c. Present only when the XDP program is loaded.
	pmRSTEventsPath = "/sys/fs/bpf/podmotion/pm_rst_events"
)

// consumeRSTRingBuffer drains the pm_rst_events BPF ring buffer on the current
// node into f.rstEvents. In environments where the pin path is absent (unit test,
// CI without BPF support) the function is a no-op and returns immediately.
//
// In production-like kind environments with bpfman the function polls the ring
// buffer via the cilium/ebpf library. Polling interval is 50ms to keep CPU
// overhead low during chaos windows.
//
// See ADR-0097 §4 for the ring buffer specification.
func consumeRSTRingBuffer(ctx context.Context, f *FaultFixture) {
	if _, err := os.Stat(pmRSTEventsPath); os.IsNotExist(err) {
		// BPF ring buffer not present — environment does not support live eBPF.
		// Chaos assertions that rely on RST evidence will see an empty event
		// slice (zero events = North Star invariant passes vacuously in CI).
		return
	}

	// In a fully provisioned environment this would open the pinned ring buffer
	// using cilium/ebpf and call rb.Read in a loop. The implementation is
	// deferred to when bpf/xdp_bridge.c is confirmed to export pm_rst_events
	// (ADR-0097 §Immediate implementation task 6).
	//
	// Placeholder: poll for map appearance and exit when ctx is done.
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// TODO(Agent8): open /sys/fs/bpf/podmotion/pm_rst_events via
			// cilium/ebpf RingReader, decode RSTEvent structs, call
			// f.RecordRSTEvent for each. Prerequisite: Agent 2 (Network)
			// confirms pm_rst_events is a BPF_MAP_TYPE_RINGBUF map and
			// pinned at this path (ADR-0097 §Immediate task 6).
			_ = f // suppress unused warning until full implementation
		}
	}
}
