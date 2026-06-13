//go:build chaos_test

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

// Package chaos provides fault injection primitives and assertion helpers for
// PodMotion chaos gate scenarios (ADR-0097).
package chaos

import (
	"context"
	"sync"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RSTEvent is a single TCP-RST evidence record read from the pm_rst_events BPF ring buffer.
type RSTEvent struct {
	// SrcIP and DstIP are the connection endpoints.
	SrcIP string
	DstIP string
	// SrcPort and DstPort are the port numbers.
	SrcPort uint16
	DstPort uint16
	// TimestampNs is the kernel timestamp of the intercepted RST.
	TimestampNs int64
}

// FaultFixture is the top-level test fixture for chaos scenarios.
// It holds a controller-runtime WithWatch client (which extends client.Client
// with Watch support), the target PodMigration NamespacedName,
// and an in-memory collector for pm_rst_events ring buffer events.
type FaultFixture struct {
	// Client must implement client.WithWatch so that WaitForSyncPoint can
	// open a watch on PodMigration objects without time.Sleep (ADR-0097 §3).
	Client client.WithWatch

	// PMNN is the NamespacedName of the PodMigration under test.
	PMNN types.NamespacedName

	mu        sync.Mutex
	rstEvents []RSTEvent
}

// RecordRSTEvent appends an RST event to the in-memory slice.
// Called by the ring buffer consumer goroutine started in Setup().
func (f *FaultFixture) RecordRSTEvent(ev RSTEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rstEvents = append(f.rstEvents, ev)
}

// RSTEvents returns a snapshot of all RST events collected so far.
func (f *FaultFixture) RSTEvents() []RSTEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]RSTEvent, len(f.rstEvents))
	copy(out, f.rstEvents)
	return out
}

// Setup pins the pm_rst_events BPF ring buffer on the source and destination
// nodes and starts a consumer goroutine. The goroutine runs until ctx is
// cancelled. See ADR-0097 §4.
//
// In unit/integration test environments where the BPF map is not present the
// function is a no-op (the map path check returns quickly).
func (f *FaultFixture) Setup(ctx context.Context) error {
	// Start the ring-buffer consumer. In environments without BPF support
	// (CI without privileged containers) this goroutine exits immediately.
	go consumeRSTRingBuffer(ctx, f)
	return nil
}
