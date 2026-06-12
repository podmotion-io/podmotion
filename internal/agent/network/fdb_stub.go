// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !linux

package network

import (
	"context"
	"fmt"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// fdbManagerStub satisfies FDBManager for non-Linux builds (macOS dev, unit tests).
type fdbManagerStub struct{}

// NewFDBManager returns the stub FDB manager on non-Linux platforms.
func NewFDBManager() FDBManager {
	return &fdbManagerStub{}
}

func (s *fdbManagerStub) AddFDBEntry(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("AddFDBEntry: %w", err)
	}
	log.Info("fdb stub: RTM_NEWNEIGH (AF_BRIDGE)", "ifName", e.IfName, "podMAC", e.PodMAC, "vtepIP", e.VTEPIP)
	log.Info("fdb stub: RTM_NEWNEIGH (AF_INET)", "ifName", e.IfName, "podIP", e.PodIP, "podMAC", e.PodMAC)
	return nil
}

func (s *fdbManagerStub) RemoveFDBEntry(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("RemoveFDBEntry: %w", err)
	}
	log.Info("fdb stub: RTM_DELNEIGH (AF_BRIDGE)", "ifName", e.IfName, "podMAC", e.PodMAC)
	log.Info("fdb stub: RTM_DELNEIGH (AF_INET)", "ifName", e.IfName, "podIP", e.PodIP)
	return nil
}

func (s *fdbManagerStub) ConfirmOverlayReady(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("ConfirmOverlayReady: %w", err)
	}
	log.Info("fdb stub: RTM_GETNEIGH read-back — overlay assumed ready",
		"ifName", e.IfName, "podIP", e.PodIP, "podMAC", e.PodMAC, "vtepIP", e.VTEPIP)
	return nil
}
