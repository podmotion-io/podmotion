/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package transfer provides WAN checkpoint transfer for cross-cluster migrations.
// OCI registry is the transfer medium (ADR-0034): the source cluster pushes a
// checkpoint image; the destination cluster pulls it. DirectP2P is explicitly
// unsupported for cross-cluster migrations because it requires routable pod IPs
// between clusters which cannot be assumed over a WAN.
package transfer

import (
	"context"
	"crypto/tls"
	"fmt"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("wan-transfer")

// TLSConfig carries optional TLS material for registry communication.
// An empty struct means use the system CA pool with standard TLS verification.
type TLSConfig struct {
	// CACert is the PEM-encoded CA certificate for the registry, or empty to use
	// the system pool.
	CACert []byte
	// ClientCert and ClientKey are PEM-encoded material for mutual TLS auth.
	// Both must be set together, or both empty.
	ClientCert []byte
	ClientKey  []byte
	// InsecureSkipVerify disables TLS verification. Never set true in production.
	InsecureSkipVerify bool
}

// ToTLSConfig converts to a *tls.Config. Returns nil (use defaults) when the
// struct is zero-valued with InsecureSkipVerify=false.
func (c TLSConfig) ToTLSConfig() (*tls.Config, error) {
	if len(c.CACert) == 0 && len(c.ClientCert) == 0 && !c.InsecureSkipVerify {
		return nil, nil
	}
	cfg := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // caller-controlled opt-in
	}
	if len(c.ClientCert) > 0 && len(c.ClientKey) > 0 {
		cert, err := tls.X509KeyPair(c.ClientCert, c.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("parsing client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// WANTransferAgent transfers a CRIU checkpoint OCI image between clusters via
// a registry reachable by both source and destination. Each container's dump
// directory becomes a separate OCI layer so that partial pulls are possible
// when only some containers change between incremental checkpoints.
type WANTransferAgent interface {
	// PushToRegistry creates an OCI image from the CRIU dump files rooted at
	// imagesDir and pushes it to registryRef (e.g. registry.example.com/pm-checkpoints/pod-abc:latest).
	PushToRegistry(ctx context.Context, imagesDir, registryRef string, tlsCfg TLSConfig) error

	// PullFromRegistry pulls the OCI image at registryRef and extracts it to
	// outputDir, preserving the per-container layer structure.
	PullFromRegistry(ctx context.Context, registryRef, outputDir string, tlsCfg TLSConfig) error
}

// WANTransferStub satisfies WANTransferAgent with no-op logging.
// Used until M14 WAN transfer is fully wired to go-containerregistry.
type WANTransferStub struct{}

var _ WANTransferAgent = (*WANTransferStub)(nil)

func (s *WANTransferStub) PushToRegistry(_ context.Context, imagesDir, registryRef string, _ TLSConfig) error {
	log.Info("stub: would push checkpoint OCI image to registry",
		"imagesDir", imagesDir, "registryRef", registryRef)
	return nil
}

func (s *WANTransferStub) PullFromRegistry(_ context.Context, registryRef, outputDir string, _ TLSConfig) error {
	log.Info("stub: would pull checkpoint OCI image from registry",
		"registryRef", registryRef, "outputDir", outputDir)
	return nil
}
