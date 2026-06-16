/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package tls loads mTLS configuration for the node agent gRPC server and operator client.
// Certificates are provisioned by cert-manager and mounted as Kubernetes secrets.
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("agent-tls")

const (
	// DefaultCertFile is the standard mount path for the TLS certificate.
	DefaultCertFile = "/etc/podmotion/tls/tls.crt"
	// DefaultKeyFile is the standard mount path for the TLS private key.
	DefaultKeyFile = "/etc/podmotion/tls/tls.key"
	// DefaultCAFile is the standard mount path for the CA bundle (for client cert verification).
	DefaultCAFile = "/etc/podmotion/tls/ca.crt"
)

// LoadServerConfig returns a *tls.Config suitable for the gRPC server.
// Requires client certificates signed by the PodMotion CA (mTLS).
//
// ADR-SEC-A §2.1 (C-330/N-339): in the default (non-dev) build this is FAIL-CLOSED —
// absent cert material is a FATAL error (the agent refuses to start fail-open). The
// fail-open branch survives ONLY under //go:build dev + PODMOTION_INSECURE_GRPC=true
// (see tls_insecure_dev.go). loadServerConfigInsecureDev is provided by exactly one of
// tls_insecure.go (default: returns a fatal error) or tls_insecure_dev.go (dev build).
func LoadServerConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if !filesExist(certFile, keyFile, caFile) {
		return loadServerConfigInsecureDev(certFile, keyFile, caFile)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}

	caPool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		// Require and verify client certificates — both operator and peer agents must present certs.
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}, nil
}

// LoadClientConfig returns a *tls.Config for the operator-to-agent gRPC client.
//
// ADR-SEC-A §2.1 (C-330/N-340): fail-closed in the default build — absent cert material
// is a FATAL error. The fail-open branch survives ONLY under //go:build dev +
// PODMOTION_INSECURE_GRPC=true (see tls_insecure_dev.go).
func LoadClientConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if !filesExist(certFile, keyFile, caFile) {
		return loadClientConfigInsecureDev(certFile, keyFile, caFile)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	caPool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no valid certificates found in CA file %q", caFile)
	}
	return pool, nil
}

func filesExist(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return false
		}
	}
	return true
}
