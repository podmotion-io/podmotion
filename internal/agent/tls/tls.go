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

const (
	// DefaultCertFile is the standard mount path for the TLS certificate.
	DefaultCertFile = "/etc/podmotion/tls/tls.crt"
	// DefaultKeyFile is the standard mount path for the TLS private key.
	DefaultKeyFile = "/etc/podmotion/tls/tls.key"
	// DefaultCAFile is the standard mount path for the CA bundle (for client cert verification).
	DefaultCAFile = "/etc/podmotion/tls/ca.crt"
)

var log = logf.Log.WithName("agent-tls")

// LoadServerConfig returns a *tls.Config suitable for the gRPC server.
// Requires client certificates signed by the PodMotion CA (mTLS).
// Falls back to insecure (nil) if cert files are absent — dev/test mode only.
func LoadServerConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if !filesExist(certFile, keyFile, caFile) {
		log.Info("TLS cert files not found — starting gRPC server without TLS (dev mode only)",
			"certFile", certFile, "keyFile", keyFile, "caFile", caFile)
		return nil, nil //nolint:nilnil // intentional: nil means insecure
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
// Falls back to insecure if cert files are absent.
func LoadClientConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if !filesExist(certFile, keyFile, caFile) {
		log.Info("TLS cert files not found — connecting to agent without TLS (dev mode only)")
		return nil, nil //nolint:nilnil
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
