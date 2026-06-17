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

	"github.com/podmotion-io/podmotion/internal/agent/authz"
)

// AdrSecCMarker forces the literal marker string "ADR-SEC-C" into the operator /manager binary's
// string table so a deployed binary can be confirmed to contain the operator→agent SPIFFE-verify
// fix (`strings /manager | grep -c 'ADR-SEC-C'`). That fix lives only in this binary. Exported so
// the linker cannot drop it as dead code even if every error-string reference is refactored.
const AdrSecCMarker = "ADR-SEC-C"

var log = logf.Log.WithName("agent-tls")

// ExpectedAgentSPIFFEID builds the canonical agent SPIFFE ID for a release namespace. It MUST
// match the URI SAN issued in charts/podmotion/templates/agent-mtls-certs.yaml line 56
// (spiffe://podmotion.io/ns/<ns>/sa/podmotion-agent). Derived from the runtime namespace (never
// hardcoded) so a non-default-namespace install pins the correct identity (ADR-SEC-C).
func ExpectedAgentSPIFFEID(namespace string) string {
	return authz.SPIFFEPrefix + "ns/" + namespace + "/sa/podmotion-agent"
}

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
// ADR-SEC-A: in the default (non-dev) build this is FAIL-CLOSED —
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
// ADR-SEC-A: fail-closed in the default build — absent cert material
// is a FATAL error. The fail-open branch survives ONLY under //go:build dev +
// PODMOTION_INSECURE_GRPC=true (see tls_insecure_dev.go).
//
// ADR-SEC-C: the operator dials the agent BY IP (NMC spec.agentEndpoint = <nodeIP>:9090),
// but the agent leaf carries ONLY a SPIFFE URI SAN (no IP/DNS SAN). Go's default verifier would
// require an IP SAN and fail closed. Instead we delegate verification to VerifyPeerCertificate,
// which (1) rebuilds and verifies the peer chain against the PodMotion CA, then (2) pins the agent
// SPIFFE identity by EXACT equality. namespace is the operator's runtime namespace (downward API),
// used to derive the expected agent SPIFFE ID — never hardcoded.
func LoadClientConfig(certFile, keyFile, caFile, namespace string) (*tls.Config, error) {
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

	expectedAgentID := ExpectedAgentSPIFFEID(namespace)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// ADR-SEC-C: verification is FULLY delegated to VerifyPeerCertificate below, which
		// rebuilds the chain against caPool AND pins the agent SPIFFE ID by exact equality. This is
		// STRICTLY STRONGER than Go's default IP-SAN match — it is NOT an unverified path
		// (ADR-SEC-A). RootCAs is intentionally omitted (ignored under InsecureSkipVerify);
		// caPool is captured into the callback closure instead.
		InsecureSkipVerify:    true, //nolint:gosec // verification delegated to VerifyPeerCertificate (chain build + SPIFFE-ID exact pin); stronger than default IP-SAN match (ADR-SEC-C)
		VerifyPeerCertificate: verifyAgentSPIFFE(caPool, expectedAgentID),
	}, nil
}

// verifyAgentSPIFFE returns the operator-side peer-cert verifier (ADR-SEC-C). The closure
// captures caPool (the SAME pool loaded by loadCAPool — it MUST be used even though
// tls.Config.RootCAs is ignored under InsecureSkipVerify) and the expected agent SPIFFE ID.
//
// In order:
//  1. Parse each rawCert; rawCerts[0] is the leaf, rawCerts[1:] are intermediates.
//  2. Build x509.VerifyOptions{Roots: caPool, Intermediates: <rawCerts[1:]>, KeyUsages: ServerAuth}.
//  3. leaf.Verify(opts) — fail closed on ANY error (the chain-of-trust check Go no longer does).
//  4. Require EXACTLY ONE URI SAN on the verified leaf (shared helper).
//  5. Assert the URI equals expectedAgentID by EXACT string equality — never prefix/suffix/contains.
//  6. Log the matched ID.
func verifyAgentSPIFFE(caPool *x509.CertPool, expectedAgentID string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("ADR-SEC-C: peer presented no certificate")
		}
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for i, raw := range rawCerts {
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("ADR-SEC-C: parse peer cert[%d]: %w", i, err)
			}
			certs = append(certs, c)
		}
		leaf := certs[0]

		intermediates := x509.NewCertPool()
		for _, c := range certs[1:] {
			intermediates.AddCert(c)
		}
		opts := x509.VerifyOptions{
			Roots:         caPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if _, err := leaf.Verify(opts); err != nil {
			return fmt.Errorf("ADR-SEC-C: agent cert chain verify failed: %w", err)
		}

		// Read the canonical single SPIFFE URI from the VERIFIED leaf (shared helper requires
		// exactly one URI SAN — a multi-URI or zero-URI cert is rejected here).
		id, ok := authz.CanonicalSPIFFEID(leaf)
		if !ok {
			return fmt.Errorf("ADR-SEC-C: agent leaf must carry exactly one SPIFFE URI SAN (got %d)", len(leaf.URIs))
		}
		// EXACT equality pin — never HasPrefix/HasSuffix/Contains. A stolen operator leaf, a
		// peer-agent leaf for another identity, or any non-agent CA-signed leaf MUST NOT match.
		if id != expectedAgentID {
			return fmt.Errorf("ADR-SEC-C: agent SPIFFE ID mismatch: got %q, expected %q", id, expectedAgentID)
		}
		log.Info("ADR-SEC-C: operator→agent peer verified", "spiffe", id, "expected", expectedAgentID)
		return nil
	}
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
