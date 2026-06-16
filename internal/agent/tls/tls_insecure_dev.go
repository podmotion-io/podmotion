//go:build dev

/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package tls

import (
	"crypto/tls"
	"fmt"
	"os"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var devLog = logf.Log.WithName("agent-tls")

// loadServerConfigInsecureDev is the DEV-BUILD (//go:build dev) fail-open path. Per ADR-0023:39-46
// and ADR-SEC-A §2.4, it is additionally gated on PODMOTION_INSECURE_GRPC=true and emits the exact
// WARN line ADR-0023:42 specifies. Absent that env, even the dev build fails closed.
func loadServerConfigInsecureDev(certFile, keyFile, caFile string) (*tls.Config, error) {
	if os.Getenv("PODMOTION_INSECURE_GRPC") != "true" {
		return nil, fmt.Errorf("ADR-SEC-A: TLS material absent at %q/%q/%q and PODMOTION_INSECURE_GRPC!=true — refusing to start fail-open", certFile, keyFile, caFile)
	}
	devLog.Info("WARNING: PODMOTION_INSECURE_GRPC=true — starting gRPC server WITHOUT TLS (dev build only, insecure)",
		"certFile", certFile, "keyFile", keyFile, "caFile", caFile)
	return nil, nil //nolint:nilnil // intentional dev-only insecure: nil means plaintext
}

// loadClientConfigInsecureDev is the DEV-BUILD operator-client fail-open path, identically gated.
func loadClientConfigInsecureDev(certFile, keyFile, caFile string) (*tls.Config, error) {
	if os.Getenv("PODMOTION_INSECURE_GRPC") != "true" {
		return nil, fmt.Errorf("ADR-SEC-A: operator client TLS material absent and PODMOTION_INSECURE_GRPC!=true — refusing to dial plaintext")
	}
	devLog.Info("WARNING: PODMOTION_INSECURE_GRPC=true — operator dialing agent WITHOUT TLS (dev build only, insecure)")
	return nil, nil //nolint:nilnil
}
