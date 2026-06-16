//go:build !dev

/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package tls

import (
	"crypto/tls"
	"fmt"
)

// loadServerConfigInsecureDev is the DEFAULT-BUILD (production) implementation: there is no
// insecure fallback. ADR-SEC-A §2.1 (C-330/N-339): absent cert material is a FATAL error so the
// agent refuses to start fail-open. The fail-open path exists only in tls_insecure_dev.go under
// //go:build dev + PODMOTION_INSECURE_GRPC=true.
func loadServerConfigInsecureDev(certFile, keyFile, caFile string) (*tls.Config, error) {
	return nil, fmt.Errorf("ADR-SEC-A: TLS material absent at %q/%q/%q — refusing to start fail-open (fail-closed mTLS required)", certFile, keyFile, caFile)
}

// loadClientConfigInsecureDev is the DEFAULT-BUILD (production) implementation. ADR-SEC-A §2.1
// (C-330/N-340): the operator refuses to dial plaintext.
func loadClientConfigInsecureDev(certFile, keyFile, caFile string) (*tls.Config, error) {
	return nil, fmt.Errorf("ADR-SEC-A: operator agent client has no TLS material at %q/%q/%q — refusing to dial plaintext (fail-closed mTLS required)", certFile, keyFile, caFile)
}
