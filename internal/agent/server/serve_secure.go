//go:build !dev

/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

import "fmt"

// adrSecAHandleNoTLS is the DEFAULT-BUILD (production) behavior: a nil tlsCfg reaching
// ListenAndServe is a fatal refusal to serve plaintext (ADR-SEC-A §2.1, C-330). It NEVER logs
// "gRPC server starting without TLS". This is defense-in-depth behind the fail-closed
// LoadServerConfig which already fatals before this point.
func adrSecAHandleNoTLS(addr string) error {
	return fmt.Errorf("ADR-SEC-A: refusing to serve gRPC without TLS at %q (fail-closed mTLS required)", addr)
}
