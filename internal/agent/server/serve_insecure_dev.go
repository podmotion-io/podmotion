//go:build dev

/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// adrSecAHandleNoTLS is the DEV-BUILD (//go:build dev) behavior: it permits the server to
// continue serving plaintext (returns nil). This path is only reachable when LoadServerConfig
// returned (nil,nil), which in the dev build requires PODMOTION_INSECURE_GRPC=true (already
// gated + WARN-logged in internal/agent/tls/tls_insecure_dev.go).
func adrSecAHandleNoTLS(addr string) error {
	log.Info("gRPC server starting without TLS — dev build insecure (PODMOTION_INSECURE_GRPC)", "addr", addr)
	return nil
}
