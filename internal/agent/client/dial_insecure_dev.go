//go:build dev

/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package client

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// adrSecADialNoTLS is the DEV-BUILD (//go:build dev) behavior: it appends insecure transport
// credentials so the operator may dial plaintext. This path is only reachable when
// LoadClientConfig returned (nil,nil), which in the dev build requires PODMOTION_INSECURE_GRPC=true
// (gated + WARN-logged in internal/agent/tls/tls_insecure_dev.go). Marker: ADR-SEC-A.
func adrSecADialNoTLS(opts []grpc.DialOption) ([]grpc.DialOption, error) {
	return append(opts, grpc.WithTransportCredentials(insecure.NewCredentials())), nil
}
