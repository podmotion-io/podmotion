//go:build !dev

/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package client

import (
	"fmt"

	"google.golang.org/grpc"
)

// adrSecADialNoTLS is the DEFAULT-BUILD (production) behavior: the operator REFUSES to dial an
// agent without a TLS config (ADR-SEC-A §2.1, C-330/N-340). The "ADR-SEC-A" marker string lands
// in the operator binary string table here for §P-VERIFY-MULTI deployed-provenance grep.
func adrSecADialNoTLS(opts []grpc.DialOption) ([]grpc.DialOption, error) {
	return nil, fmt.Errorf("ADR-SEC-A: operator agent client has no TLS config — refusing to dial plaintext (fail-closed mTLS required)")
}
