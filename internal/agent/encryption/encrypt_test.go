/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package encryption_test

import (
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/encryption"
)

// TestEncryptionStub_PassThrough verifies the stub returns the original path unchanged.
func TestEncryptionStub_PassThrough(t *testing.T) {
	stub := &encryption.EncryptionStub{}

	path := "/tmp/checkpoint.tar"
	got, err := stub.EncryptCheckpointLayer(path, nil)
	if err != nil {
		t.Fatalf("EncryptCheckpointLayer: %v", err)
	}
	if got != path {
		t.Errorf("expected pass-through path %q, got %q", path, got)
	}

	got2, err := stub.DecryptCheckpointLayer(path, nil)
	if err != nil {
		t.Fatalf("DecryptCheckpointLayer: %v", err)
	}
	if got2 != path {
		t.Errorf("expected pass-through path %q, got %q", path, got2)
	}
}

// TestGenerateEphemeralKey verifies key generation returns non-empty keys of expected lengths.
func TestGenerateEphemeralKey(t *testing.T) {
	pub, priv, err := encryption.GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("GenerateEphemeralKey: %v", err)
	}
	// P-256 uncompressed public key: 65 bytes (0x04 prefix + 32 + 32).
	if len(pub) != 65 {
		t.Errorf("public key length: got %d, want 65", len(pub))
	}
	// P-256 private key: 32 bytes.
	if len(priv) != 32 {
		t.Errorf("private key length: got %d, want 32", len(priv))
	}
}
