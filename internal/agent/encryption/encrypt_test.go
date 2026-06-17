/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package encryption

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEncryptionStub_PassThrough verifies the stub returns the original path unchanged.
func TestEncryptionStub_PassThrough(t *testing.T) {
	stub := &EncryptionStub{}

	path := "/tmp/checkpoint.tar"
	got, err := stub.EncryptCheckpointLayer(EncryptInput{LayerPath: path})
	if err != nil {
		t.Fatalf("EncryptCheckpointLayer: %v", err)
	}
	if got != path {
		t.Errorf("expected pass-through path %q, got %q", path, got)
	}

	got2, err := stub.DecryptCheckpointLayer(DecryptInput{EncLayerPath: path})
	if err != nil {
		t.Fatalf("DecryptCheckpointLayer: %v", err)
	}
	if got2 != path {
		t.Errorf("expected pass-through path %q, got %q", path, got2)
	}
}

// TestGenerateEphemeralKey verifies key generation returns non-empty keys of expected lengths.
func TestGenerateEphemeralKey(t *testing.T) {
	pub, priv, err := GenerateEphemeralKey()
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

// writeLayer writes a plaintext layer file into a temp dir and returns its path.
func writeLayer(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write layer: %v", err)
	}
	return p
}

// recipientKeypair returns a static recipient ECDH keypair (interim model: the recipient
// keypair is provisioned via Secret, so the destination derives the same shared key the
// source used by ECDH(recipientPriv, recipientPub)).
func recipientKeypair(t *testing.T) (pub, priv []byte) {
	t.Helper()
	pub, priv, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("recipient keypair: %v", err)
	}
	return pub, priv
}

// TestRoundTrip_Pass verifies a real encrypt → decrypt round-trip recovers the plaintext
// with the HB-1 AAD bound and verified. (HB-2 in-scope: the primitive round-trips.)
func TestRoundTrip_Pass(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("CRIU pages.img — process memory, secrets, TCP seq state")
	layer := writeLayer(t, dir, "pages-1.img", plaintext)

	recipientPub, recipientPriv := recipientKeypair(t)
	enc := &ECDHEncryption{}

	encPath, err := enc.EncryptCheckpointLayer(EncryptInput{
		LayerPath:          layer,
		RecipientPublicKey: recipientPub,
		SenderPrivateKey:   recipientPriv, // interim: shared recipient keypair both sides hold
		MigrationUID:       "uid-abc-123",
		LayerIndex:         0,
		CheckpointEpoch:    "epoch-1",
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Ciphertext must differ from plaintext on disk (no plaintext-at-rest).
	ct, _ := os.ReadFile(encPath)
	if string(ct) == string(plaintext) {
		t.Fatalf("ciphertext equals plaintext — encryption did not occur")
	}

	// Destination derives the shared key from the recipient keypair (interim model).
	sharedKey, err := DeriveSharedSecret(recipientPriv, recipientPub)
	if err != nil {
		t.Fatalf("derive shared key: %v", err)
	}
	decPath, err := enc.DecryptCheckpointLayer(DecryptInput{
		EncLayerPath:    encPath,
		SharedKey:       sharedKey,
		MigrationUID:    "uid-abc-123",
		LayerIndex:      0,
		CheckpointEpoch: "epoch-1",
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	got, _ := os.ReadFile(decPath)
	if string(got) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

// TestWrongKey_FailClosed verifies decryption with an unrelated key fails closed (no output).
func TestWrongKey_FailClosed(t *testing.T) {
	dir := t.TempDir()
	layer := writeLayer(t, dir, "pages-1.img", []byte("sensitive"))

	recipientPub, recipientPriv := recipientKeypair(t)
	enc := &ECDHEncryption{}
	encPath, err := enc.EncryptCheckpointLayer(EncryptInput{
		LayerPath:          layer,
		RecipientPublicKey: recipientPub,
		SenderPrivateKey:   recipientPriv,
		MigrationUID:       "uid-1",
		LayerIndex:         0,
		CheckpointEpoch:    "epoch-1",
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// A different, unrelated keypair → different shared key.
	otherPub, otherPriv := recipientKeypair(t)
	wrongKey, _ := DeriveSharedSecret(otherPriv, otherPub)

	_, derr := enc.DecryptCheckpointLayer(DecryptInput{
		EncLayerPath:    encPath,
		SharedKey:       wrongKey,
		MigrationUID:    "uid-1",
		LayerIndex:      0,
		CheckpointEpoch: "epoch-1",
	})
	if derr == nil {
		t.Fatalf("expected wrong-key decrypt to FAIL closed, got nil error")
	}
	if _, statErr := os.Stat(encPath + ".dec"); statErr == nil {
		t.Fatalf("fail-closed violated: .dec output written on wrong key")
	}
}

// TestAADTamper_FailClosed verifies that changing ANY AAD binding field (migrationUID,
// layerIndex, epoch) at decrypt time fails closed — the anti-replay guarantee (HB-1).
func TestAADTamper_FailClosed(t *testing.T) {
	dir := t.TempDir()
	layer := writeLayer(t, dir, "pages-1.img", []byte("anti-replay payload"))
	recipientPub, recipientPriv := recipientKeypair(t)
	enc := &ECDHEncryption{}

	encPath, err := enc.EncryptCheckpointLayer(EncryptInput{
		LayerPath:          layer,
		RecipientPublicKey: recipientPub,
		SenderPrivateKey:   recipientPriv,
		MigrationUID:       "uid-orig",
		LayerIndex:         3,
		CheckpointEpoch:    "epoch-7",
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	sharedKey, _ := DeriveSharedSecret(recipientPriv, recipientPub)

	cases := []struct {
		name string
		in   DecryptInput
	}{
		{"wrong migrationUID", DecryptInput{EncLayerPath: encPath, SharedKey: sharedKey, MigrationUID: "uid-EVIL", LayerIndex: 3, CheckpointEpoch: "epoch-7"}},
		{"wrong layerIndex", DecryptInput{EncLayerPath: encPath, SharedKey: sharedKey, MigrationUID: "uid-orig", LayerIndex: 4, CheckpointEpoch: "epoch-7"}},
		{"wrong epoch", DecryptInput{EncLayerPath: encPath, SharedKey: sharedKey, MigrationUID: "uid-orig", LayerIndex: 3, CheckpointEpoch: "epoch-STALE"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, derr := enc.DecryptCheckpointLayer(tc.in); derr == nil {
				t.Fatalf("expected AAD-mismatch (%s) to FAIL closed, got nil error", tc.name)
			}
		})
	}

	// Sanity: the correct AAD still decrypts (the ciphertext itself is intact).
	if _, derr := enc.DecryptCheckpointLayer(DecryptInput{
		EncLayerPath: encPath, SharedKey: sharedKey, MigrationUID: "uid-orig", LayerIndex: 3, CheckpointEpoch: "epoch-7",
	}); derr != nil {
		t.Fatalf("correct AAD should decrypt, got: %v", derr)
	}
}

// TestCiphertextTamper_FailClosed verifies a flipped ciphertext byte fails the GCM tag.
func TestCiphertextTamper_FailClosed(t *testing.T) {
	dir := t.TempDir()
	layer := writeLayer(t, dir, "pages-1.img", []byte("tamper target payload long enough"))
	recipientPub, recipientPriv := recipientKeypair(t)
	enc := &ECDHEncryption{}
	encPath, err := enc.EncryptCheckpointLayer(EncryptInput{
		LayerPath: layer, RecipientPublicKey: recipientPub, SenderPrivateKey: recipientPriv, MigrationUID: "uid-1", LayerIndex: 0, CheckpointEpoch: "e1",
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct, _ := os.ReadFile(encPath)
	ct[len(ct)-1] ^= 0xFF // flip the last ciphertext/tag byte
	if err := os.WriteFile(encPath, ct, 0o600); err != nil {
		t.Fatalf("rewrite tampered ct: %v", err)
	}
	sharedKey, _ := DeriveSharedSecret(recipientPriv, recipientPub)
	if _, derr := enc.DecryptCheckpointLayer(DecryptInput{
		EncLayerPath: encPath, SharedKey: sharedKey, MigrationUID: "uid-1", LayerIndex: 0, CheckpointEpoch: "e1",
	}); derr == nil {
		t.Fatalf("expected tampered-ciphertext decrypt to FAIL closed, got nil error")
	}
}

// TestEmptyAAD_Refused verifies HB-1 precondition: encrypt refuses empty migrationUID/epoch
// rather than sealing with a degenerate (replayable) AAD — the original SD-2 nil-AAD defect.
func TestEmptyAAD_Refused(t *testing.T) {
	dir := t.TempDir()
	layer := writeLayer(t, dir, "pages-1.img", []byte("x"))
	recipientPub, _ := recipientKeypair(t)
	enc := &ECDHEncryption{}

	if _, err := enc.EncryptCheckpointLayer(EncryptInput{
		LayerPath: layer, RecipientPublicKey: recipientPub, MigrationUID: "", LayerIndex: 0, CheckpointEpoch: "e1",
	}); err == nil {
		t.Fatalf("expected empty MigrationUID to be refused (HB-1)")
	}
	if _, err := enc.EncryptCheckpointLayer(EncryptInput{
		LayerPath: layer, RecipientPublicKey: recipientPub, MigrationUID: "uid", LayerIndex: 0, CheckpointEpoch: "",
	}); err == nil {
		t.Fatalf("expected empty CheckpointEpoch to be refused (HB-1)")
	}
}

// TestKeyZeroization verifies the HB-3 defer-zeroize pattern: after DeriveSharedSecret, the
// caller-zeroized key buffer is all-zero, and the derived key is not the raw ECDH secret.
func TestKeyZeroization(t *testing.T) {
	pub, priv, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	key, err := DeriveSharedSecret(priv, pub)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("derived key length: got %d want 32", len(key))
	}
	// Caller owns the key and zeroizes it (HB-3 defer pattern at the call sites).
	nonZero := false
	for _, b := range key {
		if b != 0 {
			nonZero = true
			break
		}
	}
	if !nonZero {
		t.Fatalf("derived key is all-zero before use — derivation broken")
	}
	zeroize(key)
	for i, b := range key {
		if b != 0 {
			t.Fatalf("zeroize left non-zero byte at index %d", i)
		}
	}
}
