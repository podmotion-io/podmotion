/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package provenance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// TestSignVerifyRoundTrip proves a manifest signed by an ECDSA-P256 key verifies, and that any
// tamper (flipped digest in the file set) invalidates the signature (ADR-SEC-B B1/B2).
func TestSignVerifyRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	files := []FileEntry{
		{Name: "inventory.img", Size: 10, SHA256: "aa"},
		{Name: "pages-1.img", Size: 20, SHA256: "bb"},
		{Name: TCPSocketStateFile, Size: 5, SHA256: "cc"},
	}
	m := &Manifest{
		Schema: ManifestSchema, Migration: "mig", MigrationUID: "uid-1",
		Alg: "ecdsa-p256-sha256", Files: files, SocketStateSHA256: "cc",
	}
	m.SetDigest = ComputeSetDigest(files)
	canon, err := CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(key, canon)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(&key.PublicKey, canon, sig) {
		t.Fatal("valid signature failed to verify")
	}

	// Tamper: change a file digest → canonical bytes differ → signature must NOT verify.
	m.Files[0].SHA256 = "ff"
	m.SetDigest = ComputeSetDigest(m.Files)
	tampered, _ := CanonicalJSON(m)
	if Verify(&key.PublicKey, tampered, sig) {
		t.Fatal("tampered manifest verified against original signature — replay/tamper not caught")
	}

	// Wrong key must not verify the original.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if Verify(&other.PublicKey, canon, sig) {
		t.Fatal("signature verified under a non-operator key (B2)")
	}
}

func TestSetDigestBindsFileMembership(t *testing.T) {
	a := []FileEntry{{Name: "x", Size: 1, SHA256: "h"}}
	b := []FileEntry{{Name: "x", Size: 1, SHA256: "h"}, {Name: "y", Size: 2, SHA256: "g"}}
	if ComputeSetDigest(a) == ComputeSetDigest(b) {
		t.Fatal("set_digest did not change when a file was added (membership not bound)")
	}
}
