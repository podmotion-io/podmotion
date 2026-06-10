/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package encryption provides opt-in OCI checkpoint image encryption for PodMotion.
//
// Encryption is opt-in in v0.1 (ADR-0029). When disabled, EncryptionStub logs a
// warning and passes data through unencrypted. Encryption uses ECDH P-256 ephemeral
// key exchange — one key pair per migration — so a compromised key cannot decrypt
// checkpoints from other migrations.
//
// Integration with cosign/imgcrypt is deferred to M13; M11 establishes the interface
// and the ECDH key-generation logic which is pure stdlib.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("checkpoint-encryption")

// CheckpointEncryption encrypts and decrypts OCI checkpoint layers.
type CheckpointEncryption interface {
	// EncryptCheckpointLayer encrypts the checkpoint .img files at layerPath using
	// the recipient's ECDH public key. Returns path to the encrypted layer.
	EncryptCheckpointLayer(layerPath string, recipientPublicKey []byte) (string, error)

	// DecryptCheckpointLayer decrypts an encrypted OCI layer back to .img files.
	DecryptCheckpointLayer(encLayerPath string, privateKey []byte) (string, error)
}

// GenerateEphemeralKey generates an ECDH P-256 key pair for a single migration.
// Returns DER-encoded public key, raw private key bytes, and any error.
func GenerateEphemeralKey() (publicKey, privateKey []byte, err error) {
	curve := ecdh.P256()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ECDH P-256 key: %w", err)
	}
	// PublicKey().Bytes() returns uncompressed point form (65 bytes for P-256).
	pub := priv.PublicKey().Bytes()
	raw := priv.Bytes()
	return pub, raw, nil
}

// deriveSharedSecret performs ECDH key agreement given raw private key bytes and
// the peer's uncompressed public key bytes, returning a SHA-256 derived key.
func deriveSharedSecret(privateKeyBytes, peerPublicKeyBytes []byte) ([]byte, error) {
	curve := ecdh.P256()
	priv, err := curve.NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	pub, err := curve.NewPublicKey(peerPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse peer public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement: %w", err)
	}
	// Derive a 32-byte AES key via SHA-256 of the shared secret (HKDF-lite).
	h := sha256.Sum256(shared)
	return h[:], nil
}

// ECDHEncryption is the real implementation using stdlib ECDH + AES-GCM.
// Full cosign/imgcrypt OCI layer wrapping is wired in M13; here we encrypt the raw
// .img directory into a single encrypted blob file.
type ECDHEncryption struct{}

func (e *ECDHEncryption) EncryptCheckpointLayer(layerPath string, recipientPublicKey []byte) (string, error) {
	// Generate an ephemeral sender key pair for this encryption operation.
	senderPub, senderPriv, err := GenerateEphemeralKey()
	if err != nil {
		return "", err
	}

	sharedKey, err := deriveSharedSecret(senderPriv, recipientPublicKey)
	if err != nil {
		return "", err
	}
	_ = senderPub // sent OOB to recipient (included in M13 OCI layer descriptor annotation)

	plain, err := os.ReadFile(layerPath)
	if err != nil {
		return "", fmt.Errorf("read layer for encryption: %w", err)
	}

	encrypted, err := aesGCMEncrypt(sharedKey, plain)
	if err != nil {
		return "", err
	}

	outPath := layerPath + ".enc"
	if err := os.WriteFile(outPath, encrypted, 0o600); err != nil {
		return "", fmt.Errorf("write encrypted layer: %w", err)
	}
	return outPath, nil
}

func (e *ECDHEncryption) DecryptCheckpointLayer(encLayerPath string, privateKey []byte) (string, error) {
	// In full M13 integration the sender ephemeral public key is read from the OCI layer
	// descriptor annotation. For M11 we expect the caller to pass the shared key directly
	// as the privateKey parameter (pre-derived via deriveSharedSecret).
	data, err := os.ReadFile(encLayerPath)
	if err != nil {
		return "", fmt.Errorf("read encrypted layer: %w", err)
	}
	plain, err := aesGCMDecrypt(privateKey, data)
	if err != nil {
		return "", err
	}
	outPath := encLayerPath + ".dec"
	if err := os.WriteFile(outPath, plain, 0o600); err != nil {
		return "", fmt.Errorf("write decrypted layer: %w", err)
	}
	return outPath, nil
}

// aesGCMEncrypt encrypts plaintext using AES-256-GCM. The nonce is prepended to the ciphertext.
func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesGCMDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// EncryptionStub passes through unencrypted with a log warning (ADR-0029 opt-in default).
type EncryptionStub struct{}

func (s *EncryptionStub) EncryptCheckpointLayer(layerPath string, _ []byte) (string, error) {
	log.Info("WARNING: checkpoint encryption is disabled — layer passed through unencrypted (ADR-0029)",
		"layerPath", layerPath)
	return layerPath, nil
}

func (s *EncryptionStub) DecryptCheckpointLayer(encLayerPath string, _ []byte) (string, error) {
	log.Info("WARNING: checkpoint encryption is disabled — pass-through decrypt", "path", encLayerPath)
	return encLayerPath, nil
}
