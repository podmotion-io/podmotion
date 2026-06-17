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
// SD-2 wiring (Sprint 37, M22 — ADR-0029, ADR-0160). The ECDHEncryption path is wired
// into the agent CRIU checkpoint write path. Per the Security Reviewer's SD-2 conditions:
//
//	HB-1 — every AES-GCM seal binds a NON-NIL Additional Authenticated Data (AAD) value
//	       that commits the ciphertext to migrationUID + layerIndex + checkpointEpoch.
//	       A layer encrypted for one migration/layer/epoch cannot be replayed into a
//	       different one: GCM tag verification fails closed on any AAD mismatch.
//	HB-3 — derived shared-secret key material is zeroized on every return path
//	       (defer zeroize). Key bytes never outlive the operation that derived them.
//
// HB-2 scope statement — what is and is NOT round-tripped end-to-end by this change:
//
//	IN SCOPE (real round-trip, proven by encrypt_test.go): EncryptCheckpointLayer →
//	DecryptCheckpointLayer over a real ECDH-derived key with the HB-1 AAD bound. The
//	primitive seals and opens checkpoint .img bytes with authenticated encryption and
//	fail-closed AAD verification.
//
//	OUT OF SCOPE for SD-2 (deferred to the ADR-0160 transfer-path redesign): the
//	GetCheckpointTar/PutCheckpointTar in-flight path is NOT switched to ciphertext in
//	this change. That path is governed by ADR-SEC-B, whose signed manifest commits to
//	per-file PLAINTEXT digests verified after extraction on the destination; transferring
//	ciphertext would break SEC-B verification and requires a coordinated proto + operator
//	signing + destination-extraction redesign (ADR-0160 D-series). Until then, in-transit
//	confidentiality remains mTLS (ADR-SEC-A) and integrity remains SEC-B, exactly as
//	ADR-0029 §Interim posture records. SD-2 closes the nil-AAD defect and wires the
//	at-rest encrypt/decrypt of the CRIU layer set; the in-flight cutover is ADR-0160.
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

// EncryptInput carries the per-layer encryption context. The three binding fields
// (MigrationUID, LayerIndex, CheckpointEpoch) are the HB-1 AAD: they are authenticated
// (not encrypted) by AES-GCM and bind the ciphertext to a single migration, a single
// layer position, and a single checkpoint epoch. A layer cannot be replayed into a
// different migration, swapped with another layer, or replayed from a stale epoch —
// GCM Open fails closed if any of the three differs from the value present at seal time.
type EncryptInput struct {
	// LayerPath is the on-disk path of the plaintext CRIU .img layer to encrypt.
	LayerPath string
	// RecipientPublicKey is the destination's ECDH P-256 uncompressed public key (65 bytes).
	RecipientPublicKey []byte
	// SenderPrivateKey is OPTIONAL. When set, the encryptor derives the shared key from this
	// private key against RecipientPublicKey instead of generating a fresh ephemeral keypair.
	// This is the INTERIM key-exchange path (ADR-0029 KEY_EXCHANGE_INTERIM): the destination
	// keypair is provisioned via Secret, the source uses recipientPriv as SenderPrivateKey so
	// both sides compute the identical ECDH(recipientPriv, recipientPub) shared key without the
	// sender ephemeral pubkey needing to ride the wire. In the ADR-0160 end-state this is left
	// empty and the fresh ephemeral sender pubkey is carried in the OCI layer descriptor.
	SenderPrivateKey []byte
	// MigrationUID binds the layer to one PodMigration CR's .metadata.uid (anti-replay).
	MigrationUID string
	// LayerIndex binds the layer to its position in the sorted checkpoint layer set
	// (prevents an attacker from swapping layer N for layer M within the same migration).
	LayerIndex int
	// CheckpointEpoch binds the layer to a single checkpoint generation (prevents replay
	// of a stale checkpoint's layer into a newer checkpoint of the same migration).
	CheckpointEpoch string
}

// DecryptInput mirrors EncryptInput for the restore (destination) path. The AAD fields
// MUST reproduce exactly the values used at encryption time or GCM Open fails closed.
type DecryptInput struct {
	// EncLayerPath is the on-disk path of the encrypted layer to decrypt.
	EncLayerPath string
	// SharedKey is the pre-derived 32-byte ECDH shared key (see DeriveSharedSecret).
	// The destination derives it from its own private key + the sender's ephemeral
	// public key carried out-of-band (ADR-0160 layer descriptor).
	SharedKey []byte
	// MigrationUID / LayerIndex / CheckpointEpoch reproduce the seal-time AAD.
	MigrationUID    string
	LayerIndex      int
	CheckpointEpoch string
}

// buildAAD constructs the non-nil HB-1 Additional Authenticated Data. The format is the
// fixed, unambiguous "<migrationUID>:<layerIndex>:<checkpointEpoch>" triple; it is never
// empty (the encrypt path rejects empty MigrationUID/CheckpointEpoch before reaching here).
func buildAAD(migrationUID string, layerIndex int, checkpointEpoch string) []byte {
	return []byte(fmt.Sprintf("%s:%d:%s", migrationUID, layerIndex, checkpointEpoch))
}

// zeroize overwrites a byte slice in place. HB-3: called via defer on every path that
// derives or holds key material so the secret does not outlive the operation.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// CheckpointEncryption encrypts and decrypts OCI checkpoint layers.
type CheckpointEncryption interface {
	// EncryptCheckpointLayer encrypts the checkpoint .img file described by in using the
	// recipient's ECDH public key and the HB-1 AAD binding. Returns path to the encrypted layer.
	EncryptCheckpointLayer(in EncryptInput) (string, error)

	// DecryptCheckpointLayer decrypts an encrypted layer back to .img bytes, reproducing the
	// HB-1 AAD from in. AAD mismatch (wrong migration/layer/epoch) fails closed.
	DecryptCheckpointLayer(in DecryptInput) (string, error)
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

// DeriveSharedSecret performs ECDH key agreement given raw private key bytes and the
// peer's uncompressed public key bytes, returning a SHA-256 derived 32-byte AES key.
// Exported so the destination restore path can pre-derive the key once and pass it via
// DecryptInput.SharedKey. The CALLER owns the returned slice and MUST zeroize it (HB-3).
func DeriveSharedSecret(privateKeyBytes, peerPublicKeyBytes []byte) ([]byte, error) {
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
	defer zeroize(shared) // HB-3: raw shared secret cleared once derived key is computed.
	// Derive a 32-byte AES key via SHA-256 of the shared secret (HKDF-lite).
	h := sha256.Sum256(shared)
	out := make([]byte, len(h))
	copy(out, h[:])
	zeroize(h[:]) // HB-3: clear the on-stack digest copy too.
	return out, nil
}

// ECDHEncryption is the real implementation using stdlib ECDH + AES-GCM.
// Full cosign/imgcrypt OCI layer wrapping is wired in a later milestone (ADR-0160); here we
// encrypt each raw .img layer into a single encrypted blob file with HB-1 AAD binding.
type ECDHEncryption struct{}

func (e *ECDHEncryption) EncryptCheckpointLayer(in EncryptInput) (string, error) {
	// HB-1 precondition: the AAD binding fields must be present, or the seal would bind to
	// an empty/degenerate AAD and the anti-replay guarantee would be void. Fail closed.
	if in.MigrationUID == "" {
		return "", fmt.Errorf("EncryptCheckpointLayer: MigrationUID empty — refusing to seal without AAD migration binding (HB-1)")
	}
	if in.CheckpointEpoch == "" {
		return "", fmt.Errorf("EncryptCheckpointLayer: CheckpointEpoch empty — refusing to seal without AAD epoch binding (HB-1)")
	}

	// Select the sender private key. INTERIM path: caller supplies SenderPrivateKey (the
	// Secret-provisioned recipient private key) so source and destination derive the identical
	// ECDH shared key. END-STATE path: generate a fresh ephemeral keypair and carry the sender
	// pubkey OOB (ADR-0160 OCI layer descriptor).
	var senderPriv []byte
	if len(in.SenderPrivateKey) > 0 {
		senderPriv = make([]byte, len(in.SenderPrivateKey))
		copy(senderPriv, in.SenderPrivateKey)
	} else {
		senderPub, gen, genErr := GenerateEphemeralKey()
		if genErr != nil {
			return "", genErr
		}
		senderPriv = gen
		_ = senderPub // sent OOB to recipient (ADR-0160 OCI layer descriptor annotation).
	}
	defer zeroize(senderPriv) // HB-3: sender private key cleared on return.

	sharedKey, err := DeriveSharedSecret(senderPriv, in.RecipientPublicKey)
	if err != nil {
		return "", err
	}
	defer zeroize(sharedKey) // HB-3: derived AES key cleared on every return path.

	plain, err := os.ReadFile(in.LayerPath)
	if err != nil {
		return "", fmt.Errorf("read layer for encryption: %w", err)
	}
	defer zeroize(plain) // plaintext layer holds process memory — clear after seal.

	aad := buildAAD(in.MigrationUID, in.LayerIndex, in.CheckpointEpoch)
	encrypted, err := aesGCMEncrypt(sharedKey, plain, aad)
	if err != nil {
		return "", err
	}

	outPath := in.LayerPath + ".enc"
	if err := os.WriteFile(outPath, encrypted, 0o600); err != nil {
		return "", fmt.Errorf("write encrypted layer: %w", err)
	}
	return outPath, nil
}

func (e *ECDHEncryption) DecryptCheckpointLayer(in DecryptInput) (string, error) {
	if in.MigrationUID == "" || in.CheckpointEpoch == "" {
		return "", fmt.Errorf("DecryptCheckpointLayer: AAD binding fields empty — cannot reproduce HB-1 AAD (fail closed)")
	}
	data, err := os.ReadFile(in.EncLayerPath)
	if err != nil {
		return "", fmt.Errorf("read encrypted layer: %w", err)
	}
	aad := buildAAD(in.MigrationUID, in.LayerIndex, in.CheckpointEpoch)
	plain, err := aesGCMDecrypt(in.SharedKey, data, aad)
	if err != nil {
		// GCM Open failure is fail-closed: wrong key OR AAD mismatch (wrong migration/
		// layer/epoch) OR tampered ciphertext all land here. Do not write any output.
		return "", fmt.Errorf("decrypt checkpoint layer (fail-closed — wrong key, AAD mismatch, or tamper): %w", err)
	}
	defer zeroize(plain) // plaintext holds process memory — clear after it is written out.
	outPath := in.EncLayerPath + ".dec"
	if err := os.WriteFile(outPath, plain, 0o600); err != nil {
		return "", fmt.Errorf("write decrypted layer: %w", err)
	}
	return outPath, nil
}

// aesGCMEncrypt encrypts plaintext using AES-256-GCM with non-nil AAD (HB-1). The nonce is
// prepended to the ciphertext; the AAD is authenticated but NOT stored (the decryptor
// reconstructs it from the migration/layer/epoch context).
func aesGCMEncrypt(key, plaintext, additionalData []byte) ([]byte, error) {
	if len(additionalData) == 0 {
		// HB-1 invariant guard: this function is never called with empty AAD. A nil AAD
		// would silently drop the anti-replay binding (the original SD-2 defect).
		return nil, fmt.Errorf("aesGCMEncrypt: additionalData (AAD) is empty — HB-1 binding required")
	}
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
	return gcm.Seal(nonce, nonce, plaintext, additionalData), nil
}

func aesGCMDecrypt(key, ciphertext, additionalData []byte) ([]byte, error) {
	if len(additionalData) == 0 {
		return nil, fmt.Errorf("aesGCMDecrypt: additionalData (AAD) is empty — HB-1 binding required")
	}
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
	return gcm.Open(nil, nonce, ct, additionalData)
}

// EncryptionStub passes through unencrypted with a log warning (ADR-0029 opt-in default).
type EncryptionStub struct{}

func (s *EncryptionStub) EncryptCheckpointLayer(in EncryptInput) (string, error) {
	log.Info("WARNING: checkpoint encryption is disabled — layer passed through unencrypted (ADR-0029)",
		"layerPath", in.LayerPath)
	return in.LayerPath, nil
}

func (s *EncryptionStub) DecryptCheckpointLayer(in DecryptInput) (string, error) {
	log.Info("WARNING: checkpoint encryption is disabled — pass-through decrypt", "path", in.EncLayerPath)
	return in.EncLayerPath, nil
}
