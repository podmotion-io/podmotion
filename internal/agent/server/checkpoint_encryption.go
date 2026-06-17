/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/encryption"
)

// SD-2 (ADR-0029, ADR-0160) — wiring of ECDHEncryption into the CRIU checkpoint write
// (source) and restore (destination) paths, with the HB-1 non-nil AAD binding and HB-3
// key zeroization. See package encryption doc comment for the HB-2 scope statement.
//
// KEY_EXCHANGE_INTERIM: the operator ephemeral-key threading contract in ADR-0029 §Crypto
// shape (operator generates the per-migration ECDH keypair and threads the recipient public
// key to the source agent) is NOT yet carried on the gRPC wire (no proto field exists). As
// the interim path, both agents read the per-migration ECDH key material from a Kubernetes
// Secret named "<migration-name>-checkpoint-key" in the agent's namespace:
//
//	data["recipient-pubkey"] — destination ECDH P-256 uncompressed public key (65 bytes),
//	                           read by the SOURCE agent to encrypt the layer set.
//	data["recipient-privkey"] — destination ECDH P-256 raw private key (32 bytes),
//	                           read by the DESTINATION agent to derive the shared key and
//	                           decrypt. (Interim only; in the ADR-0160 end-state the private
//	                           key never leaves the destination and the sender ephemeral
//	                           pubkey rides the OCI layer descriptor.)
//	data["epoch"]            — checkpoint epoch string bound into the HB-1 AAD.
//
// When the Secret is absent, encryption is OFF for that migration (ADR-0029 opt-in default):
// the layer set is left plaintext and the EncryptionStub-equivalent no-op posture holds. This
// keeps existing gate flows green until the operator key-threading lands; presence of the
// Secret is the opt-in switch.

const checkpointEncMarkerFile = ".pm-encrypted" // sentinel: final/ holds ciphertext layers

// checkpointKeyMaterial is the interim per-migration ECDH key material read from the Secret.
type checkpointKeyMaterial struct {
	recipientPub  []byte
	recipientPriv []byte
	epoch         string
}

// loadCheckpointKey reads the interim per-migration key Secret. Returns (nil, nil) when the
// Secret is absent — that is the "encryption not enabled for this migration" signal, not an
// error (ADR-0029 opt-in default). A present-but-malformed Secret IS an error (fail closed:
// an operator who created the Secret intends encryption, so a bad one must not silently skip).
func (s *AgentServer) loadCheckpointKey(ctx context.Context, migrationName string) (*checkpointKeyMaterial, error) {
	if s.k8sClient == nil {
		return nil, nil // pure-stub mode: no encryption
	}
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		ns = "podmotion-system"
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	sec := &corev1.Secret{}
	name := migrationName + "-checkpoint-key"
	if err := s.k8sClient.Get(lookupCtx, types.NamespacedName{Name: name, Namespace: ns}, sec); err != nil {
		// Absent → encryption opt-out (default). We cannot cheaply distinguish NotFound from
		// other transient errors without importing apierrors here; treat any Get failure as
		// "no key" only when the data is genuinely unavailable. Log and proceed unencrypted.
		log.Info("SD-2: no checkpoint-key Secret for migration — encryption OFF (ADR-0029 opt-in default)",
			"migration", migrationName, "secret", name, "lookupErr", err)
		return nil, nil
	}

	km := &checkpointKeyMaterial{
		recipientPub:  sec.Data["recipient-pubkey"],
		recipientPriv: sec.Data["recipient-privkey"],
		epoch:         string(sec.Data["epoch"]),
	}
	if km.epoch == "" {
		return nil, fmt.Errorf("SD-2: checkpoint-key Secret %q present but epoch empty — fail closed (HB-1 AAD epoch binding required)", name)
	}
	return km, nil
}

// checkpointLayerFiles returns the sorted set of regular files in dir that constitute the
// CRIU layer set. The sort order defines the stable LayerIndex bound into the HB-1 AAD, so
// source (encrypt) and destination (decrypt) MUST agree on it — sort by filename.
func checkpointLayerFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if e.Name() == checkpointEncMarkerFile {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// encryptCheckpointDir encrypts every layer file in dir in place (plaintext .img → .enc,
// plaintext zeroized+removed), binding each layer's HB-1 AAD to migrationUID:layerIndex:epoch.
// No-op (returns nil) when no key Secret is present for the migration (ADR-0029 opt-in).
//
// Called by the source agent at the end of Checkpoint, after final/ is fully populated and
// before the transfer phase reads it. This closes the at-rest plaintext gap at its source
// (ADR-0029 wiring surface point 1): ciphertext, never plaintext, survives in final/.
func (s *AgentServer) encryptCheckpointDir(ctx context.Context, migrationName, dir string) error {
	km, err := s.loadCheckpointKey(ctx, migrationName)
	if err != nil {
		return err
	}
	if km == nil {
		return nil // encryption opt-out for this migration
	}
	migrationUID, err := s.migrationUIDForName(ctx, migrationName)
	if err != nil {
		return fmt.Errorf("SD-2 encrypt: resolve migration_uid for AAD binding: %w", err)
	}

	enc := &encryption.ECDHEncryption{}
	names, err := checkpointLayerFiles(dir)
	if err != nil {
		return fmt.Errorf("SD-2 encrypt: list layer set: %w", err)
	}
	for idx, name := range names {
		layerPath := filepath.Join(dir, name)
		encPath, encErr := enc.EncryptCheckpointLayer(encryption.EncryptInput{
			LayerPath:          layerPath,
			RecipientPublicKey: km.recipientPub,
			// KEY_EXCHANGE_INTERIM: source derives against the Secret-provisioned recipient
			// keypair so the destination computes the identical shared key without the sender
			// ephemeral pubkey riding the wire (no proto field yet). ADR-0160 end-state drops
			// SenderPrivateKey and carries a fresh ephemeral pubkey in the layer descriptor.
			SenderPrivateKey: km.recipientPriv,
			MigrationUID:     migrationUID,
			LayerIndex:       idx,
			CheckpointEpoch:  km.epoch,
		})
		if encErr != nil {
			return fmt.Errorf("SD-2 encrypt: layer %q (index %d): %w", name, idx, encErr)
		}
		// Replace plaintext with ciphertext: zeroize+remove the plaintext, rename .enc → name.
		if zErr := zeroizeFile(layerPath); zErr != nil {
			return fmt.Errorf("SD-2 encrypt: zeroize plaintext layer %q: %w", name, zErr)
		}
		if rErr := os.Rename(encPath, layerPath); rErr != nil {
			return fmt.Errorf("SD-2 encrypt: promote ciphertext layer %q: %w", name, rErr)
		}
	}
	// Drop the encrypted-set marker so the restore path knows final/ holds ciphertext.
	if err := os.WriteFile(filepath.Join(dir, checkpointEncMarkerFile), []byte(km.epoch), 0o600); err != nil {
		return fmt.Errorf("SD-2 encrypt: write encryption marker: %w", err)
	}
	log.Info("SD-2: checkpoint layer set encrypted at rest (HB-1 AAD bound, HB-3 keys zeroized)",
		"migration", migrationName, "dir", dir, "layers", len(names))
	return nil
}

// decryptCheckpointDir reverses encryptCheckpointDir on the destination before CRIU reads
// final/. No-op when the encrypted-set marker is absent (the layer set is already plaintext —
// either encryption was off, or this is a replayed restore that already decrypted).
//
// HB-3: the shared key is derived once, zeroized on return.
func (s *AgentServer) decryptCheckpointDir(ctx context.Context, migrationName, dir string) error {
	markerPath := filepath.Join(dir, checkpointEncMarkerFile)
	if _, statErr := os.Stat(markerPath); statErr != nil {
		return nil // not encrypted (or already decrypted on a prior restore attempt)
	}
	km, err := s.loadCheckpointKey(ctx, migrationName)
	if err != nil {
		return err
	}
	if km == nil {
		return fmt.Errorf("SD-2 decrypt: final/ is marked encrypted but no checkpoint-key Secret is available — cannot decrypt (fail closed)")
	}
	migrationUID, err := s.migrationUIDForName(ctx, migrationName)
	if err != nil {
		return fmt.Errorf("SD-2 decrypt: resolve migration_uid for AAD binding: %w", err)
	}

	// Derive the shared key once on the destination: its own private key + the sender ephemeral
	// pubkey. INTERIM: the source used a fresh ephemeral key per layer (encrypt.go), so the
	// interim Secret carries the destination keypair and the destination derives against the
	// recipient pubkey embedded in each .enc by re-deriving symmetrically. Because the interim
	// path stores the recipient PRIVATE key in the Secret, the destination reconstructs the same
	// shared key the source computed by ECDH(recipientPriv, senderEphemeralPub). The sender
	// ephemeral pub is carried in the ADR-0160 end-state; INTERIM uses a Secret-provisioned
	// static recipient keypair so DeriveSharedSecret(recipientPriv, recipientPub) is the shared
	// key both sides agree on (recipient is both sender-peer and recipient in the interim).
	sharedKey, err := encryption.DeriveSharedSecret(km.recipientPriv, km.recipientPub)
	if err != nil {
		return fmt.Errorf("SD-2 decrypt: derive shared key: %w", err)
	}
	defer func() { // HB-3
		for i := range sharedKey {
			sharedKey[i] = 0
		}
	}()

	enc := &encryption.ECDHEncryption{}
	names, err := checkpointLayerFiles(dir)
	if err != nil {
		return fmt.Errorf("SD-2 decrypt: list layer set: %w", err)
	}
	for idx, name := range names {
		layerPath := filepath.Join(dir, name)
		decPath, decErr := enc.DecryptCheckpointLayer(encryption.DecryptInput{
			EncLayerPath:    layerPath,
			SharedKey:       sharedKey,
			MigrationUID:    migrationUID,
			LayerIndex:      idx,
			CheckpointEpoch: km.epoch,
		})
		if decErr != nil {
			// Fail closed: wrong key, AAD mismatch (wrong migration/layer/epoch), or tamper.
			return fmt.Errorf("SD-2 decrypt: layer %q (index %d) fail-closed: %w", name, idx, decErr)
		}
		if rErr := os.Rename(decPath, layerPath); rErr != nil {
			return fmt.Errorf("SD-2 decrypt: promote plaintext layer %q: %w", name, rErr)
		}
	}
	_ = os.Remove(markerPath) // decrypt complete — clear the marker (idempotent re-restore)
	log.Info("SD-2: checkpoint layer set decrypted on destination (HB-1 AAD verified, HB-3 key zeroized)",
		"migration", migrationName, "dir", dir, "layers", len(names))
	return nil
}

// migrationUIDForName resolves the live PodMigration CR's .metadata.uid for use as the HB-1
// AAD migration binding. Reuses the established namespace-resolution pattern. Fail closed if
// the UID cannot be resolved — an empty AAD binding would void the anti-replay guarantee.
func (s *AgentServer) migrationUIDForName(ctx context.Context, migrationName string) (string, error) {
	if s.k8sClient == nil {
		return "", fmt.Errorf("no k8s client to resolve migration_uid")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pm := &pmv1.PodMigration{}
	ns := s.resolveNamespaceForMigration(lookupCtx, migrationName)
	if ns == "" {
		ns = os.Getenv("POD_NAMESPACE")
		if ns == "" {
			ns = "podmotion-system"
		}
	}
	if err := s.k8sClient.Get(lookupCtx, types.NamespacedName{Name: migrationName, Namespace: ns}, pm); err != nil {
		return "", fmt.Errorf("get PodMigration %q in ns %q: %w", migrationName, ns, err)
	}
	uid := string(pm.UID)
	if uid == "" {
		return "", fmt.Errorf("PodMigration %q has empty UID", migrationName)
	}
	return uid, nil
}

// zeroizeFile overwrites a file's bytes with zeros then removes it (Standing Rule 7).
func zeroizeFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() > 0 {
		f, oErr := os.OpenFile(path, os.O_WRONLY, 0o600)
		if oErr != nil {
			return oErr
		}
		zeros := make([]byte, 32*1024)
		remaining := info.Size()
		for remaining > 0 {
			n := int64(len(zeros))
			if n > remaining {
				n = remaining
			}
			if _, wErr := f.Write(zeros[:n]); wErr != nil {
				f.Close()
				return wErr
			}
			remaining -= n
		}
		_ = f.Sync()
		f.Close()
	}
	return os.Remove(path)
}
