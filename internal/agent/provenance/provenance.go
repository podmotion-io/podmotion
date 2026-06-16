/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package provenance implements ADR-SEC-B checkpoint provenance: a signed checkpoint manifest
// (operator-held key, agent verify-only), end-to-end transfer-integrity hashing, and the
// anti-replay migration/socket-state binding.
//
// Trust model (ADR-SEC-B §2.1): the OPERATOR is the sole signing authority; agents are
// verify-only. The operator signs with the private key of its mTLS client cert
// (spiffe://podmotion.io/ns/<ns>/sa/podmotion-operator). Agents verify using the operator leaf
// public key pinned to that SPIFFE ID and chained to the trusted CA they already hold
// (ca.crt) — no new secret. HMAC is rejected (§6): a shared key would let any agent forge.
//
// Marker: this package carries the ADR-SEC-B deployed-provenance marker on BOTH binaries
// (operator signs, agent verifies).
package provenance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
)

// ADRSecBMarker forces the ADR-SEC-B marker string into every binary that imports this package
// (operator: sign path; agent: verify path) for §P-VERIFY-MULTI deployed-provenance grep.
const ADRSecBMarker = "ADR-SEC-B"

// ManifestSchema is the canonical schema identifier for checkpoint-manifest/v1.
const ManifestSchema = "podmotion.io/checkpoint-manifest/v1"

// OperatorSPIFFESuffix is the SPIFFE-ID suffix the agent pins when selecting the operator leaf
// from the trusted CA chain (ADR-SEC-B §2.1).
const OperatorSPIFFESuffix = "/sa/podmotion-operator"

// FileEntry is one file in the checkpoint set with its size and SHA-256.
type FileEntry struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is the signed provenance record (ADR-SEC-B §2.2). The Signature field is NOT part of
// the signed bytes — it is carried alongside (proto manifest_sig) — so CanonicalJSON omits it.
type Manifest struct {
	Schema            string      `json:"schema"`
	Migration         string      `json:"migration"`
	MigrationUID      string      `json:"migration_uid"`
	SourceNode        string      `json:"source_node"`
	SourceSPIFFEID    string      `json:"source_spiffe_id"`
	CreatedUnix       int64       `json:"created_unix"`
	Alg               string      `json:"alg"`
	Files             []FileEntry `json:"files"`
	SocketStateSHA256 string      `json:"socket_state_sha256"`
	SetDigest         string      `json:"set_digest"`
	// OperatorCertPEM is the operator leaf certificate (PEM) whose key signed this manifest.
	// ADR-SEC-B §2.1: the agent does NOT receive a new secret — it VERIFIES this cert chains to
	// the trusted CA (ca.crt the agent already holds) AND carries the operator SPIFFE ID, then
	// uses its public key to verify the signature. Carrying the cert in the signed bytes is sound:
	// trust derives from the CA chain, not from the manifest, and the signature still binds the
	// file set. A forged cert fails the CA-chain pin; a real operator cert with a wrong key fails
	// the signature check.
	OperatorCertPEM string `json:"operator_cert_pem"`
}

// TCPSocketStateFile is the canonical filename for the socket-state sidecar (ADR-SEC-B §2.4).
const TCPSocketStateFile = "tcp_socket_state.json"

// SHA256Hex returns the lowercase hex SHA-256 of b.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ComputeSetDigest computes the digest over the canonically-sorted (name,size,sha256) tuples.
// A change to any file, size, name, or the file list itself changes this value (ADR-SEC-B §2.2).
func ComputeSetDigest(files []FileEntry) string {
	sorted := make([]FileEntry, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	h := sha256.New()
	for _, f := range sorted {
		fmt.Fprintf(h, "%s\x00%d\x00%s\n", f.Name, f.Size, f.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CanonicalJSON serializes the manifest deterministically for signing/verification. Files are
// sorted by name so producer and verifier agree on the signed bytes regardless of tar order.
func CanonicalJSON(m *Manifest) ([]byte, error) {
	c := *m
	sorted := make([]FileEntry, len(m.Files))
	copy(sorted, m.Files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	c.Files = sorted
	return json.Marshal(&c)
}

// LoadSigner reads the operator private key (PEM, the key half of its mTLS cert) and returns a
// crypto.Signer plus the algorithm string recorded in the manifest (read from the key, not
// hardcoded — ADR-SEC-B §2.1). Supports Ed25519 and ECDSA-P256.
func LoadSigner(keyPath string) (crypto.Signer, string, error) {
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("ADR-SEC-B: read operator signing key %q: %w", keyPath, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, "", fmt.Errorf("ADR-SEC-B: no PEM block in operator key %q", keyPath)
	}
	key, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return k, "ed25519", nil
	case *ecdsa.PrivateKey:
		if k.Curve.Params().BitSize != 256 {
			return nil, "", fmt.Errorf("ADR-SEC-B: unsupported ECDSA curve %s (P-256 required)", k.Curve.Params().Name)
		}
		return k, "ecdsa-p256-sha256", nil
	default:
		return nil, "", fmt.Errorf("ADR-SEC-B: unsupported operator key type %T (Ed25519 or ECDSA-P256 required)", key)
	}
}

func parsePrivateKey(der []byte) (interface{}, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("ADR-SEC-B: cannot parse operator private key (tried PKCS8/EC/PKCS1)")
}

// Sign signs the canonical manifest bytes with the operator key. For Ed25519 the message is
// signed directly; for ECDSA-P256 the SHA-256 digest is signed.
func Sign(signer crypto.Signer, canonical []byte) ([]byte, error) {
	switch signer.(type) {
	case ed25519.PrivateKey:
		return signer.Sign(nil, canonical, crypto.Hash(0))
	default: // ECDSA-P256
		digest := sha256.Sum256(canonical)
		return signer.Sign(nil, digest[:], crypto.SHA256)
	}
}

// Verify verifies a signature over canonical bytes using the operator public key.
func Verify(pub crypto.PublicKey, canonical, sig []byte) bool {
	switch p := pub.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(p, canonical, sig)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(canonical)
		return ecdsa.VerifyASN1(p, digest[:], sig)
	default:
		return false
	}
}

// OperatorPublicKeyFromCA pins the operator leaf public key. caPEM is the trusted CA bundle
// (ca.crt). leafPEM is the operator certificate (operator's tls.crt) whose key signed the
// manifest — the agent receives it implicitly by trusting the same CA. Here the agent does not
// receive the leaf over the wire; instead it loads the operator cert that cert-manager issued
// against the shared CA from a known path and verifies it chains to the CA AND carries the
// operator SPIFFE ID, then returns its public key. If the chain or SPIFFE pin fails, error.
func OperatorPublicKeyFromCA(caPEM, operatorCertPEM []byte) (crypto.PublicKey, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("ADR-SEC-B: no CA certs in bundle")
	}
	block, _ := pem.Decode(operatorCertPEM)
	if block == nil {
		return nil, fmt.Errorf("ADR-SEC-B: no PEM block in operator cert")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ADR-SEC-B: parse operator cert: %w", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("ADR-SEC-B: operator cert does not chain to trusted CA: %w", err)
	}
	if !hasOperatorSPIFFE(leaf) {
		return nil, fmt.Errorf("ADR-SEC-B: operator cert lacks %s SPIFFE SAN", OperatorSPIFFESuffix)
	}
	return leaf.PublicKey, nil
}

func hasOperatorSPIFFE(c *x509.Certificate) bool {
	for _, u := range c.URIs {
		if len(u.String()) >= len(OperatorSPIFFESuffix) &&
			u.String()[len(u.String())-len(OperatorSPIFFESuffix):] == OperatorSPIFFESuffix {
			return true
		}
	}
	return false
}
