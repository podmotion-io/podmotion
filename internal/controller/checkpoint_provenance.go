/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package controller

import (
	"context"
	"fmt"
	"os"
	"time"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/grpclimits"
	"github.com/podmotion-io/podmotion/internal/agent/provenance"
	agenttls "github.com/podmotion-io/podmotion/internal/agent/tls"
)

// operatorSigningKeyPath is the operator's mTLS private key, mounted 0400 by ADR-SEC-A §2.1.
// ADR-SEC-B §2.1: the operator signs the checkpoint manifest with this same key — no second
// secret. Overridable via OPERATOR_TLS_KEY for non-standard mounts.
func operatorSigningKeyPath() string {
	if p := os.Getenv("OPERATOR_TLS_KEY"); p != "" {
		return p
	}
	return agenttls.DefaultKeyFile
}

// operatorCertPath is the operator's mTLS leaf certificate (the public half of the signing key),
// carried in the manifest so the agent can CA-pin + SPIFFE-pin it (ADR-SEC-B §2.1).
func operatorCertPath() string {
	if p := os.Getenv("OPERATOR_TLS_CERT"); p != "" {
		return p
	}
	return agenttls.DefaultCertFile
}

// buildSignedCheckpointManifest constructs the ADR-SEC-B signed checkpoint manifest over the
// exact tar bytes the source returned, signs it with the operator key, and returns
// (canonicalManifestJSON, signature, tarSha256). tarSha256 is the source-computed hash forwarded
// unchanged when present; if the source did not supply one (older agent), the operator computes
// it over the bytes it holds. The "ADR-SEC-B" marker lands in the operator binary via the
// imported provenance package and the error strings here.
func (r *PodMigrationReconciler) buildSignedCheckpointManifest(
	ctx context.Context,
	pm *pmv1.PodMigration,
	sourceNode string,
	tarData []byte,
	sourceTarSha256 string,
) (manifestJSON, manifestSig []byte, tarSha256 string, err error) {
	_ = ctx

	// Wire-integrity hash. Forward the source hash unchanged (ADR-SEC-B §2.3 step 2); if absent,
	// compute over the bytes the operator holds.
	tarSha256 = sourceTarSha256
	computed := provenance.SHA256Hex(tarData)
	if tarSha256 == "" {
		tarSha256 = computed
	} else if tarSha256 != computed {
		// The bytes the operator holds do not match the source-declared hash — corruption between
		// source GetCheckpointTar and here. Fail closed (migration stalls pre-TrafficVerified).
		return nil, nil, "", fmt.Errorf("ADR-SEC-B: source tar_sha256 %q != operator-recomputed %q (transfer corruption)", sourceTarSha256, computed)
	}

	// Enumerate per-file digests from the tar (the operator hashes what it actually received).
	files, ferr := provenance.FilesFromTarGz(tarData, grpclimits.MaxDecompressedTarBytes)
	if ferr != nil {
		return nil, nil, "", ferr
	}

	socketStateSHA := ""
	if e := provenance.FindFile(files, provenance.TCPSocketStateFile); e != nil {
		socketStateSHA = e.SHA256
	}

	signer, alg, serr := provenance.LoadSigner(operatorSigningKeyPath())
	if serr != nil {
		return nil, nil, "", serr
	}
	operatorCertPEM, certErr := os.ReadFile(operatorCertPath())
	if certErr != nil {
		return nil, nil, "", fmt.Errorf("ADR-SEC-B: read operator cert for manifest pin: %w", certErr)
	}

	m := &provenance.Manifest{
		Schema:            provenance.ManifestSchema,
		Migration:         pm.Name,
		MigrationUID:      string(pm.UID),
		SourceNode:        sourceNode,
		SourceSPIFFEID:    "spiffe://podmotion.io/ns/" + pm.Namespace + "/sa/podmotion-agent",
		CreatedUnix:       time.Now().Unix(),
		Alg:               alg,
		Files:             files,
		SocketStateSHA256: socketStateSHA,
		OperatorCertPEM:   string(operatorCertPEM),
	}
	m.SetDigest = provenance.ComputeSetDigest(files)

	canonical, cerr := provenance.CanonicalJSON(m)
	if cerr != nil {
		return nil, nil, "", fmt.Errorf("ADR-SEC-B: canonicalize manifest: %w", cerr)
	}
	sig, signErr := provenance.Sign(signer, canonical)
	if signErr != nil {
		return nil, nil, "", fmt.Errorf("ADR-SEC-B: sign manifest: %w", signErr)
	}
	return canonical, sig, tarSha256, nil
}
