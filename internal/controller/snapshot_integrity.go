/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// ADR-0393 snapshot-integrity primitives.
//
// The SourcePodSpecSnapshot is protected by an operator-KEYED HMAC-SHA256, not a keyless hash.
// This is the load-bearing security property: the node agent SA is a co-writer of the
// podmigrations/status subresource (charts/podmotion/templates/clusterrole.yaml grants both the
// operator and the agent podmigrations/status:[get,patch,update], and subresource RBAC has no
// field granularity). A keyless SHA256 co-located on the same writable artifact would be integrity
// theater — any co-writer could rewrite the spec bytes and recompute the hash. Keying the HMAC with
// a secret the agent SA cannot read closes that: a co-writer can still write bytes, but cannot
// produce a valid MAC, so the consume path (verifySnapshotIntegrity) fails closed on a forged
// snapshot rather than laundering an attacker-chosen PodSpec through r.Create.
const (
	snapshotHMACSecretName = "podmotion-operator-snapshot-hmac"
	snapshotHMACSecretKey  = "hmac.key"
	snapshotHMACMinKeyLen  = 32
)

// snapshotHMACKey returns the operator-only HMAC key, loading-or-creating it lazily from a Secret
// in the operator's own namespace on first use and caching it in-process. The Secret is readable
// only by principals with a secrets:get grant in the operator namespace; the node agent's
// ClusterRole (podmotion-agent-role) has no secrets grant at all, so the agent cannot recover the
// key even though it can write the snapshot field. The key is durable across operator restarts,
// which is required so a snapshot captured before a crash still verifies after the restart
// (ADR-0393 D-ACCEPT).
//
// Fail-closed: any inability to obtain the key returns an error; callers (capture and consume)
// treat that as "cannot prove integrity" and refuse to proceed, never falling open.
func (r *PodMigrationReconciler) snapshotHMACKey(ctx context.Context) ([]byte, error) {
	r.snapshotHMACKeyMu.Lock()
	defer r.snapshotHMACKeyMu.Unlock()

	if len(r.testOnlySnapshotHMACKey) > 0 {
		return r.testOnlySnapshotHMACKey, nil
	}
	if len(r.snapshotHMACKeyCache) > 0 {
		return r.snapshotHMACKeyCache, nil
	}
	if r.KubeClient == nil {
		return nil, fmt.Errorf("ADR-0393: no KubeClient available to load the operator snapshot HMAC key (fail-closed)")
	}

	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		ns = "podmotion-system"
	}
	secrets := r.KubeClient.CoreV1().Secrets(ns)

	sec, err := secrets.Get(ctx, snapshotHMACSecretName, metav1.GetOptions{})
	if err == nil {
		if k := sec.Data[snapshotHMACSecretKey]; len(k) >= snapshotHMACMinKeyLen {
			r.snapshotHMACKeyCache = k
			return k, nil
		}
		return nil, fmt.Errorf("ADR-0393: operator snapshot HMAC secret %s/%s exists but key %q is missing/too short",
			ns, snapshotHMACSecretName, snapshotHMACSecretKey)
	}
	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("ADR-0393: get operator snapshot HMAC secret %s/%s: %w", ns, snapshotHMACSecretName, err)
	}

	// Not present — mint a fresh random key and persist it. Idempotent under a create race.
	key := make([]byte, snapshotHMACMinKeyLen)
	if _, rErr := rand.Read(key); rErr != nil {
		return nil, fmt.Errorf("ADR-0393: generate operator snapshot HMAC key: %w", rErr)
	}
	newSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      snapshotHMACSecretName,
			Namespace: ns,
			Labels:    map[string]string{"app.kubernetes.io/name": "podmotion"},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{snapshotHMACSecretKey: key},
	}
	created, cErr := secrets.Create(ctx, newSec, metav1.CreateOptions{})
	if cErr != nil {
		if apierrors.IsAlreadyExists(cErr) {
			// Another operator replica created it first — re-read and use theirs.
			sec2, gErr := secrets.Get(ctx, snapshotHMACSecretName, metav1.GetOptions{})
			if gErr != nil {
				return nil, fmt.Errorf("ADR-0393: re-get operator snapshot HMAC secret after create race: %w", gErr)
			}
			if k := sec2.Data[snapshotHMACSecretKey]; len(k) >= snapshotHMACMinKeyLen {
				r.snapshotHMACKeyCache = k
				return k, nil
			}
			return nil, fmt.Errorf("ADR-0393: operator snapshot HMAC secret created concurrently but key %q invalid", snapshotHMACSecretKey)
		}
		return nil, fmt.Errorf("ADR-0393: create operator snapshot HMAC secret %s/%s: %w", ns, snapshotHMACSecretName, cErr)
	}
	r.snapshotHMACKeyCache = created.Data[snapshotHMACSecretKey]
	return r.snapshotHMACKeyCache, nil
}

// computeSnapshotHMAC computes the keyed HMAC-SHA256 over the snapshot's integrity-bound inputs.
// Fields are length-delimited by a NUL separator so no concatenation ambiguity exists between,
// e.g., a serviceAccountName ending in the same bytes a UID begins with. pmUID binds the snapshot
// to a single migration object (a snapshot cannot be replayed onto a different PodMigration).
func computeSnapshotHMAC(key []byte, s *pmv1.SourcePodSpecSnapshot, pmUID string) string {
	mac := hmac.New(sha256.New, key)
	writeField := func(b []byte) {
		mac.Write(b)
		mac.Write([]byte{0})
	}
	writeField(s.PodSpecJSON)
	writeField([]byte(s.SourcePodUID))
	writeField([]byte(pmUID))
	writeField([]byte(s.SecurityContextDigest))
	writeField([]byte(s.ServiceAccountName))
	return hex.EncodeToString(mac.Sum(nil))
}

// podSecurityContextDigest is a SHA256 over the JSON-serialized pod-level SecurityContext. It is a
// belt-and-suspenders re-assert on the security-sensitive subset of the spec (the whole PodSpecJSON
// is already covered by the HMAC); a mismatch on recreate is a tamper signal that fails closed.
func podSecurityContextDigest(spec *corev1.PodSpec) (string, error) {
	b, err := json.Marshal(spec.SecurityContext)
	if err != nil {
		return "", fmt.Errorf("ADR-0393: marshal pod security context: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// verifySnapshotIntegrity implements ADR-0393 D5: the snapshot may be consumed only when it is
// present, deserializable, bound to this migration/source-pod, byte-consistent on its security
// context, and carries a valid operator-keyed HMAC. Any failure returns (false, reason) and the
// caller fails closed (no recreate) — never a guessed/widened pod.
func (r *PodMigrationReconciler) verifySnapshotIntegrity(ctx context.Context, pm *pmv1.PodMigration) (bool, string) {
	s := pm.Status.SourcePodSpecSnapshot
	if s == nil {
		return false, "no snapshot present"
	}
	if len(s.PodSpecJSON) == 0 {
		return false, "snapshot pod spec is empty"
	}
	var spec corev1.PodSpec
	if err := json.Unmarshal(s.PodSpecJSON, &spec); err != nil {
		return false, "snapshot pod spec does not deserialize to a valid PodSpec"
	}
	if pm.Spec.SourcePodUID != "" && s.SourcePodUID != pm.Spec.SourcePodUID {
		return false, "snapshot SourcePodUID does not match pm.Spec.SourcePodUID (stale/mis-bound)"
	}
	digest, err := podSecurityContextDigest(&spec)
	if err != nil {
		return false, "could not recompute security context digest"
	}
	if digest != s.SecurityContextDigest {
		return false, "security context digest mismatch (tamper)"
	}
	if spec.ServiceAccountName != s.ServiceAccountName {
		return false, "service account name mismatch (tamper)"
	}
	key, err := r.snapshotHMACKey(ctx)
	if err != nil {
		return false, fmt.Sprintf("operator snapshot HMAC key unavailable: %v", err)
	}
	want := computeSnapshotHMAC(key, s, string(pm.UID))
	if !hmac.Equal([]byte(want), []byte(s.IntegrityHMAC)) {
		return false, "integrity HMAC mismatch (tamper/forgery)"
	}
	return true, ""
}
