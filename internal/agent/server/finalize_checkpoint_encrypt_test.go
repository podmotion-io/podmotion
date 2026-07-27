/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// finalize_checkpoint_encrypt_test.go — A-01 contract test (finding C-1).
//
// C-1 was: the ctr-native (DEFAULT) checkpoint branch returned before encryptCheckpointDir, so a
// checkpoint produced by containerd-native `ctr tasks checkpoint` shipped PLAINTEXT process memory
// at rest, while only the raw-CRIU fallback path encrypted. Both branches now route through the
// single shared primitive finalizeCheckpointDir(migrationName, imagesDir) — guard-BEFORE-encrypt
// ordering (verifyShmemPagemapCompleteness reads plaintext first, then encryptCheckpointDir).
//
// These tests are driven from a REAL produced checkpoint image set (a pycriu-built mm-*.img with a
// real anon-shared VMA + its matching pagemap-shmem image, plus config.json to mark the ctr-native
// shape and an mm layer to encrypt) — NOT zero-entry writeMinimalImg synthetics (per arch_a-C1 /
// B-09). They assert:
//
//   1. Both the ctr-native corpus (config.json present) and the raw-CRIU corpus (no config.json)
//      reach encryptCheckpointDir: after finalizeCheckpointDir every plaintext layer is replaced
//      by ciphertext and a .pm-encrypted marker (checkpointEncMarkerFile) is written.
//   2. Verification: the .pm-encrypted marker exists on the CTR path — the exact plaintext-shipping
//      bug (C-1) is what its absence would prove.
//   3. guard-BEFORE-encrypt ordering: a corpus whose anon-shared VMA has NO matching
//      pagemap-shmem image fails the shmem guard (typed FailedPrecondition) and does NOT encrypt
//      (no marker, layers still plaintext) — the guard must have read plaintext to detect the gap.
//
// FALSIFIABILITY / "would have caught the bug": TestFinalizeCheckpointDir_CtrPathEncrypts_C1 fails
// against the PRE-A-01 ctr branch, which returned WITHOUT calling encryptCheckpointDir — the
// .pm-encrypted marker would be absent and the mm layer would still be plaintext. It only passes
// once the ctr branch routes through finalizeCheckpointDir (the fix).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"github.com/podmotion-io/podmotion/internal/agent/encryption"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// realCheckpointCorpusGenPy produces a REAL CRIU-shaped mm-*.img via pycriu with a single
// anon-shared VMA (VMA_ANON_SHARED = 1<<3 in criu vma.proto). argv[2] selects whether the matching
// pagemap-shmem-<shmid>.img is written (shape "complete") or omitted (shape "incomplete"), so the
// finalize shmem guard can be exercised both green and red against real decoded image content. A
// small non-image mm layer is always present so encryptCheckpointDir has a layer to seal.
const realCheckpointCorpusGenPy = `
import sys, os
import pycriu

out = sys.argv[1]
shape = sys.argv[2]
SHMID = 4242

# VMA status bits — MUST match the production guard's constants (shmem_pagemap_guard.go:
# VMA_ANON_SHARED = 1<<8). A VMA carrying this bit + a non-zero shmid obligates a matching
# pagemap-shmem-<shmid>.img, which is exactly what verifyShmemPagemapCompleteness checks.
VMA_ANON_SHARED = 1 << 8

def dump(fn, magic, entries):
    with open(os.path.join(out, fn), 'wb') as f:
        pycriu.images.dump({'magic': magic, 'entries': entries}, f)

# One mm image with a single anon-shared VMA referencing SHMID → obligates pagemap-shmem-SHMID.img.
vma = {'start': 0x7f0000000000, 'end': 0x7f0000001000, 'pgoff': 0, 'shmid': SHMID,
       'prot': 0, 'flags': 0, 'status': VMA_ANON_SHARED, 'fd': -1, 'fdflags': 0}
mm = {'mm_start_code': 0, 'mm_end_code': 0, 'mm_start_data': 0, 'mm_end_data': 0,
      'mm_start_stack': 0, 'mm_start_brk': 0, 'mm_brk': 0, 'mm_arg_start': 0, 'mm_arg_end': 0,
      'mm_env_start': 0, 'mm_env_end': 0, 'exe_file_id': 0, 'vmas': [vma], 'dumpable': 1}
dump('mm-9.img', 'MM', [mm])

if shape == 'complete':
    # Matching pagemap-shmem image so the shmem-completeness guard is satisfied.
    pm = {'pages_id': 1, 'maps': [{'vaddr': 0x7f0000000000, 'nr_pages': 1}]}
    with open(os.path.join(out, 'pagemap-shmem-%d.img' % SHMID), 'wb') as f:
        pycriu.images.dump({'magic': 'PAGEMAP', 'entries': [pm]}, f)
elif shape == 'incomplete':
    # Deliberately omit pagemap-shmem-SHMID.img → the guard must fire (and must have read the
    # PLAINTEXT mm image to discover the missing key).
    pass
else:
    sys.stderr.write('unknown shape %s\n' % shape)
    sys.exit(2)

print('CKPT_CORPUS_OK', shape)
`

// genRealCheckpointCorpus writes a real-shape checkpoint image set into dir. If ctr is true it also
// writes a config.json (the marker of a ctr-native produced set); the raw-CRIU shape omits it. It
// skips (like pycriuEnv) when python3/pycriu are unavailable.
func genRealCheckpointCorpus(t *testing.T, dir, shape string, ctr bool) {
	t.Helper()
	pypath, extraEnv := pycriuEnv(t) // skips if pycriu unavailable
	genPath := filepath.Join(t.TempDir(), "pm-gen-ckpt-corpus.py")
	if err := os.WriteFile(genPath, []byte(realCheckpointCorpusGenPy), 0o600); err != nil {
		t.Fatalf("write checkpoint corpus generator: %v", err)
	}
	cmd := exec.Command("python3", genPath, dir, shape)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("genRealCheckpointCorpus(%q): %v\noutput: %s", shape, err, out)
	}
	if !strings.Contains(string(out), "CKPT_CORPUS_OK") {
		t.Fatalf("genRealCheckpointCorpus(%q): generator did not report CKPT_CORPUS_OK; output: %s", shape, out)
	}
	if ctr {
		// config.json is the ctr-native marker (staged by ctr checkpoint). Its presence models a
		// ctr-produced set; encryptCheckpointDir treats it as an ordinary layer to seal.
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"ociVersion":"1.0.0"}`), 0o600); err != nil {
			t.Fatalf("write config.json: %v", err)
		}
	}
}

// newFinalizeTestServer builds an AgentServer whose k8s client carries the PodMigration (with a
// UID for the HB-1 AAD binding) and the "<migration>-checkpoint-key" Secret that turns encryption
// ON (ADR-0029 opt-in). POD_NAMESPACE is set so loadCheckpointKey/migrationUIDForName resolve to ns.
func newFinalizeTestServer(t *testing.T, ns, migration string) *AgentServer {
	t.Helper()
	t.Setenv("POD_NAMESPACE", ns)

	// Interim key material: a single P-256 keypair the source uses to derive the shared key
	// (recipient-pubkey + recipient-privkey), plus a non-empty epoch (required by loadCheckpointKey).
	pub, priv, err := encryption.GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("GenerateEphemeralKey: %v", err)
	}

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("pmv1.AddToScheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1.AddToScheme: %v", err)
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migration, Namespace: ns, UID: types.UID("uid-" + migration)},
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: migration + "-checkpoint-key", Namespace: ns},
		Data: map[string][]byte{
			"recipient-pubkey":  pub,
			"recipient-privkey": priv,
			"epoch":             []byte("epoch-1"),
		},
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, sec).Build()
	return New("test-node", &criu.StubCheckpointer{}, cl)
}

// assertEncrypted asserts finalizeCheckpointDir reached encryptCheckpointDir: the .pm-encrypted
// marker exists and the mm layer content is ciphertext (differs from the pre-finalize plaintext).
func assertEncrypted(t *testing.T, dir string, plaintextMM []byte) {
	t.Helper()
	markerPath := filepath.Join(dir, checkpointEncMarkerFile)
	if _, statErr := os.Stat(markerPath); statErr != nil {
		t.Fatalf("Verification: expected %s marker after finalizeCheckpointDir (proves encryptCheckpointDir ran); stat err: %v", checkpointEncMarkerFile, statErr)
	}
	nowMM, err := os.ReadFile(filepath.Join(dir, "mm-9.img"))
	if err != nil {
		t.Fatalf("read mm layer after finalize: %v", err)
	}
	if string(nowMM) == string(plaintextMM) {
		t.Fatalf("mm-9.img is unchanged after finalizeCheckpointDir — encryptCheckpointDir did NOT run (plaintext shipped, C-1 regression)")
	}
}

// TestFinalizeCheckpointDir_CtrPathEncrypts_C1 is the "would have caught the bug" test for C-1.
// It drives finalizeCheckpointDir on a real ctr-native produced corpus (config.json present) and
// asserts both the shmem guard AND encryptCheckpointDir run. Against the PRE-A-01 ctr branch (which
// returned before encryptCheckpointDir) the .pm-encrypted marker would be absent and mm-9.img would
// still be plaintext — this test would FAIL, exactly catching the plaintext-shipping bug.
func TestFinalizeCheckpointDir_CtrPathEncrypts_C1(t *testing.T) {
	const ns, mig = "podmotion-system", "mig-ctr"
	withRepoPycriuPath(t) // production guard reads this pycriuPythonPath var
	dir := t.TempDir()
	genRealCheckpointCorpus(t, dir, "complete", true /* ctr */)
	plaintextMM, err := os.ReadFile(filepath.Join(dir, "mm-9.img"))
	if err != nil {
		t.Fatalf("read plaintext mm layer: %v", err)
	}

	s := newFinalizeTestServer(t, ns, mig)
	if finErr := s.finalizeCheckpointDir(mig, dir); finErr != nil {
		t.Fatalf("finalizeCheckpointDir (ctr corpus) returned error: %v", finErr)
	}
	assertEncrypted(t, dir, plaintextMM)
}

// TestFinalizeCheckpointDir_RawPathEncrypts asserts the raw-CRIU corpus (no config.json) reaches
// encryptCheckpointDir identically — the both-dumpers-reach-encrypt half of the contract.
func TestFinalizeCheckpointDir_RawPathEncrypts(t *testing.T) {
	const ns, mig = "podmotion-system", "mig-raw"
	withRepoPycriuPath(t) // production guard reads this pycriuPythonPath var
	dir := t.TempDir()
	genRealCheckpointCorpus(t, dir, "complete", false /* raw */)
	plaintextMM, err := os.ReadFile(filepath.Join(dir, "mm-9.img"))
	if err != nil {
		t.Fatalf("read plaintext mm layer: %v", err)
	}

	s := newFinalizeTestServer(t, ns, mig)
	if finErr := s.finalizeCheckpointDir(mig, dir); finErr != nil {
		t.Fatalf("finalizeCheckpointDir (raw corpus) returned error: %v", finErr)
	}
	assertEncrypted(t, dir, plaintextMM)
}

// TestFinalizeCheckpointDir_GuardBeforeEncrypt asserts guard-BEFORE-encrypt ordering: an incomplete
// shmem set (anon-shared VMA with NO matching pagemap-shmem image) fails the guard with a typed
// FailedPrecondition and does NOT encrypt. The guard could only detect the missing key by reading
// the PLAINTEXT mm image — so proving it fires proves it read plaintext first, before any encrypt.
func TestFinalizeCheckpointDir_GuardBeforeEncrypt(t *testing.T) {
	const ns, mig = "podmotion-system", "mig-guard"
	withRepoPycriuPath(t) // production guard reads this pycriuPythonPath var
	dir := t.TempDir()
	genRealCheckpointCorpus(t, dir, "incomplete", true /* ctr */)

	s := newFinalizeTestServer(t, ns, mig)
	finErr := s.finalizeCheckpointDir(mig, dir)
	if finErr == nil {
		t.Fatalf("expected finalizeCheckpointDir to FAIL on an incomplete shmem set (missing pagemap-shmem), but it succeeded")
	}
	// Typed status per ADR-0246: the shmem-completeness guard returns codes.FailedPrecondition.
	if code := status.Code(finErr); code != codes.FailedPrecondition {
		t.Fatalf("expected codes.FailedPrecondition from the shmem guard, got %v (%v)", code, finErr)
	}
	// Guard ran BEFORE encrypt: no ciphertext marker was written.
	if _, statErr := os.Stat(filepath.Join(dir, checkpointEncMarkerFile)); statErr == nil {
		t.Fatalf("guard-before-encrypt violated: %s marker exists even though the shmem guard failed (encryptCheckpointDir must NOT have run)", checkpointEncMarkerFile)
	}
}
