/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package seccomp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
)

// withTempSavedDir redirects the package savedProfileDir to a temp dir for the duration of
// a test so the /run/podmotion/seccomp-restore path is not required (and is not polluted).
func withTempSavedDir(t *testing.T) string {
	t.Helper()
	orig := savedProfileDir
	dir := t.TempDir()
	savedProfileDir = dir
	t.Cleanup(func() { savedProfileDir = orig })
	return dir
}

// fakeReader returns a fixed profile (or error), standing in for the live OCI bundle read.
type fakeReader struct {
	profile string
	err     error
}

func (f fakeReader) ReadSeccompProfile(string) (string, error) { return f.profile, f.err }

// fakeMutator records calls and can be made to fail a fixed number of restore attempts,
// standing in for the (partial) Kill+Create OCI-spec mutation.
type fakeMutator struct {
	unconfinedCalls int
	profileCalls    int
	lastProfile     string
	failRestores    int // number of ApplyProfile calls to fail before succeeding
	failUnconfined  bool
}

func (f *fakeMutator) ApplyUnconfined(context.Context, string) error {
	f.unconfinedCalls++
	if f.failUnconfined {
		return errors.New("apply-unconfined boom")
	}
	return nil
}

func (f *fakeMutator) ApplyProfile(_ context.Context, _, profile string) error {
	f.profileCalls++
	f.lastProfile = profile
	if f.failRestores > 0 {
		f.failRestores--
		return errors.New("apply-profile boom")
	}
	return nil
}

// TestSwapToUnconfined_SavesRealProfile verifies SD-3: the REAL profile read from the
// (faked) live bundle is persisted to <containerID>.json and a SeccompWeakened event fires.
func TestSwapToUnconfined_SavesRealProfile(t *testing.T) {
	withTempSavedDir(t)
	rec := record.NewFakeRecorder(8)
	mut := &fakeMutator{}
	m := &ContainerdSeccompManager{
		Recorder: rec,
		Reader:   fakeReader{profile: "embedded:SCMP_ACT_ERRNO"},
		Mutator:  mut,
	}

	cid := "container-abc123"
	pod := types.NamespacedName{Namespace: "default", Name: "web-0"}
	if err := m.SwapToUnconfined(context.Background(), cid, "default", pod); err != nil {
		t.Fatalf("SwapToUnconfined: %v", err)
	}

	// The REAL profile must be on disk — never the old "runtime/default" hardcode.
	p, err := loadProfile(cid)
	if err != nil {
		t.Fatalf("loadProfile after swap: %v", err)
	}
	if p.Profile != "embedded:SCMP_ACT_ERRNO" {
		t.Errorf("saved profile = %q, want the real read profile", p.Profile)
	}
	if p.PodName != "web-0" || p.PodNamespace != "default" {
		t.Errorf("pod identity not persisted: %+v", p)
	}
	if mut.unconfinedCalls != 1 {
		t.Errorf("ApplyUnconfined calls = %d, want 1", mut.unconfinedCalls)
	}
	assertEvent(t, rec, eventReasonSeccompWeakened)
}

// TestSwapToUnconfined_ReadError_NoSaveNoSwap verifies a live-read failure aborts before
// any swap and persists nothing (so RestoreSeccomp will not later re-apply a bogus profile).
func TestSwapToUnconfined_ReadError_NoSaveNoSwap(t *testing.T) {
	dir := withTempSavedDir(t)
	mut := &fakeMutator{}
	m := &ContainerdSeccompManager{
		Reader:  fakeReader{err: errors.New("config.json missing")},
		Mutator: mut,
	}
	err := m.SwapToUnconfined(context.Background(), "c1", "default", types.NamespacedName{Name: "p", Namespace: "default"})
	if err == nil {
		t.Fatal("expected error on live-read failure")
	}
	if mut.unconfinedCalls != 0 {
		t.Errorf("ApplyUnconfined should not be called on read failure, got %d", mut.unconfinedCalls)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("no profile should be persisted on read failure, found %d files", len(entries))
	}
}

// TestRestoreSeccomp_RestoresAndCleansUp verifies the happy path: the saved profile is
// re-applied, the saved file is deleted, and a SeccompRestored event fires.
func TestRestoreSeccomp_RestoresAndCleansUp(t *testing.T) {
	withTempSavedDir(t)
	rec := record.NewFakeRecorder(8)
	mut := &fakeMutator{}
	m := &ContainerdSeccompManager{
		Recorder: rec,
		Reader:   fakeReader{profile: "embedded:SCMP_ACT_ERRNO"},
		Mutator:  mut,
	}
	cid := "container-restore"
	pod := types.NamespacedName{Namespace: "ns", Name: "pod-1"}

	if err := m.SwapToUnconfined(context.Background(), cid, "ns", pod); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if err := m.RestoreSeccomp(context.Background(), cid, "ns", pod); err != nil {
		t.Fatalf("RestoreSeccomp: %v", err)
	}
	if mut.lastProfile != "embedded:SCMP_ACT_ERRNO" {
		t.Errorf("restored profile = %q, want the saved real profile", mut.lastProfile)
	}
	// Saved file must be gone.
	if _, err := os.Stat(savedProfilePath(cid)); !os.IsNotExist(err) {
		t.Errorf("saved file not cleaned up after restore: err=%v", err)
	}
	assertEvent(t, rec, eventReasonSeccompRestored)
}

// TestRestoreSeccomp_RetryThenSucceed verifies ADR-0009 §4.1: restore retries up to 3
// times; succeeding on attempt 3 still cleans up and emits SeccompRestored (no failure event).
func TestRestoreSeccomp_RetryThenSucceed(t *testing.T) {
	withTempSavedDir(t)
	rec := record.NewFakeRecorder(8)
	mut := &fakeMutator{failRestores: 2} // fail twice, succeed on the 3rd
	m := &ContainerdSeccompManager{
		Recorder: rec,
		Reader:   fakeReader{profile: "unconfined"},
		Mutator:  mut,
	}
	cid := "container-retry"
	pod := types.NamespacedName{Namespace: "ns", Name: "pod-retry"}
	if err := m.SwapToUnconfined(context.Background(), cid, "ns", pod); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if err := m.RestoreSeccomp(context.Background(), cid, "ns", pod); err != nil {
		t.Fatalf("RestoreSeccomp should succeed on attempt 3: %v", err)
	}
	if mut.profileCalls != 3 {
		t.Errorf("ApplyProfile calls = %d, want 3 (2 fail + 1 success)", mut.profileCalls)
	}
	if _, err := os.Stat(savedProfilePath(cid)); !os.IsNotExist(err) {
		t.Errorf("saved file not cleaned up after eventual success")
	}
}

// TestRestoreSeccomp_FailsAfterThree verifies ADR-0009 §4.2/§4.3: after 3 failed attempts
// a SeccompRestorationFailed event fires, the saved file is preserved (still Unconfined),
// and an error is returned.
func TestRestoreSeccomp_FailsAfterThree(t *testing.T) {
	withTempSavedDir(t)
	rec := record.NewFakeRecorder(8)
	mut := &fakeMutator{failRestores: 99} // always fail
	m := &ContainerdSeccompManager{
		Recorder: rec,
		Reader:   fakeReader{profile: "embedded:SCMP_ACT_ERRNO"},
		Mutator:  mut,
		// KubeClient nil — annotation patch is skipped (logged), test still asserts the event.
	}
	cid := "container-fail"
	pod := types.NamespacedName{Namespace: "ns", Name: "pod-fail"}
	if err := m.SwapToUnconfined(context.Background(), cid, "ns", pod); err != nil {
		t.Fatalf("swap: %v", err)
	}
	err := m.RestoreSeccomp(context.Background(), cid, "ns", pod)
	if err == nil {
		t.Fatal("expected restore to fail after max attempts")
	}
	if mut.profileCalls != maxRestoreAttempts {
		t.Errorf("ApplyProfile calls = %d, want %d", mut.profileCalls, maxRestoreAttempts)
	}
	// Saved file MUST survive so a later retry / crash-recovery can re-attempt.
	if _, statErr := os.Stat(savedProfilePath(cid)); statErr != nil {
		t.Errorf("saved file should be preserved on restore failure: %v", statErr)
	}
	assertEvent(t, rec, eventReasonSeccompRestorationFailed)
}

// TestRecoverOrphanedProfiles_RestoresAndEmitsRestart verifies the crash-recovery path:
// a profile left on disk by a prior agent is restored, cleaned up, and a
// SeccompRestoreAfterRestart event is emitted.
func TestRecoverOrphanedProfiles_RestoresAndEmitsRestart(t *testing.T) {
	withTempSavedDir(t)
	rec := record.NewFakeRecorder(8)
	mut := &fakeMutator{}
	m := &ContainerdSeccompManager{Recorder: rec, Mutator: mut}

	// Simulate an orphan left by a crashed predecessor.
	cid := "orphan-xyz"
	if err := persistProfile(savedProfile{
		ContainerID:  cid,
		Namespace:    "ns",
		PodName:      "orphan-pod",
		PodNamespace: "ns",
		Profile:      "embedded:SCMP_ACT_ERRNO",
	}); err != nil {
		t.Fatalf("persist orphan: %v", err)
	}

	n, err := m.RecoverOrphanedProfiles(context.Background())
	if err != nil {
		t.Fatalf("RecoverOrphanedProfiles: %v", err)
	}
	if n != 1 {
		t.Errorf("recovered = %d, want 1", n)
	}
	if _, statErr := os.Stat(savedProfilePath(cid)); !os.IsNotExist(statErr) {
		t.Errorf("orphan file not cleaned up after recovery")
	}
	assertEvent(t, rec, eventReasonSeccompRestoreAfterRestart)
}

// TestRecoverOrphanedProfiles_NoDir is a clean no-op when the dir does not exist.
func TestRecoverOrphanedProfiles_NoDir(t *testing.T) {
	orig := savedProfileDir
	savedProfileDir = filepath.Join(orig, "does-not-exist-xyz")
	t.Cleanup(func() { savedProfileDir = orig })
	m := &ContainerdSeccompManager{Mutator: &fakeMutator{}}
	n, err := m.RecoverOrphanedProfiles(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("expected (0, nil) when dir absent, got (%d, %v)", n, err)
	}
}

// TestParseSeccompProfile covers the OCI config.json profile decode semantics (SD-3).
func TestParseSeccompProfile(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{"no-linux", `{}`, profileUnconfined},
		{"linux-no-seccomp", `{"linux":{}}`, profileUnconfined},
		{"embedded-errno", `{"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ERRNO"}}}`, "embedded:SCMP_ACT_ERRNO"},
		{"embedded-no-action", `{"linux":{"seccomp":{}}}`, "embedded:unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseSeccompProfile([]byte(c.json))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestStub_SaveAndRestore keeps the original no-op stub invariant under the new signature.
func TestStub_SaveAndRestore(t *testing.T) {
	stub := &SeccompManagerStub{}
	pod := types.NamespacedName{Namespace: "default", Name: "p"}
	if err := stub.SwapToUnconfined(context.Background(), "c", "default", pod); err != nil {
		t.Fatalf("stub swap: %v", err)
	}
	if err := stub.RestoreSeccomp(context.Background(), "c", "default", pod); err != nil {
		t.Fatalf("stub restore: %v", err)
	}
}

// assertEvent drains a FakeRecorder channel and fails if no event contains reason.
func assertEvent(t *testing.T, rec *record.FakeRecorder, reason string) {
	t.Helper()
	for {
		select {
		case ev := <-rec.Events:
			if contains(ev, reason) {
				return
			}
		default:
			t.Fatalf("expected an event with reason %q, none found", reason)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// _ ensures corev1 import is used even if event-type constants change.
var _ = corev1.EventTypeWarning
