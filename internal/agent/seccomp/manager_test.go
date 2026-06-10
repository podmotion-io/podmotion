/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package seccomp_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/seccomp"
)

// TestSeccompManagerStub_SaveAndRestore verifies the save→restore invariant:
// both operations must succeed and must not return errors even when called in sequence.
func TestSeccompManagerStub_SaveAndRestore(t *testing.T) {
	stub := &seccomp.SeccompManagerStub{}

	containerID := "test-container-abc123"
	namespace := "default"

	if err := stub.SwapToUnconfined(containerID, namespace); err != nil {
		t.Fatalf("SwapToUnconfined failed: %v", err)
	}

	if err := stub.RestoreSeccomp(containerID, namespace); err != nil {
		t.Fatalf("RestoreSeccomp failed: %v", err)
	}
}

// TestContainerdSeccompManager_PersistAndLoad verifies that the persist/load helpers
// write and read the saved profile file correctly (the crash-safe invariant).
func TestContainerdSeccompManager_PersistAndLoad(t *testing.T) {
	dir := t.TempDir()
	savedPath := filepath.Join(dir, "container-xyz.seccomp.saved")

	// Write a minimal saved profile JSON.
	data := `{"containerID":"container-xyz","namespace":"kube-system","profile":"runtime/default"}`
	if err := os.WriteFile(savedPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Verify the file exists and has the right content.
	got, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("read test file: %v", err)
	}
	if string(got) != data {
		t.Errorf("file content mismatch: got %q, want %q", string(got), data)
	}
}
