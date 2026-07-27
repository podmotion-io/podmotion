/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0414_devshm_dump_capture_test.go — dump-side /dev/shm content capture for the ctr fast path.
//
// Ground truth (live-decoded on the KVM cluster): the containerd/ctr-checkpoint fast path records
// /dev/shm as an EXTERNAL sandbox bind mount (config.json: {"destination":"/dev/shm","type":"bind",
// "source":"/run/.../sandboxes/<id>/shm"}; mountpoints image: ext_key='/dev/shm', root_dev=<N>).
// runc's CRIU therefore never tar-serializes /dev/shm content — no tmpfs-dev-<root_dev>.tar.gz.img
// is written — so a workload with real POSIX-shmem state (PostgreSQL.<N>) loses it at dump and the
// internalizing restore (ADR-0414) has an empty tmpfs. captureCtrDevShmContent closes that half by
// tar-serializing the live sandbox shm dir into the CRIU-native content image. These tests cover
// the decomposed, python-free pieces: the image naming, the config.json source resolution + host
// re-root, and the tar content image itself.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDevShmContentImageName(t *testing.T) {
	// CRIU names the tmpfs content image tmpfs-dev-<root_dev>.tar.gz.img (verified live: /dev
	// root_dev=558 -> tmpfs-dev-558.tar.gz.img). The restore reads it back by the same root_dev
	// the mountpoints entry carries, so this basename must match CRIU's exactly.
	if got := devShmContentImageName(532); got != "tmpfs-dev-532.tar.gz.img" {
		t.Fatalf("devShmContentImageName(532) = %q, want tmpfs-dev-532.tar.gz.img", got)
	}
}

func TestDevShmHostSourceDir(t *testing.T) {
	writeCfg := func(t *testing.T, body string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("rke2-sandbox-bind is re-rooted onto /host-run", func(t *testing.T) {
		// The real shape captured from a live redis checkpoint's config.json.
		dir := writeCfg(t, `{"mounts":[
			{"destination":"/dev","type":"tmpfs","source":"tmpfs"},
			{"destination":"/dev/shm","type":"bind","source":"/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/abc123/shm","options":["rbind","rprivate","rw"]}
		]}`)
		got, ok := devShmHostSourceDir(dir)
		if !ok {
			t.Fatal("expected ok=true for a /dev/shm sandbox bind under /run")
		}
		want := "/host-run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/abc123/shm"
		if got != want {
			t.Fatalf("host source dir = %q, want %q", got, want)
		}
	})

	t.Run("system-containerd sandbox bind is re-rooted onto /host-run", func(t *testing.T) {
		dir := writeCfg(t, `{"mounts":[
			{"destination":"/dev/shm","type":"bind","source":"/run/containerd/io.containerd.grpc.v1.cri/sandboxes/deadbeef/shm"}
		]}`)
		got, ok := devShmHostSourceDir(dir)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if want := "/host-run/containerd/io.containerd.grpc.v1.cri/sandboxes/deadbeef/shm"; got != want {
			t.Fatalf("host source dir = %q, want %q", got, want)
		}
	})

	t.Run("no /dev/shm mount -> ok=false", func(t *testing.T) {
		dir := writeCfg(t, `{"mounts":[{"destination":"/data","type":"bind","source":"/run/foo"}]}`)
		if _, ok := devShmHostSourceDir(dir); ok {
			t.Fatal("expected ok=false when config.json has no /dev/shm mount")
		}
	})

	t.Run("source not under /run (unreachable from agent) -> ok=false", func(t *testing.T) {
		dir := writeCfg(t, `{"mounts":[{"destination":"/dev/shm","type":"bind","source":"/var/lib/somewhere/shm"}]}`)
		if _, ok := devShmHostSourceDir(dir); ok {
			t.Fatal("expected ok=false for a /dev/shm source not under /run")
		}
	})

	t.Run("missing config.json -> ok=false", func(t *testing.T) {
		if _, ok := devShmHostSourceDir(t.TempDir()); ok {
			t.Fatal("expected ok=false when config.json is absent")
		}
	})
}

// readTarGz returns the set of member names in a gzip tarball.
func readTarGz(t *testing.T, path string) map[string]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("output is not a valid gzip stream: %v", err)
	}
	defer gz.Close()
	names := map[string]bool{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names[h.Name] = true
	}
	return names
}

func TestWriteDevShmContentImage(t *testing.T) {
	// Populated /dev/shm: the content image must be a valid gzip tar carrying the segment file at
	// its ./-relative path, so CRIU's restore_tmpfs extracts dev/shm/PostgreSQL.<N> back into the
	// CRIU-owned tmpfs before files-reg opens it.
	t.Run("captures the POSIX-shmem segment file", func(t *testing.T) {
		shmDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(shmDir, "PostgreSQL.3620463376"), []byte("shared-memory-bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), devShmContentImageName(532))
		if err := writeDevShmContentImage(context.Background(), shmDir, out); err != nil {
			t.Fatalf("writeDevShmContentImage: %v", err)
		}
		names := readTarGz(t, out)
		if !names["./PostgreSQL.3620463376"] {
			t.Fatalf("content image missing the shm segment file; members=%v", names)
		}
	})

	// Empty /dev/shm (e.g. Redis): still a valid, CRIU-consumable tarball — an empty owned tmpfs,
	// exactly what CRIU's own dump_tmpfs writes when there is nothing under /dev/shm.
	t.Run("empty /dev/shm yields a valid empty content image", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), devShmContentImageName(532))
		if err := writeDevShmContentImage(context.Background(), t.TempDir(), out); err != nil {
			t.Fatalf("writeDevShmContentImage on empty dir: %v", err)
		}
		// Must be a readable gzip tar (the "." root entry is acceptable; the point is it decodes).
		readTarGz(t, out)
	})

	// A tar failure must leave no partial/torn content image in the checkpoint dir.
	t.Run("failure removes any partial image", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), devShmContentImageName(532))
		if err := writeDevShmContentImage(context.Background(), "/nonexistent/shm/source/dir", out); err == nil {
			t.Fatal("expected an error tarring a nonexistent source dir")
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Fatalf("expected no content image left behind on failure, stat err = %v", statErr)
		}
	})
}
