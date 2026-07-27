/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package criu

// criu_stats_internal_test.go — fail-closed phase-gate remediation (item 1a/1b) unit coverage,
// redesigned per ADR-Redesign for the go-criu in-process reader (no python3/pycriu dependency).
//
// decodeCRIUStats must fail closed (return an error, never a silent 0) whenever the stats-dump
// image is absent, has a magic mismatch, or fails to unmarshal — and must return the real,
// byte-exact pages_written*4096/1MiB value when a genuine stats-dump image decodes successfully.
// writeFakeStatsDump below constructs a real go-criu StatsEntry, marshals it with the same
// protobuf library the production decoder uses, and lays it out with the exact magic/size header
// stats.readStatisticsFile expects — this is a real round trip through the production decode
// path, not a mock of it.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/checkpoint-restore/go-criu/v7/stats"
	"google.golang.org/protobuf/proto"
)

func u32p(v uint32) *uint32 { return &v }
func u64p(v uint64) *uint64 { return &v }

// writeFakeStatsDump marshals a real DumpStatsEntry with the given pagesWritten count and
// writes it into dir/stats-dump using the exact on-disk layout go-criu/v7/stats expects
// (primary magic @0x0, secondary magic @0x4, payload size @0x8, protobuf payload @0xC).
func writeFakeStatsDump(t *testing.T, dir string, pagesWritten uint64) {
	t.Helper()

	entry := &stats.StatsEntry{
		Dump: &stats.DumpStatsEntry{
			FreezingTime:       u32p(100),
			FrozenTime:         u32p(200),
			MemdumpTime:        u32p(300),
			MemwriteTime:       u32p(400),
			PagesScanned:       u64p(pagesWritten + 100),
			PagesSkippedParent: u64p(0),
			PagesWritten:       u64p(pagesWritten),
			PagesLazy:          u64p(0),
		},
	}
	payload, err := proto.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal fake StatsEntry: %v", err)
	}

	buf := make([]byte, stats.PayloadOffset+len(payload))
	binary.LittleEndian.PutUint32(buf[stats.PrimaryMagicOffset:], stats.ImgServiceMagic)
	binary.LittleEndian.PutUint32(buf[stats.SecondaryMagicOffset:], stats.StatsMagic)
	binary.LittleEndian.PutUint32(buf[stats.SizeOffset:], uint32(len(payload)))
	copy(buf[stats.PayloadOffset:], payload)

	if err := os.WriteFile(filepath.Join(dir, stats.StatsDump), buf, 0o600); err != nil {
		t.Fatalf("write fake stats-dump: %v", err)
	}
}

// TestDecodeCRIUStats_MissingImage_FailsClosed asserts that an ImagesDir with no stats-dump
// file produces an error, never a fabricated (0, nil).
func TestDecodeCRIUStats_MissingImage_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	mb, err := decodeCRIUStats(dir)
	if err == nil {
		t.Fatalf("expected decodeCRIUStats to fail closed on missing stats image, got (%d, nil)", mb)
	}
}

// TestDecodeCRIUStats_CorruptMagic_FailsClosed asserts that a stats-dump file present but with
// the wrong magic bytes (e.g. truncated/corrupted write) fails closed, not (0, nil). This is the
// direct regression test for the exact bug class the redesign closes: a decode failure must
// never be silently coerced into "zero dirty pages."
func TestDecodeCRIUStats_CorruptMagic_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, stats.StatsDump), []byte("not a real criu stats image"), 0o600); err != nil {
		t.Fatalf("write corrupt stats-dump: %v", err)
	}
	mb, err := decodeCRIUStats(dir)
	if err == nil {
		t.Fatalf("expected decodeCRIUStats to fail closed on corrupt stats image, got (%d, nil)", mb)
	}
}

// TestDecodeCRIUStats_RealDecode_ByteExact asserts that a genuine, well-formed stats-dump image
// decodes to the byte-exact pages_written*4096/1MiB value via the go-criu in-process reader —
// the same computation verified live against the KVM cluster's real CRIU 4.2 binary (13753
// pages_written * 4096 bytes/page == the exact pages-1.img size on disk).
func TestDecodeCRIUStats_RealDecode_ByteExact(t *testing.T) {
	dir := t.TempDir()
	const pagesWritten = 13753 // 13753 * 4096 = 56,332,288 bytes = 53.72 MiB -> 53 MiB (int division)
	writeFakeStatsDump(t, dir, pagesWritten)

	gotMB, err := decodeCRIUStats(dir)
	if err != nil {
		t.Fatalf("decodeCRIUStats: unexpected error: %v", err)
	}
	wantMB := int64(pagesWritten*statsPageSizeBytes) / (1024 * 1024)
	if gotMB != wantMB {
		t.Errorf("decodeCRIUStats() = %d MB, want %d MB", gotMB, wantMB)
	}
}

// TestDecodeCRIUStats_MeasuredZero_NotAnError asserts that a genuinely idle round (real
// pages_written == 0, successfully decoded) returns (0, nil) — "measured zero" and "could not
// measure" must be structurally distinguishable, and this is the "measured zero" case, which
// must NOT be an error.
func TestDecodeCRIUStats_MeasuredZero_NotAnError(t *testing.T) {
	dir := t.TempDir()
	writeFakeStatsDump(t, dir, 0)

	gotMB, err := decodeCRIUStats(dir)
	if err != nil {
		t.Fatalf("decodeCRIUStats: unexpected error for a genuine zero-dirty-page round: %v", err)
	}
	if gotMB != 0 {
		t.Errorf("decodeCRIUStats() = %d MB, want 0", gotMB)
	}
}
