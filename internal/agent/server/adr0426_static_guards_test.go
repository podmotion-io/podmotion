/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0426_static_guards_test.go — §P-VERIFY V8/V8b/V8c: the mechanical guards against the wiring
// asymmetry (F1) and the round-2/round-3 demand-shaped-inference regressions returning silently.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// adr0426ExemptFromLiteralNameSearch names the files allowed to still mention the DELETED
// /dev/shm-literal identifiers — because they are documenting the deletion/retarget itself (the same
// precedent TestADR0420_PVERIFY5_WithdrawnMarkerIsAbsent sets for its own file).
var adr0426ExemptFromLiteralNameSearch = map[string]bool{
	"adr0426_dump_side_content_capture.go": true,
	"adr0426_static_guards_test.go":        true,
	"adr0414_devshm_dump_capture_test.go":  true,
	"adr0415_capture_gate_test.go":         true,
}

// TestADR0426_V8_DeletedIdentifiersAppearNowhereInTheTree asserts the wiring-asymmetry guard: the
// deleted /dev/shm-literal functions, and the demand-shaped name round 3 rejected, must not reappear
// anywhere outside the files that document their own deletion.
func TestADR0426_V8_DeletedIdentifiersAppearNowhereInTheTree(t *testing.T) {
	forbidden := []string{
		"captureCtrDevShmContent",
		"readDevShmMountInfo",
		"devShmHostSourceDir",
		"devShmContentImageName",
		"writeDevShmContentImage",
		"captureContentAbsentDemandedMounts",
	}
	root := repoRootForADR0420(t)
	var hits []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if adr0426ExemptFromLiteralNameSearch[filepath.Base(path)] {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, f := range forbidden {
			if strings.Contains(string(b), f) {
				hits = append(hits, path+": "+f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf("ADR-0426 D1e deleted these identifiers; they must not reappear outside the files documenting the deletion: %v", hits)
	}
}

// TestADR0426_V8_ExactlyTwoProductionCallSites asserts captureContentAbsentMounts is called from
// exactly two production sites in server.go (the ctr fast path and the raw-CRIU fallback path), and
// from zero sites in the PODMOTION_MOCK_CRIU limb (D3a).
func TestADR0426_V8_ExactlyTwoProductionCallSites(t *testing.T) {
	root := repoRootForADR0420(t)
	b, err := os.ReadFile(filepath.Join(root, "internal", "agent", "server", "server.go"))
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	re := regexp.MustCompile(`captureContentAbsentMounts\(`)
	locs := re.FindAllIndex(b, -1)
	// One occurrence is the definition site itself is in a different file (adr0426_dump_side_content_capture.go),
	// so every match in server.go is a call site.
	if len(locs) != 2 {
		t.Fatalf("expected exactly 2 captureContentAbsentMounts( call sites in server.go (ctr + raw-CRIU); found %d", len(locs))
	}

	mockStart := strings.Index(string(b), `os.Getenv("PODMOTION_MOCK_CRIU")`)
	if mockStart == -1 {
		t.Fatal("could not locate the PODMOTION_MOCK_CRIU branch in server.go")
	}
	// The mock-manifest branch is the "if !mockCRIU { return err } ... write mock manifest" limb
	// immediately following the mockCRIU check; bound it to a generous window and assert no capture
	// call falls inside it (D3a).
	windowEnd := mockStart + 4000
	if windowEnd > len(b) {
		windowEnd = len(b)
	}
	if strings.Contains(string(b[mockStart:windowEnd]), "captureContentAbsentMounts(") {
		t.Error("D3a: the PODMOTION_MOCK_CRIU limb must contain ZERO captureContentAbsentMounts( call sites — that branch writes no mountpoints.img/files.img for the scanner to read")
	}
}

// TestADR0426_V8c_CaptureLegConsultsNoSourceDirectoryProperty is the static mirror of V2c: the
// capture leg's code path between mountHostSourceDir resolving ok==true and writeTmpfsContentImage
// being called must contain no inspection of the resolved source directory's CONTENTS — no
// os.ReadDir/filepath.Walk/Readdirnames/os.Stat-on-the-source/instance-method ReadDir — and no
// branch on a value derived from one. The only permitted stat is against the OUTPUT image path (the
// already_present check), not the source.
//
// WIDENED per the round-4 review (Arch-B): the prior pattern list caught only the package-level
// `os.ReadDir(` and no `os.Stat(` at all, so a reintroduction of the round-2 emptiness-gate
// regression spelled as a bare `.Stat(` against the source directory, or as an instance-method
// `<dirHandle>.ReadDir(` (os.File.ReadDir / fs.ReadDirFile), would pass this guard silently. The
// widened list catches both idioms.
func TestADR0426_V8c_CaptureLegConsultsNoSourceDirectoryProperty(t *testing.T) {
	root := repoRootForADR0420(t)
	b, err := os.ReadFile(filepath.Join(root, "internal", "agent", "server", "adr0426_dump_side_content_capture.go"))
	if err != nil {
		t.Fatalf("read adr0426_dump_side_content_capture.go: %v", err)
	}
	body := string(b)
	forbidden := []string{"os.ReadDir(", "filepath.Walk(", "filepath.WalkDir(", ".Readdirnames("}
	for _, tok := range forbidden {
		if strings.Contains(body, tok) {
			t.Errorf("V8c: the capture leg must consult no property of the resolved source directory but its reachability — found %q", tok)
		}
	}

	// os.Stat( is permitted ONLY against the output image path (the already_present check at
	// `os.Stat(outPath)`). Any other os.Stat( call — in particular one against hostDir/srcDir, the
	// resolved SOURCE — is the round-2 emptiness-gate regression wearing a different Go idiom.
	statRe := regexp.MustCompile(`os\.Stat\(([^)]*)\)`)
	for _, m := range statRe.FindAllStringSubmatch(body, -1) {
		arg := strings.TrimSpace(m[1])
		if arg != "outPath" {
			t.Errorf("V8c: found os.Stat(%s) — the only permitted os.Stat in the capture leg is against the OUTPUT image path (os.Stat(outPath)), never the resolved source directory", arg)
		}
	}

	// `.ReadDir(` as an INSTANCE METHOD (os.File.ReadDir / fs.ReadDirFile), not just the
	// package-level os.ReadDir( already forbidden above — a call like `f.ReadDir(-1)` on a handle
	// opened against the source directory is functionally identical to os.ReadDir and must be
	// caught the same way.
	readDirMethodRe := regexp.MustCompile(`\.ReadDir\(`)
	for _, m := range readDirMethodRe.FindAllString(body, -1) {
		_ = m
		t.Errorf("V8c: found an instance-method %q call — the capture leg must not enumerate the resolved source directory's contents by any spelling of ReadDir", ".ReadDir(")
	}
}

// TestADR0426_V8d_HostRunRootHasExactlyOneMutationSiteOutsideTestSeam is the mechanical guard both
// Arch-A and Arch-B flagged as missing (non-blocking, round-2 implementation review): every OTHER
// invariant this ADR introduced got a static test guard (V8/V8b/V8c above), but hostRunRoot's
// "production code MUST NEVER assign to this outside of the initializer" invariant was comment-only.
// This walks every non-test .go file in the package plus the one test seam file and asserts:
//  1. The declaration site (adr0426_dump_side_content_capture.go) has EXACTLY ONE assignment to
//     hostRunRoot — the initializer itself (`var hostRunRoot = "/host-run"`).
//  2. No other production (non-test) .go file in the package assigns to hostRunRoot at all.
//  3. adr0426_test_seam_test.go's withHostRunRootForTest is the ONLY other mutation site anywhere in
//     the package — test files are allowed to mutate hostRunRoot through that one seam, and nowhere
//     else, so a second ad hoc `hostRunRoot = ...` slipped into some other _test.go file would also
//     be caught, not just a production regression.
func TestADR0426_V8d_HostRunRootHasExactlyOneMutationSiteOutsideTestSeam(t *testing.T) {
	root := repoRootForADR0420(t)
	pkgDir := filepath.Join(root, "internal", "agent", "server")

	// Matches an assignment to hostRunRoot (`hostRunRoot = ...` or `var hostRunRoot = ...`), never a
	// comparison (`hostRunRoot == ...`) and never a mere read/reference.
	assignRe := regexp.MustCompile(`\bhostRunRoot\s*=[^=]`)

	const declFile = "adr0426_dump_side_content_capture.go"
	const seamFile = "adr0426_test_seam_test.go"
	const guardFile = "adr0426_static_guards_test.go"

	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(pkgDir, e.Name())
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("read %s: %v", e.Name(), rerr)
		}
		matches := assignRe.FindAllString(string(b), -1)

		switch e.Name() {
		case guardFile:
			// This file itself, which quotes the very assignment forms it is scanning for
			// (in string literals, comments, and Errorf format strings) — self-referential
			// mentions here are documentation of the guard, not a mutation site. Same precedent
			// as adr0426ExemptFromLiteralNameSearch above.
			continue
		case declFile:
			if len(matches) != 1 {
				t.Errorf("V8d: expected exactly 1 assignment to hostRunRoot in %s (the initializer), found %d: %v", e.Name(), len(matches), matches)
			} else if !strings.Contains(string(b), `var hostRunRoot = "/host-run"`) {
				t.Errorf("V8d: %s's single hostRunRoot assignment is not the expected initializer `var hostRunRoot = \"/host-run\"`", e.Name())
			}
		case seamFile:
			if len(matches) != 2 {
				t.Errorf("V8d: expected exactly 2 assignments to hostRunRoot in %s (the override + the t.Cleanup restore inside withHostRunRootForTest), found %d: %v", e.Name(), len(matches), matches)
			}
			if !strings.Contains(string(b), "func withHostRunRootForTest(") {
				t.Errorf("V8d: %s no longer defines withHostRunRootForTest — it is supposed to be the sole test-seam mutation site for hostRunRoot", e.Name())
			}
		default:
			if len(matches) != 0 {
				t.Errorf("V8d: found an assignment to hostRunRoot outside the initializer (%s) and the test seam (%s), in %s: %v — production code must never assign to hostRunRoot, and no other file may mutate it either", declFile, seamFile, e.Name(), matches)
			}
		}
	}
}

// TestADR0426_V8b_DumpSideDispositionReadsNoDemandCount is §P-VERIFY V8b: named in this file's own
// header as one of the guards this file provides, but — per both reviewers — never actually
// implemented until now.
//
// Three assertions, matching the ADR text exactly:
//  1. Neither D1d stage — capture nor disposition, i.e. captureContentAbsentMounts's whole body —
//     references DemandedRegular/DemandedDir in an `if`/`switch`/ternary-shaped branch condition.
//     They may appear only in log statements and metric-label expressions (both string-valued
//     call arguments, never conditions).
//  2. destinationRebindDemandScanPy (D4) DOES apply the `& S_IFMT != S_IFDIR` filter — the restore
//     side is where the count is load-bearing and must stay narrowed.
//  3. The dump-side scanner (contentCaptureDemandScanPy) still computes both counts with the SAME
//     shipped mask spelling (_S_IFMT / _S_IFDIR), so the two sides cannot drift even though only
//     one of them gates.
func TestADR0426_V8b_DumpSideDispositionReadsNoDemandCount(t *testing.T) {
	root := repoRootForADR0420(t)
	b, err := os.ReadFile(filepath.Join(root, "internal", "agent", "server", "adr0426_dump_side_content_capture.go"))
	if err != nil {
		t.Fatalf("read adr0426_dump_side_content_capture.go: %v", err)
	}
	src := string(b)

	// Isolate captureContentAbsentMounts's body (both D1d stages live inside it) and assert
	// e.DemandedRegular / e.DemandedDir appear ONLY inside a log.Info(...) call's arguments, never
	// inside an `if` condition.
	fnStart := strings.Index(src, "func captureContentAbsentMounts(")
	if fnStart == -1 {
		t.Fatal("could not locate captureContentAbsentMounts in adr0426_dump_side_content_capture.go")
	}
	body := src[fnStart:]

	for _, field := range []string{"DemandedRegular", "DemandedDir"} {
		idx := 0
		for {
			rel := strings.Index(body[idx:], field)
			if rel == -1 {
				break
			}
			pos := idx + rel
			// Find the start of the line containing this occurrence and check it is a log.Info
			// argument line (diagnostic), never an `if`/`switch`/ternary-shaped condition line.
			lineStart := strings.LastIndex(body[:pos], "\n") + 1
			lineEnd := strings.Index(body[pos:], "\n")
			if lineEnd == -1 {
				lineEnd = len(body)
			} else {
				lineEnd += pos
			}
			line := strings.TrimSpace(body[lineStart:lineEnd])
			if strings.HasPrefix(line, "if ") || strings.Contains(line, "if e.") || strings.Contains(line, "switch ") {
				t.Errorf("V8b: found %q inside what looks like a branch-condition line: %q — the dump-side disposition must not gate on a demand count", field, line)
			}
			idx = pos + len(field)
		}
	}

	// Belt-and-suspenders structural check: no `if` statement anywhere in the function body tests
	// e.DemandedRegular or e.DemandedDir directly.
	forbiddenConditions := []string{
		"if e.DemandedRegular", "if e.DemandedDir",
		"e.DemandedRegular ==", "e.DemandedRegular !=", "e.DemandedRegular >", "e.DemandedRegular <",
		"e.DemandedDir ==", "e.DemandedDir !=", "e.DemandedDir >", "e.DemandedDir <",
	}
	for _, tok := range forbiddenConditions {
		if strings.Contains(body, tok) {
			t.Errorf("V8b: found %q in captureContentAbsentMounts — a dump-side branch condition must never read a demand count", tok)
		}
	}

	// Assertion 2: destinationRebindDemandScanPy (D4) DOES apply the S_IFDIR filter.
	demandScanSrc := readDemandScanAssemblySource(t)
	if !strings.Contains(demandScanSrc, "& _S_IFMT) == _S_IFDIR") {
		t.Error("V8b: destinationRebindDemandScanPy must apply the & S_IFMT != S_IFDIR filter — this is the restore-side leg where the count IS load-bearing")
	}

	// Assertion 3: the dump-side scanner still computes both counts with the SAME shipped mask
	// spelling, so the two sides cannot drift even though only the restore side gates on it.
	if !strings.Contains(contentCaptureDemandScanPy, "_S_IFMT = 0o170000") || !strings.Contains(contentCaptureDemandScanPy, "_S_IFDIR = 0o040000") {
		t.Error("V8b: contentCaptureDemandScanPy must compute demand counts with the same shipped S_IFMT/S_IFDIR mask spelling as the restore-side scanner")
	}
	if !strings.Contains(contentCaptureDemandScanPy, "demanded_regular") || !strings.Contains(contentCaptureDemandScanPy, "demanded_dir") {
		t.Error("V8b: contentCaptureDemandScanPy must still compute and emit both counts (diagnostic-only) so the two sides cannot silently drift")
	}
}
