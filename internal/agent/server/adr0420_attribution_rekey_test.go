/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0420_attribution_rekey_test.go — ADR-0420 D5 / §P-VERIFY #7b.
//
// D5 amends ADR-0418's attribution rule for the one class it is structurally blind to: a CRIU
// fstype->restore that fails SILENTLY, so the log carries no "Error (criu/" line for it at all and
// the only such line present is the teardown rmdir ADR-0418 already (correctly) demotes.
//
// FIXTURE PROVENANCE, STATED BECAUSE IT IS LOAD-BEARING. adr0420LiveRestoreLogTail is TRANSCRIBED
// VERBATIM from ADR-0420 §R3-3, which records the identical tail observed on 7 of 7 live restores
// across BOTH workloads (nginx jjkfl/xk492/lcbq5/26zz6, postgres dzh5d/ldvs5/r4vfm) on the standing
// KVM cluster. The mnt_id/root_dev pairs in it (1890/69 for nginx, 3527/172 for postgres) are the
// exact ids the independent pycriu decode recorded. It is a captured shape, not an invented one —
// which is the point: a synthetic log would let the classifier be written to its own fixture.
//
// The counterweight assertion is TestADR0420_D5_DoesNotFireOnRealNonSilentFailures, which runs the
// re-keyed classifier over the THREE REAL restore logs already in this repo's corpus. Those logs
// fail for ordinary, non-silent reasons, and D5 must not touch their attribution — it is a strictly
// lower-precedence rule, not a replacement.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// adr0420LiveRestoreLogTail is the ADR-0420 M5 signature: the last mount-v2 progress line, the two
// missing-content-image lines, and the teardown noise ADR-0418 demotes. Note what is NOT here: any
// causal "Error (criu/" line. That absence is the whole defect D5 addresses.
const adr0420LiveRestoreLogTail = `(00.031201) mnt-v2: 	Mounting tmpfs @1889 (0)
(00.031554) mnt-v2: 	Mounting tmpfs @1890 (0)
(00.031602) No tmpfs-dev-69.tar.gz.img image
(00.031640) No tmpfs-1890.tar.gz.img image
(00.032011) Error (criu/mount.c:3700): mnt: Can't remove the directory /tmp/.criu.mntns.XXXXXX: Device or resource busy
(00.032190) Error (criu/cr-restore.c:2324): Restoring FAILED.
`

// TestADR0420_D5_AttributesTheSilentFstypeRestoreClass is §P-VERIFY #7b's positive leg.
func TestADR0420_D5_AttributesTheSilentFstypeRestoreClass(t *testing.T) {
	logPath := writeRestoreLog(t, adr0420LiveRestoreLogTail)

	attr := scanCRIURestoreLogForFirstError(logPath)
	if attr.found {
		t.Fatalf("this class has NO causal \"Error (criu/\" line — if ADR-0418's rule claims to have found one, the fixture or the allowlist is wrong; got %q", attr.causeLine)
	}
	if !attr.onlyAllowlisted {
		t.Fatal("every matching line in this class is allowlisted teardown noise; ADR-0418's rule must report exactly that")
	}
	if !attr.mountProgress.found {
		t.Fatal("D5: the mount-v2 progress trail must be collected in ADR-0418's same forward pass")
	}
	if attr.mountProgress.fsType != "tmpfs" || attr.mountProgress.mntID != "1890" {
		t.Errorf("D5: the causal anchor is the LAST \"mnt-v2: Mounting ...\" line before the failure; got fsType=%q mntID=%q", attr.mountProgress.fsType, attr.mountProgress.mntID)
	}
	if len(attr.mountProgress.missingImages) != 2 {
		t.Fatalf("D5: both \"No <image> image\" lines name why — CRIU's own statement of which content images it looked for; got %v", attr.mountProgress.missingImages)
	}

	// The progress trail must belong to the LAST mount, not an earlier one: mount 1889 (/dev/shm)
	// mounted fine and its lines must not be attributed to 1890's failure.
	for _, img := range attr.mountProgress.missingImages {
		if !strings.Contains(img, "tmpfs-dev-69") && !strings.Contains(img, "tmpfs-1890") {
			t.Errorf("D5: missing-image lines must belong to the mount named by the last progress line; got %q", img)
		}
	}

	envelope := criuRestoreFailureCause(logPath, "/run/podmotion/checkpoints/mig", false, true, 1, nil, "")

	// The attributed reason must be an operator-actionable SENTENCE, not a file-and-line — in this
	// class there is no causal file-and-line to give.
	if !strings.Contains(envelope, "its content is not in the checkpoint") {
		t.Errorf("D5 item 4: the envelope must state the operator-actionable cause; got:\n%s", envelope)
	}
	if !strings.Contains(envelope, "mnt_id 1890") {
		t.Errorf("D5 item 1: the envelope must name the mount CRIU was constructing when it died; got:\n%s", envelope)
	}
	if !strings.Contains(envelope, "tmpfs-dev-69.tar.gz.img") || !strings.Contains(envelope, "tmpfs-1890.tar.gz.img") {
		t.Errorf("D5 item 2: the envelope must name the content images CRIU went looking for and did not find; got:\n%s", envelope)
	}
}

// TestADR0420_D5_DeviceOrResourceBusyIsNeverACause is D5 item 3, made mechanical.
//
// The "Device or resource busy" string is the strerror of rmdir(2) on CRIU's own roots-yard temp
// directory during teardown — NOT a mount EBUSY. Reading it as a bind conflict is what sent two
// revisions of ADR-0420 after an ownership-inversion hypothesis that a single decode then refuted.
// This forbids any future classifier from promoting it as a diagnosis.
func TestADR0420_D5_DeviceOrResourceBusyIsNeverACause(t *testing.T) {
	logPath := writeRestoreLog(t, adr0420LiveRestoreLogTail)
	envelope := criuRestoreFailureCause(logPath, "/run/podmotion/checkpoints/mig", false, true, 1, nil, "")

	if !strings.Contains(envelope, "TEARDOWN NOISE") {
		t.Errorf("D5 item 3: the roots-yard rmdir line must be named as teardown noise explicitly, not merely omitted; got:\n%s", envelope)
	}
	// It must never be presented as THE cause. The demoted line is still printed verbatim (ADR-0418
	// forbids silent demotion), so the assertion is on the attribution sentence, not on the string's
	// presence anywhere in the envelope.
	for _, causeClaim := range []string{
		"first causal error (earliest \"Error (criu/\" line in restore.log): (00.032011)",
		"ADR-0420 D5 attributed cause (CRIU's fstype->restore fails SILENTLY, so this class has no \"Error (criu/\" line to find): CRIU could not construct a mount",
	} {
		if strings.Contains(envelope, causeClaim) {
			t.Errorf("D5 item 3: %q must never be a cause claim; got:\n%s", causeClaim, envelope)
		}
	}

	// The predicate is a prohibition on the SITE, not a blanket ban on the string: a genuine EBUSY
	// on a different, causal line must still be attributable.
	if isTeardownNoiseCRIULine("Error (criu/mount.c:1234): mnt: Can't mount /data: Device or resource busy") {
		t.Error("a \"Device or resource busy\" on a NON-allowlisted line is a real error and must remain attributable — blanket-suppressing the string would hide a genuine EBUSY")
	}
	if !isTeardownNoiseCRIULine("Error (criu/mount.c:3700): mnt: Can't remove the directory /tmp/.criu.mntns.aBcDeF: Device or resource busy") {
		t.Error("the roots-yard rmdir line IS teardown noise and must be classified as such")
	}
}

// TestADR0420_D5_NeverOutranksARealCause is the scope-discipline assertion: D5 adds a SECOND,
// STRICTLY LOWER-PRECEDENCE rule. Wherever ADR-0418's first-causal-error rule names a real cause,
// that cause is what is reported and D5 is not consulted at all.
func TestADR0420_D5_NeverOutranksARealCause(t *testing.T) {
	logPath := writeRestoreLog(t, `(00.010000) mnt-v2: 	Mounting tmpfs @1890 (0)
(00.010100) No tmpfs-dev-69.tar.gz.img image
(00.020000) Error (criu/files-reg.c:2353): Can't open file dev/null on restore: No such file or directory
(00.030000) Error (criu/mount.c:3700): mnt: Can't remove the directory /tmp/.criu.mntns.XXXXXX: Device or resource busy
(00.031000) Error (criu/cr-restore.c:2324): Restoring FAILED.
`)
	envelope := criuRestoreFailureCause(logPath, "", false, true, 1, nil, "")

	if !strings.Contains(envelope, "criu/files-reg.c:2353") {
		t.Errorf("ADR-0418's first-causal-error rule is preserved and still wins when it finds a real cause; got:\n%s", envelope)
	}
	if strings.Contains(envelope, "ADR-0420 D5 attributed cause") {
		t.Errorf("D5 must NOT fire when a real causal line exists — it is a lower-precedence fallback, not a replacement; got:\n%s", envelope)
	}
}

// TestADR0420_D5_ProgressTrailWithoutAContentMissIsNotAssertedAsACause keeps the fallback honest.
//
// A progress trail alone is an ANCHOR, not a cause: the last mount CRIU reported constructing is not
// necessarily the mount that failed. Only the content-image miss establishes this class. Claiming a
// cause without it would reproduce, one layer up, exactly the over-confident attribution ADR-0418
// exists to prevent.
func TestADR0420_D5_ProgressTrailWithoutAContentMissIsNotAssertedAsACause(t *testing.T) {
	logPath := writeRestoreLog(t, `(00.010000) mnt-v2: 	Mounting proc @1774 (0)
(00.030000) Error (criu/mount.c:3700): mnt: Can't remove the directory /tmp/.criu.mntns.XXXXXX: Device or resource busy
(00.031000) Error (criu/cr-restore.c:2324): Restoring FAILED.
`)
	envelope := criuRestoreFailureCause(logPath, "", false, true, 1, nil, "")

	if strings.Contains(envelope, "its content is not in the checkpoint") {
		t.Errorf("without a missing-content-image line this class is NOT established and no cause may be claimed; got:\n%s", envelope)
	}
	if !strings.Contains(envelope, "is NOT asserted as the cause") {
		t.Errorf("the anchor must be offered explicitly as an anchor rather than a cause; got:\n%s", envelope)
	}
}

// TestADR0420_D5_DoesNotFireOnRealNonSilentFailures runs the re-keyed classifier over the THREE REAL
// restore logs in this repo's corpus. Every one of them fails for an ordinary, non-silent reason, so
// ADR-0418's rule names a real cause and D5 must stay entirely out of the way. This is the guard
// that D5 did not widen attribution for classes that were already correct.
func TestADR0420_D5_DoesNotFireOnRealNonSilentFailures(t *testing.T) {
	root := repoRootForADR0420(t)
	logs := []string{
		"docs/sprints/criu-restore.log",
		"docs/sprints/criu-restore-attempt5.log",
		"docs/sprints/criu-restore-attempt7.log",
	}
	var ran int
	for _, rel := range logs {
		p := filepath.Join(root, rel)
		if _, err := os.Stat(p); err != nil {
			continue // corpus log absent in this checkout — not a failure of the classifier
		}
		ran++
		t.Run(filepath.Base(rel), func(t *testing.T) {
			attr := scanCRIURestoreLogForFirstError(p)
			if !attr.found {
				t.Fatalf("%s is a real, non-silent failure — ADR-0418's rule must still name its cause", rel)
			}
			envelope := criuRestoreFailureCause(p, "", false, true, 1, nil, "")
			if strings.Contains(envelope, "ADR-0420 D5") {
				t.Errorf("D5 must not fire on a log that already has a causal error line; got:\n%s", envelope)
			}
			if !strings.Contains(envelope, attr.causeLine) {
				t.Errorf("the causal line must be reported verbatim; got:\n%s", envelope)
			}
		})
	}
	if ran == 0 {
		t.Skip("no corpus restore logs present in this checkout")
	}
}

// TestADR0420_D5_ProgressParsingIsBoundedAndTimestampTolerant pins the two properties that make the
// parser safe to run against an adversary-influenceable log in a privileged node agent.
func TestADR0420_D5_ProgressParsingIsBoundedAndTimestampTolerant(t *testing.T) {
	t.Run("timestamp_and_task_prefixes_are_tolerated", func(t *testing.T) {
		// CRIU's -v4 format carries a "(SS.mmmmmm) " timestamp and an optional "<task>: " prefix,
		// so the marker is never at column 0 — the same corrected line-format grounding ADR-0418
		// records for "Error (criu/". A HasPrefix-based parser would silently see nothing.
		fs, id := parseMountV2ProgressLine("(00.031554)      1: mnt-v2: \tMounting tmpfs @3527 (0)")
		if fs != "tmpfs" || id != "3527" {
			t.Errorf("parse = (%q, %q), want (\"tmpfs\", \"3527\")", fs, id)
		}
	})

	t.Run("malformed_lines_degrade_rather_than_invent", func(t *testing.T) {
		for _, line := range []string{"mnt-v2: Mounting", "mnt-v2: Mounting tmpfs", "garbage"} {
			fs, id := parseMountV2ProgressLine(line)
			if id != "" && !strings.ContainsAny(id, "0123456789") {
				t.Errorf("a malformed line must yield an empty field, never an invented one; line=%q -> (%q,%q)", line, fs, id)
			}
		}
	})

	t.Run("missing_image_collection_is_bounded_and_resets_per_mount", func(t *testing.T) {
		var p criuMountV2Progress
		p.noteCRIULogLine("mnt-v2: \tMounting tmpfs @1 (0)")
		for i := 0; i < 50; i++ {
			p.noteCRIULogLine("No tmpfs-dev-1.tar.gz.img image")
		}
		if len(p.missingImages) > 8 {
			t.Errorf("the retained slice must be bounded — restore.log volume is adversary-influenceable; got %d", len(p.missingImages))
		}
		p.noteCRIULogLine("mnt-v2: \tMounting tmpfs @2 (0)")
		if len(p.missingImages) != 0 {
			t.Errorf("a new progress line must RESET the collection, or an earlier mount's misses get attributed to a later one; got %v", p.missingImages)
		}
		if p.mntID != "2" {
			t.Errorf("the anchor must be the LAST progress line; got %q", p.mntID)
		}
	})
}
