/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0420_restore_attribution_rekey.go — ADR-0420 D5: amend ADR-0418's attribution rule for the
// one failure class it is STRUCTURALLY BLIND TO.
//
// ADR-0418 attributes a restore failure to the first "Error (criu/" line in restore.log, skipping a
// known-non-fatal allowlist. That rule is correct and is NOT reverted. It has one blind spot, and
// this project is currently sitting in it.
//
// THE BLIND SPOT, DECODED (ADR-0420 M5, against the deployed CRIU 4.2 binaries on all three nodes,
// confirmed on 7/7 live restores across postgres and nginx). criu/filesystems.c tmpfs_restore
// resolves a mount's content by open_image_at(CR_FD_TMPFS_DEV, mi->s_dev) ->
// tmpfs-dev-<root_dev>.tar.gz, falling back on an empty image to open_image_at(CR_FD_TMPFS_IMG,
// mi->mnt_id) -> tmpfs-<mnt_id>.tar.gz. If neither exists it returns -1 HAVING PRINTED NOTHING: all
// three failure exits converge on `mov $0xffffffff,%ebp`, and the function's only pr_err
// (filesystems.c:460, "Can't restore tmpfs content") is the tar-failed branch, which appears in
// none of the live logs. The caller loads fstype->restore from DWARF offset 0x18, calls it, and
// propagates the -1 with NO print_on_level anywhere between the call and the failure.
//
// Consequence: a failing fstype->restore produces NO "Error (criu/" line at all. The first such
// line in the log is always the teardown rmdir at mount.c:3700 — which ADR-0418 already correctly
// demotes as non-causal — leaving attribution with NOTHING, i.e. returning exactly the opaque
// failure ADR-0418 exists to eliminate. This is not a defect in ADR-0418's reasoning; it is a class
// its evidence did not contain.
//
// THE SIGNAL THAT *IS* PRESENT is the mount-v2 progress trail, unambiguous in every one of those
// logs: the last "mnt-v2: Mounting <fs> @<mnt_id> (<n>)" line names the mount CRIU was constructing
// when it died, and the immediately-following "No <image> image" lines name WHY — the content CRIU
// went looking for is not in the checkpoint.
//
// SCOPE DISCIPLINE. D5 changes attribution KEYING AND REPORTING ONLY. It does not change what CRIU
// is invoked with, does not change the restore path, and does not weaken ADR-0418's
// first-causal-error rule for any other class: it adds a SECOND, STRICTLY LOWER-PRECEDENCE rule
// that fires only when the first yields nothing but demoted lines. Whenever ADR-0418's rule names a
// real cause, that cause is reported and this one is not consulted.

import (
	"fmt"
	"strings"
)

// criuMountV2ProgressMarker is the mount-v2 engine's per-mount progress line prefix. Matched with
// strings.Contains, never strings.HasPrefix: CRIU's -v4 line format carries a "(SS.mmmmmm) "
// timestamp and an optional task prefix, so the token is never at column 0 (the same corrected
// line-format grounding ADR-0418 records for "Error (criu/").
const criuMountV2ProgressMarker = "mnt-v2:"

// criuTeardownNoiseSubstring is the string that made the mount-EBUSY reading plausible for two ADRs
// running. It is the strerror of rmdir(2) on CRIU's own roots-yard temp directory during teardown
// (cleanup_mnt_ns, the single call site of mount.c:3700 in the whole deployed binary, reached on
// the unwind between cr-restore.c:2321 and "Restoring FAILED." at :2324) — NOT a mount EBUSY.
//
// ADR-0420 D5 item 3 FORBIDS it from ever being promoted as a diagnosis. isTeardownNoiseCRIULine is
// the mechanical form of that prohibition, and TestADR0420_D5_DeviceOrResourceBusyIsNeverACause is
// the guard that a future classifier cannot quietly reintroduce the reading.
const criuTeardownNoiseSubstring = "Device or resource busy"

// criuTerminalAnnouncementSubstring is CRIU's own "I have failed" announcement, emitted by
// restore_root_task (cr-restore.c:2324, restore_root_task+1988 @0x68d24 on all three deployed
// binaries) AFTER the real failure has already been decided.
//
// WHY THIS IS A SEPARATE CLASS FROM THE ADR-0418 ALLOWLIST, AND WHY D5 NEEDS IT. The line carries
// the substring "Error (criu/", so ADR-0418's first-causal-error rule matches it. On every OTHER
// failure class that is harmless: a real causal line always precedes it, so it never wins. On the
// class D5 exists for it is decisive and wrong — a silent fstype->restore emits no error line at
// all, so after ADR-0418 correctly demotes the teardown rmdir at mount.c:3700 the FIRST remaining
// match is this announcement, and the envelope confidently reports "first causal error: Restoring
// FAILED." That is not a demotion failure and not an allowlist gap; it is the opaque attribution
// ADR-0418 exists to eliminate, wearing a causal label.
//
// RECORDED HONESTLY AS A DIVERGENCE FROM ADR-0420's OWN TEXT: M5 states that demoting mount.c:3700
// leaves this class "with no attributable line whatsoever." Against the SHIPPED ADR-0418
// implementation it does not — it leaves the terminal announcement, which is worse than nothing
// because it is a confident wrong answer. D5 cannot fire at all until that is fixed, so excluding
// the announcement from CAUSE CANDIDACY is a precondition of D5 rather than a separate change.
//
// It is deliberately NOT added to criuKnownNonFatalLinePatterns: that allowlist is for non-fatal
// DIAGNOSTICS and its own doc block makes membership amendable only by ADR with a per-entry
// disassembly proof. This line is not a diagnostic — it is the terminal announcement, already
// captured verbatim as criuRestoreFailureAttribution.terminalLine and still reported as such. It is
// excluded from being a CAUSE, not suppressed: nothing about it is hidden, and its match is still
// counted in matchCount.
const criuTerminalAnnouncementSubstring = "Restoring FAILED."

// isCRIUTerminalAnnouncementLine reports whether a line is CRIU's terminal "Restoring FAILED."
// announcement — recorded as context, never nameable as the cause of the failure it announces.
func isCRIUTerminalAnnouncementLine(line string) bool {
	return strings.Contains(line, criuTerminalAnnouncementSubstring)
}

// isNonCausalCRIULine is the union of the two classes that may never be named as a cause: ADR-0418's
// known-non-fatal diagnostics and CRIU's own terminal announcement.
func isNonCausalCRIULine(line string) bool {
	return isKnownNonFatalCRIULine(line) || isCRIUTerminalAnnouncementLine(line)
}

// isTeardownNoiseCRIULine reports whether a line is CRIU teardown noise that must never be
// surfaced as the cause of a restore failure.
//
// It is deliberately NOT a general "Device or resource busy" ban: the substring is only teardown
// noise on the roots-yard rmdir line, and blanket-suppressing it everywhere would hide a genuine
// EBUSY if one ever appeared on a different, causal line. The conjunction is the point — this is a
// prohibition on the SITE, not on the string.
func isTeardownNoiseCRIULine(line string) bool {
	return strings.Contains(line, criuTeardownNoiseSubstring) && isKnownNonFatalCRIULine(line)
}

// criuMountV2Progress is the ADR-0420 D5 causal anchor for the silent-fstype->restore class: the
// last mount CRIU's mount-v2 engine reported constructing, plus the content images it then reported
// missing.
type criuMountV2Progress struct {
	// found is true when at least one mount-v2 progress line was seen in the log.
	found bool
	// line is the last "mnt-v2: Mounting ..." line, verbatim.
	line string
	// fsType is the filesystem CRIU was constructing ("tmpfs", "devtmpfs", ...), parsed from line.
	fsType string
	// mntID is the mnt_id CRIU was constructing, verbatim as printed (kept as a string: it is a
	// value read out of an adversary-influenceable log, and it is only ever reported, never used
	// as a number).
	mntID string
	// missingImages are the "No <image> image" lines that followed the LAST progress line — CRIU's
	// own statement of which content images it went looking for and did not find. Reset whenever a
	// new progress line appears, so these always belong to the mount named by line.
	missingImages []string
}

// noteCRIULogLine folds one restore.log line into the progress trail. It is called from inside
// ADR-0418's existing single forward pass — D5 adds no second read of the log, no second file
// handle, and no unbounded buffer: it retains one line and a short slice.
func (p *criuMountV2Progress) noteCRIULogLine(line string) {
	if strings.Contains(line, criuMountV2ProgressMarker) && strings.Contains(line, "Mounting ") {
		p.found = true
		p.line = line
		p.fsType, p.mntID = parseMountV2ProgressLine(line)
		p.missingImages = nil
		return
	}
	// "No tmpfs-dev-69.tar.gz.img image" / "No tmpfs-1890.tar.gz.img image" — CRIU's open_image_at
	// miss. Only collected AFTER a progress line, so an unrelated earlier miss is never attributed
	// to the mount that failed.
	if p.found && strings.Contains(line, "No ") && strings.HasSuffix(strings.TrimSpace(line), " image") {
		if len(p.missingImages) < 8 { // bounded: the real shape is exactly two
			p.missingImages = append(p.missingImages, strings.TrimSpace(line))
		}
	}
}

// parseMountV2ProgressLine extracts the filesystem name and mnt_id from a mount-v2 progress line of
// the shape "mnt-v2: \tMounting tmpfs @1890 (0)". Returns empty strings for either field it cannot
// read — the caller degrades to reporting the verbatim line rather than inventing a value.
func parseMountV2ProgressLine(line string) (fsType, mntID string) {
	idx := strings.Index(line, "Mounting ")
	if idx < 0 {
		return "", ""
	}
	rest := strings.TrimSpace(line[idx+len("Mounting "):])
	at := strings.Index(rest, "@")
	if at < 0 {
		return strings.TrimSpace(rest), ""
	}
	fsType = strings.TrimSpace(rest[:at])
	mntID = rest[at+1:]
	if cut := strings.IndexAny(mntID, " \t"); cut >= 0 {
		mntID = mntID[:cut]
	}
	return fsType, strings.TrimSpace(mntID)
}

// hasContentImageMiss reports whether the trail carries CRIU's own "content image not found"
// statement — the signature that distinguishes THIS class (a silent fstype->restore on a mount
// whose content is not in the checkpoint) from any other mount that merely happened to be last.
func (p *criuMountV2Progress) hasContentImageMiss() bool {
	return p.found && len(p.missingImages) > 0
}

// renderD5Attribution writes the ADR-0420 D5 attribution block.
//
// It is called ONLY when ADR-0418's first-causal-error rule yielded no real cause (every match was
// allowlisted, or there was no "Error (criu/" line at all). The reported reason is deliberately an
// operator-actionable SENTENCE, not a file-and-line: a file-and-line is what an operator cannot act
// on, and in this class there is no causal file-and-line to give.
//
// HONESTY BOUNDARY, stated in the output itself: CRIU's progress line carries the mnt_id, not the
// in-container mountpoint, so this block names the mnt_id and does NOT invent a path. Resolving
// mnt_id -> mountpoint would require decoding the checkpoint's own mountpoints image, which this
// helper deliberately does not do — it reports what the log actually says.
func renderD5Attribution(b *strings.Builder, p *criuMountV2Progress) {
	if !p.found {
		return
	}
	switch {
	case p.hasContentImageMiss():
		what := "a mount"
		if p.fsType != "" && p.mntID != "" {
			what = fmt.Sprintf("the %s mount with mnt_id %s", p.fsType, p.mntID)
		} else if p.mntID != "" {
			what = fmt.Sprintf("the mount with mnt_id %s", p.mntID)
		}
		fmt.Fprintf(b, "ADR-0420 D5 attributed cause (CRIU's fstype->restore fails SILENTLY, so this class has no \"Error (criu/\" line to find): CRIU could not construct %s — its content is not in the checkpoint\n", what)
		fmt.Fprintf(b, "  CRIU went looking for, and did not find: %s\n", strings.Join(p.missingImages, "; "))
		fmt.Fprintf(b, "  last mount-v2 progress line (the causal anchor): %s\n", p.line)
		fmt.Fprintf(b, "  what this means: this mount was EXTERNAL at dump time, so CRIU dumped no content for it; internalizing it on restore hands CRIU an empty superblock to fill from an image that does not exist (ADR-0420 M5/M6)\n")
	default:
		// A progress trail with no content-image miss: still the strongest anchor available when
		// ADR-0418's rule found nothing, but the CAUSE is not established. Say exactly that.
		fmt.Fprintf(b, "ADR-0420 D5: no causal \"Error (criu/\" line exists, and no missing-content-image line was found either — the last mount CRIU reported constructing is the only anchor available, and it is NOT asserted as the cause: %s\n", p.line)
	}
}
