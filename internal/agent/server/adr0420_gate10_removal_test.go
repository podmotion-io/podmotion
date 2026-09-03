// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package server

// adr0420_gate10_removal_test.go — ADR-0420 D4, Gate 1 (D3 + D3a) coverage.
//
// The region D3 touches had zero test coverage before this file: a repo-wide grep for the
// deleted block's identifiers returned no hits in any _test.go file, which is precisely why a
// fail-open mitigation could sit on the restore datapath unconstrained. These are static
// source-level guards in the same spirit as the production-script guards in
// patch_checkpoint_test.go and the structural regression guard in adr0354_static_grep_test.go:
// they assert the deletion stays deleted, that nothing was smuggled in to replace it, and that
// the surviving undecoded kernel-behavior claim cannot silently revert to reading as
// established mechanism.
//
// D1/D1a/D1b are NOT covered here. ADR-0420 gates all D1 implementation behind two blocking
// preconditions: an on-disk decode of a real mountpoints image from the standing KVM cluster
// (assertion #1), and the mandatory mechanism spike on what CRIU's mount-v2 engine does with a
// preserved ext_key entry (assertion #2). Neither is discharged, so D1 ships on Gate 2 with its
// own tests.
//
// See docs/adr/0420-mount-forest-ownership-coherence-and-residue-reconciliation.md.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// adr0420DeletedToken assembles a token that must NOT appear in production source. The pieces
// are concatenated rather than written as one literal on purpose: ADR-0420 assertion #8 requires
// that a repo-wide `grep -rn "<token>" .` return zero hits outside the ADR text and docs/, and a
// guard test carrying the literal would itself be a hit, falsifying the assertion it proves.
func adr0420DeletedToken(parts ...string) string {
	return strings.Join(parts, "")
}

// TestADR0420_D3_Gate10BlockDeletedFromServerGo is ADR-0420 assertion #8's removal-symmetry
// check: the deleted block's three identifying tokens are gone from server.go. Each was used
// SOLELY inside the removed block, so a reappearance means the mitigation was restored or
// re-derived rather than left deleted.
func TestADR0420_D3_Gate10BlockDeletedFromServerGo(t *testing.T) {
	src := readServerGoSource(t)

	for _, tc := range []struct {
		token string
		why   string
	}{
		{
			token: adr0420DeletedToken("gate", "10"),
			why:   "the deleted mitigation's log-line prefix — its return means the fail-open pre-umount block is back on the restore datapath",
		},
		{
			token: adr0420DeletedToken("sys", "Mounts"),
			why:   "the hardcoded 13-entry mountpoint list the block iterated instead of reading the kernel's actual mount table",
		},
		{
			token: adr0420DeletedToken("placeholderID", "ForUmount"),
			why:   "the block's `ctr task ls` substring-match target; it had no consumer outside the block and must not reappear",
		},
	} {
		if strings.Contains(src, tc.token) {
			t.Errorf("ADR-0420 D3 (assertion #8): server.go still contains %q — %s", tc.token, tc.why)
		}
	}
}

// TestADR0420_D3_NoSuccessorPrimitiveSmuggledIn is ADR-0420 assertion #9. The ADR struck D2
// (`mount_residue_reconcile`, a privileged broker umount2(MNT_DETACH) op) in full and replaced
// the gate10 block with nothing. This asserts the strike is genuine rather than partially
// smuggled in under another name: no such op, no typed residue error, and no new privileged
// surface anywhere in the agent tree.
func TestADR0420_D3_NoSuccessorPrimitiveSmuggledIn(t *testing.T) {
	forbidden := []struct {
		token string
		why   string
	}{
		{
			token: adr0420DeletedToken("mount_residue", "_reconcile"),
			why:   "the struck D2 broker op string",
		},
		{
			token: adr0420DeletedToken("MountResidue", "Unresolved"),
			why:   "the struck D2 typed error",
		},
	}

	root := adr0420RepoRoot(t)
	var hits []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable subtrees are not the subject of this guard
		}
		if info.IsDir() {
			// docs/ carries the ADR's own struck-D2 text; .git carries history. Both are
			// explicitly excluded by assertion #9 ("outside this ADR's struck-D2 text").
			switch info.Name() {
			case ".git", "docs", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// This guard file names the tokens (assembled, not literal); skip it regardless.
		if strings.HasSuffix(path, "adr0420_gate10_removal_test.go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil //nolint:nilerr // same rationale as above
		}
		for _, f := range forbidden {
			if strings.Contains(string(b), f.token) {
				hits = append(hits, path+": "+f.token+" ("+f.why+")")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(hits) > 0 {
		t.Errorf("ADR-0420 assertion #9: D2 is struck and must not be reintroduced under any name, "+
			"but found:\n  %s", strings.Join(hits, "\n  "))
	}
}

// adr0420BaseHEAD is the commit ADR-0420 records as its base ("Base HEAD: 6160038"). Gate 1's
// diff is taken against it.
const adr0420BaseHEAD = "6160038"

// TestADR0420_D3_BrokerUntouchedByThisADR is the second half of ADR-0420 assertion #9, checked
// mechanically rather than by claim: `git diff` for Gate 1 must show
// internal/agent/netnsbroker/broker.go UNCHANGED against the ADR's base HEAD.
//
// A token scan is deliberately NOT used here. broker.go already carries pre-existing umount
// authority for netns bind-path teardown (nsenterHostMntCombined("umount", "-l", bindPath)),
// which long predates this ADR and is unrelated to the struck D2. What assertion #9 actually
// forbids is a new Op string, dispatch case, or Response field.
//
// ADR-0421 D1e NARROWS THIS GUARD from byte-identity to that stated requirement, and the reason
// is recorded here because silently loosening a security guard is worse than the guard being
// wrong. The byte-identity form asserted a property of ONE commit ("this ADR did not touch the
// broker") as a permanent invariant on the file, so it failed on the first legitimate later
// change to broker.go for any reason at all — including ADR-0421 D1e, which adds the
// per-container CRI subtree to hostRealpathAllowed's server-pinned path family and adds no op,
// no dispatch case and no Response field. A guard that must be disabled to make a correct change
// teaches that guards are obstacles. So the check now compares the broker's PRIVILEGED SURFACE —
// its dispatch op set and its Response field set — between the base HEAD revision and the
// working tree, and fails on any ADDITION to either. That is assertion #9's actual content, it
// still fires on exactly the smuggled-privilege case it was written for, and unlike the diff it
// keeps firing for every future commit rather than only until the next unrelated edit.
func TestADR0420_D3_BrokerUntouchedByThisADR(t *testing.T) {
	root := adr0420RepoRoot(t)

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available; the broker-unchanged check is verified at the gate instead")
	}
	// Confirm the base commit is reachable in this checkout before trusting a diff against it.
	verify := exec.Command("git", "-C", root, "cat-file", "-e", adr0420BaseHEAD+"^{commit}")
	if err := verify.Run(); err != nil {
		t.Skipf("ADR-0420 base HEAD %s not present in this checkout (shallow clone or rewritten "+
			"history); the broker-unchanged check is verified at the gate instead", adr0420BaseHEAD)
	}

	const brokerRel = "internal/agent/netnsbroker/broker.go"
	baseSrc, err := exec.Command("git", "-C", root, "show", adr0420BaseHEAD+":"+brokerRel).Output()
	if err != nil {
		t.Fatalf("read %s at %s: %v", brokerRel, adr0420BaseHEAD, err)
	}
	headSrc, err := os.ReadFile(filepath.Join(root, brokerRel))
	if err != nil {
		t.Fatalf("read working-tree %s: %v", brokerRel, err)
	}

	for _, surface := range []struct {
		name string
		of   func(string) map[string]bool
		why  string
	}{
		{
			name: "dispatch op",
			of:   adr0420BrokerDispatchOps,
			why: "a new op is a new privileged operation the de-privileged agent can invoke; " +
				"a privileged unmount surface here would be strictly more destructive than the " +
				"privileged:true the agent gave up",
		},
		{
			name: "Response field",
			of:   adr0420BrokerResponseFields,
			why:  "a new response field is a new channel for privileged state to leave the broker",
		},
	} {
		base, head := surface.of(string(baseSrc)), surface.of(string(headSrc))
		if len(base) == 0 {
			t.Fatalf("extracted zero %ss from the base revision of %s — the guard is not "+
				"observing what it claims to observe", surface.name, brokerRel)
		}
		for name := range head {
			if !base[name] {
				t.Errorf("ADR-0420 assertion #9: %s adds %s %q relative to base HEAD %s — %s",
					brokerRel, surface.name, name, adr0420BaseHEAD, surface.why)
			}
		}
	}
}

// adr0420BrokerDispatchOps extracts the set of op strings the broker's request dispatch accepts,
// as `case "<op>":` labels. Ops are lower_snake_case by convention, which keeps this from
// matching unrelated string switches elsewhere in the file.
func adr0420BrokerDispatchOps(src string) map[string]bool {
	return adr0420MatchSet(src, regexp.MustCompile(`(?m)^\s*case "([a-z][a-z0-9_]*)":`))
}

// adr0420BrokerResponseFields extracts the exported field names of the broker's Response struct.
func adr0420BrokerResponseFields(src string) map[string]bool {
	const marker = "type Response struct {"
	i := strings.Index(src, marker)
	if i < 0 {
		return nil
	}
	body := src[i+len(marker):]
	if j := strings.Index(body, "\n}"); j >= 0 {
		body = body[:j]
	}
	return adr0420MatchSet(body, regexp.MustCompile(`(?m)^\t([A-Z][A-Za-z0-9]*)\s+\S`))
}

func adr0420MatchSet(src string, re *regexp.Regexp) map[string]bool {
	out := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		out[m[1]] = true
	}
	return out
}

// TestADR0420_D3_SharedHelpersSurviveDeletion is the other half of ADR-0420 assertion #8. ctrArgs and nsenterCmd were CALLED by the deleted block but are not owned by it
// — they have many other consumers and must survive. A deletion that took them out would be an
// over-broad revert, so this asserts both still exist and still have non-test callers outside
// the removed region.
func TestADR0420_D3_SharedHelpersSurviveDeletion(t *testing.T) {
	src := readServerGoSource(t)

	for _, tc := range []struct {
		helper  string
		minCall int
	}{
		{helper: "ctrArgs(", minCall: 2},
		{helper: "nsenterCmd(", minCall: 2},
	} {
		if n := strings.Count(src, tc.helper); n < tc.minCall {
			t.Errorf("ADR-0420 assertion #8: helper %s has %d call sites in server.go, want >= %d — "+
				"D3 deletes the block that called it, NOT the helper itself",
				tc.helper, n, tc.minCall)
		}
	}
}

// TestADR0420_D3a_UndecodedMntDetachClaimIsAnnotated is ADR-0420 assertion #10. D3a annotates, it does
// not delete and does not assert the negation: the inherited MNT_DETACH-on-sysfs claim must
// still be present (zero hits is a FAIL) and must carry the UNDECODED marker on the same line,
// so it cannot silently return to reading as established mechanism. ADR-0420's struck D2 was
// authored against this exact sentence taken as decoded.
func TestADR0420_D3a_UndecodedMntDetachClaimIsAnnotated(t *testing.T) {
	const claim = "cannot be unmounted even with MNT_DETACH"

	var matches []string
	for _, line := range strings.Split(readServerGoSource(t), "\n") {
		if strings.Contains(line, claim) {
			matches = append(matches, line)
		}
	}

	if len(matches) == 0 {
		t.Fatalf("ADR-0420 assertion #10: the inherited %q claim is GONE from server.go. "+
			"D3a annotates the claim as undecoded; it neither deletes it nor asserts its "+
			"negation. Zero hits is a FAIL.", claim)
	}
	if len(matches) != 1 {
		t.Errorf("ADR-0420 assertion #10: expected exactly one occurrence of the inherited claim, got %d:\n  %s",
			len(matches), strings.Join(matches, "\n  "))
	}
	for _, line := range matches {
		if !strings.Contains(line, "UNDECODED") {
			t.Errorf("ADR-0420 D3a (assertion #10): the inherited MNT_DETACH claim appears WITHOUT "+
				"the UNDECODED annotation, so it reads as established mechanism:\n  %s", line)
		}
		if !strings.Contains(line, "ADR-0420") {
			t.Errorf("ADR-0420 D3a: the UNDECODED annotation must cite where the claim will be "+
				"decided (the ADR-0420 mechanism spike, item 5):\n  %s", line)
		}
	}
}

// TestADR0420_D3_NoStaleCompatModeRationaleRemains asserts D3's "the comment is removed WITH the
// code" requirement. A stale rationale left standing is how a future session re-derives the same
// dead mitigation — that is not hypothetical here, it is what happened with D2. Both surviving
// compat-mode mentions must now be explicitly marked stale or undecoded rather than reading as
// live justification.
func TestADR0420_D3_NoStaleCompatModeRationaleRemains(t *testing.T) {
	src := readServerGoSource(t)

	// The argv must still OMIT compat mode — that omission is the mechanism grounding for D3.
	if !strings.Contains(src, "--mntns-compat-mode is intentionally OMITTED") {
		t.Error("ADR-0420 M2: server.go no longer records that --mntns-compat-mode is intentionally " +
			"omitted. That omission is what makes the deleted umount-pass mitigation dead code; " +
			"if compat mode returns, D3's grounding is void and must be re-argued.")
	}

	// The formerly-stale raw-CRIU-path note must now carry its correction.
	if strings.Contains(src, "CRIU compat-mode tries to umount /sys → EBUSY.") {
		t.Error("ADR-0420 D3: the stale raw-CRIU-path note still justifies the host-mount-namespace " +
			"choice by the compat-mode umount pass. That pass does not run on this path; the note " +
			"must be corrected, not left standing.")
	}
}

// TestADR0420_D3_NoFailOpenSwallowReintroduced is ADR-0420 assertion #14. The deleted block logged and
// swallowed every umount failure — there was no path by which it could report failure. The
// zero-tech-debt pillar treats fail-open fallback code on the restore datapath as antithetical,
// not as an acceptable shortcut, so this asserts the specific swallow lines are gone and were
// not reinstated under new wording.
func TestADR0420_D3_NoFailOpenSwallowReintroduced(t *testing.T) {
	src := readServerGoSource(t)

	for _, tc := range []struct {
		token string
		why   string
	}{
		{
			token: "lazy-umount skipped (mount absent or error)",
			why:   "the swallowed-failure log line — the block's only response to any umount error",
		},
		{
			token: "lazy-umounted successfully",
			why:   "the success log line of a step that never re-read to confirm anything was detached",
		},
		{
			token: "Non-fatal: some mounts may not exist in this container",
			why:   "the fail-open rationale comment on the restore datapath",
		},
	} {
		if strings.Contains(src, tc.token) {
			t.Errorf("ADR-0420 assertion #14: server.go still contains %q — %s", tc.token, tc.why)
		}
	}
}

// adr0420RepoRoot walks up from the package directory to the module root (the directory holding
// go.mod), so the repo-wide guards above do not depend on the test's working directory.
func adr0420RepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod above %s", dir)
		}
		dir = parent
	}
}
