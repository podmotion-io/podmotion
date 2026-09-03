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
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

// TestADR0420_D3_BrokerUntouchedByThisADR is one of three independent checks that together make up
// the second half of ADR-0420 assertion #9: the op-set/Response-field diff below (D2-renaming
// absence is checked by TestADR0420_D3_NoSuccessorPrimitiveSmuggledIn above, and privilege smuggled
// into an EXISTING op's body across the whole netnsbroker package — not just broker.go — is checked
// by TestADR0420_D3_NetnsbrokerContentDigestLedger below). Checked mechanically rather than
// by claim: `git diff` for Gate 1 must show internal/agent/netnsbroker/broker.go UNCHANGED against
// the ADR's base HEAD.
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
	baseSrc, headSrc := adr0420BrokerSources(t)

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
		base, head := surface.of(baseSrc), surface.of(headSrc)
		if len(base) == 0 {
			t.Fatalf("extracted zero %ss from the base revision of %s — the guard is not "+
				"observing what it claims to observe", surface.name, adr0420BrokerRel)
		}
		if len(head) == 0 {
			t.Fatalf("extracted zero %ss from the working tree of %s — the guard is not "+
				"observing what it claims to observe (an ordinary refactor — renaming Handle, "+
				"hoisting the switch into a helper, aliasing the switch tag, or moving the "+
				"Response struct — makes this comparison loop iterate zero times and silently "+
				"PASS even when a new privileged op or field was added alongside it)",
				surface.name, adr0420BrokerRel)
		}
		for name := range head {
			if !base[name] {
				t.Errorf("ADR-0420 assertion #9: %s adds %s %q relative to base HEAD %s — %s",
					adr0420BrokerRel, surface.name, name, adr0420BaseHEAD, surface.why)
			}
		}
	}
}

// adr0420BrokerRel is the broker source both halves of assertion #9 are checked against.
const adr0420BrokerRel = "internal/agent/netnsbroker/broker.go"

// adr0420BrokerSources returns the broker source at ADR-0420's base HEAD and in the working tree.
// It skips (never fails) when git or the base commit is unavailable, because in that situation the
// guard cannot observe anything and a failure would be noise rather than signal — the gate re-runs
// it in a full checkout.
func adr0420BrokerSources(t *testing.T) (base, head string) {
	t.Helper()
	root := adr0420RepoRoot(t)

	// Fix 1 (Security Reviewer, 2026-09-03): these were t.Skip. A skip exits 0 with nothing
	// checked, and no other gate in this repo re-verifies assertion #9's unmount-authority
	// half — a repo-wide `grep -rln "TestADR0420"` across Makefile, hack/, .github/, and every
	// *.sh/*.yaml/*.yml/*.mk/*.js returns zero hits, so "verified at the gate instead" named a
	// gate that does not exist. That made a skip here indistinguishable from a pass for the one
	// file whose entire purpose is proving a fail-open mitigation stays deleted — a check that
	// cannot tell "I verified" from "I couldn't verify so I assumed fine" is worse than no check
	// at all. git is a hard, non-optional dependency of this repo's own workflow (every
	// build/deploy/close step assumes a git checkout; nothing about this project runs from a
	// plain tarball), so an environment where `git` is absent is not a real target for this guard
	// to stay quiet in — it is a hard failure.
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("ADR-0420 assertion #9: git is not available in this environment, so the broker " +
			"privileged-surface check (TestADR0420_D3_BrokerUntouchedByThisADR) cannot run. No other " +
			"gate re-verifies this — see the Fix 1 comment above — so this is a hard failure, not a skip.")
	}
	// Confirm the base commit is reachable in this checkout before trusting a diff against it.
	verify := exec.Command("git", "-C", root, "cat-file", "-e", adr0420BaseHEAD+"^{commit}")
	if err := verify.Run(); err != nil {
		t.Fatalf("ADR-0420 assertion #9: base HEAD %s is not reachable in this checkout (shallow "+
			"clone or rewritten history — docs/security/PRE-PUBLICATION-HISTORY-SCRUB-PLAN.md's "+
			"planned history rewrite will make this the normal case, not an edge case). No other "+
			"gate re-verifies the broker privileged-surface check — see the Fix 1 comment above — so "+
			"this is a hard failure, not a skip: an unreachable base HEAD must be treated as an "+
			"unproven guard, not a silently-passing one.", adr0420BaseHEAD)
	}

	baseSrc, err := exec.Command("git", "-C", root, "show", adr0420BaseHEAD+":"+adr0420BrokerRel).Output()
	if err != nil {
		t.Fatalf("read %s at %s: %v", adr0420BrokerRel, adr0420BaseHEAD, err)
	}
	headSrc, err := os.ReadFile(filepath.Join(root, adr0420BrokerRel))
	if err != nil {
		t.Fatalf("read working-tree %s: %v", adr0420BrokerRel, err)
	}
	return string(baseSrc), string(headSrc)
}

// adr0420NetnsbrokerRelDir is the root package the content-digest ledger below covers. It is no
// longer the WHOLE scanned scope — see adr0420DigestLedgerScopeRelDirs — but remains the anchor
// import path the dependency-closure derivation starts from.
const adr0420NetnsbrokerRelDir = "internal/agent/netnsbroker"

// adr0420DigestException is one reviewed, recorded delta: the file changed (or was added/
// removed) relative to base HEAD, a specific ADR is responsible, and — critically — digest pins
// the EXACT expected content hash of the change that was reviewed. Pinning the digest, not just
// the path, is what keeps this an allowlist of one reviewed diff rather than a standing blank
// check on the path: a path-only exception ("broker.go may differ from base") would silently
// admit ANY subsequent change to that file forever, including an unrelated privileged-surface
// widening slipped in under cover of the one legitimate, already-reviewed edit. Pinning digest
// means a SECOND, unreviewed change to an already-excepted file changes its head digest away from
// the recorded value and is caught exactly like a change to any other file — the exception covers
// the one diff it names, nothing else, ever.
type adr0420DigestException struct {
	digest string // expected SHA-256 (hex) of the working-tree file once this exception applies
	reason string // must cite the responsible ADR and a one-line reason
}

// adr0420ExceptionReasonADRPattern is Fix 2's minimum-viable reason validation: a reason string
// that does not even NAME a real ADR is not a review record, it is prose that happens to sit next
// to a correct digest. This does not make the check exhaustive (a reason can still cite a real ADR
// and be substantively wrong about what that ADR permits — that remains a human-review question),
// but "reason: x" paired with a correct digest must no longer silently pass.
var adr0420ExceptionReasonADRPattern = regexp.MustCompile(`ADR-(\d{3,})`)

// adr0420AdmissibleADRExceptionNumbers is Fix 2's SOLE source of truth for which ADR numbers an
// exception's reason may cite (2026-09-03, replaces the docs/adr/-presence filesystem check).
//
// The set of ADRs an exception could legitimately cite is small and known: today it is exactly
// the ADRs that have touched this ledger's scope, ADR-0420 (this file) and ADR-0421 (D1e, the
// cripaths dependency — see adr0420DigestExceptions above). Pinning that set in-file, checked
// unconditionally, closes the gap the old filesystem check could not: docs/adr/ is gitignored/
// local-only by design (CLAUDE.md's IP-protection policy), so it is absent on every fresh clone
// and in the real gate/CI environment where this check matters most — the old code silently
// degraded to skipping the "does this ADR actually exist" check there, logging that degradation
// via t.Logf, which Go's testing package only prints on failure or under -v. The real gate
// entrypoint (Makefile's `test` target) runs `go test` WITHOUT -v, so that notice never actually
// appeared where it mattered, and a reason citing a fabricated ADR number (e.g. "ADR-0000: fake")
// passed silently in every real gate run. An in-file allowlist has no such environment-dependent
// degraded mode: it is checked identically everywhere, with or without -v, with or without
// docs/adr/ present.
//
// Update this map (a reviewed act, same as adr0420DigestExceptions itself) whenever a new ADR
// legitimately needs to cite an exception here — do not widen it speculatively.
var adr0420AdmissibleADRExceptionNumbers = map[string]bool{
	"0420": true,
	"0421": true,
}

// adr0420DigestExceptions is the SOLE escape valve for the content-digest ledger below: an
// in-file, reviewed allowlist of intentional deltas between ADR-0420's base HEAD
// (adr0420BaseHEAD) and the working tree, across every directory in the ledger's scanned scope
// (adr0420DigestLedgerScopeRelDirs) — no longer just internal/agent/netnsbroker itself. Each key
// is a path relative to the module root (e.g. "internal/agent/netnsbroker/broker.go"). A file not
// listed here must be byte-identical to base HEAD (present, absent, or unchanged consistently on
// both sides), and a listed file's working-tree content must match the pinned digest exactly, or
// the ledger fails closed. Adding or updating an entry here is a reviewed act, not a guard being
// disabled — see the ADR-0420 assertion #9 amendment (2026-09-03) for why that distinction
// matters, and adr0420ValidateDigestExceptions for the minimum bar a reason must clear.
var adr0420DigestExceptions = map[string]adr0420DigestException{
	"internal/agent/netnsbroker/broker.go": {
		digest: "fd50bfe618841f0db1954c8749ea0ef84b01c73e612561c3214ad6f571ec558e",
		reason: "ADR-0421 D1e: adds the per-container CRI subtree to hostRealpathAllowed's " +
			"server-pinned path family by importing the shared class list from internal/agent/cripaths " +
			"(replacing the single hardcoded sandbox-subtree marker). Adds no broker Op, no dispatch " +
			"case, no Response field — that half of assertion #9 is checked independently, on the same " +
			"two revisions, by TestADR0420_D3_BrokerUntouchedByThisADR above.",
	},
	"internal/agent/cripaths/cripaths.go": {
		digest: "fa7e9e65574de871b923e0fc86baf6444567f52ff77b4a230c360c8116e4aa65",
		reason: "ADR-0421 D1e: new package, entirely new relative to base HEAD. hostRealpathAllowed " +
			"(the broker's SC-1 privileged-surface check) derives its admitted path-marker set from " +
			"this package via cripaths.AllDirRels()/cripaths.Marker() instead of a hardcoded sandbox-" +
			"only marker, so it is now part of the ledger's dependency closure " +
			"(adr0420DigestLedgerScopeRelDirs) rather than invisible outside the single hardcoded " +
			"netnsbroker directory this ledger scanned before the 2026-09-03 Fix 1 hardening. It " +
			"imports nothing (see the package doc comment) and adds no broker Op, dispatch case, or " +
			"Response field of its own.",
	},
}

// adr0420DigestLedgerWorkingTreeFiles returns every non-test *.go file found ANYWHERE under dir
// — recursively, via filepath.WalkDir — keyed by its path relative to dir (forward-slash
// normalized, e.g. "mounts/mounts.go" for a file in a subdirectory).
func adr0420DigestLedgerWorkingTreeFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		out[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatalf("adr0420DigestLedgerWorkingTreeFiles: walk %s: %v", dir, err)
	}
	return out
}

// adr0420DigestLedgerBaseFiles returns every non-test *.go file that existed ANYWHERE under
// relDir AT rev — recursively, via `git ls-tree -r <rev> -- <relDir>` — read from that revision
// (git show), never from the working tree, keyed the same way as
// adr0420DigestLedgerWorkingTreeFiles.
//
// The `-- relDir` pathspec form (rather than the `rev:relDir` tree-ish form this used before Fix
// 1) is load-bearing, not cosmetic: `rev:relDir` is a fatal "Not a valid object name" when relDir
// did not exist at rev at all — which is exactly the case for internal/agent/cripaths, a package
// ADR-0421 D1e added after adr0420BaseHEAD and therefore genuinely absent from base. The pathspec
// form returns an empty, successful listing for a not-yet-existing directory instead, so a
// dependency that is brand new relative to base HEAD is reported as "every file in it is NEW"
// (the correct, reviewable outcome) rather than crashing the whole ledger.
func adr0420DigestLedgerBaseFiles(t *testing.T, root, rev, relDir string) map[string][]byte {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "ls-tree", "-r", "--name-only", rev, "--", relDir).Output()
	if err != nil {
		t.Fatalf("adr0420DigestLedgerBaseFiles: git ls-tree -r %s -- %s: %v", rev, relDir, err)
	}
	prefix := relDir + "/"
	files := map[string][]byte{}
	for _, name := range strings.Fields(string(out)) {
		if !strings.HasPrefix(name, prefix) {
			continue // outside relDir (should not happen with an exact pathspec, but be strict)
		}
		rel := strings.TrimPrefix(name, prefix)
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		b, showErr := exec.Command("git", "-C", root, "show", rev+":"+name).Output()
		if showErr != nil {
			t.Fatalf("adr0420DigestLedgerBaseFiles: git show %s:%s: %v", rev, name, showErr)
		}
		files[rel] = b
	}
	return files
}

// adr0420DigestFiles hashes every entry in files with SHA-256, returning path -> lowercase hex
// digest. Applied identically to the base-revision snapshot and the working-tree snapshot so the
// two sides are compared as content, never as text-scanned tokens or shapes.
func adr0420DigestFiles(files map[string][]byte) map[string]string {
	out := make(map[string]string, len(files))
	for rel, b := range files {
		sum := sha256.Sum256(b)
		out[rel] = hex.EncodeToString(sum[:])
	}
	return out
}

// adr0420DigestLedgerScopeRelDirs is Fix 1 (Arch-A, Security Reviewer, KVM Expert, Runtime
// Architect — found independently by all four, 2026-09-03): the ledger's scanned scope must be
// the real dependency closure, not a single hardcoded directory constant.
//
// Before this, the ledger hashed only adr0420NetnsbrokerRelDir. broker.go imports
// internal/agent/cripaths (ADR-0421 D1e — the ONE pre-existing exception the ledger grants), and
// hostRealpathAllowed (the broker's actual SC-1 privileged-surface check) derives its admitted
// path-marker SET from that external package via cripaths.AllDirRels()/cripaths.Marker(). Because
// cripaths lives outside the single scanned directory, a future widening of its marker list was
// completely invisible to the ledger — zero signal across every check in this file.
//
// The fix: derive the scanned directory set from `go list -deps` on adr0420NetnsbrokerRelDir,
// filtered to this module's own import path. This is a real dependency-graph primitive — it
// reaches every future in-module import of the broker package, not just the one found this
// round — not another hand-maintained enumeration of the kind assertion #9's token/shape/site
// scanner already proved unbounded (see the doc comment on
// TestADR0420_D3_NetnsbrokerContentDigestLedger below).
func adr0420DigestLedgerScopeRelDirs(t *testing.T, root string) []string {
	t.Helper()

	modOut, err := exec.Command("go", "list", "-m").Output()
	if err != nil {
		t.Fatalf("adr0420DigestLedgerScopeRelDirs: go list -m: %v", err)
	}
	modPath := strings.TrimSpace(string(modOut))
	if modPath == "" {
		t.Fatalf("adr0420DigestLedgerScopeRelDirs: go list -m returned an empty module path")
	}

	pkgImportPath := modPath + "/" + adr0420NetnsbrokerRelDir
	depsCmd := exec.Command("go", "list", "-deps", pkgImportPath)
	depsCmd.Dir = root
	// GOOS MUST be pinned to linux, not inherited from the ambient environment (Fix 1, round 3 —
	// Security Reviewer + KVM Expert + Precedent Architect, independently, 2026-09-03; distinct
	// from the four reviewers credited above who found the separate cripaths scope-widening gap
	// this function exists to close): broker.go carries //go:build linux and is the ONLY file
	// that imports internal/agent/cripaths (broker_other.go, //go:build !linux, does not). Before
	// this fix, depsCmd.Dir was set but depsCmd.Env was not, so the child `go list -deps` process
	// inherited whatever GOOS the ambient environment happened to carry; under an unpinned
	// GOOS=darwin it would silently omit cripaths from the closure — with zero failure signal
	// anywhere in this file. Since the netnsbroker package this ledger covers is itself
	// explicitly a linux-only privileged sidecar, pinning GOOS=linux (rather than enumerating
	// multiple GOOS values the way the deleted scanner's build matrix did) is the correct,
	// proportionate fix.
	depsCmd.Env = append(os.Environ(), "GOOS=linux")
	depsOut, err := depsCmd.Output()
	if err != nil {
		t.Fatalf("adr0420DigestLedgerScopeRelDirs: go list -deps %s: %v", pkgImportPath, err)
	}

	modPrefix := modPath + "/"
	seen := map[string]bool{}
	var dirs []string
	for _, line := range strings.Fields(string(depsOut)) {
		if !strings.HasPrefix(line, modPrefix) {
			continue // stdlib or third-party dependency: outside this module's own source
		}
		rel := strings.TrimPrefix(line, modPrefix)
		if rel == "" || seen[rel] {
			continue
		}
		seen[rel] = true
		dirs = append(dirs, rel)
	}
	sort.Strings(dirs)
	if len(dirs) == 0 {
		t.Fatalf("adr0420DigestLedgerScopeRelDirs: go list -deps %s produced zero in-module "+
			"directories — the guard is not observing what it claims to observe", pkgImportPath)
	}
	return dirs
}

// adr0420CompareDigests is the pure comparison core of the content-digest ledger: given a base
// snapshot, a head snapshot (both path -> hex digest), and the exception allowlist, it returns
// one human-readable violation string per failing entry and nothing when there are none. It
// touches no filesystem, no git, and no *testing.T.
//
// Extracted out of TestADR0420_D3_NetnsbrokerContentDigestLedger (Fix 3, QA Lead, 2026-09-03):
// before this, the compare-and-fail branches (CHANGED-not-excepted, NEW, REMOVED,
// exception-digest-mismatch) were reachable only by feeding real git history and the real
// working tree through the whole test, so in an ordinary green run every failure branch was dead
// code — nothing proved they actually fire, or fire with the right verdict, when they should.
// TestADR0420_D3_CompareDigestsFailureBranches below feeds this function synthetic maps and
// exercises each branch directly.
func adr0420CompareDigests(base, head map[string]string, exceptions map[string]adr0420DigestException) []string {
	allPaths := map[string]bool{}
	for rel := range base {
		allPaths[rel] = true
	}
	for rel := range head {
		allPaths[rel] = true
	}
	sorted := make([]string, 0, len(allPaths))
	for rel := range allPaths {
		sorted = append(sorted, rel)
	}
	sort.Strings(sorted)

	var violations []string
	for _, rel := range sorted {
		baseSum, inBase := base[rel]
		headSum, inHead := head[rel]
		if inBase && inHead && baseSum == headSum {
			continue // unchanged — the common case
		}
		if exc, excepted := exceptions[rel]; excepted {
			// Fix 2 (Security Reviewer + KVM Expert, independently, 2026-09-03): a path that is
			// present in the exception list AND legitimately removed (inBase, !inHead) has no head
			// content to compare a digest against — headSum=="" can never equal exc.digest, so
			// before this fix a removed-and-excepted file always fell through to the REMOVED
			// violation below, whose own remediation text ("add a reviewed exception entry... or
			// restore the file") was unreachable advice: the exception entry already existed and
			// following the remediation did not clear the violation. TestADR0420_D3_
			// ValidateDigestExceptionsPhantomEntry's "present in base only" case correctly encodes
			// the intended behavior (zero violations for a reviewed removal) — this branch now
			// matches that test rather than contradicting it. The two cases a listed exception can
			// legitimately cover are distinct: a SURVIVING file's content change (needs a digest
			// match — there is real head content to verify against) vs. a REVIEWED REMOVAL (no head
			// content exists at all; the path's presence in adr0420DigestExceptions, with a reason
			// citing the responsible ADR, IS the review record — there is nothing else to check).
			switch {
			case inHead && headSum == exc.digest:
				// The exception covers the ONE reviewed digest, not the path in general: a further,
				// unreviewed edit on top of an already-excepted file moves headSum away from
				// exc.digest and must still fail — otherwise a file that legitimately changed once
				// could absorb any later change for free, forever.
				continue
			case inBase && !inHead && exc.digest == baseSum:
				// Reviewed, documented removal: the exception entry itself is the review record — but
				// "pin the exact reviewed content hash" must mean something for a removal too. The only
				// content that ever existed for a removed file is what stood at base HEAD, so the pinned
				// digest is checked against baseSum here (there is no headSum to check it against). A
				// removal exception whose digest does NOT match base HEAD's digest — a stale entry, a
				// copy-paste from a different path, or a removal layered on an unreviewed prior edit —
				// falls through to the mismatch violation below instead of being silently waved through.
				continue
			}
			violations = append(violations, "ADR-0420 assertion #9: "+rel+" does not match its "+
				"recorded exception digest (exception pins "+exc.digest+", working tree is "+headSum+
				", present="+strconv.FormatBool(inHead)+") — this is a SECOND, unreviewed change on "+
				"top of the one adr0420DigestExceptions["+strconv.Quote(rel)+"] already covers ("+
				exc.reason+"); update the exception's digest only after reviewing what changed, or "+
				"revert")
			continue
		}
		switch {
		case inBase && !inHead:
			violations = append(violations, "ADR-0420 assertion #9: "+rel+" was REMOVED relative to "+
				"base HEAD and is not in adr0420DigestExceptions — add a reviewed exception entry "+
				"with its ADR and reason, or restore the file")
		case !inBase && inHead:
			violations = append(violations, "ADR-0420 assertion #9: "+rel+" is NEW relative to base "+
				"HEAD and is not in adr0420DigestExceptions — a new file in this scope is a new "+
				"privileged surface that must be reviewed and recorded, not silently admitted")
		default:
			violations = append(violations, "ADR-0420 assertion #9: "+rel+" CHANGED relative to base "+
				"HEAD (digest "+baseSum+" -> "+headSum+") and is not in adr0420DigestExceptions — add "+
				"a reviewed exception entry with its ADR and reason, or revert the change")
		}
	}
	return violations
}

// adr0420DigestExceptionViolations is the pure comparison core of exception-list validation,
// extracted out of adr0420ValidateDigestExceptions (Fix 2 phantom-entry hardening, 2026-09-03) for
// the same reason adr0420CompareDigests was extracted out of the content-digest ledger test (Fix
// 3, round 2): a *testing.T-reporting function's failure branches are otherwise reachable only by
// feeding real git history and the real working tree through the whole test, so in an ordinary
// green run every failure branch is dead code — nothing proves it fires, or fires with the right
// verdict, when it should. It touches no *testing.T; adr0420ValidateDigestExceptions below wraps
// it and reports each returned string via t.Error.
//
// A stale exception — one whose pinned digest no longer matches ANY observed delta — is worse
// than no exception at all: it is a standing, reviewed-looking permission that no longer
// describes reality, and (as importantly) its mere presence must never be read as "this path is
// generally excused" — see the per-entry digest match in adr0420CompareDigests, which is what
// actually prevents that reading. Every entry must correspond to a real, current delta.
func adr0420DigestExceptionViolations(root string, base, head map[string]string, exceptions map[string]adr0420DigestException) []string {
	var violations []string
	for rel, exc := range exceptions {
		if strings.TrimSpace(exc.reason) == "" {
			violations = append(violations, "ADR-0420 assertion #9: adr0420DigestExceptions["+
				strconv.Quote(rel)+"] has an empty reason \u2014 every exception must carry the "+
				"responsible ADR and a one-line reason")
			continue
		}
		if strings.TrimSpace(exc.digest) == "" {
			violations = append(violations, "ADR-0420 assertion #9: adr0420DigestExceptions["+
				strconv.Quote(rel)+"] has an empty digest \u2014 every exception must pin the exact "+
				"reviewed content hash, not just the path")
		}

		if m := adr0420ExceptionReasonADRPattern.FindStringSubmatch(exc.reason); m == nil {
			violations = append(violations, "ADR-0420 assertion #9: adr0420DigestExceptions["+
				strconv.Quote(rel)+"]'s reason does not cite a real ADR (must contain \"ADR-\" "+
				"followed by digits) \u2014 a reason without a named ADR is prose sitting next to a "+
				"correct digest, not a review record: "+strconv.Quote(exc.reason))
		} else {
			num := m[1]
			for len(num) < 4 {
				num = "0" + num
			}
			if !adr0420AdmissibleADRExceptionNumbers[num] {
				violations = append(violations, "ADR-0420 assertion #9: adr0420DigestExceptions["+
					strconv.Quote(rel)+"] cites ADR-"+m[1]+" which is not in the in-file admissible-ADR "+
					"allowlist (adr0420AdmissibleADRExceptionNumbers) \u2014 add it there (a reviewed act) "+
					"if this ADR genuinely needs to cite an exception, or correct the reason if it does not: "+
					strconv.Quote(exc.reason))
			}
		}

		baseSum, inBase := base[rel]
		headSum, inHead := head[rel]
		switch {
		case inBase && inHead && baseSum == headSum:
			violations = append(violations, "ADR-0420 assertion #9: adr0420DigestExceptions["+
				strconv.Quote(rel)+"] records a delta, but base HEAD and the working tree are "+
				"byte-identical for it \u2014 remove the stale exception entry so a future real change "+
				"at this path is not silently masked")
		case !inBase && !inHead:
			// Present in NEITHER snapshot: adr0420CompareDigests only ever iterates the UNION of
			// base/head keys, so an exception-only key like this one never reaches its checks at
			// all \u2014 a "phantom" exception passes on text validity alone (non-empty reason, pinned
			// digest, ADR pattern, ADR in the allowlist) with no verification the path means anything
			// in the ledger's currently-derived scope on either revision. That is itself a
			// violation: a stale/phantom exception naming a path absent from both revisions.
			violations = append(violations, "ADR-0420 assertion #9: adr0420DigestExceptions["+
				strconv.Quote(rel)+"] is a phantom exception \u2014 this path exists in NEITHER base "+
				"HEAD "+adr0420BaseHEAD+" nor the working tree's ledger scope, so it cannot "+
				"correspond to any reviewed delta \u2014 remove the stale exception entry")
		}
	}
	return violations
}

// adr0420ValidateDigestExceptions is Fix 2 (Arch-B, 2026-09-03), hardened by Fix 2 round 2
// (Security Reviewer, 2026-09-03): an exception entry with a non-empty reason and a correct
// digest was previously ACCEPTED even when the reason didn't name anything real \u2014 "reason: x"
// passed as long as the pinned digest matched. This validates to a real minimum bar: every reason
// must cite a real ADR number (contain "ADR-" followed by digits), AND that number must appear in
// the in-file adr0420AdmissibleADRExceptionNumbers allowlist.
//
// This replaces an earlier form of this check (round 1, 2026-09-03) that instead stat'd
// docs/adr/ and globbed for a matching file on disk. That form had a real, structural gap
// (Security Reviewer, round 2): docs/adr/ is INTENTIONALLY gitignored/local-only (CLAUDE.md's
// IP-protection policy), so it is absent on every fresh clone and in the real gate/CI environment
// \u2014 precisely where this check matters most. The filesystem check degraded to skipping the
// "does this ADR exist" half there, and the degraded-mode notice it logged used t.Logf, which Go's
// testing package only prints on failure or under -v; the real gate entrypoint (Makefile's `test`
// target) runs `go test` without -v, so the notice never actually surfaced in a real gate run, and
// a reason citing a fabricated ADR (e.g. "ADR-0000: fake") passed silently every time. Pinning the
// admissible set in-file removes the environment dependency entirely: the same check, with the
// same result, runs whether or not docs/adr/ exists and whether or not -v is passed \u2014 there is
// no more degraded mode to announce.
//
// This is not exhaustive \u2014 a reason can cite an admissible ADR and still be substantively wrong
// about what that ADR permits, which remains a human-review question \u2014 but "reason: x" next to
// a correct digest no longer passes, and neither does a reason citing an ADR this ledger does not
// recognize.
func adr0420ValidateDigestExceptions(t *testing.T, root string, base, head map[string]string, exceptions map[string]adr0420DigestException) {
	t.Helper()

	for _, violation := range adr0420DigestExceptionViolations(root, base, head, exceptions) {
		t.Error(violation)
	}
}

// TestADR0420_D3_ValidateDigestExceptionsPhantomEntry is Fix 2's proof coverage (Arch-B, KVM
// Expert, 2026-09-03 — the exception-list side of the same gap Fix 1 closed on the
// dependency-closure side): synthetic, table-driven proof — via the pure
// adr0420DigestExceptionViolations core (same extraction pattern as
// TestADR0420_D3_CompareDigestsFailureBranches proves adr0420CompareDigests) — that an exception
// entry whose key is present in NEITHER the base snapshot NOR the head snapshot is itself flagged
// as a violation, rather than silently passing on text validity (non-empty reason, pinned digest,
// ADR pattern, ADR file on disk) alone. Every case's reason cites a real, on-disk ADR (ADR-0420
// itself) so the only violation a case can trigger is the one under test, not the separate "cites
// no real ADR" check Fix 2 also added.
func TestADR0420_D3_ValidateDigestExceptionsPhantomEntry(t *testing.T) {
	root := adr0420RepoRoot(t)
	const validReason = "ADR-0420: synthetic fixture, not a real exception"

	for _, tc := range []struct {
		name       string
		base       map[string]string
		head       map[string]string
		exceptions map[string]adr0420DigestException
		wantSubstr string // substring the sole violation must contain; "" means zero violations
		wantCount  int
	}{
		{
			name: "exception present in neither base nor head is a phantom violation",
			base: map[string]string{},
			head: map[string]string{},
			exceptions: map[string]adr0420DigestException{
				"internal/agent/netnsbroker/does_not_exist_on_either_side.go": {
					digest: "deadbeef00000000000000000000000000000000000000000000000000000000",
					reason: validReason,
				},
			},
			wantSubstr: "internal/agent/netnsbroker/does_not_exist_on_either_side.go\"] is a phantom exception",
			wantCount:  1,
		},
		{
			name: "exception present in base only (legitimately removed) is not a phantom violation",
			base: map[string]string{"internal/agent/netnsbroker/removed.go": "digestA"},
			head: map[string]string{},
			exceptions: map[string]adr0420DigestException{
				"internal/agent/netnsbroker/removed.go": {
					digest: "deadbeef00000000000000000000000000000000000000000000000000000000",
					reason: validReason,
				},
			},
			wantCount: 0,
		},
		{
			name: "exception present in head only (legitimately added) is not a phantom violation",
			base: map[string]string{},
			head: map[string]string{"internal/agent/netnsbroker/added.go": "deadbeef00000000000000000000000000000000000000000000000000000000"},
			exceptions: map[string]adr0420DigestException{
				"internal/agent/netnsbroker/added.go": {
					digest: "deadbeef00000000000000000000000000000000000000000000000000000000",
					reason: validReason,
				},
			},
			wantCount: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := adr0420DigestExceptionViolations(root, tc.base, tc.head, tc.exceptions)
			if len(got) != tc.wantCount {
				t.Fatalf("adr0420DigestExceptionViolations(%s) returned %d violation(s), want %d: %v",
					tc.name, len(got), tc.wantCount, got)
			}
			if tc.wantSubstr != "" {
				if len(got) != 1 || !strings.Contains(got[0], tc.wantSubstr) {
					t.Fatalf("adr0420DigestExceptionViolations(%s) = %v, want exactly one violation containing %q",
						tc.name, got, tc.wantSubstr)
				}
			}
		})
	}
}

// TestADR0420_D3_NetnsbrokerContentDigestLedger is the unmount-authority half of ADR-0420
// assertion #9. It supersedes the token/shape/site scanner this file carried through five rounds
// of narrowing (var adr0420UnmountTokens, adr0420UnmountSites, adr0420AuthorityCallArgStringLits,
// adr0420BuildMatrix and its Makefile-parsing staleness check, and
// TestADR0420_D3_BrokerUnmountAuthorityNotWidenedInPlace) per a §9 deep-consistency cycle-breaker
// pass (2026-09-03): that apparatus asked an enumeration-based source scanner to be complete over
// an open, unbounded space of spellings (case, identifier vs. call-argument, wrapper vs.
// underlying primitive, raw syscall by number), and each round's fix closed one point while
// leaving the residual space provably unbounded — the ADR's own amendment names two such limits
// that no round of scanning could ever close. See the "AMENDMENT" note under assertion #9 in
// docs/adr/0420-mount-forest-ownership-coherence-and-residue-reconciliation.md for the full
// verdict and both permanent limits, which apply to this replacement exactly as they applied to
// the scanner it replaces (see the doc comment on the two named limits below).
//
// The mechanism: hash every non-test *.go file under the ledger's SCOPE — adr0420NetnsbrokerRelDir
// plus every in-module package it depends on, transitively, per adr0420DigestLedgerScopeRelDirs
// (Fix 1, 2026-09-03; before that hardening this was a single hardcoded directory constant, which
// is what let ADR-0421 D1e's internal/agent/cripaths dependency go unobserved) — recursively, at
// ADR-0420's base HEAD (adr0420BaseHEAD) and in the working tree. The (relative-path, digest) SET
// must be identical between the two, except for entries explicitly present in
// adr0420DigestExceptions — each carrying the ADR responsible and a one-line reason
// (adr0420ValidateDigestExceptions checks the reason actually names a real ADR). Any other
// addition, removal, or content change fails closed with the exact path and what changed
// (adr0420CompareDigests). This is complete by construction over the whole dependency closure's
// source: no spelling, wrapper, subdirectory, build tag, raw syscall, or external package evades a
// digest, because none of them change what a digest measures (whether the bytes changed) — unlike
// the scanner it replaces, which had to be told which spellings, shapes, and sites to look for.
//
// TWO PERMANENT LIMITS, carried forward unchanged from the token scanner this replaces (recorded
// in the ADR amendment, restated here because a reader of this test should not have to cross-
// reference the ADR to know what this guard does NOT prove):
//
//  1. This proves the ledger's scanned scope's SOURCE did not change outside the reviewed
//     exception list. It does NOT prove the AGENT-REACHABLE unmount capability did not grow:
//     server.go's existing brokerCmd -> Client.Exec -> Op:"exec" path can already drive an
//     arbitrary execAllowlist-admitted argv, including "umount -l <target>", with zero broker.go
//     diff and therefore zero digest-ledger signal. A digest ledger proves the source didn't
//     change; it says nothing about capability reachable via that pre-existing exec path.
//  2. This is a source-content comparison, not runtime enforcement. There is no seccomp-bpf
//     filter or capability restriction on this privileged CAP_SYS_ADMIN broker process. Closing
//     either limit would require kernel-level enforcement on the broker process or a dedicated,
//     narrowly-scoped broker op replacing the general exec path — both are real roadmap items
//     (broker.go carries a FOLLOW-ON note proposing exactly the latter), neither is implemented by
//     this test.
func TestADR0420_D3_NetnsbrokerContentDigestLedger(t *testing.T) {
	root := adr0420RepoRoot(t)

	// Fix 1 (Security Reviewer, 2026-09-03): these three were t.Skip; see the identical rationale
	// on the equivalent guard in adr0420BrokerSources above — no gate anywhere in this repo
	// re-verifies the content-digest ledger, so a skip here is indistinguishable from a pass for
	// the one file that exists to prove a fail-open mitigation stays deleted. All three are hard
	// failures now, not skips: git and the go toolchain are both hard, non-optional dependencies
	// of this repo's own workflow, and an unreachable base HEAD must read as an unproven guard,
	// not a silently-passing one — doubly so once docs/security/PRE-PUBLICATION-HISTORY-SCRUB-
	// PLAN.md's planned history rewrite makes that the normal case.
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("ADR-0420 assertion #9: git is not available in this environment, so the content-" +
			"digest ledger (TestADR0420_D3_NetnsbrokerContentDigestLedger) cannot run. No other gate " +
			"re-verifies this — see the Fix 1 comment above — so this is a hard failure, not a skip.")
	}
	verify := exec.Command("git", "-C", root, "cat-file", "-e", adr0420BaseHEAD+"^{commit}")
	if err := verify.Run(); err != nil {
		t.Fatalf("ADR-0420 assertion #9: base HEAD %s is not reachable in this checkout (shallow "+
			"clone or rewritten history). No other gate re-verifies the content-digest ledger — see "+
			"the Fix 1 comment above — so this is a hard failure, not a skip.", adr0420BaseHEAD)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatalf("ADR-0420 assertion #9: the go toolchain is not available in this environment, so " +
			"the content-digest ledger's dependency-closure scope (adr0420DigestLedgerScopeRelDirs, " +
			"which shells out to `go list -deps`) cannot be derived. No other gate re-verifies this " +
			"— see the Fix 1 comment above — so this is a hard failure, not a skip.")
	}

	scopeDirs := adr0420DigestLedgerScopeRelDirs(t, root)

	baseDigest := map[string]string{}
	headDigest := map[string]string{}
	for _, relDir := range scopeDirs {
		baseRaw := adr0420DigestLedgerBaseFiles(t, root, adr0420BaseHEAD, relDir)
		for rel, b := range adr0420DigestFiles(baseRaw) {
			baseDigest[relDir+"/"+rel] = b
		}

		dir := filepath.Join(root, filepath.FromSlash(relDir))
		headRaw := adr0420DigestLedgerWorkingTreeFiles(t, dir)
		for rel, b := range adr0420DigestFiles(headRaw) {
			headDigest[relDir+"/"+rel] = b
		}
	}

	if len(baseDigest) == 0 {
		t.Fatalf("hashed zero non-test .go files from base HEAD %s across the ledger's scope %v "+
			"— the guard is not observing what it claims to observe", adr0420BaseHEAD, scopeDirs)
	}
	if len(headDigest) == 0 {
		t.Fatalf("hashed zero non-test .go files from the working tree across the ledger's scope "+
			"%v — the guard is not observing what it claims to observe", scopeDirs)
	}

	for _, violation := range adr0420CompareDigests(baseDigest, headDigest, adr0420DigestExceptions) {
		t.Error(violation)
	}
	adr0420ValidateDigestExceptions(t, root, baseDigest, headDigest, adr0420DigestExceptions)
}

// TestADR0420_D3_CompareDigestsFailureBranches is Fix 3 (QA Lead, 2026-09-03): synthetic,
// table-driven proof that adr0420CompareDigests's failure branches actually fire, and fire with
// the right verdict, independent of whatever the real git history and working tree happen to
// contain right now. Before this test, CHANGED-not-excepted, NEW, REMOVED, and
// exception-digest-mismatch were reachable only through TestADR0420_D3_NetnsbrokerContentDigestLedger
// against real state — so in an ordinary green run, every one of them was dead code. This restores
// the kind of synthetic proof coverage the six deleted token-scan tests had, adapted to the new
// content-digest mechanism.
func TestADR0420_D3_CompareDigestsFailureBranches(t *testing.T) {
	const (
		digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		digestC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	)

	for _, tc := range []struct {
		name       string
		base       map[string]string
		head       map[string]string
		exceptions map[string]adr0420DigestException
		wantSubstr string // substring the sole violation must contain; "" means zero violations
		wantCount  int
	}{
		{
			name:       "unchanged file produces no violation",
			base:       map[string]string{"pkg/a.go": digestA},
			head:       map[string]string{"pkg/a.go": digestA},
			exceptions: nil,
			wantCount:  0,
		},
		{
			name:       "changed file with no exception fails as CHANGED",
			base:       map[string]string{"pkg/a.go": digestA},
			head:       map[string]string{"pkg/a.go": digestB},
			exceptions: nil,
			wantSubstr: "pkg/a.go CHANGED relative to base HEAD",
			wantCount:  1,
		},
		{
			name:       "new file with no exception fails as NEW",
			base:       map[string]string{},
			head:       map[string]string{"pkg/new.go": digestA},
			exceptions: nil,
			wantSubstr: "pkg/new.go is NEW relative to base HEAD",
			wantCount:  1,
		},
		{
			name:       "removed file with no exception fails as REMOVED",
			base:       map[string]string{"pkg/gone.go": digestA},
			head:       map[string]string{},
			exceptions: nil,
			wantSubstr: "pkg/gone.go was REMOVED relative to base HEAD",
			wantCount:  1,
		},
		{
			name: "exception whose pinned digest does not match current content fails as mismatch",
			base: map[string]string{"pkg/excepted.go": digestA},
			head: map[string]string{"pkg/excepted.go": digestC},
			exceptions: map[string]adr0420DigestException{
				"pkg/excepted.go": {digest: digestB, reason: "ADR-9999: test fixture, not real"},
			},
			wantSubstr: "pkg/excepted.go does not match its recorded exception digest",
			wantCount:  1,
		},
		{
			name: "exception whose pinned digest matches current content produces no violation",
			base: map[string]string{"pkg/excepted.go": digestA},
			head: map[string]string{"pkg/excepted.go": digestB},
			exceptions: map[string]adr0420DigestException{
				"pkg/excepted.go": {digest: digestB, reason: "ADR-9999: test fixture, not real"},
			},
			wantCount: 0,
		},
		{
			// Gap 1 (QA Lead REJECT + Security Reviewer, independently, 2026-09-03): the
			// removed-file-exception branch (inBase && !inHead in adr0420CompareDigests) had zero
			// coverage anywhere -- this is the case that exercises it directly. The exception's
			// pinned digest matches the BASE revision's digest (the only content that ever existed
			// for the removed file), so the reviewed removal is correctly treated as non-violating.
			name: "removed file with an exception whose digest matches base HEAD produces no violation",
			base: map[string]string{"pkg/removed-reviewed.go": digestA},
			head: map[string]string{},
			exceptions: map[string]adr0420DigestException{
				"pkg/removed-reviewed.go": {digest: digestA, reason: "ADR-9999: test fixture, not real"},
			},
			wantCount: 0,
		},
		{
			// The companion case (Arch-B, 2026-09-03): a removal exception whose pinned digest does
			// NOT match base HEAD's digest for that path must still fail as a mismatch -- otherwise
			// the digest field on a removal exception would be decorative rather than a real pin on
			// the exact reviewed content.
			name: "removed file with an exception whose digest does NOT match base HEAD fails as mismatch",
			base: map[string]string{"pkg/removed-mismatched.go": digestA},
			head: map[string]string{},
			exceptions: map[string]adr0420DigestException{
				"pkg/removed-mismatched.go": {digest: digestB, reason: "ADR-9999: test fixture, not real"},
			},
			wantSubstr: "pkg/removed-mismatched.go does not match its recorded exception digest",
			wantCount:  1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := adr0420CompareDigests(tc.base, tc.head, tc.exceptions)
			if len(got) != tc.wantCount {
				t.Fatalf("adr0420CompareDigests(%s) returned %d violation(s), want %d: %v",
					tc.name, len(got), tc.wantCount, got)
			}
			if tc.wantSubstr != "" {
				if len(got) != 1 || !strings.Contains(got[0], tc.wantSubstr) {
					t.Fatalf("adr0420CompareDigests(%s) = %v, want exactly one violation containing %q",
						tc.name, got, tc.wantSubstr)
				}
			}
		})
	}
}

// adr0420BrokerDispatchOps extracts the set of op strings the broker's request dispatch accepts.
//
// It is ANCHORED to the real dispatch switch — the `switch req.Op` inside func Handle — and read
// from the parsed AST rather than matched line-wise. Both properties are corrections for verified
// bypasses of this guard's previous line-regex form (`(?m)^\s*case "([a-z][a-z0-9_]*)":`):
//
//  1. MULTI-VALUE CASE CLAUSES. The regex captured exactly one group per line, so a clause of the
//     form `case "host_realpath", "mount_residue_reconcile":` yielded only "host_realpath" and
//     every op after the comma was invisible to the guard — a new privileged op could be added to
//     the dispatch, in the same clause as an existing one, and the surface diff would show
//     nothing. An *ast.CaseClause carries its entire List, so every expression in the clause is
//     extracted by construction; there is no "first match on the line" to take.
//
//  2. ANY-CASE-IN-THE-FILE MATCHING. The regex matched case clauses anywhere in broker.go, not
//     just the dispatch. That both polluted the op set with non-ops (resolveNetnsExecBinary's
//     `case "ip":` is a binary-key switch, not a privileged operation) and gave a way to mask a
//     real addition: seed the intended op string into some unrelated string switch first, and it
//     is thereafter present in the BASE set and never reported when it later appears in the
//     dispatch. Anchoring to `switch req.Op` means the set is exactly the privileged surface this
//     guard claims to measure, and nothing else in the file can add to or launder it.
//
// Returns nil when the dispatch switch cannot be located (parse failure, Handle renamed, tag no
// longer req.Op). The caller treats an empty BASE set as a fatal "the guard is not observing what
// it claims to observe" rather than as "no ops found", so a silent breakage cannot read as a pass.
func adr0420BrokerDispatchOps(src string) map[string]bool {
	file, err := parser.ParseFile(token.NewFileSet(), "broker.go", src, 0)
	if err != nil {
		return nil
	}
	ops := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != "Handle" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			// Only the dispatch itself: `switch req.Op {`.
			sel, ok := sw.Tag.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "Op" || sw.Body == nil {
				return true
			}
			// Also anchor sel.X: checking sel.Sel.Name alone means a decoy
			// `switch anyOtherStruct.Op` anywhere in Handle's body would be
			// harvested identically to the real dispatch. Handle's request
			// parameter is named "req" (verified from source: `func Handle(req
			// Request) Response`), so require the switch tag to be exactly req.Op.
			reqIdent, ok := sel.X.(*ast.Ident)
			if !ok || reqIdent.Name != "req" {
				return true
			}
			for _, stmt := range sw.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				// EVERY expression in the clause list, not just the first.
				for _, expr := range clause.List {
					lit, ok := expr.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					op, unquoteErr := strconv.Unquote(lit.Value)
					if unquoteErr != nil {
						continue
					}
					ops[op] = true
				}
			}
			// KEEP WALKING (return true, not false). Returning false here would
			// PRUNE ast.Inspect's traversal of this switch's own children — including
			// every CaseClause body — so a second `switch req.Op` (or `switch
			// <anything>.Op` anchored to req the same way) nested inside one of THIS
			// switch's case bodies (e.g. inside `default:`) would never be visited and
			// its case labels would be silently invisible to this extractor. The
			// line-regex form this replaced had no such blind spot (it matched case
			// clauses anywhere in the file); pruning after the first match would have
			// been a regression relative to it, not just a missed improvement.
			return true
		})
	}
	return ops
}

// adr0420BrokerResponseFields extracts the exported field names of the broker's Response struct.
//
// Read from the parsed AST — walking *ast.TypeSpec's *ast.StructType.Fields.List — rather than a
// line regex, for the same reason adr0420BrokerDispatchOps was converted in the round this guard
// was introduced. The line-regex form (`(?m)^\t([A-Z][A-Za-z0-9]*)\s+\S`) captured at most ONE
// name per field line, so a multi-name field spec — `Stdout, Stderr, Residue []byte` — yielded
// ZERO matches for that entire line: none of the three names satisfied the single-capture-group
// pattern. Because the caller's comparison is additions-only (it fails only when HEAD has a name
// BASE lacks), a field set that SHRINKS this way is silently invisible — worse than the
// case-clause bug this whole assertion-#9 hardening effort started from, since there the bypass
// at least required an attacker-controlled addition; here an ordinary refactor to a multi-name
// spec makes the extractor itself under-report, with no adversarial input needed.
func adr0420BrokerResponseFields(src string) map[string]bool {
	file, err := parser.ParseFile(token.NewFileSet(), "broker.go", src, 0)
	if err != nil {
		return nil
	}
	fields := map[string]bool{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name == nil || ts.Name.Name != "Response" {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			for _, field := range st.Fields.List {
				if len(field.Names) == 0 {
					// Embedded/nested field: no explicit name, so it is named by its
					// type (e.g. `SomeEmbedded` for `SomeEmbedded` or `*SomeEmbedded`).
					if name := adr0420EmbeddedFieldTypeName(field.Type); name != "" && ast.IsExported(name) {
						fields[name] = true
					}
					continue
				}
				// EVERY name in a multi-name spec (`Stdout, Stderr, Residue []byte`),
				// not just the first — this is exactly what the regex form dropped.
				for _, n := range field.Names {
					if n != nil && ast.IsExported(n.Name) {
						fields[n.Name] = true
					}
				}
			}
		}
	}
	return fields
}

// adr0420EmbeddedFieldTypeName resolves the effective field name of an embedded struct field
// (one with no Names) from its type expression: a plain identifier, a pointer to one, or a
// package-qualified selector (named by the selector's final identifier, matching Go's own
// embedding rule).
func adr0420EmbeddedFieldTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return adr0420EmbeddedFieldTypeName(t.X)
	case *ast.SelectorExpr:
		if t.Sel != nil {
			return t.Sel.Name
		}
	}
	return ""
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
