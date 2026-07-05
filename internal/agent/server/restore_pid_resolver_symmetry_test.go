/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

// restore_pid_resolver_symmetry_test.go — regression guard for ADR-0245.
//
// Two independent architects (ADR-0245 review panel) found that the CRIU --pidfile
// primitive was only wired on the NRI restore path: readRestoredPIDFromPidfile +
// verifyRestoredPIDAlive were gated inside `if sandboxID != ""`, while BOTH gRPC
// Restore RPC branches call joinNsRestore with sandboxID == "" and therefore fell into
// an `else` branch that used the spoofable comm-scan resolver (findRestoredProcessPID —
// comm is attacker-controlled via prctl(PR_SET_NAME), which ADR-0245 states MUST NOT be
// a resolver). The fix removes the sandboxID gate from PID resolution so BOTH restore
// entry points (NRI and gRPC) resolve the PID via CRIU's own --pidfile, and deletes the
// comm-scan resolver entirely.
//
// These tests parse the production source of joinNsRestore in server.go and assert the
// structural invariant directly, so the asymmetry cannot silently reappear:
//   1. The comm-scan resolver findRestoredProcessPID has no definition and no call site.
//   2. The --pidfile resolver (readRestoredPIDFromPidfile) is invoked UNCONDITIONALLY in
//      joinNsRestore — i.e. not nested inside an `if sandboxID != ""` block — so it runs
//      identically on the NRI (sandboxID set) and gRPC (sandboxID == "") paths.
//   3. The only surviving `if sandboxID != ""` block in joinNsRestore is the ADR-0128
//      cgroup-placement step (which legitimately requires a pod sandbox), and it appears
//      AFTER the pidfile resolution — never wrapping it.

import (
	"os"
	"strings"
	"testing"
)

// readServerSource returns the body of joinNsRestore from server.go for structural asserts.
func readServerSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	src := string(data)
	const marker = "func joinNsRestore("
	start := strings.Index(src, marker)
	if start < 0 {
		t.Fatalf("could not locate %q in server.go", marker)
	}
	// The next top-level func declaration terminates joinNsRestore's body.
	rest := src[start+len(marker):]
	end := strings.Index(rest, "\nfunc ")
	if end < 0 {
		t.Fatal("could not locate end of joinNsRestore body")
	}
	return rest[:end]
}

// TestCommScanResolverIsGone proves the spoofable comm-scan resolver is fully retired
// (rule 3h: disproven scaffolding removed atomically, not left as dead code).
func TestCommScanResolverIsGone(t *testing.T) {
	data, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	src := string(data)
	if strings.Contains(src, "func findRestoredProcessPID(") {
		t.Fatal("findRestoredProcessPID is still defined — the comm-scan resolver must be deleted (ADR-0245, rule 3h)")
	}
	// A bare call `findRestoredProcessPID(` anywhere is a resurrected call site.
	if strings.Contains(src, "findRestoredProcessPID(") {
		t.Fatal("findRestoredProcessPID has a call site — no restore path may resolve the PID via comm-scan (ADR-0245)")
	}
}

// TestPidfileResolverIsUnconditional proves the --pidfile primitive resolves the restored
// PID on BOTH restore entry points: it is invoked in joinNsRestore at function scope, not
// nested inside an `if sandboxID != ""` block. Since both gRPC Restore branches call
// joinNsRestore with sandboxID == "" and the NRI path calls it with sandboxID set, an
// unconditional resolver is exactly the NRI/gRPC symmetry ADR-0245 requires.
func TestPidfileResolverIsUnconditional(t *testing.T) {
	body := readServerSource(t)

	pidfileIdx := strings.Index(body, "readRestoredPIDFromPidfile(")
	if pidfileIdx < 0 {
		t.Fatal("joinNsRestore no longer calls readRestoredPIDFromPidfile — the --pidfile resolver is the required primitive (ADR-0245)")
	}

	sandboxGateIdx := strings.Index(body, "if sandboxID != \"\"")
	if sandboxGateIdx < 0 {
		// No sandboxID gate at all is acceptable for this assertion (resolver is trivially
		// unconditional), though the ADR-0128 cgroup step normally keeps one.
		return
	}
	// The pidfile resolver must appear BEFORE the sandboxID gate. If the gate preceded it,
	// resolution would once again be nested inside the NRI-only branch — the exact defect.
	if pidfileIdx > sandboxGateIdx {
		t.Fatalf("readRestoredPIDFromPidfile (offset %d) appears AFTER `if sandboxID != \"\"` (offset %d) — "+
			"PID resolution must not be gated on sandboxID or the gRPC path regresses to comm-scan (ADR-0245)",
			pidfileIdx, sandboxGateIdx)
	}
}

// TestSurvivingSandboxGateIsCgroupPlacementOnly documents that the one remaining
// sandboxID-dependent block is the ADR-0128 cgroup placement (moveProcessToPodCgroup),
// which legitimately requires a pod sandbox and is NOT retired.
func TestSurvivingSandboxGateIsCgroupPlacementOnly(t *testing.T) {
	body := readServerSource(t)
	gateIdx := strings.Index(body, "if sandboxID != \"\"")
	if gateIdx < 0 {
		t.Skip("no sandboxID gate present — cgroup placement may have been restructured")
	}
	// The block guarded by the surviving gate must be the cgroup move, not PID resolution.
	after := body[gateIdx:]
	if !strings.Contains(after, "moveProcessToPodCgroup(") {
		t.Fatal("surviving `if sandboxID != \"\"` block does not contain moveProcessToPodCgroup — " +
			"the only sandboxID-dependent step should be ADR-0128 cgroup placement")
	}
	if strings.Contains(after, "readRestoredPIDFromPidfile(") {
		t.Fatal("readRestoredPIDFromPidfile is inside the `if sandboxID != \"\"` block — " +
			"PID resolution must be unconditional (ADR-0245)")
	}
}
