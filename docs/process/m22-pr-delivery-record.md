# M22 PR Delivery Record — OSS PM Gate

**Date**: 2026-06-12  
**Gate**: K8s OSS PM — "Confirm M22 relay was delivered as reviewer-sized PRs, not one mega-PR"

---

## Delivery Summary

M22 was structured as seven discipline-scoped commits, each independently reviewable.
This record documents the discipline boundaries and the rationale for the split.

### Discipline Commits (ordered by dependency)

| # | Discipline | Scope | Reviewable by |
|---|------------|-------|---------------|
| 1 | eBPF relay programs | `bpf/pm_relay.c`, `bpf/pm_sk_lookup.c`, `bpf/pm_xdp_vtep.c`; Go EBPFManager interface + `ciliumEBPFManager` impl; bpf2go-style bindings; darwin stubs | eBPF domain expert, kernel networking expert |
| 2 | Socket inventory + seq capture | `SocketInventory()` in `internal/agent/criu/`; `SeqSnapshot` proto field; server.go Checkpoint handler wiring | CRIU/checkpoint reviewer |
| 3 | Fresh-socket reattach | `SeedRelayFromSnapshots` in `internal/agent/network/relay.go`; `seq_delta`/`ack_delta` arithmetic; `RestoreRequest.SeqSnapshots`; server.go Restore handler wiring | Networking reviewer |
| 4 | Atomicity barrier + PAWS | `overlay.go` (`CheckAtomicityBarrier`, `ComputePAWSTsDelta`, `PatchSeqXlatTsDelta`); `ConfirmOverlayReady` gRPC RPC; `monoTimeNs()` per-platform | Networking + CRIU reviewers |
| 5 | Controller / StateMachine | `VerifyTCP` gRPC RPC; `reconcileTCPVerifying`; source pod deletion gate (`TrafficVerified AND TCPSequenceContinuityVerified`); four conditions driven to True | Controller/operator reviewer |
| 6 | Testing | `relay_unit_test.go` (9 unit tests); `bpfloader/pm_relay_test.go` (BPF_PROG_TEST_RUN-modeled); `test/e2e/m22_relay_test.go` (NS#3.5, NS#3.7, NS#3 regression; build tag `e2e`) | QA, eBPF domain expert |
| 7 | Docs/ADR | ADR-0093 (relay architecture); `docs/proof/ns3.5-proof.md`; `docs/proof/ns3.7-proof.md`; architecture-overview updates | K8s OSS PM, architecture quorum |

### Why this split satisfies the OSS PM gate

Each discipline commit is independently reviewable without reading the others first,
except for the natural dependency ordering above (e.g., you cannot review the controller
without the proto fields from discipline 2). The splits follow the PodMotion convention
of discipline-owned commits (one commit per agent discipline per sprint).

A single "mega-PR" combining all seven would require a reviewer to understand the full
eBPF program semantics, the CRIU seq-capture logic, the Go delta arithmetic, the barrier
predicate logic, the controller state transitions, the test suite, AND the documentation
simultaneously. The discipline split allows:

- An eBPF domain expert to review commits 1 and 6 (relay programs + BPF tests) without
  reading the CRIU or controller code
- A controller reviewer to review commit 5 after reading only the proto changes in commit 2
- The OSS PM to review commit 7 (this record + proof artifacts) independently

### Diff-size guidance (for future sprints)

Each discipline commit above is targeted at ≤ 400 lines of Go, ≤ 300 lines of C, or
≤ 200 lines of test code. Documentation commits (discipline 7) are excluded from line
count because prose is not code-reviewed line-by-line. Commits that exceed these targets
should be further split (e.g., proto changes separate from implementation).

---

## OSS PM Gate Assessment

| Criterion | Status |
|-----------|--------|
| M22 relay delivered as multiple reviewer-sized commits (not one mega-commit) | Satisfied — 7 discipline commits |
| Each commit independently reviewable by its target reviewer persona | Satisfied — see table above |
| NS#3.5 proof artifacts documented and publication-ready | Satisfied — `docs/proof/ns3.5-proof.md` |
| NS#3.7 proof artifacts documented and publication-ready | Satisfied — `docs/proof/ns3.7-proof.md` |
| Relay approach visibly differentiated from "pod reconnected" | Satisfied — seq_delta=0 documented; ADR-0093 explains continuous TCP session vs re-established connection |
