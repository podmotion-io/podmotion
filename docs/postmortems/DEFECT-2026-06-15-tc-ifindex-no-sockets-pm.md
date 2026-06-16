# PM Impact Report — Sprint 32 Human-Found Defect Protocol (§14b)

**Date:** 2026-06-15
**Author:** Opus PM Architect
**Protocol:** §14b Human-Found Defect Protocol (Chad found both defects during active monitoring)
**Sprint:** 32 — NP-TCP-FULL-STRICT (North Star: `tcpPreservationMode=Strict`, seq_delta=0, zero RST)
**Status:** Sprint CONTINUES with re-ordered scope (see §5, §6). Gate is **blocked** until P0/P1 land.

> Terminology note: SPRINT32-PLAN.md still uses the legacy label `tcpPreservationMode=Full`.
> The actual CRD enum (`api/v1alpha1/podmigration_types.go` L16) is `Strict | BestEffort | None`.
> This report uses **Strict**, which is the North-Star mode. SPRINT32-PLAN should be corrected.

---

## 1. Defect Summary (as found)

**Defect A — Wrong veth ifindex in zero-window arm (TC clsact attach to node eth0).**
`ArmZeroWindow` (`internal/agent/server/server.go` L4361) resolves the source-pod veth via
`resolveVethIfindex(podUID)` (`internal/agent/server/zerowindow_linux.go` L49) and passes the
result to `armZeroWindowBPF`. The resolver's veth-pairing logic is a stated heuristic that only
fires when the container has exactly one non-`lo` interface (L105: `if len(cIfNames) == 1`), and
its iflink/ifindex matching is incomplete (L84–111, comment admits "Simplified heuristic"). On the
observed run it returned ifindex=2 (the kind node's own `eth0`), so the TC clsact/egress filter
attached to the wrong link and the kernel returned **EOPNOTSUPP**. No window=0 is ever written to
the source pod's veth.

**Defect B — No ESTABLISHED TCP sockets at checkpoint (test-setup defect).**
`ExportTCPRepairState` (`internal/agent/network/tcprepair_export.go` L91) enumerates ESTABLISHED
sockets from `/proc/<pid>/net/tcp[6]` (L370 filter `fields[3] != "01"`). It logged
`no ESTABLISHED sockets found` and returned `nil, nil` (L99–102) — i.e. there was no live TCP
client connected to `redis-int:6379` inside the migrated pod's netns at the freeze instant. This
is a **test-harness/workload defect**, not a code defect in the export path: the export code is
correct but had nothing to capture.

**Critical distinction:** Defect A is an *implementation* defect (real code bug). Defect B is a
*test-fixture* defect (the SUT had no connection to preserve). They block different criteria and
have different fixes and different blast radius. Do not conflate them.

---

## 2. Blast Radius — Gate Criteria

### 2a. Criteria blocked by Defect A (wrong veth ifindex → no zero-window hold)

| GC | Workstream | Why blocked by A |
|----|-----------|------------------|
| **GC-25** | WS-ZWIN | "window=0 observed on source iface during freeze" — cannot be observed; filter is on the wrong link, EOPNOTSUPP. **Cannot be proven.** |
| **GC-26** | WS-ZWIN | "Zero-window released after restore confirmed" — nothing was armed, so there is no real release to prove. **Cannot be proven** as a real hold→release cycle. |
| **GC-32** | WS-ZWIN | Watchdog rollback path depends on a *real* zero-window hold being armed (`disarmZeroWindowBPF(ctx, ifindex)` in the watchdog goroutine, server.go L4417). With ifindex=2 the watchdog disarms a no-op. Rollback-on-timeout *event* (`ZeroWindowWatchdogFired`) may still fire, but the "source pod preserved with a genuine hold engaged" semantics are not exercised. **Partially blocked — event provable, hold semantics not.** |
| GC-31 | WS-INTEGRATE | "Active TCP connection survives migration" — without the hold the peer is not flow-controlled during freeze; in-flight segments during the freeze window can advance the peer's seq and break seq_delta=0. **Blocked transitively** (also blocked by B). |
| GC-30 | WS-INTEGRATE | `Strict` reaches `Completed` — the controller may still reach Completed because `armZeroWindowBPF` *deliberately degrades gracefully* (L135: logs and returns nil on arm failure). So GC-30 can pass **falsely green** while the hold is absent — this is a **proof-integrity risk**, not just a blocker. |

> Note the graceful-degradation trap: `armZeroWindowBPF` returns `nil` even when the real arm
> fails (zerowindow_linux.go L120–139). This means Defect A does **not** fail the migration — it
> silently produces a Strict migration with NO hold. A naive gate could score GC-30 green. The
> gate MUST assert an observable window=0 (GC-25) as a hard precondition for crediting GC-30/GC-31.

### 2b. Criteria blocked by Defect B (no ESTABLISHED sockets)

| GC | Workstream | Why blocked by B |
|----|-----------|------------------|
| **GC-27** | WS-REPAIR | "TCP_REPAIR socket state exported — snd_seq, rcv_seq present in checkpoint" — export returned empty; no seqs captured. **Cannot be proven.** |
| **GC-28** | WS-REPAIR | "CRIU restore with TCP socket state — connections resume without reset" — no socket to restore. **Cannot be proven.** |
| **GC-31** | WS-INTEGRATE | "Active TCP connection survives migration without disconnect" — there was no active connection. **Cannot be proven** (also requires A). |

### 2c. Criteria NOT affected (provable independent of A and B)

GC-1..GC-22 (Sprint 31 cold-migration baseline — carried forward), GC-23, GC-24 (WS-XDP load/pin),
GC-29 (WS-ARP gARP + /32 route). These do not depend on a live socket or the zero-window hold and
remain on track, subject to T-CLEAN preconditions.

### 2d. North-Star criteria status

GC-30 and GC-31 are the North-Star-defining criteria (SPRINT32-PLAN §9). **Both are currently
unprovable** — GC-31 requires both defects fixed; GC-30 is at risk of a false-green and must be
gated behind GC-25 + GC-27/28. **The North Star is not currently demonstrable.**

---

## 3. Blast Radius — ADR Implementation Gaps

| ADR | Status | Gap exposed | Reopen? |
|-----|--------|-------------|---------|
| **ADR-0157** (Zero-window timing/watchdog) | Accepted | The arm *timing/watchdog* contract is implemented, but veth *resolution* (a precondition the ADR assumes is solved) is not robust. ADR-0157 governs *when* to arm, not *which ifindex*. The ifindex resolver is an unspecified implementation detail. **Implementation gap, not an ADR decision gap.** | **No** — fix is below the ADR. |
| **ADR-0049 / 0131 / 0142** (zero-window hold orchestration) | Accepted | Same: these specify the hold semantics; `resolveVethIfindex` correctness is downstream. The graceful-degradation `return nil` on arm failure (zerowindow_linux.go L135) is arguably *inconsistent* with ADR-0049's "BPF program must be armed on the source veth" intent — it converts a hard failure into a silent no-op. Worth a one-line clarification, not a reopen. | **No** (consider a non-blocking amendment to forbid silent-degrade in Strict). |
| **ADR-0156** (TCP_REPAIR export format) | Accepted | None. Export code is correct; Defect B is a missing workload, not a format/code gap. ADR-0156's own "defect" context (SocketInventory zero-seq bug) is already addressed by this export path. | **No.** |
| **ADR-0162** (Strict-path netns external links) | Accepted (gate13) | Indirectly relevant: a healthy Strict dump must also handle the source netns links. Not implicated by A or B directly, but it is on the same critical path to a real `--tcp-established` dump. | **No.** |
| ADR-0155 (XDP bridge lifecycle), ADR-0158 (gARP) | Accepted | Not implicated. | No. |
| ADR-0159/0160/0161 (cert-manager, encryption, compliance) | Accepted | Out of scope for these defects. | No. |

**Conclusion: zero ADRs need to be reopened.** Both defects sit *below* the ADR layer (one
implementation bug, one test fixture). This is the most important finding for sprint continuity.

---

## 4. Sprint Impact Decision

**Recommendation: CONTINUE the sprint with re-ordered scope. Do NOT reset. Do NOT pause the
whole sprint.**

Rationale:
- **North Star is still achievable within the sprint.** Both defects are fixable without
  reopening any ADR (§3). seq_delta=0 / zero-RST remain reachable once a real hold is armed
  on the correct veth (A) against a real ESTABLISHED connection (B).
- WS-XDP (GC-23/24) and WS-ARP (GC-29) are unaffected and can continue in parallel.
- WS-ZWIN and WS-REPAIR gate criteria are *currently unprovable* but the fixes are bounded and
  local. WS-INTEGRATE was always last in the dependency chain (SPRINT32-PLAN §2 sequencing) and
  must not open its gate until A and B are fixed.
- The graceful-degradation false-green (§2a) is the one item that makes "continue" risky if left
  unaddressed: the gate could pass without a real hold. P1 below closes that hole.

**Gate status: BLOCKED.** The 32/32 gate cannot open until P0+P1 land. This is a *gate* block,
not a *sprint* block — prerequisite workstreams keep running.

---

## 5. Prioritized Remediation Backlog

Ordered. Each item names the file and the acceptance assertion the gate must check.

**P0 — Fix veth ifindex resolution (Defect A). [BLOCKER for GC-25/26/32]**
- File: `internal/agent/server/zerowindow_linux.go`, `resolveVethIfindex` (L49–113).
- Replace the `len(cIfNames)==1` heuristic with a deterministic peer match: read the container
  veth's `iflink` from inside the pod netns (via `/proc/<pid>/ns/net` + netlink, or
  `nsenter`-style read of `/sys/class/net/<eth0>/iflink`), then find the host link whose
  `ifindex == that iflink`. The existing `resolveReplVethPeer` logic at server.go L893–913 already
  does exactly this pairing for the replication veth (`eth0@if<N>` → host ifindex N) — **reuse it**
  rather than maintaining a second, weaker heuristic.
- Acceptance: `ArmZeroWindow` attaches to a link whose ifindex != node eth0 (2); no EOPNOTSUPP;
  GC-25 observes window=0 on the *pod* veth.

**P1 — Remove silent-degrade for Strict mode (proof-integrity). [BLOCKER for honest GC-30]**
- File: `internal/agent/server/zerowindow_linux.go`, `armZeroWindowBPF` (L120–139).
- The current `return nil` on arm failure (L135) is acceptable for `BestEffort`/PoC but MUST hard-
  fail (or set an explicit `Armed=false` blocking reason that the controller treats as fatal) when
  `tcpPreservationMode=Strict`. Otherwise GC-30 can score green with no hold. Thread the mode (or
  a `strict bool`) into the arm path so the failure surfaces.
- Acceptance: a Strict migration with a failed arm does NOT reach `Completed`; the gate cannot
  credit GC-30 without GC-25 also passing.

**P2 — Establish a real TCP client fixture in the gate harness (Defect B). [BLOCKER for GC-27/28/31]**
- Not a product-code fix. Test-harness change: before checkpoint on `podmotion-s32-int`, start a
  long-lived client *inside the migrated pod's netns* with an ESTABLISHED connection to
  `redis-int:6379` (e.g. `redis-cli --no-raw` holding a `SUBSCRIBE`, or a `nc` keepalive), and
  assert via `/proc/<pid>/net/tcp` that state `01` exists before freeze.
- Add this as a named §8 gate precondition: **"Live-socket precondition — at least one ESTABLISHED
  socket in the SUT pod netns to `redis-int:6379` is asserted before the freeze."** A gate run that
  freezes with zero ESTABLISHED sockets is **invalid** (mirror the T-CLEAN "invalid → discarded"
  rule).
- Acceptance: `ExportTCPRepairState` returns ≥1 entry with non-zero snd_nxt/rcv_nxt (the
  GC-27 log line at tcprepair_export.go L170 fires).

**P3 — Gate-credit ordering guard. [Proof integrity]**
- Gate logic (Arch-A Opus quorum): GC-30 and GC-31 may only be credited if GC-25 AND
  (GC-27 AND GC-28) are independently green in the same run. Encodes §2a/§4 so graceful-degradation
  can never produce a false North-Star pass.

**P4 — Re-run WS-ZWIN and WS-REPAIR gates, then open WS-INTEGRATE.**
- After P0–P3, re-run WS-ZWIN (GC-25/26/32) and WS-REPAIR (GC-27/28) on their dedicated clusters
  under §14d Monitor Agent. Only when both pass does WS-INTEGRATE open (unchanged from
  SPRINT32-PLAN §2 dependency rule). Full 32/32 gate runs last, under T-CLEAN + live-socket +
  deployed-provenance preconditions.

**P5 (housekeeping, non-blocking) — Correct SPRINT32-PLAN terminology.**
- Replace `tcpPreservationMode=Full` with `=Strict` throughout SPRINT32-PLAN.md to match the CRD
  enum and avoid agent confusion on future dispatches.

---

## 6. Nav Point Re-Authorization (§18 — recommendation only; Chad decides)

**Recommendation: NO re-authorization of Nav Point scope required.**

- The Nav Point (NP-TCP-FULL-STRICT) scope, North Star, and the 32 gate criteria are **unchanged**.
- No ADR is reopened (§3); no new capability is added; no criterion is dropped or redefined.
- The work is *corrective* (one implementation bug, one fixture gap, one proof-integrity guard),
  not a *scope* change. This falls within agent-owned sprint-design authority under the standing
  model — agents fix defects inside an approved Nav Point without re-approval.

**What DOES warrant Chad's attention (decisions only he should make):**
1. **Accept the gate-block** until P0–P3 land (low-risk; this is just "don't open the gate yet").
2. **Ratify P1** — making Strict-mode arm failure *fatal* is a behavior change to the degradation
   contract. It is the correct call for proof integrity, but it is a deliberate policy shift from
   the PoC's "log and continue." Recommend Chad explicitly bless it (one sentence) since it touches
   the spirit of ADR-0049's hold contract.
3. **Confirm the live-socket precondition** as a permanent §8 gate gate item (like T-CLEAN), so this
   class of test-fixture defect cannot recur silently.

If Chad wants P1 to ride a formal amendment ADR rather than a code-level policy change, that is the
only path that would touch the ADR corpus — and even then it is an *amendment*, not a reopen.

---

## 7. One-line verdict

Two below-the-ADR defects (one real bug in `resolveVethIfindex`, one missing test fixture) block
the North-Star criteria but break no ADR. Sprint continues; gate stays shut behind P0–P3; Chad
need only bless the Strict-mode hard-fail policy and the live-socket precondition.
