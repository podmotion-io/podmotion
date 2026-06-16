# DEFECT POSTMORTEM — 2026-06-15

**Sprint:** 32
**Protocol:** §14b Human-Found Defect Protocol (dual-Opus, no severity threshold)
**Author:** Opus QA Architect
**Status:** Root-caused; reproduction tests specified; fixes scoped (not applied — orchestrator dispatches dev agents per Standing Rule 3)

Two defects reached the human monitor that the Sprint 32 pipeline did not catch.

| ID | Symptom | Class | Verdict |
|----|---------|-------|---------|
| A | `armZeroWindowBPF(ifindex=2)` → TC clsact attach on kind node `eth0` fails EOPNOTSUPP (-95) | Brittle-chain lookup with silent wrong-value fallthrough (§4a) | **Systemic** |
| B | `ExportTCPRepairState: no ESTABLISHED sockets found` for redis-int (GC-27/GC-28 unprovable) | Test-setup precondition not enforced | **Isolated** (code is correct) |

---

## Defect A — Wrong veth ifindex in ArmZeroWindow

### Where
- Caller: `ArmZeroWindow` — `internal/agent/server/server.go:4372` calls `resolveVethIfindex(podUID)`.
- Buggy resolver: `resolveVethIfindex` — `internal/agent/server/zerowindow_linux.go:49`.
- Correct sibling (used by the *replacement*-pod path only): `resolveReplVethPeer(replPID)` — `internal/agent/server/server.go:895`.

### Root cause
`resolveVethIfindex` does not actually correlate the container interface to its host-side veth peer. It walks `/sys/class/net/*`, finds host links where `ifindex != iflink` (i.e. "any veth"), and then applies this fallthrough heuristic (zerowindow_linux.go:105):

```go
// Simplified heuristic: match by interface count (1 non-lo in container → 1 veth pair).
if len(cIfNames) == 1 {
    return uint32(hIfIndex), nil   // returns the FIRST host veth encountered
}
```

It returns the **first** host veth it iterates over from `os.ReadDir("/sys/class/net")`, with **no correlation** to the source pod's netns. On a kind node the directory iteration surfaces a low-numbered interface, and the function returns ifindex `2` — which is the kind container's own `eth0` (the Docker uplink), an interface that is **not clsact-capable**, producing EOPNOTSUPP (-95) on TC attach.

Critically, the container-side iflink is read and then **discarded** — the `cIfName` loop variable is consumed only by `_ = cIfName` (line 109). The comment at lines 85–104 openly admits it cannot enter the netns and substitutes a count-based guess. There is no comparison of the container `eth0@if<N>` peer index against `hIfIndex`. The "correlation" is a coincidence that holds only when exactly one host veth exists *and* it happens to sort first — neither is true on a multi-pod kind node.

`resolveReplVethPeer` (server.go:895) does it correctly: it `nsenter`s into the pod netns, runs `ip -o link show eth0`, parses `eth0@if<N>` via `parseVethPeerIndex`, then maps `<N>` to the host link name via `hostLinkNameByIndex`. The atomic enforcement boundary is the netns entry: the peer index is *read from inside the pod*, so it cannot be confused with an unrelated host veth.

### §4a brittle-chain assessment — CONFIRMED
`resolveVethIfindex` is a textbook §4a brittle chain:
- It **sequences multiple independent lookups** (FindContainerPID → read `/proc/<pid>/net/dev` → ReadDir `/sys/class/net` → per-link ifindex/iflink reads) with **no atomic enforcement boundary** tying the result back to the source pod's netns.
- It **silently falls through to a wrong value**: every failure branch (`return 0, nil`) and the count==1 shortcut return *without error*, and the caller treats `ifindex==0` as "stub, skip" and any non-zero value as authoritative. There is no validation that the returned ifindex is the source pod's peer or even clsact-capable.

This is the same defect shape §4a exists to flag: a lookup chain that "succeeds" with a value that was never verified against the invariant it is supposed to satisfy.

### Why the pipeline missed it (WS-ZWIN GC-25 gap)
GC-25 (zero-window hold) is exercised by `test/e2e/zero_window_hold_test.go`. Two gaps let the wrong ifindex through:

1. **The bpftool criterion asserts existence, not target.** Criterion 1 (zero_window_hold_test.go:127) runs `bpftool prog show --json` on the node and asserts the output `ContainSubstring("sched_cls")` — i.e. that *some* SCHED_CLS program exists *anywhere on the node*. It never asserts the program is attached to the **source pod's host-side veth ifindex**. An attach to the wrong interface — or a pre-existing CNI sched_cls prog — satisfies the assertion. (In the field the attach to eth0 failed outright with EOPNOTSUPP, but even a successful attach to the wrong veth would have passed.)

2. **The degraded path swallows the failure.** `armZeroWindowBPF` (zerowindow_linux.go:135) logs and `return nil` on any arm failure, by design ("protective optimisation … log and continue"). So EOPNOTSUPP never surfaces as an RPC error; `ZeroWindowArmed=True` is still set, and the e2e condition check (zero_window_hold_test.go:120) passes regardless. The only signal was a log line — which is exactly what the human monitor caught.

Net: there is **no test anywhere that asserts `resolveVethIfindex` returns the source pod's host-side peer ifindex.** The function has zero unit coverage (`grep` for it across `*_test.go` returns nothing).

### Reproduction test (Defect A)
Unit test, `internal/agent/server/zerowindow_linux_test.go` (new, `//go:build linux`). Create two veth pairs in a fresh netns so the directory contains more than one veth, move one end into a child netns, and assert `resolveVethIfindex` returns the *correct* peer, not "the first veth":

```go
//go:build linux

func TestResolveVethIfindex_ReturnsSourcePeerNotFirstVeth(t *testing.T) {
    // Requires root/CAP_NET_ADMIN; skip otherwise.
    if os.Geteuid() != 0 { t.Skip("needs root to create veth pairs") }

    // Create a DECOY veth pair (lower ifindex) and a REAL pair whose peer
    // lives in a child netns that maps to a known container PID.
    decoyHost, _ := mkVethPair(t, "pmdecoy0", "pmdecoy1")     // sorts first
    realHost, realPeerIdx, pid := mkVethPairInChildNetns(t)    // the source pod

    got, err := resolveVethIfindex(podUIDForPID(pid))
    if err != nil { t.Fatalf("resolveVethIfindex: %v", err) }

    if got == uint32(decoyHost) {
        t.Fatalf("returned DECOY first-veth ifindex %d — brittle-chain fallthrough bug", got)
    }
    if got != uint32(realHost) {
        t.Fatalf("got ifindex %d, want source pod host peer %d (iflink=%d)",
            got, realHost, realPeerIdx)
    }
}
```

A second, hermetic variant with no root requirement: refactor the correlation core out of `resolveVethIfindex` into a pure function `func matchHostPeer(containerPeerIfindex int, hostLinks []hostLink) (uint32, bool)` and table-test it with a multi-veth fixture where the first entry is a decoy. This is the durable regression guard and removes the count==1 heuristic entirely.

### Fix direction (for dev agent)
Replace the heuristic body of `resolveVethIfindex` with the proven `resolveReplVethPeer` technique: enter the pod netns (`nsenter --net=/proc/<pid>/ns/net ip -o link show eth0`), parse `eth0@if<N>` with the existing `parseVethPeerIndex`, and return `<N>` directly as the ifindex (the host peer's ifindex *is* `<N>`). Then have `armZeroWindowBPF` **reject** (not log-and-continue) an ifindex that is not clsact-attachable, OR validate it is the pod peer before the attach. Eliminate every `return 0, nil` fallthrough that masks a real resolution failure — fail closed per ADR-0049.

---

## Defect B — No ESTABLISHED TCP sockets at checkpoint

### Where
- `ExportTCPRepairState` — `internal/agent/network/tcprepair_export.go:91`; emits the message at line 100.
- Called from `Checkpoint` — `internal/agent/server/server.go:3284`.

### Root cause — test-setup, not code
`ExportTCPRepairState` calls `parseEstablishedWithInodes(rootPID)`, which reads `/proc/<rootPID>/net/tcp[6]` and filters for state `01` (ESTABLISHED). With zero ESTABLISHED rows it logs "no ESTABLISHED sockets found" and returns `(nil, nil)` — **correct, fail-soft behavior**: the checkpoint continues without a SeqSnapshot (ADR-0156 D4), and `VerifyTCP` (server.go:3855) correctly treats "no source snapshots + no destination ESTABLISHED" as a stateless migration that is trivially verified.

The defect is that the **GC-27/GC-28 fixture did not hold an ESTABLISHED connection** at freeze time. The `tcp-writer-persistent` pod was not maintaining an open socket to `redis-int:6379`. Likely causes (in order of probability):
1. The writer opened a connection per write and closed it (TIME_WAIT, not ESTABLISHED, at the freeze instant) instead of a persistent long-lived socket.
2. redis-int had not finished readiness, so the connection had not yet established when the migration froze.
3. The connection was idle long enough that an intermediary or keepalive reset it before freeze.

There is no `redis-int` bug and no PodMotion code bug — the proof obligation simply had no subject. GC-27 (TCP_REPAIR export) and GC-28 (restore) are **unfalsifiable without a live ESTABLISHED socket**, so a green run here was a false pass, not a true one.

### Why the pipeline missed it
The Sprint 32 pipeline has **no precondition gate asserting the fixture actually holds an ESTABLISHED connection before the migration starts.** The TCP_REPAIR unit test (`internal/agent/network/tcprepair_export_test.go:60`) *does* the right thing — it actively writes 5×4096B over a loopback socket and asserts `len(entries) != 0` — but that hermetic guarantee was never replicated as a **live precondition assertion in the e2e/integration path**. The system silently degrades "no sockets" into "stateless migration verified," so the absence of the proof subject is indistinguishable from a genuinely stateless workload. This is a §8 Step-0 clean-state-precondition gap applied to the *positive* side: the test must prove its own subject exists before claiming to verify it.

### Reproduction test (Defect B)
An integration precondition assertion, run against the live fixture immediately before triggering the migration (and mirrored as a unit test on the parser):

```go
// Precondition gate: the GC-27/28 fixture MUST hold a live ESTABLISHED socket
// to redis-int:6379 before checkpoint, or the proof obligation is vacuous.
func TestGC27_FixtureHoldsEstablishedConn(t *testing.T) {
    pid := containerPIDFor(t, "tcp-writer-persistent")
    entries, err := network.ExportTCPRepairState(int32(pid))
    if err != nil { t.Fatalf("export: %v", err) }
    var toRedis int
    for _, e := range entries {
        if e.DstPort == 6379 { toRedis++ }
    }
    if toRedis == 0 {
        t.Fatalf("GC-27 precondition FAILED: tcp-writer-persistent holds no "+
            "ESTABLISHED socket to redis-int:6379 — GC-27/GC-28 would be vacuous")
    }
}
```

The fixture itself must be fixed to keep one socket open for the whole test (single `net.Dial`, periodic keepalive write on the *same* conn, never reconnect-per-write).

### Fix direction (for dev agent)
1. Fix the `tcp-writer-persistent` fixture to hold a single persistent ESTABLISHED connection to redis-int:6379 with TCP keepalive enabled.
2. Add the precondition gate above to the GC-27/28 path so a vacuous run fails loudly instead of passing as "stateless." This is the durable fix — the fixture can rot again; the gate cannot be silently satisfied.

---

## c. Systemic vs isolated verdict

- **Defect A — SYSTEMIC.** The root cause is a brittle-chain resolver (§4a) that returns an unverified value, plus a class of tests that assert "an artifact exists" rather than "the artifact targets the correct object," plus a graceful-degradation path that converts hard failures into log lines. All three are reusable failure modes present elsewhere (see ranked list).
- **Defect B — ISOLATED (code correct).** The PodMotion code behaved correctly and fail-soft. The defect is a missing positive-precondition gate around one proof obligation and a broken fixture. The *category* of gap (no "prove the subject exists" gate) recurs, but no production code path is wrong.

---

## d. Ranked list of untested paths in the same defect class

Class = "netns-correlated lookup that can silently return a wrong/empty value, with no test asserting the value targets the correct object."

1. **`resolveVethIfindex` via `DisarmZeroWindow` (server.go:4482).** Same buggy resolver, same wrong-ifindex risk on the disarm side; a wrong ifindex here would fail to detach the real hold (leak) while logging success. No test.
2. **`armZeroWindowBPF` / `disarmZeroWindowBPF` graceful-degradation branches (zerowindow_linux.go:135, 154).** Both convert real attach/detach failures into `return nil`. No test asserts that a *genuine* arm failure is surfaced when it must be (AC1). The degraded path is the silent-fallthrough partner of the §4a chain.
3. **`pollUnackedZero` / `txQueueZero` (zerowindow_linux.go:165, 202).** Read `/proc/<pid>/net/tcp[6]`; on any read error `return nil`/best-effort, declaring "drained" when it may not be. No test for the error-masking path → could green-light a freeze with un-drained tx_queue.
4. **`ExportTCPRepairState` fd-map / pidfd degradation branches (tcprepair_export.go:107, 120, 148).** Each falls back to "zero seq" entries on error and continues. No test asserts that zero-seq fallback is distinguishable from a genuine snapshot — a wrong-but-present snapshot could pass `VerifyTCP` where a missing one would fail closed.
5. **`FindContainerPID` consumers generally.** Every resolver keyed on `podUID → PID` shares the silent `return 0, nil` idiom (e.g. zerowindow_linux.go:54). None assert the PID actually belongs to the intended pod's netns before using it for netns-scoped operations.

Recommend WS-ZWIN add a "target-correctness" assertion layer (ifindex belongs to source pod peer; SCHED_CLS attached to *that* ifindex specifically) and that all `return _, nil` silent-fallthrough branches in the resolver chain be audited under §4a and converted to fail-closed per ADR-0049.
