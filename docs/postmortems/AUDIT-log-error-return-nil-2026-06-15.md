# Audit: log.Error + return nil / continue on mutating steps

**Date**: 2026-06-15
**Scope**: `internal/agent/server/server.go`, `internal/agent/server/zerowindow_linux.go`
**Trigger**: ADR-0049 Amendment D — Sprint 32 fail-closed enforcement (A1/A2/C3)

---

## Method

Grepped for `log.Error|log.Warn` in both files, excluded comment lines, then manually classified each hit by (a) whether a `return nil` or silent continue follows and (b) whether the step is a privileged mutating operation on the migration critical path.

Two categories:

- **MUTATING** — fail-closed under Strict is required per ADR-0049 Amendment D. Action: fix required or already fixed in this sprint.
- **BENIGN** — degrade-and-continue is correct (no-op on a path that was never committed, CR metadata, or post-success bookkeeping).

---

## Findings

### FIXED in this sprint

| File | Line | Pattern | Classification | Action |
|------|------|---------|----------------|--------|
| server.go | ~3760 | `patchCheckpointImages` failed, log.Error, proceed | **MUTATING** — security fail-open (un-patched images carry source identity) | **FIXED (A1)**: under Strict (`SeqSnapshots>0`) now returns typed error, aborts restore, controller initiates rollback. BestEffort/None: degrade retained, PATCH_ERROR surfaced in log. |
| zerowindow_linux.go | 101-114 | `ArmZeroWindowHold` failed, log.Error, return nil (ZeroWindowArmed still set True by caller) | **MUTATING** — false-green: armed=true reported when hold never placed | **FIXED (A2)**: under Strict returns `fmt.Errorf("zero-window arm failed under Strict: ArmZeroWindowHold: %w", err)`. Caller returns `armed=false` with BlockingReason. BestEffort/None: degrade retained, error clearly logged. |
| zerowindow_linux.go | 96-98 | `ifindex==0`, log.Info, return nil (non-veth CNI, hold silently skipped) | **MUTATING** — false-green for non-veth CNIs under Strict | **FIXED (C3)**: under Strict returns typed error "CNI unsupported for zero-window hold". Caller surfaces blocking CR-status reason via `armed=false + BlockingReason`. BestEffort/None: degrade retained. |

### BENIGN — degrade-and-continue is correct

| File | Line | Pattern | Rationale |
|------|------|---------|-----------|
| server.go | 670 | `resolveReplVethPeer` failed, continue | Post-restore tc-redirect is an ADR-0139 optimization; core IP handoff does not depend on it. Not on critical migration path. |
| server.go | 676 | `installTCRedirect` failed, continue | Same — tc redirect is acceleration, not correctness. Degrade correct. |
| server.go | 687 | `installOldIPForwardAccept` failed, continue | iptables FORWARD accept — non-fatal fallback; traffic may still flow via existing rules. |
| server.go | 698 | `installOldIPNotrack` failed, continue | conntrack optimization, not required for basic migration correctness. |
| server.go | 714 | `SendGratuitousARP` failed, continue | Gratuitous ARP is an optimization to accelerate ARP convergence; not required for correctness (regular ARP will converge). |
| server.go | 727 | `DiscoverVTEPMAC` failed, continue (inside InjectIPHandoff) | MAC discovery for FDB entry; failure means FDB optimization is skipped, not that migration fails. |
| server.go | 762 | deferred SIGCONT failed, will retry on requeue | ADR-0142 D3: retry on requeue is the specified recovery path. Not a silent swallow. |
| server.go | 1189 | `installOldIPNotrack` on source, continue | Source-side conntrack optimization, same as 698. Benign. |
| server.go | 2056 | `mkdir` in setupRootfsDirs, continue | Best-effort rootfs prep; dir may already exist; CRIU will fail loudly if missing required dirs. |
| server.go | 2071 | `touch` in setupRootfsFiles, continue | Same — placeholder file creation; CRIU will fail loudly if a required file is absent. |
| server.go | 3129 | PID resolution failure in PreDumpRound, log.Error, fallback | Falls back to no pre-dump rather than blocking; PreDump is an optimization (ADR-0128). |
| server.go | 3297 | PID resolution failure in Checkpoint, log.Error, fallback | Falls back gracefully; CRIU checkpoint proceeds without PID pin. |
| server.go | 3322 | TCP_REPAIR export failed, continue without SeqSnapshot | ADR-0156 D4: explicitly accepted — TCP preservation degrades to None on this path. |
| server.go | 3378 | `writeTCPSocketStateJSON` failed | Evidence-only JSON (GC-27 diagnostics); does not affect migration correctness. |
| server.go | 3462 | config.json staging failed in raw CRIU path | This is an intermediate staging step; if it fails, restore will fail loudly at `joinNsRestore`. Not a silent false-green — just earlier logging of what will be a hard error downstream. |
| server.go | 3467 | config.json read failed | Same — downstream hard failure. |
| server.go | 3481 | `upsertMigrationCheckpoint` CR update failed | CR metadata bookkeeping; does not affect migration state machine correctness. |
| server.go | 3738 | `ReportRestoreConfirmed` failed (join-ns path) | As documented in comment: surfaces as gate timeout rather than false-green; source pod not deleted. Acceptable. |
| server.go | 3800 | `ReportRestoreConfirmed` failed (raw CRIU path) | Same — gate timeout, not false-green. |
| zerowindow_linux.go | 156 | `disarmZeroWindowBPF` failed, continue | Disarm of a hold that may never have been armed (BPF object failure). True no-op — there is no hold to remove. Benign per ADR-0049 Amendment D. |

---

## Not-yet-addressed (not in scope of ADR-0049 Amendment D, tracked separately)

1. **server.go:3322 — TCP_REPAIR export failure**: Under Strict this silently degrades to a migration without TCP sequence preservation. ADR-0156 D4 accepts this; however a future ADR may close this under Strict to match the fail-closed mandate. Not addressed here because it is out of ADR-0049 Amendment D scope and governed by ADR-0156.

2. **server.go:762 — deferred SIGCONT FAILED**: Retries on requeue but does not set a blocking CR-status condition on failure. The restored process tree is stuck in SIGSTOP. While the requeue strategy is documented, adding a CR-status condition for the "SIGCONT retry budget exceeded" case would make it queryable. Out of scope for this sprint.

---

## Summary

Three mutating `log.Error + return nil` patterns confirmed and fixed (A1, A2, C3). All remaining patterns are correctly classified as benign degrade-and-continue. No additional MUTATING patterns requiring immediate fix were identified in the audited files.

## Tracking

A1 SeqSnapshots proxy: server.go restore site previously used len(SeqSnapshots)>0 as Strict proxy. Replaced with explicit TCPPreservationMode field in RestoreRequest (commit: this). Tracked and resolved.
