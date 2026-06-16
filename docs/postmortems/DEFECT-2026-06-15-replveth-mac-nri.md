# DEFECT-2026-06-15: replVethMAC never populated on the gRPC Restore path → injectIPHandoff requeue loop → Verifying timeout

- **Date:** 2026-06-15
- **Gate:** gate34-strict-tcp (tcpPreservationMode=Strict)
- **Phase failed:** Verifying
- **Protocol:** §14b Human-Found Defect Protocol
- **Author:** Opus QA Architect
- **Severity:** High — blocks Strict-mode live migration completion (gARP / IP handoff never sent)
- **Logs:** /tmp/sprint32-gate34-logs.txt

---

## 1. Root cause

`pm.Status.ReplVethMAC` was empty (`""`) when the controller reached `injectIPHandoff`.
`injectIPHandoff` (internal/controller/podmigration_controller.go:2567) treats an empty
`ReplVethMAC` as "NRI plugin writeback pending" and requeues every 3s. The MAC is never
written, so the loop runs until the migration times out in Verifying. gARP / `InjectIPHandoff`
(ADR-0133 D2) is never issued, so the old pod IP is never redirected to the destination veth.

### What the logs actually show (corrects the original defect framing)

The original report attributed this to "the NRI StartContainer hook never fires on CRIU
join-netns restore." That symptom is real, but it is **not the proximate cause of the empty
MAC**. The logs show the restore did **not** run through the NRI hook at all — it ran through
the **gRPC `Restore` RPC raw-CRIU fallback path**:

```
L218 joinNsRestore: restore.log confirms 'Restore finished successfully'
L219 joinNsRestore: found restored process  pid=27069
L220 Restore: joinNsRestore succeeded (raw CRIU path via joinNs)  migration=gate34-strict-tcp pid=27069
L221 ReportRestoreConfirmed: criuRestoreConfirmed set true  restoredPID=27069 replVethMAC=""
```

The NRI plugin connected (L143–149) but never logged `NRI HandleStartContainer called` with
`checkpointRefPresent=true` for this migration. The controller's `reconcileRestoringNRI` waited
out its 60s `criuConfirmTimeout` and fell back to the agent `Restore` gRPC RPC
(podmigration_controller.go:2392–2443). That fallback is the path that ran.

### The actual bug: the gRPC Restore path hardcodes an empty MAC

The MAC is collected in exactly **one** place — the NRI `OnStartContainer` callback in
`cmd/agent/main.go:275–302`, which loops over `ReadReplVethMAC(pid, netnsPath)` and passes the
result into `ReportRestoreConfirmed` (main.go:318).

Both gRPC `Restore` RPC code paths in `internal/agent/server/server.go` call
`ReportRestoreConfirmed(..., int32(pid), "")` with a **literal empty string** for `replVethMAC`:

- server.go:3737 — `ctr checkpoint` / config.json restore path
- server.go:3803 — raw CRIU `joinNsRestore` fallback path (the one that ran in gate34)

So whenever restore completes via the gRPC RPC rather than via the NRI hook,
`replVethMAC` is structurally guaranteed to be empty. `injectIPHandoff` then waits forever for
a "NRI writeback" that, on this path, is never authored by anyone.

`ReadReplVethMAC` (server.go:521) is a free function taking `(pid, sandboxNetnsPath)`. It does
**not** depend on the NRI hook firing — it just `nsenter`s the netns and reads eth0. Nothing
prevents the gRPC path from calling it; it simply never does.

### Verdict

**Root cause confirmed, but reclassified:** the empty `replVethMAC` is a **gRPC-Restore-path
omission**, not an NRI hook bypass. The NRI hook not firing is a contributing condition (it is
what diverted control to the gРPC fallback), but even with the NRI hook permanently disabled
the migration should still populate the MAC — the fallback path is a first-class restore path
and must satisfy the same status contract.

---

## 2. Systemic vs isolated

**Systemic across every gRPC Restore path.** Not specific to join-netns and not specific to
Strict:

- **join-netns raw CRIU path** (server.go:3790–3805): empty MAC. ← gate34 hit this.
- **config.json / ctr-checkpoint path** (server.go ~3737): empty MAC.
- **tcpPreservationMode=None cold path:** routes through the same gRPC `Restore` RPC and the
  same `joinNsRestore` (`Restore: joinNsRestore` at L3790, `strictMode=false`), so it carries
  the identical empty-MAC defect. None happens to mask it functionally because
  `injectIPHandoff` is reached with `SourcePodIP` semantics that may short-circuit
  (podmigration_controller.go:2555 skips handoff when `SourcePodIP==""`), but any cold path
  that *does* set `SourcePodIP` would deadlock identically.

The **NRI hook path is the only path that populates the MAC.** Every non-NRI restore is
affected. Since NRI did not fire in this kind/containerd 1.7.24 environment (the agent inferred
NRI version v0.6.1 — see L147), the gRPC fallback is in practice the **primary** path here, not
an edge case. That makes this defect effectively always-on for the current test cluster.

### Does the restore agent invoke any NRI hook manually post-restore?

No. The gRPC `Restore` RPC calls `joinNsRestore` directly and then `ReportRestoreConfirmed`.
It never calls `HandleStartContainer`, `OnStartContainer`, or any equivalent, and never calls
`ReadReplVethMAC`. There is no manual hook invocation and no MAC collection on this path.

---

## 3. Fix options (enumerated — not implemented)

**Option A — Agent reads the MAC post-restore on the gRPC path (recommended).**
In both gRPC `Restore` branches, replace the `""` argument with a `ReadReplVethMAC(pid,
netnsPath)` call (mirroring main.go:275–302, including the brief retry loop, since eth0 can lag
the post-restore settle). The function already exists and is path-agnostic; `pid` is in hand
(`rawPID` / restore result PID) and the netns path is resolvable via the same
`ResolvedNetnsPath` / `SandboxNetnsPath` helpers the NRI path uses. Smallest, most localized
fix; closes the gap on *all* gRPC restore paths at once. **This is the architecturally correct
home for MAC collection** — it belongs to "restore completed," not to "NRI hook fired."

- *Risk:* `ReadReplVethMAC` is best-effort; on the gРPC path there is no second writer, so a
  read failure must be loud and should fail the restore (or at least the gate) rather than
  silently pass an empty MAC, to avoid re-introducing a silent requeue loop.

**Option B — Manually invoke NRI-equivalent logic post-restore.**
Have the gРPC path call the same `OnStartContainer` callback body (refactored into a shared
`finalizeRestore(pid, netnsPath, migration, ns)` helper used by both the NRI callback and the
gРPC RPC). This unifies MAC collection + `SingleHomeRestoredPod` + `ReportRestoreConfirmed` so
the two paths can never drift again. More refactoring than A, but eliminates the entire class
of "NRI path does X, gРPC path forgot X" defects (note `SingleHomeRestoredPod`, ADR-0137, is
*also* only called on the NRI path — a latent sibling of this bug).

**Option C — Pre-populate replVethMAC at DestinationNetnsReady (before CRIU restore).**
The placeholder/replacement pod's veth and eth0 exist as soon as the sandbox netns is ready,
*before* CRIU restore runs (CRIU joins that existing netns; ADR-0125, it does not mint eth0).
So the controller could read the MAC at `DestinationNetnsReady` / `PrepareDestination` and
stash it in status, decoupling MAC availability from the restore mechanism entirely. Most
robust against future restore-path changes, but requires a new agent RPC (or extending
`PrepareDestination`'s response) and is the largest change.

**Option D (additional) — Make `injectIPHandoff` self-heal instead of waiting forever.**
Orthogonal hardening: if `ReplVethMAC` is empty after restore is confirmed, have the controller
actively fetch it (e.g., a `GetReplVethMAC` RPC, or via `restoredPIDForMigration` + a read RPC)
rather than passively requeuing on the assumption that some other actor will write it. Removes
the "wait for a writeback that never comes" deadlock as a category, regardless of which restore
path ran. Best combined with A or B, not as a standalone fix.

**Recommended:** **A + B together** — refactor a shared `finalizeRestore` helper (B) whose body
includes the `ReadReplVethMAC` collection (A), and call it from both the NRI callback and the
two gРPC branches. Optionally add D as defense-in-depth. C is the cleanest long-term but is a
larger architectural move; defer unless restore-path proliferation continues.

---

## 4. Pipeline gap

**No test exercises the gРPC Restore path's status contract.** Specifically:

- No unit test asserts that `ReportRestoreConfirmed` is called with a **non-empty**
  `replVethMAC` on the gРPC path. The two `Restore`-RPC call sites passing `""` were never
  flagged because nothing checks the resulting status field.
- No integration/E2E test asserts `pm.Status.ReplVethMAC != ""` after Restoring, nor that
  `injectIPHandoff` ever *progresses past* the requeue branch. The E2E suite (test/e2e/) has
  cold, precopy, postcopy, ordering, wireguard, and traffic tests, but none assert on
  `ReplVethMAC` or that `InjectIPHandoff` was actually issued (grep for `replVethMAC` /
  `InjectIPHandoff` across test/ returns nothing).
- The gate harness checks end-state TCP preservation but the migration timed out *before*
  reaching that assertion, so the gate "failed" only via timeout, not via a targeted signal
  pointing at the empty MAC.

**The kind/containerd environment guarantees the gРPC fallback path runs** (NRI v0.6.1, hook
does not fire for join-ns restore), yet **every existing happy-path expectation was implicitly
written against the NRI path** that populates the MAC. The test matrix never ran the path the
production-like cluster actually takes.

### Test that would have caught it

1. **Unit (fastest):** a `Restore`-RPC test that stubs `joinNsRestore` and asserts the
   subsequent `ReportRestoreConfirmed` (or the patched CR status) carries a non-empty
   `ReplVethMAC`. Would have failed immediately on the literal `""`.
2. **Controller integration:** drive a PodMigration through Restoring→Verifying on the gРPC
   path (NRI disabled) with envtest, assert `Status.ReplVethMAC != ""` and that
   `conditionIPHandoffInjected` reaches `True` rather than looping `NRI writeback pending`.
3. **E2E gate assertion:** add a bounded-time invariant — "within N s of `criuRestoreConfirmed`,
   `Status.ReplVethMAC` is non-empty" — so a stuck requeue surfaces as a precise failure, not a
   blanket Verifying timeout. (Aligns with the §14d SUT-liveness / Monitor-Agent contract:
   a phase that requeues unchanged for >N s is a liveness violation, not "in progress.")

---

## 5. §4a assessment — the replVethMAC population chain

Tracing the primitive chain that must hold for IP handoff to succeed:

1. **Source of truth:** replacement pod eth0 MAC, readable via `ReadReplVethMAC(pid,
   netnsPath)` (server.go:521) — netns-scoped `ip -o link show eth0`. *Path-agnostic, sound.*
2. **Collection trigger:** **only** wired into the NRI `OnStartContainer` callback
   (cmd/agent/main.go:290). **Broken invariant:** collection is bound to the *mechanism*
   (NRI) rather than the *event* (restore completed). Any restore that completes by another
   mechanism skips collection.
3. **Writeback:** `ReportRestoreConfirmed(..., replVethMAC)` (server.go:242) faithfully writes
   whatever it is handed — but is handed `""` by both gРPC callers (3737, 3803). *The writer is
   correct; the callers violate the contract.*
4. **Consumer:** `injectIPHandoff` (controller:2567) hard-gates on non-empty `ReplVethMAC` and
   requeues otherwise — with **no timeout and no active fetch**. *A passive consumer waiting on
   an optional producer = unbounded deadlock.*

**§4a verdict:** the chain has a **single-writer / multi-path-producer mismatch**. The status
field `ReplVethMAC` is a required input for a required downstream action (gARP handoff), but it
is populated by only one of several restore code paths, and the consumer assumes a producer
that may never run. Two §4a primitive violations:

- **Locality:** MAC collection is colocated with NRI rather than with restore-completion, so it
  does not travel with all restore paths. (Sibling violation: `SingleHomeRestoredPod` / ADR-0137
  has the *same* NRI-only locality and is a latent repeat of this defect.)
- **Liveness:** the consumer's "requeue until present" has no upper bound and no escalation, so
  a missing optional becomes a silent hang rather than a fast, attributable failure.

Fixing #2 (move collection to restore-completion — Options A/B) closes the immediate defect;
fixing #4 (bound + actively fetch — Option D) hardens the chain against the next producer that
forgets to write.
