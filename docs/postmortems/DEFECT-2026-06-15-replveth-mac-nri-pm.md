# DEFECT-2026-06-15 — replVethMAC empty at ReportRestoreConfirmed (NRI StartContainer never fires on CRIU join-netns restore)

**Author:** Opus PM Architect (§14b Human-Found Defect Protocol)
**Date:** 2026-06-15
**Gate:** gate34-strict-tcp (WS-INTEGRATE, `podmotion-s32-int`), failed in `Verifying`
**Logs of record:** `/tmp/sprint32-gate34-logs.txt`
**Defect ID (proposed):** **E1** (continuing the C1/pycriu/D1 lettered series)
**Blast radius:** **Medium → High for Sprint 32 close** (hard-blocks GC-29 / GC-30 / GC-31)

---

## 0. One-paragraph statement

On the WS-INTEGRATE cluster, CRIU restore completed successfully via the operator's
**gRPC `Restore` RPC path** (`Restore called` → `Restore: joinNsRestore succeeded (raw CRIU
path via joinNs)` → CR condition `Restored / Container restored by agent`). That path calls
`ReportRestoreConfirmed(..., replVethMAC="")` — it **hardcodes an empty MAC** (server.go:3737,
server.go:3803). The **only** code that reads the replacement pod's `eth0` MAC
(`server.ReadReplVethMAC`) lives inside the **NRI `StartContainer` closure** in
`cmd/agent/main.go` (lines 277–302). That closure **never executed** for this migration —
the log contains **zero** `NRI StartContainer: invoking CRIU restore` / `HandleStartContainer`
records. With `pm.Status.ReplVethMAC` never populated, the controller's `injectIPHandoff`
correctly refused to proceed and requeued every 3s for ~2.5 minutes (`replVethMAC not yet
present in status — requeuing (NRI plugin writeback pending)`, log lines 374–423) until the
`Verifying` phase timed out. gARP (GC-29) requires `replVethMAC` as a mandatory input, so it
was never sent. **The hang behavior is correct; the missing precondition is the defect.**

---

## 1. Root cause — divergent restore paths, single MAC-collection site

There are **two** restore entry points into `joinNsRestore`, and only one collects the MAC:

| Path | Entry | Collects `replVethMAC`? | `ReportRestoreConfirmed` MAC arg |
|------|-------|------------------------|----------------------------------|
| **NRI StartContainer** | `cmd/agent/main.go` OnStartContainer closure → `JoinNsRestore` | **Yes** — `ReadReplVethMAC` w/ 6× retry (main.go:277–302) | `replVethMAC` (real) |
| **gRPC `Restore` RPC** | `internal/agent/server/server.go` `Restore()` → `joinNsRestore` | **No** | `""` (hardcoded, server.go:3737, 3803) |

`ReadReplVethMAC` is invoked from **exactly one** call site in the entire tree (main.go:290).
The gRPC `Restore` path has no equivalent. So **whether a migration ever gets a `replVethMAC`
depends entirely on which restore path the runtime/controller drives** — and that is not an
invariant any contract enforces today.

The premise's phrasing ("CRIU bypasses containerd lifecycle hooks") is the **observed symptom
class**, not a new kernel/CRIU behavior: on this integration cluster the replacement container
was restored through the operator-driven gRPC `Restore` RPC rather than by a containerd
`StartContainer` event carrying `podmotion.io/checkpoint-ref`. With no `StartContainer`
dispatch into `HandleStartContainer`, the MAC-collection closure is unreachable. The result is
identical regardless of *why* the hook didn't fire: **the MAC-collection logic is structurally
coupled to one of two restore paths, and the gate exercised the other one.**

---

## 2. Task 1 — Blast radius

**By tcpPreservationMode:**

- **None (cold / `NoOpCNI`, ADR-0154):** **Not affected.** The None path performs no IP
  handoff and sends no gARP; `replVethMAC` is never consulted. `injectIPHandoff` is a no-op /
  not entered for None. Sprint 31's 22/22 cold gate did not depend on this value. **No
  regression on None.**
- **Strict / Full (stateful):** **Affected — hard block.** ADR-0133 D1/D2/D3 make
  `replVethMAC` a **mandatory** input to the destination neighbor/FDB handoff and therefore to
  GC-29 gARP. Without it the `Restoring→Verifying→Complete` progression cannot finish.
  (gate34 ran `Strict`; the same gap applies to `Full`, which is a superset of the Strict
  datapath.)

**New defect vs pre-existing gap newly exposed:** **Pre-existing structural gap, newly
exposed by Sprint 32.** The `replVethMAC` plumbing was authored against the **NRI restore
path** (ADR-0133 D3 explicitly says "collected by the NRI plugin at StartContainer / JoinNsRestore
time"). Sprint 31 never needed the value (cold/None). Sprint 32 is the **first** sprint whose
North Star (`Full`/Strict TCP preservation, GC-29 gARP) actually consumes it end-to-end — and
WS-INTEGRATE is the first context where the restore was driven through the gRPC `Restore` RPC
rather than a checkpoint-ref-bearing `StartContainer`. The latent single-site coupling was
always present; Sprint 32 is simply the first load on it. It is **not** a code change that
*introduced* a regression this sprint.

---

## 3. Task 2 — ADR implications

**Existing ADR:** **Yes — ADR-0133 (Flannel VXLAN pod-IP handoff wiring), Decision 3** owns the
`replVethMAC` population mechanism, and it specifies it **only** for the NRI plugin path:
> "`replVethMAC` — collected by the **NRI plugin at StartContainer / JoinNsRestore time** … The
> plugin includes it in the extended `ReportRestoreConfirmed` call."

ADR-0158 (gARP implementation) **amends ADR-0133** and consumes `replVethMAC` as a hard input
to `InjectDestinationRoutes` but **does not re-specify how it is populated** — it inherits the
ADR-0133 D3 assumption.

**Verdict: ADR-0133 needs amendment (does NOT need a brand-new ADR).** The amendment must
state a **path-independent post-CRIU MAC-population contract**:

> The replacement pod's `eth0` MAC (`replVethMAC`) MUST be collected and written to
> `pm.Status.ReplVethMAC` by **whichever restore path actually executes** — NRI
> `StartContainer` **or** the gRPC `Restore` RPC. `ReportRestoreConfirmed` MUST NOT be called
> with an empty MAC on any Strict/Full migration; an empty MAC on a stateful migration is a
> **fail-closed** error (consistent with the ADR-0049 / C1 "privileged mutating steps fail
> closed, no silent false-green" direction), not a best-effort log-and-continue.

Concretely the amendment authorizes lifting `ReadReplVethMAC` out of the NRI closure into a
shared post-restore step that **both** `JoinNsRestore` and the gRPC `Restore` path invoke
before their respective `ReportRestoreConfirmed` calls — i.e. make MAC collection a property of
`joinNsRestore` completion, not of the caller. This is an ADR-0133 implementation-decision
amendment; ADR-0158's gARP spec is unchanged.

Note: ADR-0133 D3's own self-description ("reads `/sys/class/net/eth0/address` inside the pod
netns") is already superseded by the in-tree `ReadReplVethMAC`, which uses `nsenter --net … ip
link` (sysfs reads the host's interfaces). The amendment should also correct that stale prose.

---

## 4. Task 3 — Sprint scope impact

**Does it block Sprint 32 close? — YES.** Confirmed: GC-29 (gARP + /32 host route) requires
`replVethMAC`; GC-30 (`Full` reaches `Completed`) and GC-31 (TCP connection survives) are
downstream of a completed handoff. With `replVethMAC=""` the migration cannot leave `Verifying`.
Sprint 32 closes only on 32/32 (§1, SPRINT32-PLAN); this caps it at ≤29/32 until fixed.

**Workstream scope:**

- **WS-ARP (GC-29):** **Functionally blocked but not at fault.** WS-ARP's gARP/`SendGratuitousARP`
  + `/32` route emission is implemented (`kindnet_provider_linux.go`, ADR-0158) and is **starved
  of its input**, not broken. WS-ARP's gate cannot pass end-to-end until the MAC is supplied.
- **WS-INTEGRATE (GC-30/GC-31):** **Directly blocked.** This is where the two restore paths
  converge and where the defect surfaces. The fix lands here (the shared post-restore
  MAC-collection step) plus the ADR-0133 amendment.
- **WS-REPAIR:** **Not in scope / not affected.** TCP_REPAIR seq-state export (GC-27/GC-28) is
  orthogonal to MAC collection. Note the gate's `tcpSeqSnapshots` show `sndNxt=0/rcvNxt=0`,
  which is a **separate** WS-REPAIR observation to route to quorum, but it is **not** this
  defect and did not cause the `Verifying` hang. Do not fold it into E1.
- **WS-XDP / WS-ZWIN:** Not affected (the gate confirmed `armZeroWindowBPF` armed, ADR-0049
  working).

---

## 5. Task 4 — Pattern classification

**Different class from C1/D1.**

- **C1 / pycriu / D1 class = silent false-green:** a privileged step fails, the failure is
  logged, **the success signal (CR status / continued execution) is left unchanged**, and the
  system proceeds as if healthy. The danger is a *false Complete*.
- **E1 (this defect) = divergent-path contract gap / honest-hang:** the system did **not**
  report green. It correctly recognized the missing precondition (`replVethMAC not yet present
  … requeuing`) and **fail-stopped by timing out** in `Verifying`. There is no false-green here;
  the gating logic worked exactly as designed. The defect is that **a required value is
  produced on only one of two semantically-equivalent restore paths**, with no invariant
  forcing parity — a *structural coupling / missing-contract* defect, not a *degradation-
  contract* defect.

There **is** a real shared meta-pattern worth naming for the §14c chaos backlog, but it is
**not** C1's pattern: **"capability implemented on one restore path only."** `ReadReplVethMAC`
has a single call site gated behind the NRI hook; `SingleHomeRestoredPod` (ADR-0137/0138) is
wired into the **same** NRI closure (main.go:310) and is **equally absent on the gRPC `Restore`
path** — meaning a gRPC-path restore also skips single-homing. That is a **latent sibling of
E1** and should be swept in the same fix (route to quorum as E1-adjacent, see §6).

---

## 6. Task 5 — §18 items requiring Nav Point re-ordering / strategic scope change

Per instruction, this section lists **only** items that require Nav Point re-ordering or
strategic scope changes. Everything else is routed to quorum (listed after, for completeness).

**Requires Chad / Nav Point action — NONE that re-order the Nav Point sequence.**
E1 is a within-sprint defect fix on an already-approved Nav Point (Sprint 32 Full-mode TCP
preservation). It does **not** introduce a new capability, change the North Star, or reorder
the WS dependency graph. The single item that rises to strategic visibility (not re-ordering)
is:

- **S-1 (Chad ratification, mirrors C1 precedent):** The ADR-0133 amendment makes "empty
  `replVethMAC` on a Strict/Full migration" a **fail-closed error** rather than best-effort.
  This is the same *fail-closed-under-Strict* policy decision Chad is already ratifying for C1
  (ADR-0049). Recommend folding E1's fail-closed clause into that **single** standing decision
  ("privileged/required mutating + identity-collection steps fail closed under Strict/Full, no
  silent false-green") rather than a separate Nav Point. **No sequence change; one ratification
  line item appended to the existing C1 decision.**

**Routed to quorum (no Nav Point impact):**

1. **Q-1 — ADR-0133 amendment** (path-independent post-CRIU MAC-population contract; move
   `ReadReplVethMAC` into a shared `joinNsRestore`-completion step invoked by both the NRI and
   gRPC `Restore` paths; correct the stale sysfs prose). Standard ADR amendment quorum.
2. **Q-2 — E1-adjacent sibling sweep:** `SingleHomeRestoredPod` (ADR-0137/0138) is wired only
   into the NRI closure and is likewise skipped on the gRPC `Restore` path. Fix in the same PR
   as Q-1 (both belong to the shared post-restore step).
3. **Q-3 — Test-coverage gate (ADR-0100):** add a WS-INTEGRATE assertion that
   `pm.Status.ReplVethMAC` is **non-empty before `Verifying` is entered** on any Strict/Full
   migration, and a path-parity test asserting both restore paths populate it. The absence of
   this assertion is why E1 reached a human-found gate rather than CI.
4. **Q-4 — Separate observation, do not fold into E1:** `tcpSeqSnapshots` show
   `sndNxt=0/rcvNxt=0` at restore. Route to WS-REPAIR quorum as an independent check on the
   TCP_REPAIR capture window (ADR-0150/0156); it did not cause this hang.

**Gate-credit hold:** GC-29/GC-30/GC-31 remain **BLOCKED** until E1 is honestly closed
(`replVethMAC` populated on the executed restore path + gARP confirmed sent). No gate re-run
should claim these criteria before the ADR-0133 amendment lands and the path-parity test passes.

---

## 7. Evidence index

- `cmd/agent/main.go:277–302` — sole `ReadReplVethMAC` call site, inside NRI OnStartContainer closure.
- `cmd/agent/main.go:310` — `SingleHomeRestoredPod` wired into the same closure (sibling gap).
- `internal/agent/server/server.go:3737, 3803` — gRPC `Restore` path calls `ReportRestoreConfirmed(..., "")`.
- `internal/agent/server/server.go:242–268` — `ReportRestoreConfirmed` accepts empty MAC silently (`if replVethMAC != ""`).
- `internal/controller/podmigration_controller.go:2562–2596` — `injectIPHandoff` requeues while `ReplVethMAC == ""`.
- `docs/adr/0133-…D3` — specifies MAC collection on the NRI path only (root contract gap).
- `docs/adr/0158-…` — consumes `replVethMAC` for gARP; inherits ADR-0133 D3 assumption.
- Logs: `Restore called` / `joinNsRestore succeeded (raw CRIU path via joinNs)` (l.199, l.220);
  zero `NRI StartContainer` records; `replVethMAC not yet present … requeuing` (l.374–423).
