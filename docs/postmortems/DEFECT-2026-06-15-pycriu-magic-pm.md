# DEFECT-2026-06-15 — pycriu MagicException — PM Report (§14b)

**Protocol:** §14b Human-Found Defect Protocol — opened by Monitor Agent during `gate33-strict-tcp`.
**Author:** Opus PM Architect
**Date:** 2026-06-15
**Status:** OPEN — quorum pending
**Companion defect:** C1 (silent-degrade / Strict false-green), tracked in `docs/postmortems/DEFECT-2026-06-15-QUORUM.md`.

---

## Defect Summary

`pycriu.images.MagicException 1194725922` raised at `/dev/shm/pm-patch-ckpt.py` line 121, during a
`patchCheckpointImages` call. Root cause: `pycriu`'s `magic.by_val[img_magic]` lookup
(`pycriu/images/images.py:569`) failed on an image-magic value not present in the magic table, and
`images.py:571` re-raised it as `MagicException`. Restore aborted; migration rolled back cleanly,
source pod preserved (ADR-0012 invariant held).

**Magic value `1194725922` = `0x47361222`.** Verified NOT present in `pycriu/images/magic.py`
(`grep -c 1194725922` → 0). This is a genuinely unknown / unhandled image type, not a corruption of a
known magic — i.e. an image format the in-tree vendored `pycriu` does not know how to decode. (For
contrast, `TCP_STREAM` magic `1363563782` IS in the table with a handler at `images.py:501` — so this
is not the TCP_REPAIR socket image type per se.)

---

## 1. Blast Radius

**pycriu usage is confined to exactly two functions, both in `internal/agent/server/server.go`.**
No pycriu usage exists anywhere else in `internal/`, `cmd/`, or `test/` (verified by grep across all
`*.go`). The vendored library lives at `pycriu/` and is invoked only as a `python3` subprocess.

| Site | Function | Line | Operation | Error handling |
|---|---|---|---|---|
| A | `patchCheckpointImages` | server.go:2645 | `images.load` + `images.dump` (mutating) on `mountpoints-*`, `netns-10`, `netdev-10`, `ifaddr-10` | returns error to caller |
| B | `buildMaskedPathExtMountArgs` | server.go:1663 | `images.load` (read-only scan) on `mountpoints-*` | returns error to caller |

**Both sites parse CRIU `.img` files through the same `pycriu.images.load` path that raised the
exception.** Therefore the same MagicException is reachable from `buildMaskedPathExtMountArgs` (Site B),
not just `patchCheckpointImages` (Site A) — any `.img` carrying an unknown magic will fail B's scan too.
Site B's failure is fail-loud by design (ADR-0124 D4/AC5: caller must NOT invoke CRIU restore), so a
MagicException there would correctly block restore rather than silently proceed.

**The more important blast-radius finding is within Site A itself: `patchCheckpointImages` is called
from two places with INCONSISTENT error handling.**

- **server.go:1987** (checkpoint/`ctr` path) — `return 0, fmt.Errorf("patch checkpoint images: %w", err)`. Hard-fails. Correct.
- **server.go:3724** (Restore / `joinNsRestore` path) — `log.Error(patchErr, "...patchCheckpointImages failed (non-fatal, proceeding)")`. **Swallows the error and continues into CRIU restore with un-patched (or partially-patched) images.**

This second call site is the same class of defect as C1: a real failure is logged and execution proceeds
as if it succeeded. The gate's "Restore aborted" outcome means CRIU itself then failed downstream on the
un-patched image — i.e. the silent-proceed at :3724 converted a clean, attributable patch failure into a
later, harder-to-diagnose CRIU restore abort. The roll-back was clean, but the diagnosis path was not.

**Conclusion (blast radius):** The pycriu decode failure is reachable from both pycriu sites. Beyond the
single line-121 failure, the audit surfaced a latent silent-proceed at `patchCheckpointImages`'s restore
call site (server.go:3724) that degrades error attribution for ANY patch failure, not only MagicException.

---

## 2. In-Flight Sprint Work That Should Pause

Sprint 32 is in the **pre-sprint ADR phase** (no workstream has launched per the kickoff checklist).
`gate33` is a Sprint 33-numbered gate run exercising the carried-forward Strict-TCP path; it is blocked.

**Recommended holds:**

- **WS-REPAIR (ADR-0150) — HOLD pending pycriu fix.** WS-REPAIR exports TCP_REPAIR socket state into the
  CRIU checkpoint, which **expands the set of `.img` files that `patchCheckpointImages` and
  `buildMaskedPathExtMountArgs` will load and decode.** Any new image type WS-REPAIR introduces (or any
  CRIU 4.2 image the vendored pycriu doesn't recognize) re-triggers exactly this MagicException. WS-REPAIR
  must not gate (GC-27/GC-28) until the pycriu decode path has a defined behavior for unknown magics.
- **WS-INTEGRATE — already gated behind all four prereqs; no separate action**, but it inherits the
  pycriu surface and must not run until A is resolved.
- **WS-XDP, WS-ZWIN, WS-ARP — may proceed.** They do not touch the checkpoint-image decode path. (WS-ZWIN
  is, however, entangled with C1 — see §3.)

No Sprint 32 ADR needs to pause; this defect can be resolved in parallel with the ADR quorum phase.

---

## 3. C1 + pycriu Together — Is `patchCheckpointImages` / the checkpoint-image surface high-risk?

**Yes. The two defects share a single failure signature and that signature now appears three times in the
codebase, which is the pattern.**

| Instance | Location | Pattern |
|---|---|---|
| C1 | `armZeroWindowBPF` (zerowindow_linux.go:135) | arm fails → `log.Error … return nil`; `ZeroWindowArmed=True` set despite no hold |
| pycriu restore site | `patchCheckpointImages` caller (server.go:3724) | patch fails → `log.Error … "non-fatal, proceeding"`; restore proceeds on un-patched images |
| (C3, related) | zero-window resolver on non-veth CNI | returns `0` silently; Strict still reports success |

The common pattern is **"log-and-proceed on a hard failure of a state-mutating step, with the success
signal (CR status / continued execution) left unchanged."** This is the same false-green class §14b exists
to catch. It is not specific to `patchCheckpointImages` as a *function* — the function itself returns its
error honestly; the risk is in the **call sites that discard it** plus the silent-fallthrough idiom that
pervades the agent's privileged-operation paths.

So: `patchCheckpointImages` is a high-risk *surface* not because its internals are fragile, but because
(a) it sits on the critical restore path, (b) it decodes externally-produced binary image formats with a
hard-raise on the unknown case, and (c) at least one of its callers swallows that raise. The combination
with C1 indicates a **codebase-wide audit of `log.Error(...) ; <continue/return nil>` on privileged
mutating operations is warranted** — recommend this as a quorum-scoped task, not just a point fix.

---

## 4. ADR Implications (pycriu defect)

**Two parts, two answers.**

- **The decode failure itself is a pure bug-fix within existing ADR scope.** pycriu invocation is governed
  by ADR-0121 (python3 subprocess + PYTHONPATH); the patch operations by ADR-0124/0125/0131/0132/0162.
  Decoding an image and not crashing on an unknown magic is implementing those ADRs correctly, not changing
  them. Adding the missing magic to the table, or upgrading the vendored pycriu to match the runtime CRIU
  4.2 image version, is a bug fix.

- **Changing the *error-handling contract* at the restore call site (server.go:3724) DOES touch a
  behavioral contract and requires an ADR (or amendment).** Today that site declares the patch step
  "non-fatal, proceeding." Deciding instead that a patch failure must **abort restore and roll back**
  (rather than proceed on un-patched images) is a change to the restore-path degradation contract — the
  same category as C1's ADR-0049 degradation-contract change. This should be settled by ADR/amendment and
  ratified, not chosen ad hoc by a dev agent. **Recommendation: fold this into the same degradation-contract
  decision as C1** (a single "privileged mutating steps fail closed under Strict" contract) rather than
  spawning a separate ADR.

The choice of *how* to handle the unknown magic (extend table vs. upgrade pycriu vs. version-assert the
inventory image) is an implementation decision → **quorum, not §18.**

---

## 5. §18 Decisions Requiring Human (Chad) Authorization

Only the following require Chad's explicit authorization per §18. Everything else (which fix, test design,
pycriu upgrade vs. table extension) goes through quorum.

1. **Degradation-contract change — restore-path patch failure (server.go:3724) fails closed.**
   Changing `patchCheckpointImages`'s restore call site from "log and proceed on un-patched images" to
   "abort restore + roll back on patch failure" is a contract change. **Recommend ratifying this jointly
   with C1's ADR-0049 degradation-contract change as one decision** ("privileged mutating steps fail closed,
   no silent false-green"). C1 already requires Chad's ratification per the mini-quorum; this extends the
   same ratification to the pycriu restore path. — **AUTHORIZE.**

2. **Sprint scope change — HOLD WS-REPAIR (ADR-0150) until the pycriu decode path is resolved.**
   This re-sequences a Sprint 32 prerequisite workstream and is a sprint-scope decision. — **AUTHORIZE.**

3. **Gate-credit hold — `gate33`/GC-30/GC-31 remain BLOCKED until BOTH C1 and the pycriu defect are
   honestly closed.** Two defects (C1 + pycriu) must clear before any gate re-run; confirming the
   re-ordering of the gate-credit sequence (no Strict-TCP gate credit until both resolved) is a §18 call.
   — **AUTHORIZE.**

No Nav Point re-ordering is implicated. No new contract beyond items 1–3.

---

## Recommended Next Steps (non-§18, for quorum)

- Open a §14b mini-quorum on the pycriu MagicException covering: (a) unknown-magic handling strategy,
  (b) the server.go:3724 silent-proceed, (c) a regression test that feeds an unknown-magic `.img` through
  both `patchCheckpointImages` and `buildMaskedPathExtMountArgs`.
- Add the codebase-wide `log.Error(...);proceed`/`return nil` false-green audit (C1 + pycriu shared pattern)
  to the quorum scope.
- Run T-CLEAN before any re-gate; result is discarded if run on dirty state (§8).
