<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 The PodMotion Authors
-->

# Runbook — un-wedging a pod fail-closed-rejected by the ADR-0412 terminal-not-own gate

## Symptom

A pod is stuck in `CrashLoopBackOff` and the destination-node agent journal shows repeated
lines of the form:

```
NRI StartContainer: fail-closed reject — checkpoint-ref points at a terminal/aborting migration this pod does not own
  reason=own-mismatch migrationRef=<ref> phase=Complete replacementPodName=<name-A> thisPod=<name-B> runbook=docs/runbooks/adr-0412-terminal-not-own-recovery.md
```

(or `reason=Failed` / `reason=RollingBack` / `reason=DryRunComplete`).

This is the **intended fail-closed posture** (ADR-0412 D2): a pod carrying a
`podmotion.io/checkpoint-ref` that points at a **terminal** PodMigration it cannot prove it owns
is refused a CRIU restore, because cold-starting it could bring up a second live instance
alongside a still-running source (split-brain). The gate is working as designed.

## When this happens by legitimate accident

The one non-malicious way a pod's OWN replacement lands here is a **stale
`Status.ReplacementPodName`** — e.g. an ADR-0360 self-heal ("ghost mirror") cycle was interrupted,
so the migration reached `Complete` while `Status.ReplacementPodName` still names a *prior*
replacement pod, not the one now starting. The name binding then mismatches and the pod is
fail-closed-blocked even though it is genuinely the migration's own destination.

The safety property (never re-restore stale memory) does **not** depend on the name — only the
liveness of this cold-start edge does, and it fails safe. So recovery is always safe to perform.

## Diagnose

Confirm the migration is terminal and inspect the recorded replacement pod name:

```sh
export KUBECONFIG=/path/to/kubeconfig
NS=<namespace>
REF=<migrationRef from the log line>
POD=<thisPod from the log line>

kubectl -n "$NS" get podmigration "$REF" \
  -o jsonpath='{.status.phase}{"  replacementPodName="}{.status.replacementPodName}{"\n"}'
kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.annotations.podmotion\.io/checkpoint-ref}{"\n"}'
```

If `status.phase` is `Complete` and `status.replacementPodName` does not equal `$POD`, and `$POD`
really is the intended destination replacement, this is the stale-name accident.

## Recover

The migration is already **over** (terminal). The pod does not need a restore at all — it needs to
cold-start normally. Remove the now-obsolete restore annotation so the NRI gate short-circuits at
the "no checkpoint-ref" path and the pod starts clean:

```sh
# 1. Drop the stale checkpoint-ref (and restore-target list) from the wedged pod so the NRI
#    StartContainer hook returns nil at the "not a restore target" path — clean cold-start.
kubectl -n "$NS" annotate pod "$POD" \
  podmotion.io/checkpoint-ref- \
  podmotion.io/restore-target-containers-

# 2. If the pod is managed by a controller (Deployment/StatefulSet/ADR-0360 self-heal) that would
#    re-stamp the annotation, delete the wedged pod so it is recreated cleanly instead:
kubectl -n "$NS" delete pod "$POD"
```

### Alternative: repair the migration status (only if the replacement must keep the ref)

If you instead need the pod to remain a valid restore target (rare — the migration is already
Complete, so normally you do not), fix the stale name on the CR so the "own" discriminator matches:

```sh
kubectl -n "$NS" patch podmigration "$REF" --subresource=status --type=merge \
  -p "{\"status\":{\"replacementPodName\":\"$POD\"}}"
```

After this, the next StartContainer for `$POD` classifies as **terminal-own** and the pod
cold-starts normally (no re-restore). Prefer removing the annotation (steps 1–2) unless you have a
specific reason to keep it.

## Verify

```sh
kubectl -n "$NS" get pod "$POD" -w    # restart count stops incrementing; pod reaches Running
```

Confirm the destination-node agent journal shows no further `fail-closed reject` lines for `$POD`,
and (for the annotation-removal path) an `ADR-0197 Rule D: container is not a restore target —
clean pass-through` line or no checkpoint-ref match at all.

## Do NOT

- Do **not** widen the NRI accept-set or disable the gate to "fix" this — that re-opens the
  anti-spoof hole ADR-0412 D2 exists to close (a forged ref pointing at any unrelated terminal
  migration would then pass).
- Do **not** force a restore of a `Failed` / `RollingBack` / `DryRunComplete` migration. Those were
  aborted or never restored; cold-starting them against the checkpoint risks split-brain with the
  thawed source. The correct recovery there is to re-drive a fresh migration, not to un-wedge the
  reject.
