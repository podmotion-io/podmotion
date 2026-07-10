# Sprint 43 — Handoff State (2026-07-10)

**Status: PAUSED, not closed.** Live pod migration on the KVM cluster still fails end-to-end
for both test workloads. All work is committed on branch `sprint43`. This doc is the cold-start
resume point for the remaining datapath work.

## What works
- Deploy path is clean: `TAG=... bash hack/kvm-cluster.sh deploy-podmotion` builds+stamps
  images (`org.opencontainers.image.revision=<git short SHA>`), imports to each node, helm-upgrades.
  Restart BOTH `deploy/podmotion-operator` and `ds/podmotion-agent` after deploy (mTLS CA re-mint).
- Migration runs correctly through **Validating → Checkpointing (real CRIU dump, ~800ms freeze) →
  Transferring → Restoring**. The source pod always survives on rollback (ADR-0012 held).
- e2e live-migration tests exist and run: `make test-e2e E2E_LABEL_FILTER='live-db || live-redis'`
  (postgres = `test/e2e/db_migration_test.go`, redis = `test/e2e/redis_migration_test.go`);
  fixtures validated live (both load-gens run with 0 errors, pods reach Ready).

## The two remaining bugs (both at Restoring; diagnosed live at HEAD f940ba4)

### 1. Redis: `replVethMAC empty after restore` (ADR-0308 missed the executed path)
- Live path taken: **NRI PostStartContainer barrier fails first** —
  `holder-quiescent barrier FAILED — blocking restore: context canceled` (60s NRI-confirm timeout)
  → operator falls back to the **agent Restore RPC (raw-CRIU) path**.
- On that fallback `req.DestNetnsFd == ""` (see comment `server.go:6068` "cold migration passes
  empty string"), so `s.ResolvedNetnsPath(migrationName)` is empty (ADR-0308 stores the bind only
  on the `destNetnsFd != ""` branch, `server.go:3044`). `finalizeRestore` then falls through to
  `ReadReplVethMAC` via `nsenter --net=/proc/<pid>/ns/net` → `Permission denied` (AppArmor
  `podmotion-agent` profile does not grant ptrace-read against the restored workload's profile).
- **Fix direction:** populate `ResolvedNetnsPath` for the raw-CRIU/empty-`destNetnsFd` path from the
  agent-created bind `/run/podmotion/netns/pm-mig-<uid>/bind` (created in `PrepareDestinationNetns`),
  so `ReadReplVethMAC` uses the bind-mount branch (no ptrace). AND/OR fix the NRI holder-quiescent
  barrier so the primary NRI path completes and the fallback is never taken. Capture the exact
  AppArmor `peer=` token from a LIVE `dmesg` denial (repo evidence suggests `cri-containerd.apparmor.d`,
  not `runc`) before adding any belt-and-suspenders profile rule.

### 2. Postgres: `/dev/shm` P-0193-1 hard-stop (ADR-0311 rebind didn't match the fd)
- Verbatim: `restore aborted (strict): patchCheckpointImages: files.img REG fd id=3
  name_leaf=PostgreSQL.<n> backing_mnt_id=943: positive orphan mnt_id not in kept mountpoints
  — hard-stopped before criu restore (P-0193-1)`. Fails BEFORE criu restore starts.
- ADR-0311 added a tmpfs/`/dev/shm` REG-fd rebind in `classify_reg_fd`
  (`internal/agent/server/server.go`), but it did NOT catch this live `PostgreSQL.*` shmem fd.
  Corpus test `pycriu_corpus_test.go` passed, so the mismatch is between the test corpus and the
  real checkpoint image's fd/mount representation.
- **Fix direction:** verify the fstype / backing-mnt-id detection against a REAL postgres checkpoint
  image (not just the corpus). Make the rebind actually match the `/dev/shm` `PostgreSQL.*` fd
  (`backing_mnt_id=943` orphan) and route it through the guarded rebind-to-root path. Do NOT weaken
  the Strict P-0193-1 guard.

## Commits on `sprint43` this session (not merged to main)
- `f940ba4` shmem tmpfs REG-fd rebind (ADR-0311) — does not yet work live
- `306716d` mark ADR-0308 Accepted
- `b54504f` restore netns bind-path MAC resolution (ADR-0308) — does not yet work live on fallback path
- `5c6a78a` IP-reclaim test (ADR-0294/0302/0305/0307) — done
- `2e597a3` e2e fixtures fixed (node pins, load-gen flags, image, port, races)
- `2461329` e2e close-gate + stale-suite repair + image build-stamp provenance
- `abac6c7` restore-confirm netns gate + Strict gated-resume (ADR-0306) — cleared as unrelated to the frontier

## Fastest validation loop
For the two remaining bugs, validate DIRECTLY: `TAG=... bash hack/kvm-cluster.sh deploy-podmotion`
from committed HEAD, restart operator + agent, then create one redis and one postgres PodMigration
(targetNodeName=pm-w2, tcpPreservationMode=Strict) and watch to Complete/Failed. This is far faster
than a full test run and gives the same ground truth. (Orchestration/process notes for this sprint
live in the local-only resume-state spine, not here.)
