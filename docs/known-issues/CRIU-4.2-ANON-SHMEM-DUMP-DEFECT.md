# Known issue: CRIU 4.2 anon-shmem dump defect (`ShmemPagemapMissing`)

**Status:** Confirmed, CRIU-internal, upstream. Not a PodMotion transfer/network/storage bug.

## Symptom

Destination-side CRIU restore dies partway through (typically 35-57 tasks restored) with:

```
No pagemap-shmem-<shmid>.img image
Error (criu/shmem.c:534): Can't restore shmem content
```

As of ADR-0246, this is now caught **before transfer** by an automated
post-checkpoint completeness guard: PodMotion's `Checkpoint` RPC fails closed with a
`CheckpointFailed`/`ShmemPagemapMissing` condition reason on the `PodMigration` CR, rather than
letting a non-restorable checkpoint reach the destination node. `kubectl describe podmigration
<name>` will show this reason directly.

## Root cause

CRIU 4.2 (`gitid 0`) never writes `pagemap-shmem-<shmid>.img` for at least some anonymous
shared-memory segments (`mmap(MAP_SHARED|MAP_ANONYMOUS)` / `shm_open`) at dump time, even though
the segment is correctly recorded as a referenced vma in `mm-<pid>.img`. This is a reference
without corresponding data — a CRIU-internal dump-time serialization defect, not a PodMotion
transfer defect. The completeness guard and the on-disk decode that settled this are described in
`docs/adr/0246-checkpoint-completeness-verification-shmem-pagemap-guard.md`.

Confirmed **not** the cause:
- Transfer integrity (source `GetCheckpointTar` and destination `PutCheckpointTar` match byte-for-byte).
- The force-freeze fallback path (`internal/agent/replication/replication.go`) — the final
  checkpoint (`ctrCheckpoint`) is a standalone full dump with no `--prev-images-dir` linkage to
  any crashed pre-dump round, so it cannot mechanically inherit incompleteness from one.

## Impact / known-unsupported workload class

Workloads using anonymous shared memory (certain database or IPC-heavy workloads using
`shm_open`/`mmap(MAP_SHARED|MAP_ANONYMOUS)`) are, until the underlying CRIU defect is fixed or
worked around, a known-unsupported migration class. The `ShmemPagemapMissing` guard converts what
would otherwise be a silent corrupt restore into an explicit, immediate, pre-transfer failure —
it does not make such workloads migratable.

## What PodMotion does about it today (ADR-0246)

A post-checkpoint, pre-transfer completeness guard decodes every `mm-*.img` produced by the
final checkpoint dump (both the `ctr tasks checkpoint` path and the raw-CRIU fallback path),
enumerates every anon-shmem `shmid` referenced by a vma entry, and confirms a corresponding
non-empty `pagemap-shmem-<shmid>.img` exists in the same checkpoint image directory. If any is
missing, the `Checkpoint` RPC fails closed before `GetCheckpointTar` ever packages the image set
for transfer. This is a pure detector — it does not retry the dump, does not attempt a second
CRIU invocation, and does not silently degrade to a different transfer mode. The source pod is
never deleted on this path (`TrafficVerified` is never reached), consistent with the project's
standing invariant that a source pod is never removed until traffic verification succeeds.

## Follow-up (tracked, not yet actioned)

Testing whether a CRIU release newer than 4.2 resolves anon-shmem pagemap serialization is a
tracked follow-up item. Bumping the pinned CRIU version is explicitly **out of scope** for this
fix — it requires its own compatibility/regression pass across every other CRIU-dependent
path and would need to be proposed and validated as its own change.

## Provenance

- `criu` binary: `4.2 (gitid 0)`,
  sha256 `91c8cef402cacbef0bf412dd165e52882d56a7f6d2520aa4f5a27714731b219d` (identical on source and
  destination nodes across both reproductions).
- Two independent reproductions with two different shmids: `22685` and `11423`.
