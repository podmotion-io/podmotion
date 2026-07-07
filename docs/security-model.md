# PodMotion Security Model

Version: v0.1.0-alpha
Status: Living document

This document describes the security posture PodMotion **actually implements today**, including
its known residual gaps. It is intended to be read alongside [SECURITY.md](../SECURITY.md) (how to
report a vulnerability, supported versions, scope). Where a control is not yet implemented or is
off by default, this document says so in plain language rather than describing an intended future
state as if it already shipped.

## Threat Model Summary

PodMotion migrates live pods between nodes. The security boundary is a single Kubernetes cluster;
multi-cluster migration is not supported (ADR-0022). The operator is the trusted control authority;
the per-node agent is a privileged component that dumps and restores full process memory.

| Threat | Control | Status today |
|--------|---------|--------------|
| Checkpoint image intercepted in transit | Fail-closed mTLS on the agent gRPC server | Implemented, on by default |
| Unauthorized gRPC caller invokes checkpoint/restore | Deny-by-default per-RPC authorization keyed to the verified mTLS (SPIFFE) identity | Implemented, on by default |
| Tampered / spoofed checkpoint accepted on ingest | Signed provenance + wire-hash + per-file digest verified before extraction | Implemented, on by default |
| Checkpoint image read by an attacker with node access | tmpfs (mode 0700) + zeroize-on-exit; optional per-migration at-rest encryption | Partial — encryption is **off by default** (see below) |
| Migration triggered by an unauthorized user | Namespace RBAC on `PodMigration` + validating webhook | Partial — no per-subject/per-node authorization (see Residual Trust Boundary) |
| Seccomp left `Unconfined` after a crash | Deferred restore invariant + persisted saved profile | Implemented |
| Source pod deleted before traffic verified | `TrafficVerified` gate (ADR-0012) | Implemented |

## Agent Transport Authentication (mTLS) — fail-closed by default

All gRPC communication to and from the node agent uses mutual TLS. In the default (production)
build the agent **refuses to start if TLS material is absent** — it does not fall back to
plaintext. A nil TLS configuration reaching the listener is a fatal refusal, not a warning
(`internal/agent/tls/tls_insecure.go`, `internal/agent/server/serve_secure.go`, ADR-SEC-A). The
operator client likewise refuses to dial an agent without client-certificate material.

A plaintext/insecure path exists **only** in a special developer build (`//go:build dev`) and
**only** when `PODMOTION_INSECURE_GRPC=true` is explicitly set (`internal/agent/tls/tls_insecure_dev.go`).
It cannot be reached in a normal build. TLS 1.3 is the minimum version. Certificate material is
supplied as a Kubernetes secret mounted read-only into the agent (`agent.tls.enabled` in the Helm
chart).

### Identity and per-RPC authorization

Caller identity is the verified mTLS leaf certificate's SPIFFE ID (its single URI SAN), not a
bearer token (`internal/agent/authz/`). A deny-by-default interceptor runs first in the agent's
gRPC chain: it classifies the SPIFFE ID into a role (operator or peer agent), applies a static
per-method allowed-role policy, and binds the caller to the specific migration named in the
request. **A method absent from the policy map is denied.** A certificate whose SPIFFE ID matches
no known role is denied. Peer agents are restricted to checkpoint-transfer RPCs and are bound to
migrations their node is actually party to.

The trusted edge is therefore operator → agent (and agent → peer-agent for transfer), authenticated
by mTLS and authorized per-RPC. This is the correct place for a reviewer to focus: anything that can
present a valid operator SPIFFE identity can drive checkpoint/restore.

## Checkpoint Image Confidentiality

CRIU checkpoint images contain full process memory: heap, stack, file descriptors, and open TCP
socket state. This includes any secrets, private keys, and session tokens resident in memory at
checkpoint time.

### Storage at rest

Checkpoint images are written to a **tmpfs** mount at `/run/podmotion/checkpoints/<migration>/`,
mode 0700, size-capped (`mount -t tmpfs -o mode=0700,size=4096m` in the agent DaemonSet). They are
**zeroized on every exit path** (success or failure) and never touch a persistent host filesystem
by default. gRPC-level size caps (`MaxCheckpointTarBytes` / `MaxDecompressedTarBytes`) bound both
the on-wire and decompressed sizes and guard against decompression bombs.

> Earlier revisions of this document described checkpoints as written to
> `/var/lib/podmotion/checkpoints/`. That is incorrect for the current code — the checkpoint image
> path is the zeroized tmpfs above. (`/var/lib/podmotion` is a host directory used for the restore
> pidfile and the criu-wrapper binary, not for checkpoint image contents.)

### At-rest encryption is OFF by default

At-rest encryption exists but is **opt-in and off by default.** When no per-migration key secret is
provisioned, checkpoints stay plaintext on tmpfs, protected only by the 0700 mode, zeroization,
mTLS-in-transit, and signed-provenance integrity above. To enable it, provision a per-migration
Kubernetes secret; the source agent then encrypts each checkpoint layer in place with ECDH P-256 +
AES-256-GCM, binds the ciphertext to `migrationUID:layerIndex:epoch` as AAD, and zeroizes the
plaintext (`internal/agent/server/checkpoint_encryption.go`, `internal/agent/encryption/`,
ADR-0029). A present-but-malformed key secret fails closed. The decided long-term target is
default-on with an auditable opt-out; that has not shipped.

### Provenance verified on ingest

The destination agent verifies a checkpoint **before** it extracts it (`PutCheckpointTar`,
`internal/agent/server/server.go`, ADR-SEC-B): it rejects a checkpoint whose wire hash is absent,
verifies `sha256(tar_bytes)` before any decompression begins, verifies a signed manifest against an
operator public key pinned via the trusted CA + SPIFFE SAN, binds the `migration_uid` to the live
CR (anti-replay), and re-checks each extracted file against a per-file digest and exact-set
membership before the staging directory is promoted. There is no bypass when a manifest or
signature is absent — it is fail-closed.

## Seccomp Window

CRIU requires `Unconfined` seccomp during the memory dump, because ptrace-based dirty-page tracking
uses syscalls that most profiles block (e.g. `process_vm_readv`). The agent swaps to `Unconfined`
immediately before the dump and restores the saved profile in a `defer` that runs even on
panic/error. If the agent crashes mid-checkpoint, the saved profile is persisted and restored on
recovery. The window is bounded by the freeze window. A narrowed, CRIU-scoped seccomp profile for
the agent itself is available (`agent.seccompProfile`, ADR-0039) and is only meaningful because the
agent no longer runs fully privileged (see below).

## Agent Privilege & Host-Mount Posture

The agent DaemonSet was reduced from a blanket `privileged: true` posture to a single justified
privileged long-lived container (ADR-0148). This section is the authoritative host-mount / privilege
justification table, lifted from the DaemonSet (`charts/podmotion/templates/daemonset.yaml`).

### Containers and their privilege

| Container | Privilege | Why |
|-----------|-----------|-----|
| `agent` (main, long-lived) | `privileged: false`, drop `ALL`, add a discrete capability set | Runs the gRPC server and CRIU/eBPF logic with least privilege |
| `netns-broker` (long-lived) | `privileged: true` | **Irreducible.** `setns(CLONE_NEWNS)` into the host init mount namespace to bind/teardown per-migration network namespaces requires `CAP_SYS_ADMIN` effective in the user namespace that *owns* that mount namespace (the host). It serves only a mode-0600 Unix socket and speaks no gRPC. |
| `init-checkpoint-tmpfs` (init) | `privileged: true` | Short-lived; mounts the checkpoint tmpfs in the host mount namespace (same `setns` reasoning). Exits before the agent serves any gRPC. |
| `netns-mount-prep` (init) | `privileged: false`, add `SYS_ADMIN` | Bind + make-shared mounts on `/run/podmotion` only |
| `install-criu-wrapper` (init) | `privileged: false`, add `DAC_OVERRIDE` | Copies the criu-wrapper binary to a PodMotion-owned host dir only |

### Main agent discrete capabilities

`drop: ["ALL"]`, then add only:

| Capability | Purpose |
|-----------|---------|
| `SYS_PTRACE` | CRIU dump (`PTRACE_SEIZE`, `process_vm_readv/writev`) |
| `SYS_ADMIN` | CRIU mount-ns / `setns` / `mount` / `umount2` / `userfaultfd` |
| `CHECKPOINT_RESTORE` | CRIU 4.x checkpoint/restore-privileged operations (Linux 5.9+) |
| `DAC_READ_SEARCH` | Read `/proc/<pid>/map_files` of processes the agent does not own |
| `SYS_RESOURCE` | Read another task's rlimits across a credential boundary (`prlimit64`) |
| `NET_ADMIN` | eBPF TC/XDP attach, veth/neigh/route/FDB, zero-window hold |
| `NET_RAW` | `AF_PACKET` socket for gratuitous ARP at IP handoff |
| `BPF`, `PERFMON` (kernel ≥ 5.8) | `bpf()` program load + map ops, `perf_event_open` |

### Host-level pod settings and mounts

| Setting / mount | Access | Note |
|-----------------|--------|------|
| `hostPID: true` | — | Agent shares the host PID namespace; combined with `process_vm_readv` this is effectively host-memory read reach. Required for CRIU dump/restore and for the restore pidfile PID to be meaningful. |
| `hostNetwork: true` | — | Agent shares the host network namespace |
| `/run/containerd/containerd.sock` | **read-write** | Root-equivalent on the node (arbitrary container start/exec; cross-tenant lateral movement is an accepted `v0.1` risk, ADR-0013). Not yet isolated to a restore-only path. |
| `/sys` | read-write | eBPF / kernel feature access |
| `/var/lib/podmotion` | read-write | Restore pidfile + criu-wrapper install target (not checkpoint image contents) |
| `/var/run/criu`, `/var/run/nri` | read-write | CRIU and NRI sockets |
| `/usr/sbin`, `/etc/cni/net.d`, `/var/run/netns` | read-only | CRIU binary, CNI config, host netns handles |
| tolerations | `operator: Exists` on `NoSchedule` + `NoExecute` | The agent tolerates every taint, so it lands on control-plane and all nodes. Node-pool isolation is not implemented. |

## Residual Trust Boundary (known gaps — not yet closed)

These are true today and are disclosed deliberately:

1. **One privileged long-lived container** (`netns-broker`) and a **read-write containerd socket**
   mounted into the steady-state agent. Compromise of the agent pod is root-equivalent on the node.
2. **`hostPID` + `hostNetwork`** on the agent pod.
3. **Catch-all tolerations** — no node-pool taint isolation (ADR-0148 addressed container privilege,
   not node isolation).
4. **Migration is a pod-memory-dump primitive with no per-subject / per-node authorization.** The
   only `UserInfo`-based control is a webhook that blocks `exec`/`attach`/`proxy` **into agent pods**
   (`internal/webhook/agent_exec_block.go`). There is **no** `SubjectAccessReview` equating
   "create a `PodMigration`" with `pods/exec`/memory-read, and **no** trusted-node gate on
   `targetNodeName`. Consequently, anyone who can `create podmigrations` in a namespace can
   force-checkpoint (i.e. dump the full process memory of) any pod in that namespace and can steer
   the restore to any node with a healthy `NodeMigrationCapacity`. This is acceptable only for an
   alpha and only because it is disclosed here; it would be a blocker for a production/incubating
   posture. Mitigate by restricting `PodMigration` create/update RBAC to trusted namespaces and
   subjects.
5. **At-rest checkpoint encryption is off by default** (see above).

## RBAC Boundaries

- **Operator:** may call the TokenRequest API to issue per-migration ServiceAccountTokens and read
  `NodeMigrationCapacity` cluster-wide for scheduling. It cannot read arbitrary secrets and cannot
  impersonate other service accounts.
- **Node agent:** reads only its named TLS secrets in `podmotion-system` (Role, not ClusterRole);
  cannot read secrets in other namespaces; does not create/delete pods directly (migration is driven
  through the operator).

See `config/rbac/`.

## Restore Correctness Limitation

CRIU 4.2 does not reliably serialize anonymous shared-memory (`shmem`) mappings at checkpoint time,
so **pods whose processes hold anonymous shared-memory mappings cannot currently be restored.** This
was identified during the restore-path redesign recorded in ADR-0245 and is an upstream CRIU defect,
not a PodMotion transfer/provenance issue. A failed restore rolls back to the source pod, which is
preserved intact (ADR-0012). See the "Known Limitations" section of the top-level
[README](../README.md) for the operator-facing statement.

## Intra-Cluster Scope

Migrations are intra-cluster only (ADR-0022). The attack surface is bounded by the cluster network.
Multi-cluster migration would require additional controls (cross-cluster mTLS and RBAC federation)
and is not supported.
