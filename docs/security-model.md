# PodMotion Security Model

Version: v0.1 (M11)  
Status: Living document

## Threat Model Summary

PodMotion migrates live pods between nodes. The security boundary is the Kubernetes cluster;
multi-cluster migration is not supported until M14+ (ADR-0022). Threats addressed in v0.1:

| Threat | Control | Status |
|--------|---------|--------|
| Checkpoint image read by attacker on node storage | ECDH encryption (opt-in) | v0.1 opt-in, default in v0.2 |
| Checkpoint image intercepted in transit | mTLS between agents | v0.1 |
| Rogue agent impersonates operator | Node-scoped SAT + mTLS | v0.1 |
| Migration triggered by unauthorized user | RBAC + ValidatingWebhook | v0.1 |
| Seccomp profile left Unconfined after crash | defer RestoreSeccomp invariant | v0.1 |
| Source pod deleted before traffic verified | TrafficVerified gate (ADR-0012) | v0.1 |

## Checkpoint Image Confidentiality

CRIU checkpoint images contain full process memory: heap, stack, file descriptors, and
open TCP socket state. This includes secrets, private keys, and session tokens that were
in memory at checkpoint time.

### Encryption (opt-in, ADR-0029)

When `MigrationPolicy.spec.encryption.enabled: true` or annotation
`podmotion.io/encrypt-checkpoint: "true"` is set:

1. The operator generates an ECDH P-256 ephemeral key pair per migration (`GenerateEphemeralKey`).
2. The source agent encrypts the checkpoint layer using the destination agent's public key
   (`EncryptCheckpointLayer`).
3. The destination agent decrypts using its private key (`DecryptCheckpointLayer`).
4. The symmetric key is derived via ECDH + SHA-256 (HKDF-lite). A compromised key for
   migration N cannot decrypt migration N+1 (forward secrecy per migration).

When encryption is disabled (default v0.1), a WARNING is logged at checkpoint time.
Full cosign/imgcrypt OCI layer wrapping is added in M13.

### Storage at Rest

Checkpoint images are written to node-local ephemeral storage under
`/var/lib/podmotion/checkpoints/<migrationID>/`. This directory is owned by root:root
with mode 0700. On completion or failure, the directory is deleted by the MigrationCheckpoint
GC controller (M3).

## Seccomp Window

CRIU requires `Unconfined` seccomp during the memory dump because ptrace-based dirty page
tracking triggers syscalls that most seccomp profiles block (e.g., `process_vm_readv`).

### Invariant

The `SeccompManager` enforces a narrow window:

```
SwapToUnconfined(containerID)   // immediately before CRIU dump
defer RestoreSeccomp(containerID) // deferred — runs even on panic/error
```

The `defer` is placed in the Checkpointing phase handler. If the agent crashes mid-checkpoint,
the saved profile is persisted to `/var/run/podmotion/<containerID>.seccomp.saved` and
RestoreSeccomp reads it on recovery. The window is bounded by the freeze window (<100ms, ADR-0011).

### Why not a custom seccomp profile?

A minimal seccomp profile that allows only the syscalls CRIU needs would be ideal but requires
runtime-specific profiling per workload. Unconfined for <100ms with atomic save/restore is
a pragmatic v0.1 approach. A narrowed profile is planned for v0.2.

## Agent Authentication

### mTLS

All gRPC communication between the operator and node agents uses mutual TLS (mTLS).
Certificates are provisioned by cert-manager and mounted as Kubernetes secrets. The operator
and agents present client certificates; each verifies the other against the PodMotion CA.

TLS 1.3 minimum. See `internal/agent/tls/tls.go`.

### Node-Scoped ServiceAccountTokens (SAT)

In addition to mTLS, the operator issues a projected ServiceAccountToken per migration:

- **Audience:** `podmotion-agent/<destNodeName>` — scoped to the destination node.
  A token issued for node-A cannot be replayed against node-B.
- **Expiry:** 600 seconds (matches the migration completion timeout).
- **Bound object:** source pod — the token is revoked if the source pod is deleted.

The destination agent presents the SAT to the Kubernetes API server via TokenReview before
accepting checkpoint data. This provides a Kubernetes-native audit trail of which migrations
were authorized.

## RBAC Boundaries

### Operator

- Can call `serviceaccounts/token` (TokenRequest API) to issue migration SATs.
- Can read `NodeMigrationCapacity` CRs cluster-wide (for scheduling decisions).
- Cannot read arbitrary secrets. Cannot impersonate other service accounts.

### Node Agent

- Can read only two named secrets in `podmotion-system`: `podmotion-agent-tls` and
  `podmotion-operator-tls` (cert-manager provisioned).
- Cannot read secrets in any other namespace (Role, not ClusterRole).
- Cannot create or delete pods directly; drives migration via the operator.

See `config/rbac/security-role.yaml`.

## Intra-Cluster Scope

v0.1/v0.x migrations are intra-cluster only (ADR-0022). The attack surface is bounded by
the cluster network. Multi-cluster migration (M14+) will require additional controls:
service mesh mTLS across clusters and cross-cluster RBAC federation.
