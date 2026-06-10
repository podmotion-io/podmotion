# Proposal: `kubectl migrate` — Native Live Pod Migration for Kubernetes

- **Author**: PodMotion Authors
- **Date**: 2026-06-09
- **Status**: Draft
- **Related KEPs**: KEP-2008 (ContainerCheckpoint), KEP-XXXX (Kubelet Restore API)
- **WG**: WG Checkpoint/Restore

---

## Problem Statement

There is no standard Kubernetes mechanism to live-migrate a running pod from one node to another
while preserving its in-memory state.  Current workarounds are:

| Approach | Limitations |
|---|---|
| `kubectl drain` | Evicts pod; no state preservation; causes downtime |
| StatefulSet rolling update | Replaces pod with new replica; cold start |
| Custom operators (PodMotion, etc.) | Not built into kubectl; requires CRD installation |
| Manual CRIU + crictl | Not Kubernetes-aware; bypasses scheduler, RBAC, and networking |

The absence of a first-class migration primitive means platform teams either accept unnecessary
downtime or maintain bespoke tooling.  This proposal describes a path from a `kubectl` plugin
to a potential built-in `kubectl migrate` command.

---

## Proposal

### Command Interface

```
kubectl migrate <pod> [flags]

Flags:
  --to-node string        Target node name (optional; omit to let scheduler choose)
  --dry-run               Estimate migration cost and downtime without executing
  --timeout duration      Maximum time before migration is aborted (default: 5m)
  --strategy string       Migration strategy: live|checkpoint-restore (default: live)
  --namespace string      Target namespace (default: current context namespace)
  --wait                  Wait for migration to complete and stream status
  -o, --output string     Output format for --dry-run: table|json|yaml
```

**Examples**:

```bash
# Dry-run: estimate downtime and storage cost
kubectl migrate my-pod --dry-run

# Live-migrate to a specific node
kubectl migrate my-pod --to-node worker-3

# Migrate and wait for completion
kubectl migrate my-pod --to-node worker-3 --wait

# Migrate with a custom timeout
kubectl migrate my-pod --timeout 10m
```

**Expected output (--wait)**:

```
Migrating pod default/my-pod → worker-3
  Phase: Checkpointing   [████████░░] 80%  checkpoint size: 234 MiB
  Phase: Transferring    [████████░░] 80%  transfer rate: 450 MiB/s
  Phase: Restoring       [██████████] 100%
  Phase: Verifying       [██████████] 100%
Migration complete. Elapsed: 4.2s. Estimated downtime: 87ms.
```

---

## Implementation Strategy

### Phase 1 — kubectl Plugin (current, operator-provided)

The `kubectl-migrate` plugin (repo: `kubectl-podmotion`) translates user commands into
`PodMigration` CR operations:

```
kubectl migrate my-pod --to-node worker-3
  │
  ├─ validates: pod exists, PodMotion CRDs installed
  ├─ creates: PodMigration{spec.sourcePodName: my-pod, spec.targetNodeName: worker-3}
  └─ streams: PodMigration.status.conditions via watch
```

This approach works today without any upstream changes and gives the community time to validate
the UX before proposing a built-in command.

### Phase 2 — SIG-CLI Proposal

Once the plugin has been used in production and the UX is validated, we will open a KEP with
sig-cli to add `kubectl migrate` as a first-class subcommand.  The implementation would:

1. Detect whether an upstream migration API (Phase 3) is available; fall back to the CRD-based
   path if not.
2. Reuse the `--dry-run=client|server` flag semantics already established in kubectl.
3. Ship as an `alpha` command gated by `KUBECTL_MIGRATE=1` environment variable initially.

### Phase 3 — Upstream Work Object

A built-in `kubectl migrate` requires an upstream API object that does not depend on a third-party
operator.  Two options are being evaluated:

**Option A — `PodMigration` resource in core or a new API group**

```yaml
apiVersion: migration.k8s.io/v1alpha1
kind: PodMigration
metadata:
  name: migrate-my-pod
spec:
  sourcePod:
    name: my-pod
    namespace: default
  targetNode: worker-3
  strategy: live
```

The kubelet on the target node would handle restore (using the Kubelet Restore API from
KEP-XXXX), while a new migration controller in kube-controller-manager orchestrates the phases.

**Option B — Extend the existing Eviction API**

Add a `restoreFrom` field to the `Eviction` object and a `targetNode` field to direct the
scheduler.  This reuses existing RBAC (evictions already require `pods/evict`) but conflates
eviction semantics with migration semantics.

**Recommendation**: Option A.  Migration is a distinct lifecycle operation from eviction; mixing
them would create confusing semantics for PDBs, autoscalers, and audit logs.

---

## API Required

Regardless of phase, the following Kubernetes API capabilities are required:

| Capability | Status |
|---|---|
| `POST /checkpoint/.../container` (KEP-2008) | Beta (1.26) |
| `POST /checkpoint/.../container/restore` (KEP-XXXX) | Proposed |
| `PodMigration` work object | Proposed (this document) |
| CRI `RestoreContainer` RPC | Proposed (KEP-XXXX Phase 2) |

---

## Security and RBAC

```yaml
rules:
  - apiGroups: ["migration.k8s.io"]
    resources: ["podmigrations"]
    verbs: ["create", "get", "watch"]
  - apiGroups: [""]
    resources: ["nodes/checkpoint"]
    verbs: ["create"]
```

Migration is a privileged operation — it can move workloads across security boundaries.  The
upstream `PodMigration` API should be subject to the same admission controls as pod creation
on the target node (e.g., PodSecurity admission, OPA policies).

---

## Interaction with Existing Kubernetes Primitives

| Primitive | Interaction |
|---|---|
| PodDisruptionBudget | Migration creates a second pod before removing the source (ADR-0015). PDB `minAvailable` is therefore satisfied throughout the migration window. |
| HorizontalPodAutoscaler | Source pod counted until deleted; target pod counted after readiness probe passes. Net count unchanged. |
| ResourceQuota | Briefly over-quota during migration window. Admission controller must allow temporary burst; migration controller acquires a quota reservation. |
| LimitRange | Applied to the target pod spec at admission time. |
| TopologySpreadConstraints | Scheduler plugin accounts for in-flight migration pods. |

---

## References

- [KEP-2008: Container Checkpointing](https://github.com/kubernetes/enhancements/issues/2008)
- [KEP-XXXX: Kubelet Restore API](./kep/kep-XXXX-kubelet-restore-api.md)
- [WG Checkpoint/Restore](https://github.com/kubernetes/community/blob/master/wg-checkpointrestore/README.md)
- [PodMotion kubectl plugin](https://github.com/podmotion-io/kubectl-podmotion)
- [PodMotion ADR-0012: Source pod deletion policy](./adr/ADR-0012-source-pod-deletion.md)
- [PodMotion ADR-0015: PDB overlap-then-delete](./adr/ADR-0015-pdb-overlap-then-delete.md)
- [PodMotion ADR-0022: Intra-cluster scope](./adr/ADR-0022-intra-cluster-scope.md)
