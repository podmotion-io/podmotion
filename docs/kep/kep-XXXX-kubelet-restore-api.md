# KEP-XXXX: Kubelet Restore API

- **Feature Group**: sig-node
- **Stage**: Alpha
- **Start Date**: 2026-06-09
- **Target Release**: Kubernetes 1.33
- **Status**: Provisional
- **Authors**: PodMotion Authors, WG Checkpoint/Restore
- **Companion KEP**: KEP-2008 (ContainerCheckpoint)
- **Tracking Issue**: TBD

---

## Table of Contents

- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [API Changes](#api-changes)
  - [Kubelet Endpoint](#kubelet-endpoint)
  - [PodSpec Field](#podspec-field)
  - [Flow](#flow)
- [Design Details](#design-details)
  - [Security Considerations](#security-considerations)
  - [OCI Image Layout](#oci-image-layout)
  - [Interaction with KEP-2008](#interaction-with-kep-2008)
- [Test Plan](#test-plan)
- [Graduation Criteria](#graduation-criteria)
- [Implementation Phases](#implementation-phases)
- [Production Readiness Review](#production-readiness-review)
- [References](#references)

---

## Summary

KEP-2008 introduced `ContainerCheckpoint`, a kubelet API that checkpoints a running container's
memory and file-system state into an OCI-compatible image.  There is currently no corresponding
restore path: a checkpoint image cannot be given back to the kubelet to resume a container.

This KEP proposes:

1. A new kubelet subresource `POST /checkpoint/<namespace>/<pod>/<container>/restore` that accepts
   an OCI image reference and starts (or restarts) the named container from that checkpoint.
2. An optional `restoreFrom` field in `Container.Lifecycle` to declaratively specify a checkpoint
   image at pod-creation time.

Together these two surfaces cover the full checkpoint/restore loop and enable live pod migration,
warm-start containers, and rapid disaster recovery without re-initialising application state.

---

## Motivation

### Background

CRIU (Checkpoint/Restore In Userspace) can dump and restore the full user-space state of a Linux
process tree, including memory maps, file descriptors, TCP sockets (with IP-tables tricks), and
timers.  KEP-2008 (Kubernetes 1.25 Alpha, 1.26 Beta) exposed the checkpoint half of this lifecycle
via the kubelet API:

```
POST /checkpoint/{namespace}/{pod}/{container}
```

The checkpoint is written as an OCI image to a local or remote registry.  Restoring from that
image requires either:

- Out-of-band tooling (e.g., `crictl restore`, vendor-specific CRI extensions), or
- A full pod deletion + recreation with a manually crafted `restoreFrom` annotation understood
  only by specific runtimes.

Neither approach is portable, declarative, or safe for production use.

### Goals

1. Provide a first-class kubelet API to restore a container from a checkpoint OCI image.
2. Allow the restore to target an existing (running or not-yet-started) container slot.
3. Ensure the API is gated and requires the same `checkpoint` RBAC permission already defined.
4. Define a PodSpec field for declarative restore at pod scheduling time.
5. Maintain backward compatibility — pods without `restoreFrom` behave exactly as today.

### Non-Goals

- TCP socket state preservation (deferred; see ADR-0017 for PodMotion; equivalent Kubernetes
  upstream work is out-of-scope for this KEP).
- Cross-node migration orchestration (belongs in a higher-level controller, not kubelet).
- Restore across Kubernetes versions (checkpoint format versioning is a separate concern).
- CRI runtime implementation details beyond the interface contract.

---

## Proposal

### Kubelet Endpoint

```
POST /checkpoint/{namespace}/{pod}/{container}/restore
Content-Type: application/json

{
  "image": "registry.example.com/checkpoints/my-pod-my-container:20260609-120000",
  "timeout": 60
}
```

**Response**:

```json
{
  "items": [
    "Successfully restored container my-container in pod my-pod/default from image registry.example.com/checkpoints/my-pod-my-container:20260609-120000"
  ]
}
```

**Error codes**:
- `400 Bad Request` — malformed body or invalid image reference.
- `404 Not Found` — pod or container not found.
- `409 Conflict` — container is running; caller must stop it first or use `force: true`.
- `503 Service Unavailable` — CRI runtime does not support restore.

**RBAC**: Requires the existing `nodes/checkpoint` subresource verb `create`.  No new resource type
is needed; the symmetry with the checkpoint endpoint is intentional.

### PodSpec Field

A new optional field `restoreFrom` is added to `core/v1.Container`:

```go
// RestoreFrom, if set, causes this container to be started from a CRIU checkpoint
// image rather than executing its normal entrypoint.  The kubelet pulls the OCI image
// and invokes the CRI RestoreContainer RPC.  Once the container transitions to Running,
// the field is cleared from the live pod status to avoid infinite re-restore on crash.
// +optional
RestoreFrom *ContainerRestoreSource `json:"restoreFrom,omitempty"`
```

```go
type ContainerRestoreSource struct {
  // Image is the OCI image reference containing the checkpoint.
  // +kubebuilder:validation:MinLength=1
  Image string `json:"image"`

  // ImagePullPolicy overrides the container's ImagePullPolicy for the checkpoint image.
  // Defaults to IfNotPresent to avoid re-pulling large checkpoint artifacts on warm restart.
  // +optional
  ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

  // OnceOnly, if true, the restoreFrom source is consumed exactly once: after the first
  // successful restore the kubelet removes it from the PodSpec so subsequent restarts
  // use the normal entrypoint.  Defaults to true.
  // +optional
  OnceOnly *bool `json:"onceOnly,omitempty"`
}
```

The `OnceOnly` semantic prevents a crash-loop from repeatedly restoring from a potentially stale
checkpoint — the behaviour most callers expect for live migration.

### Flow

**Imperative (API-triggered) restore**:

```
Operator / kubectl
     │
     │  POST /checkpoint/{ns}/{pod}/{ctr}/restore
     ▼
  Kubelet
     │  validates image ref, checks CRI capability
     │  calls CRI.StopContainer (if running and force=true)
     │  calls CRI.RestoreContainer(image)
     ▼
  containerd / CRI-O
     │  pulls OCI checkpoint image
     │  calls CRIU restore
     ▼
  Container resumes execution
```

**Declarative (PodSpec) restore**:

```
Scheduler places Pod on Node
     │
     ▼
  Kubelet syncPod()
     │  detects restoreFrom != nil on container spec
     │  calls CRI.RestoreContainer(restoreFrom.Image)
     │  on success, patches pod to clear restoreFrom (if OnceOnly)
     ▼
  Container resumes execution
```

---

## Design Details

### Security Considerations

- The restore endpoint reuses the `nodes/checkpoint` RBAC subresource, ensuring operators who
  already have checkpoint access can restore.  Cluster admins may restrict restore separately in
  a follow-on KEP if the threat model requires it.
- Checkpoint images contain the full memory layout of the process, including secrets.  The OCI
  image MUST be stored in a registry with appropriate access controls.  This KEP does not impose
  additional registry authentication requirements beyond standard `imagePullSecrets`.
- The `restoreFrom.Image` field is subject to the same admission webhook policies as `image`
  (e.g., OPA Gatekeeper image allow-lists).

### OCI Image Layout

Checkpoint images created by KEP-2008 follow the OCI Image Layout Specification with a custom
media type `application/vnd.kubernetes.container.checkpoint.criu.v1`.  The restore endpoint
expects the same media type; any other layers are ignored.

### Interaction with KEP-2008

KEP-2008 and this KEP together define a complete checkpoint/restore loop:

```
Running container
     │  POST /checkpoint/.../container      (KEP-2008)
     ▼
OCI checkpoint image in registry
     │  POST /checkpoint/.../container/restore  (this KEP)
     ▼
Restored container (same memory state)
```

Both endpoints are gated by the `ContainerCheckpoint` feature gate (KEP-2008) which is extended to
cover restore.  A new `ContainerRestore` feature gate is added so early adopters can enable restore
independently once the checkpoint gate is stable.

---

## Test Plan

### Unit Tests

- [ ] Kubelet handler: valid image ref accepted, malformed ref rejected with 400.
- [ ] Kubelet handler: 404 returned when pod/container not found.
- [ ] Kubelet handler: 409 returned when container running and `force` not set.
- [ ] PodSpec field: `restoreFrom` round-trips through API server (encoding/decoding).
- [ ] `OnceOnly=true`: kubelet clears `restoreFrom` after successful restore.

### Integration Tests

- [ ] kubelet integration test: fake CRI runtime that honours RestoreContainer RPC.
- [ ] API server: admission webhook sees `restoreFrom` field.

### E2E Tests

- [ ] `[Feature:ContainerRestore]` — checkpoint a pod, delete it, restore on same node.
- [ ] `[Feature:ContainerRestore]` — declarative restore via PodSpec on pod creation.
- [ ] `[Feature:ContainerRestore]` — restore idempotency (second restore call with same image).

---

## Graduation Criteria

### Alpha (target: 1.33)

- Feature gate `ContainerRestore` introduced, off by default.
- Kubelet endpoint implemented and tested with containerd + CRI-O.
- `restoreFrom` PodSpec field added behind the same feature gate.
- Unit and integration test coverage > 80% for new code paths.

### Beta (target: 1.35)

- Feature gate on by default.
- CRI spec updated with `RestoreContainer` RPC (PR to cri-api repo).
- At least two conforming CRI runtime implementations (containerd + CRI-O).
- E2E tests in testgrid passing for 3 consecutive releases.
- Documentation published on kubernetes.io.

### GA (target: 1.37)

- Feature gate removed; behaviour always enabled.
- API server validation finalized; `restoreFrom` field immutable after first restore.
- Security audit of checkpoint image handling completed.

---

## Implementation Phases

### Phase 1 — Kubelet endpoint skeleton (Alpha)

- Add handler under `pkg/kubelet/server/server.go` mirroring the checkpoint handler.
- Add `RestoreContainer` method to the `ContainerManager` interface.
- Stub implementation returns `503` until CRI support lands.

### Phase 2 — CRI spec update

- Open PR to `kubernetes/cri-api` adding `RestoreContainerRequest/Response`.
- Coordinate with containerd and CRI-O maintainers.

### Phase 3 — PodSpec field and admission

- Add `restoreFrom` field to `core/v1.Container`.
- Add validation: `image` must be a valid OCI reference.
- Kubelet `syncPod` honours the field; clears it via status patch on success.

### Phase 4 — E2E and promotion

- Testgrid job targeting containerd + CRI-O with checkpoint/restore.
- Promote to Beta after three release cycles of stability.

---

## Production Readiness Review

| Question | Answer |
|---|---|
| Feature gated? | Yes — `ContainerRestore` |
| Metrics added? | `kubelet_container_restore_total`, `kubelet_container_restore_duration_seconds` |
| Audit logging? | Restore endpoint is audited as subresource access on `nodes` |
| Can be disabled? | Yes — feature gate off reverts to pre-KEP behaviour |
| Rollback safe? | Yes — existing pods unaffected; `restoreFrom` field ignored when gate off |

---

## References

- [KEP-2008: Container Checkpointing](https://github.com/kubernetes/enhancements/issues/2008)
- [WG Checkpoint/Restore](https://github.com/kubernetes/community/blob/master/wg-checkpointrestore/README.md)
- [CRIU project](https://criu.org)
- [PodMotion ADR-0020: WG Checkpoint/Restore alignment](../adr/ADR-0020-wg-checkpoint-restore.md)
- [PodMotion ADR-0017: TCP preservation deferred](../adr/ADR-0017-tcp-preservation-deferred.md)
- [OCI Image Layout Specification](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
