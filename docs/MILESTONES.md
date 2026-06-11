# PodMotion Milestone Reference

Definitive record of all milestones, their status, key deliverables, and dependencies.
Current version: **v0.1.0-alpha**

## Status legend

| Status | Meaning |
|--------|---------|
| ✅ Complete | All deliverables merged and testable |
| 🔨 In Progress | Active implementation underway |
| 🔲 Planned | Scoped but not started |

---

## M1 — CRDs, Node Image, Webhooks ✅ Complete

**Deliverables:**
- 5 CRDs: PodMigration, MigrationPolicy, NodeMigrationCapacity, MigrationCheckpoint, MigrationWebhookConfig
- kind node image with CRIU 4.2 + kernel 6.8 prerequisites
- AWS AMI scaffolding via image-builder Ansible role
- NFD NodeFeatureRule for `criu-capable` labeling
- ValidatingAdmissionWebhook (block unmigrateable pods)
- MutatingAdmissionWebhook (intercept evictions during migration)
- Compat prober stubs (cpu, memory, kernel feature checks)

**Dependencies:** None — bootstraps everything else.

---

## M2 — State Machine, Dry-Run, Rollback ✅ Complete

**Deliverables:**
- PodMigration 11-phase state machine (Pending → Complete / Failed → RollingBack)
- Dry-run estimation: dirty page sampling without pod impact
- Rollback pipeline: immutable order Network → Compute → Storage (ADR-0014)
- Eviction webhook interceptor (blocks eviction of actively-migrating pods)
- Leader election (3 replicas, coordination.k8s.io/v1 Lease)
- Completion timeout with auto-abort

**Dependencies:** M1 (CRDs must exist).

---

## M3 — Cold Migration Path, kubectl Plugin, E2E Fixtures ✅ Complete

**Deliverables:**
- Checkpoint controller with GC (MigrationCheckpoint CR lifecycle)
- CRIU interface + StubCheckpointer (go-criu RPC subprocess; ADR-0002)
- EndpointSlice traffic manager (add new endpoint before removing old; ADR-0012)
- TrafficVerified gate (source pod never deleted until verified; ADR-0012)
- kubectl podmotion plugin (migrate / status / cancel / describe / estimate)
- Ginkgo E2E test fixtures (kind cluster setup helpers)

**Dependencies:** M1, M2.

---

## M4 — gRPC Agent Server, mTLS, Phase Gate Wiring ✅ Complete

**Deliverables:**
- gRPC agent server on each node (ADR-0023)
- mTLS loader with cert-manager integration
- Client connection pool with per-node TLS certs
- NRI plugin stub (containerd Stopping hook → pre-dump trigger)
- Phase gate wiring: Node → Compute → Network → Storage cost-ordered evaluation (ADR-0016)
- Migration bandwidth throttling

**Dependencies:** M1, M2, M3.

---

## M5 — Iterative Pre-Copy Dirty-Page Sync ✅ Complete

**Deliverables:**
- Pre-copy loop: CRIU pre-dump rounds until dirty pages < threshold
- Convergence tracking: dirty page rate per round
- Abort-on-divergence policy for thrashing workloads (ADR-0024)
- Force-freeze after max rounds (bounded downtime guarantee)
- Destination pod pre-activation (warm, not yet live)
- MemorySynced gate signal to CutoverCoordinator
- NRI plugin integration (containerd Stopping hook)
- eBPF packet counter on new pod veth for traffic arrival detection

**Dependencies:** M3, M4.

---

## M6 — Storage Tier 0 + Tier 1, StorageReadyForFreeze Gate ✅ Complete

**Deliverables:**
- Tier 0: RWX volume re-attach (NFS, CephFS) — zero-copy path
- Tier 1: Longhorn dual-engine live migration
- StorageReadyForFreeze gate: storage reaches 95% sync before compute freeze (ADR-0011)
- PDB overlap-then-delete: both pods live simultaneously during migration (ADR-0015)

**Dependencies:** M4, M5.

---

## M7 — Storage Tier 2 + Tier 3, Node Fencing ✅ Complete

**Deliverables:**
- Tier 2: Ceph RBD live migration via `rbd migrate` (requires Squid 18.2+; ADR-0026)
- Tier 3: VolumeSnapshot → clone → rsync delta (for local PVs and AWS EBS)
- NodeFencingEmitter: stuck RWO volume event emission and recovery guidance

**Dependencies:** M6.

---

## M8 — Scheduler + Descheduler Plugins ✅ Complete

**Deliverables:**
- MigrationAwareFilter scheduler plugin (rejects nodes without CRIU capacity)
- MigrationAwareScore scheduler plugin (NUMA topology, thermal throttle scoring)
- Descheduler MigrationBalance plugin (emits PodMigration CRs instead of evictions; ADR-0025)

**Dependencies:** M1, M2.

---

## M9 — AWS ALB/NLB Integration, CNI IP Mobility ✅ Complete

**Deliverables:**
- CNI IP mobility: OVN-Kubernetes IPAMClaim / Whereabouts static IP preservation
- Gratuitous ARP + unsolicited NDP after restore
- BGP /32 host route withdrawal and re-advertisement
- AWS ALB target group registration + health check polling (ADR-0027)
- AWS NLB target group integration
- ALB connection draining before old target deregistration

**CNI compatibility target matrix (live migration):**

| CNI | IP Handoff Mechanism | Notes |
|-----|---------------------|-------|
| Flannel (VXLAN/host-gw) | Gratuitous ARP + Flannel VTEP route refresh | Current dev CNI; baseline |
| Calico (BGP mode) | BGP /32 host route withdrawal + re-advertisement via `calicoctl node status`; workloadendpoint update | Calico node re-learns pod MAC via gratuitous ARP; no IP address migration needed if IP pool spans nodes |
| Calico (VXLAN mode) | VTEP MAC update + gratuitous ARP; IPAM release on source, annotate on destination | Similar to Flannel VXLAN path |
| Cilium (eBPF native) | `cilium endpoint migrate` (if available) or Cilium IPAM release+re-acquire + XDP BPF map update; identity-based policy via SecurityIdentity re-sync | Cilium's eBPF data plane bypasses iptables; PodMotion eBPF bridge must coordinate with Cilium's BPF programs to avoid double-processing |

**Calico-specific work items:**
- Detect Calico via `NetworkPlugin=calico` annotation on node or presence of `crd.projectcalico.org` API group
- On source: call `calicoctl delete workloadendpoint` after `TrafficVerified=true`
- On destination: create new `WorkloadEndpoint` before loopback bring-up; Calico programs iptables/eBPF rules before traffic is accepted
- Test matrix: BGP peered (bird), VXLAN encap, WireGuard encryption overlay

**Cilium-specific work items:**
- Detect Cilium via `cilium.io/` node annotations or `cilium` DaemonSet presence
- Cilium assigns `CiliumEndpoint` CRs; PodMotion must create the CE on destination before restore completes
- Cilium's `kube-proxy-replacement=strict` mode means no iptables fallback — eBPF map consistency is mandatory
- XDP bridge (M10) must avoid conflicting with Cilium's XDP hook on the same interface; use TC ingress hook as fallback when Cilium XDP is active (detect via `bpftool net show`)
- Test matrix: kube-proxy-replacement=strict, Hubble enabled, WireGuard transparent encryption

**Dependencies:** M5, M6.

---

## M10 — eBPF Zero-Window Hold, XDP Bridge, TCP Repair ✅ Complete

**Deliverables:**
- eBPF TC egress zero-window hold (freeze TCP senders during cutover window; ADR-0028)
- XDP packet bridge via GENEVE tunnel (in-flight packets during IP handoff)
- TCP_REPAIR socket state export/import interfaces (full preservation v0.2; stubs v0.1; ADR-0017)
- TCP PAWS timestamp delta correction
- Envoy/Istio drain coordination
- NetworkBridgeArmed CR condition (gates cutover; ADR-0028)
- bpfman DaemonSet for eBPF program lifecycle management

**Dependencies:** M9.

---

## M11 — Security Hardening ✅ Complete

**Deliverables:**
- Seccomp profile swap: Unconfined scoped only to checkpoint window (ADR-0009)
- Checkpoint OCI image encryption (cosign/ECDH; opt-in per MigrationPolicy; ADR-0029)
- Node-scoped projected ServiceAccountToken (least-privilege agent identity)
- mTLS cert rotation automation

**Dependencies:** M4.

---

## M12 — Observability, MigrationPolicy Controller, Audit ✅ Complete

**Deliverables:**
- Prometheus metrics: histograms not summaries (ADR-0030); migration_duration_seconds, freeze_window_seconds, dirty_page_bytes, etc.
- Grafana dashboard (per-migration timeline, cluster health overview)
- MigrationPolicy controller: trigger evaluation (node pressure, custom PromQL)
- Migration window enforcement (allowedCron / blockedCron)
- Audit logger for full migration lifecycle events
- Prometheus metrics-based traffic verification (PromQL hook)
- Custom webhook verification hook (escape hatch)

**Dependencies:** M3, M5, M9.

---

## M13 — Post-Copy / Lazy-Pages Mode ✅ Complete

**Deliverables:**
- CRIU userfaultfd lazy-pages server integration (ADR-0031)
- Post-copy mode toggle in MigrationPolicy spec
- Lazy-pages server lifetime tied to restore phase (torn down on Complete/Failed)
- Convergence metrics for post-copy fault rates

**Dependencies:** M5, M10.

---

## M14 — Multi-Cluster Migration Foundation ✅ Complete

**Deliverables:**
- Cross-cluster PodMigration CRD extension (remote cluster ref fields)
- OCI registry as WAN transfer medium (ADR-0034)
- DirectP2P blocked cross-cluster (too many firewall assumptions)
- Remote cluster kubeconfig/credentials management
- Intra-cluster still primary path; multi-cluster as explicit opt-in (ADR-0022)

**Dependencies:** M4, M7, M12.

---

## M15 — GPU Workload Migration ✅ Complete

**Deliverables:**
- GPUMigration feature gate (permanently experimental; ADR-0032)
- NVIDIA CUDA context checkpoint/restore via CRIU CUDA plugin
- Driver version guard (>= 525 required)
- GPU device re-bind on destination node

**Dependencies:** M5, M11.

---

## M16 — StatefulSet-Aware Migration ✅ Complete

**Deliverables:**
- StatefulSet controller watches and creates PodMigration CRs in ordinal order
- Descending ordinal sequence (highest-index pod migrated first; ADR-0033)
- PVC follow-along: each pod's PVCs migrate with its pod
- Ordinal integrity preserved across rollback

**Dependencies:** M7, M8.

---

## M17 — Spot Instance Reclamation Automation ✅ Complete

**Deliverables:**
- IMDS poller: polls EC2 instance metadata for spot interruption notice (ADR-0035)
- SpotReclaimReconciler: 90-second lead time from notice to forced migration
- Automatic PodMigration CR creation for all migratable pods on reclaimed node
- Non-migratable pod warning events

**Dependencies:** M8, M12.

---

## M18 — Upstream Contributions + Release Scaffolding ✅ Complete

**Deliverables:**
- KEP draft: kubelet Restore API (companion to KEP-2008; WG Checkpoint/Restore)
- kubectl migrate upstream proposal (native subcommand fork)
- Upstream descheduler EvictPlugin PR guide
- OperatorHub / OLM bundle
- Helm chart release targets in Makefile
- Docusaurus versioned docs structure

**Dependencies:** M1–M17 (capstone milestone).

---

## M19 — GitOps-Aware Migration (ADR-0046)

**Problem statement:** GitOps tools (ArgoCD, Flux CD) continuously reconcile workload
controller objects (Deployments, StatefulSets, ReplicaSets) toward Git-declared state. Any
PodMotion mutation of these objects triggers reconciliation and reversion. Additionally,
PodMotion's own transient CRs in workload namespaces are at risk from prune operations.

**Core architectural rule (ADR-0046):** PodMotion MUST NOT mutate workload controller
objects. Never patch `Deployment.spec`, `StatefulSet.spec`, `ReplicaSet.spec`, or
equivalent higher-level resource specs during any migration phase.

**Primary strategy — sub-controller migration (scheduler plugin + NRI hook):**

Instead of directing migration by patching workload controllers, PodMotion works entirely
below the controller layer:

1. Source pod is deleted (the only K8s write — a pod-level operation, not a controller
   mutation). The owning ReplicaSet/StatefulSet immediately creates a replacement pod.
2. PodMotion's MutatingAdmissionWebhook injects `podmotion.io/migration-name` and
   `podmotion.io/restore-from-checkpoint` labels on the replacement pod at creation time.
3. The `MigrationAwareScore` scheduler plugin routes the replacement pod to the destination
   node by scoring it MAX and all others zero — no Deployment mutation required.
4. PodMotion's NRI `CreateContainer` hook on the destination node intercepts the container
   startup and invokes CRIU restore from the checkpoint images instead of running the
   original entrypoint.
5. From GitOps perspective: the workload controller spec is unchanged, replica count is
   satisfied, pod is Running on destination. No drift is detected.

**Deliverables:**

- `internal/gitops/` package:
  - `detector.go` — walk ownerRefs to find GitOps-managed controllers; read ArgoCD and
    Flux labels; store result as annotations on PodMigration CR during `Validating` phase
  - `argocd_client.go` — toggle `Application.spec.syncPolicy.automated.selfHeal` for the
    narrow edge cases that still need suppression (standalone pods, Argo Rollouts)
  - `flux_client.go` — toggle `Kustomization.spec.suspend` / `HelmRelease.spec.suspend`;
    trigger immediate re-reconcile via `reconcile.fluxcd.io/requestedAt` annotation on resume
  - `suspender.go` — `GitOpsSuspender` interface dispatching to argocd/flux clients;
    auto-detect GitOps tool presence via discovery API; no-op when neither is present
- MutatingAdmissionWebhook: inject migration labels on replacement pods (the labels that
  guide the scheduler plugin and NRI hook)
- Scheduler plugin: extend `MigrationAwareScore` to score destination node MAX for
  replacement pods carrying `podmotion.io/migration-name` label
- NRI plugin: implement `CreateContainer` hook; ship `criu-nri-restore` binary in node
  image; invoke CRIU restore using containerd's already-configured container namespaces
  (eliminates the overlayfs + placeholder + `--empty-ns net` workarounds from cold-migration PoC)
- PodMigration CR self-protection:
  - Inject `argocd.argoproj.io/sync-options: Prune=false` on all PodMigration CRs at
    creation (blocks ArgoCD prune; zero user config)
  - Add `podmotion.io/migration-in-progress` finalizer to all active PodMigration CRs
    (defers deletion; triggers emergency rollback if deleted while in Checkpointing phase)
- `GitOpsAwareness` field on `MigrationPolicy` CRD
- Argo Rollouts: pause via `spec.paused: true` during migration window (this is the one
  controller-level write still permitted — Rollout pause is an explicit runtime flag, not
  a spec drift)
- RBAC: new ClusterRole entries for ArgoCD Application and Flux Kustomization/HelmRelease
  patch; gated behind `--enable-gitops-integration` (auto-detect by CRD presence)
- E2E tests: ArgoCD selfHeal=true + prune=true fires during Checkpointing; Flux healthChecks
  fail during freeze; Argo Rollouts pause/resume; emergency rollback on DeletionTimestamp
  set mid-migration
- CNI compatibility: the scheduler + NRI approach is CNI-agnostic. Calico and Cilium
  endpoint lifecycle (WorkloadEndpoint, CiliumEndpoint) is handled post-restore by the
  existing network agent, not the migration routing mechanism.

**Dependencies:** M1 (webhook), M4 (NRI stub + agent), M8 (scheduler plugin), M10 (eBPF hold).

**User friction inventory:**

| Item | Required | Friction |
|---|---|---|
| ClusterRole addition for ArgoCD Application/Rollout patch | Conditional (auto-skipped if ArgoCD absent) | Low — included in Helm chart |
| ClusterRole addition for Flux Kustomization/HelmRelease patch | Conditional (auto-skipped if Flux absent) | Low — included in Helm chart |
| NRI plugin installed on all nodes | YES | None — DaemonSet in node image |
| Do NOT place PodMigration CRs in Git-managed directories | YES | Documentation only |
| `argocd-cm` resource.exclusions for podmotion.io group | Recommended | Low — one-time admin |
| `ignoreDifferences` for webhook-injected pod labels | If ArgoCD with pod-level sync | Low — copy-paste from docs |

---

## Dependency Graph (summary)

```
M1 ──► M2 ──► M3 ──► M4 ──► M5 ──► M6 ──► M7 ──► M9 ──► M10 ──► M13
                │                    │       │
                └──► M8              └──► M11│
                                            └──► M12 ──► M14
                                                         M16 (M7+M8)
                                                         M17 (M8+M12)
                                                         M15 (M5+M11)
                                                         M18 (all)
                                                         M19 (M1+M4+M8+M10)
```

---

## Version Roadmap

| Version | Milestones | Description |
|---------|-----------|-------------|
| v0.1.0-alpha | M1–M5, M8, M11 | Cold + iterative pre-copy; TIER_4 network (reconnect); no TCP preservation |
| v0.1.0 | M1–M12 | Full intra-cluster migration; eBPF network bridge; all storage tiers |
| v0.2.0 | M13, M15, M16, M17 | Post-copy, GPU, StatefulSet, spot automation; TCP_REPAIR preservation |
| v1.0.0 | M1–M18, M19 | Production-ready; GitOps-aware; OperatorHub; upstream KEPs submitted |
| v1.x+ | Multi-cluster GA | M14 graduated from experimental |

---

## PoC Sprint Log

| Sprint | Status | Key Achievement |
|--------|--------|-----------------|
| Sprint 1 | Complete | First nginx migration end-to-end (state machine wired, gRPC skeleton) |
| Sprint 2 | Complete | AgentPool wired, all 3 workloads (nginx/redis/postgres) reach Complete |
| Sprint 3 | Complete | Privileged DaemonSet, source pod deletion, Postgres data integrity via PVC |
| Sprint 4 | Complete | Checkpoint + Restore gRPC fully wired; CheckpointRef set; PrepareDestination called; destination node pinning enforced |
| Sprint 5 | Complete | CRIU opts corrected for containers; PID resolution via /proc cgroup scan; mock fallback gated on env var; CRIU errors surfaced at ERROR level; ADR-0042 written |
| Sprint 6 | Complete | Optimistic-lock conflict fixed (6 call sites); state machine reaches Checkpointing; CRIU 3.17.1 confirmed invoked; restore failed — checkpoint images missing/empty |
| Sprint 7 | Complete | Dump path fixed; transfer wired; NetworkLock=SKIP; TcpSkipInFlight=true; CRIU restore invoked but dump still empty |
| Sprint 8 | Complete | Seccomp unconfined + CAP_SYS_PTRACE confirmed; CRIU dump succeeds; restore blocked by ARM64 linuxkit hard wall; Multipass pivot |
| Sprint 9 | Complete | Multipass Ubuntu 24.04 ARM64 + k3s; CRIU 4.2 installed; real CRIU restore invoked; dump never executed (controller reconcile race) |
| Sprint 10 | Complete | Reconcile race fixed; CRIU dump succeeded; inventory.img confirmed (13 artifacts); restore failed — wrong directory path; dataIntact=false |
| Sprint 11 | Complete | CheckpointRef path fixed (full filesystem path stored); crash-safe restart path fired before Checkpoint gRPC — dump never made; dataIntact=false |
| Sprint 12 | Failed | Crash-safe restart nil-guard added (CheckpointRef check); blocker: crash-safe restart path fired on brand-new migration — Checkpointing phase skipped entirely, no gRPC CheckpointPod call made, no CRIU dump written |
| Sprint 13 | Failed | data transfer wired; blocker: CRIU not reached — container root PID resolved as 0; agent in-memory migrationPodUID map empty at Checkpoint time (agent restarted between PrepareSource and Checkpoint calls) |

## Sprint 14 Target

**Blocker:** `migrationPodUID` map in `internal/agent/server/server.go` is in-memory only. When the agent DaemonSet pod restarts between the `PrepareSource` and `Checkpoint` RPC calls, the stored pod UID is lost and `FindContainerPID` receives an empty string, returning PID 0. CRIU `Dump()` fast-fails on PID 0.

**Fix:** In `AgentServer.Checkpoint()` (`internal/agent/server/server.go`), when `podUID == ""` (map miss due to restart), fall back to resolving the pod UID directly from the Kubernetes API using the migration name and namespace passed in the `CheckpointRequest`. The `AgentServer` already holds a `k8sClient`; use it to `Get` the `PodMigration` CR and extract `spec.podName` + `spec.namespace`, then `Get` the Pod and use `pod.UID`. Store the resolved UID back in the map so subsequent calls are fast. This eliminates the in-memory-only gap without requiring persistent storage.

**Acceptance criteria:** CRIU dump writes `inventory.img`; `sprint14_key=hello_podmotion` survives migration; `dataIntact=true`, `realCRIU=true`, `inventory.img` present.
