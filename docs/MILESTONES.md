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

## M20 — Istio Service Mesh Certification 🔲 Planned

Certify PodMotion for pods running inside an Istio service mesh (both sidecar and ambient
modes). This milestone covers detection, multi-process checkpoint/restore, certificate
continuity, xDS reconnect gating, and ztunnel coordination.

**Deliverables:**

- **Istio detection at admission**: ValidatingWebhook inspects pod annotations/namespace
  labels (`istio-injection=enabled`, `sidecar.istio.io/inject`) and sets an
  `IstioAnnotated` flag on the `PodMigration` CR; triggers Istio-specific migration path
- **Sidecar-mode multi-process checkpoint** (sidecar injection path):
  - CRIU must checkpoint the entire pod PID namespace — `istio-proxy` (Envoy) +
    `pilot-agent` + the application process — in a single dump tree rooted at the init
    process; single-container checkpoint misses `istio-proxy` PIDs entirely
  - Compat prober: verify Envoy process is in a WAIT-xDS-ready state before freeze
    (Envoy mid-config-push is unsafe to freeze; emit `EvoyConfigPushInProgress` gate)
  - pilot-agent holds a UDS connection to `/var/run/secrets/istio/` SPIFFE Workload API
    socket; this FD survives CRIU restore as a pending FD — the socket will reconnect
    post-restore; no special handling required for the FD itself, but the certificate it
    references is time-limited (see SVID window below)
- **iptables redirect rules preservation**: Istio's `istio-init` init container writes
  iptables redirect rules (REDIRECT 15001 inbound, REDIRECT 15001 outbound) into the
  pod's net namespace; these rules are in the CRIU netns/iptables state and survive
  CRIU restore automatically — no extra step needed; verify in E2E that rules are intact
  post-restore via `nsenter --net -- iptables -t nat -L`
- **SVID certificate continuity**:
  - SPIFFE SVIDs issued by istiod have short TTLs (default 24h, can be as low as 1h)
  - pilot-agent auto-rotates; post-restore it will reconnect to istiod and get a fresh
    SVID within seconds; mTLS enforcement during this brief window is the risk
  - Mitigation: hold eBPF traffic (extend the zero-window gate, ADR-0045) until pilot-agent
    reports SVID acquisition; detect via health probe on `15020/healthz/ready` (returns
    200 only when Envoy xDS sync + SVID are valid)
  - Surface `SvidRenewWindowTooShort` preflight error if remaining SVID TTL < restore
    estimated duration + 30s safety margin
- **Envoy xDS reconnect gate**: post-restore, `pilot-agent` reconnects to istiod via xDS;
  Envoy `CONFIG_DUMP` status (`15000/config_dump`) goes from `STALE` → `SYNCED`; add
  gate `EnvoyXdsSynced=true` to the Verifying phase; do NOT release eBPF hold until both
  `TrafficVerified=true` AND `EnvoyXdsSynced=true`; poll `15020/healthz/ready` with 2s
  interval; timeout after 60s → rollback
- **Ambient mode** (ztunnel path, Istio ≥ 1.21):
  - No sidecar in the pod; L4/L7 handled by per-node ztunnel DaemonSet
  - Migration model: standard pod migration; ztunnel on destination node automatically
    enrolls the restored pod via Kubernetes API watches (pod label `istio.io/dataplane-mode=ambient`)
  - Source-node ztunnel cleans up its enrollment when source pod is deleted
  - Verify: after restore, ztunnel enrollment on destination appears in `ztunnel` proxy
    config dump; add E2E check
  - Risk: ztunnel is tied to node IP for L4 redirects; during the migration freeze window
    there is a brief period where neither node's ztunnel has a valid enrollment; the eBPF
    zero-window hold covers this window
- **PeerAuthentication STRICT mode gate**: if the pod's namespace enforces
  `PeerAuthentication.mtls.mode=STRICT`, any request arriving before Envoy has a valid
  SVID will be rejected with `RBAC: access denied`; the SVID gate above prevents this;
  detect STRICT mode at preflight and require SVID gate
- **VirtualService / DestinationRule continuity**: these resources are cluster-scoped and
  not tied to the pod's node; no migration action required; traffic policy is seamlessly
  applied by the destination Envoy once xDS syncs
- **Argo Rollouts + Istio traffic shifting**: if a canary Rollout controls VirtualService
  traffic weights, migration must not disrupt the weight — the pause approach from M19
  covers this; document the interaction
- **Compat prober extension**: add `IstioCertifiable` check —
  SVID TTL > threshold, Envoy not in CONFIG_PUSH, ambient vs sidecar mode detected
- **E2E certification matrix**:
  - Sidecar mode + PeerAuthentication STRICT: mTLS continuity across migration
  - Sidecar mode + `istio-proxy` resource limits (CPU/memory cgroup constraints honored)
  - Ambient mode + ztunnel enrollment round-trip
  - Failed restore rollback: source SVID still valid, traffic re-routes without gap
  - Canary Rollout paused during migration, resumed after
- **Documentation**: Istio compatibility guide in Docusaurus; add
  `migration.podmotion.io/istio-mode: sidecar|ambient` annotation to PodMigration spec;
  add Istio to compatibility matrix table in docs/compatibility.md

**Key constraints:**
- NRI + seccomp: Istio sidecar adds a seccomp profile on `istio-proxy` container;
  the CRIU/seccomp preflight (M20 must run after ADR-0046's security context harness is
  built) must include `istio-proxy`'s profile, not just the app container's
- CRIU tree rooting: the pod's init process (PID 1 in the container, typically
  `/sbin/docker-init` or `pause`) is the root; `istio-proxy` and `pilot-agent` are
  children; CRIU dump of PID 1 captures all; verify with `pstree` in the frozen state
- NRI `--join-ns` timing: same constraint as M19/ADR-0046 — restore must target the
  runc-built namespace, not attempt to pre-join at CreateContainer time
- containerd ≥ 2.0 required for NRI (same as M19)

**Dependencies:** M9 (CNI compatibility — Calico/Cilium endpoints), M10 (eBPF zero-window
hold — extended for SVID gate), M19 (GitOps-aware migration — NRI hook, sub-controller
approach, security context harness).

---

## M21 — Automated Certification Matrix & Agentic Version Validation 🔲 Planned

**Purpose:** As each OS, Kubernetes distribution, CNI, and CSI type is certified for beta, it is
enrolled in a living certification matrix that drives fully automated validation whenever upstream
versions change — with agentic quorum testing, signoff, and publication requiring zero human
intervention for routine version bumps.

**Deliverables:**

### Certification Matrix (`config/certification-matrix.yaml`)
- Structured YAML registry of every certified combination: `{os, k8s_distro, cni, csi, min_version, max_version, test_suite, tier}`
- Tier 1 (run on every PR), Tier 2 (nightly), Tier 3 (on new upstream release only) — controls matrix explosion
- Each row carries a `certified_at` date, `signoff_sha`, and `breaking_changes` note
- Schema-validated by a CI lint step; schema defined as JSON Schema in `config/certification-matrix.schema.json`
- Grows automatically: certifying a new component (e.g. EBS CSI Driver) adds a row; version bump updates the bounds

### Version Watcher (GitHub Actions — `.github/workflows/version-watcher.yml`)
- Scheduled daily workflow; polls upstream release feeds for every entry in the matrix
  - GitHub Releases API for: Calico, Cilium, Flannel, Longhorn, Rook/Ceph, aws-ebs-csi-driver, kubeadm, k3s, RKE2
  - Ubuntu LTS release page for OS entries
  - CRIU releases page
- On new version detected: opens a draft PR with `version-bump/<component>-<new-version>` branch
- PR body includes: release notes URL, changelog diff, whether the version falls within existing bounds (no-op) or requires re-certification
- Only re-certification cases advance to the agentic testing pipeline

### Agentic Quorum Testing Pipeline (`.github/workflows/cert-quorum.yml`)
- Triggered by: version-bump PR label `needs-certification`
- Fan-out: one Claude agent per affected matrix row (OS × k8s × CNI × CSI combination to re-test)
- Each agent:
  1. Provisions a kind cluster with the new component version (via `make kind-create VERSION=...`)
  2. Runs the relevant E2E test suite (`make test-e2e SUITE=<test_suite>`)
  3. Reports PASS/FAIL/FLAKY with log artifacts
- Synthesis agent collects all agent reports, determines quorum (≥ 2/3 PASS), writes structured signoff JSON
- On quorum PASS: auto-merges the version-bump PR, updates `certification-matrix.yaml` bounds, creates a GitHub Release note entry
- On quorum FAIL: opens a GitHub Issue tagged `cert-regression/<component>-<version>`, assigns to maintainers, blocks the version bump

### Signoff & Publication
- Quorum signoff artifact signed with cosign (keyless, Sigstore OIDC) and attached to the PR
- `CHANGELOG.md` entry auto-generated by synthesis agent (describes what was re-tested, pass rate, any caveats)
- Helm chart `appVersion` and `values.yaml` compatible version ranges updated automatically
- Docs site (`docs/compatibility-matrix.md`) regenerated from `certification-matrix.yaml` on every merge

### Beta Gate Integration
- `make beta-gate` target: validates that every component in the Tier 1 matrix has a passing signoff within the last 30 days; blocks release cut if any row is stale or failing
- Beta gate runs as a required check on the `release/*` branch

**Architecture notes:**
- The matrix schema uses semver range notation (`>=1.2.0 <2.0.0`) so minor bumps within a certified range are auto-approved without re-running full E2E
- Agentic test agents use `isolation: worktree` so parallel kind cluster provisioning does not share filesystem state
- Test result artifacts stored in GitHub Actions cache keyed by `<component>-<version>-<sha>` — cache hit = instant quorum on re-run
- The pipeline itself is agent-reviewed on each structural change (meta-certification: the CI system certifies itself)

### Pre-Beta Chaos & Fidelity Testing (Required Gate)

Before the beta release cut, PodMotion must pass a rich randomized multi-cluster test campaign
targeting realistic live workloads under load. This is a **hard gate** — no beta cut until all
runs are clean with zero errors and zero warnings in operator/agent logs.

**Environments:**
- AWS arm64: EKS clusters on Graviton instance types (m7g, c7g, r7g families); randomly varied sizes and AZs
- AWS amd64: EKS clusters on x86-64 instance types (m7i, c7i, r7i families); same randomization axes
- Local VMs arm64: multi-node Multipass/QEMU clusters on Apple Silicon workstation (current dev cluster: pm-control + pm-worker)
- Local VMs amd64: multi-node QEMU clusters running under Rosetta or on a dedicated x86-64 machine

All four environment buckets must pass. An architecture-only failure (e.g. passes arm64, fails amd64) is a blocking defect.

**Workload spread (all must be covered):**

| Category | Workload | Stateful? | Key migration challenge |
|----------|----------|-----------|------------------------|
| Web server | NGINX (small/medium/large replicas) | Stateless | Connection draining, topology spread |
| Web server | Node.js / Go HTTP server under wrk/k6 load | Stateless | In-flight HTTP requests mid-migration |
| Database | PostgreSQL (single + replication) | Stateful (RWO PVC) | Storage tier, PDB, checkpoint under write load |
| Database | MySQL / MariaDB | Stateful (RWO PVC) | InnoDB dirty buffer pages, large memory footprint |
| Cache | Redis standalone | Stateful (optional AOF) | Proved in NS#1 PoC; must hold under key churn |
| Cache | Redis Cluster (6-node) | Stateful | Anti-affinity conflicts, slot rebalance |
| Message broker | NATS / RabbitMQ | Stateful | In-flight messages, durable queue survival |
| Mixed | Helm-deployed multi-tier app (web + DB + cache) | Mixed | GitOps drift, service mesh, end-to-end traffic |

**Randomization axes:**
- Architecture: arm64 (Graviton / Apple Silicon), amd64 (x86-64 Intel/AMD) — both must pass all workloads
- Pod memory footprint: 64 MB, 256 MB, 1 GB, 4 GB (tests dirty-page convergence thresholds)
- Write rate: idle, 10 MB/s, 100 MB/s (tests PreCopy round convergence and ForceFreeze path)
- Number of open TCP connections: 0, 10, 1 000 (tests NetworkContinuity tiers)
- PVC size: none, 1 GB, 100 GB (tests storage tier selection and cutover latency)
- Concurrent migrations: 1, 4, 8 simultaneous PodMigration CRs (tests slot reservation and quota races)
- Cluster node count: 3, 6, 12 nodes

**Pass criteria (all required, no exceptions):**
1. Zero `ERROR` or `WARN` log lines in operator pod and agent DaemonSet across the full run
2. Zero failed PodMigration CRs (all reach `phase=Complete` or explicit `DryRunComplete`)
3. Zero data loss: workload validation script confirms all keys/rows/messages present post-migration
4. Zero service disruption exceeding the migration SLA (cold: <30s, live: <500ms)
5. Source pod deleted if and only if `TrafficVerified=True` (verified by log audit)
6. GitOps controllers (ArgoCD/Flux, if present) resumed cleanly — no drift alert after migration
7. Checkpoint directories cleaned up (no residue in `/run/podmotion/checkpoints/`) after GC
8. `make beta-gate` passes (all Tier 1 matrix entries signed off)

**Tooling required (pre-existing or to be built):**
- `test/chaos/workload_generator.go` — parameterized workload deployer; accepts randomization seed
- `test/chaos/cluster_matrix.go` — AWS cluster provisioner driven by a YAML matrix config
- `test/chaos/validator.go` — post-migration data-integrity checker per workload type
- Log audit script: `scripts/beta-log-audit.sh` — greps operator + agent logs for ERROR/WARN, fails CI on any hit
- `make pre-beta-chaos` target — drives the full campaign, blocks on pass criteria above

### Beta Release Presentations (three-audience deliverable)
Three standalone decks generated at beta cut — one per audience, all sourced from the same
living content model so they stay in sync as the product evolves:

| Deck | Audience | Length | Focus |
|------|----------|--------|-------|
| **Executive** | CEO / board / investors | 8–10 slides | Problem ($B TCO waste from overprovisioning/spot loss), solution headline, differentiation vs hypervisor live VM migration, adoption path, ask |
| **Product / Engineering Lead** | VP Eng, platform team leads | 15–20 slides | Architecture overview, migration sequence, CNI/CSI/OS support matrix, SLA targets, operational model, beta scope and GA roadmap |
| **Deep Technical** | SRE, platform engineer, contributor | Full reference | CRIU internals, ADR index, state machine, eBPF bridge design, GitOps constraint, NRI hook, security model, API reference, known limits |

The deep technical deck doubles as the project's technical reference documentation (rendered to
the Docusaurus docs site). The executive and mid-level decks are auto-generated by an agent from
the deep technical content + milestone data at each release cut.

**Dependencies:** M18 (release scaffolding), M20 (Istio certification — first Tier 3 entry that exercises the full pipeline end-to-end).

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
                                                         M20 (M9+M10+M19)
                                                         M21 (M18+M20 — beta gate)
```

---

## Version Roadmap

| Version | Milestones | Description |
|---------|-----------|-------------|
| v0.1.0-alpha | M1–M5, M8, M11 | Cold + iterative pre-copy; TIER_4 network (reconnect); no TCP preservation |
| v0.1.0 | M1–M12 | Full intra-cluster migration; eBPF network bridge; all storage tiers |
| v0.2.0 | M13, M15, M16, M17 | Post-copy, GPU, StatefulSet, spot automation; TCP_REPAIR preservation |
| v1.0.0 | M1–M19 | Production-ready; GitOps-aware; OperatorHub; upstream KEPs submitted |
| v1.1.0 | +M20 | Istio service mesh certification |
| v1.2.0 | +M21 | Automated certification matrix; agentic version validation; beta gate |
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
