# PodMotion Ecosystem Delta

PodMotion ships what it owns. This document tracks the gaps that require external ecosystem
changes — CNI vendors, cloud providers, upstream Kubernetes, distro maintainers. Each gap
has a named extension point in the codebase so when the ecosystem moves, integration is a
pull request, not a rewrite.

See [ADR-0038](adr/0038-ecosystem-delta-model.md) for the strategic rationale.

---

## Delta Table

| # | Gap | Owner | What needs to change | PodMotion extension point | Status |
|---|-----|-------|---------------------|--------------------------|--------|
| 1 | **TCP continuity on EKS (VPC CNI)** | AWS | VPC CNI needs pod IP portability — ENI secondary IP reassignment across nodes, or a pod-identity-aware routing model | `internal/agent/iphandoff/` — implement `VPCCNIHandoff` conforming to `IPHandoffStrategy` | ⏳ waiting |
| 2 | **IP mobility — generic CNI** | Calico, Cilium, OVN-K | Stable BGP /32 host-route APIs exposed per-CNI for pod IP announcement at destination | `IPHandoffStrategy` interface (stubs for Calico BGP + OVN-K in M9) | 🔄 partial |
| 3 | **Kubelet Restore API (KEP-2008 Part 2)** | sig-node / Kubernetes upstream | KEP-2008 restore path merged into kubelet; `POST /checkpoint/{ns}/{pod}/{container}/restore` | `internal/agent/criu/` — swap out-of-kubelet containerd task API for in-kubelet path | ⏳ waiting (KEP draft filed in M18) |
| 4 | **CRIU 4.x in distro base repos** | Ubuntu, Red Hat, Amazon | Ship CRIU ≥4.0 in `apt`/`dnf` without requiring PPA, EPEL, or source builds | `images/` Dockerfiles — remove PPA step when distros ship 4.x | ⏳ waiting |
| 5 | **NRI API stability (GA)** | containerd / CNCF | NRI reaches v1.0 GA with stable API guarantees | `internal/agent/nri/` — NRI pre-dump trigger hook | 🔄 in-progress (NRI v0.6+ usable) |
| 6 | **SELinux policy for CRIU** | Red Hat | Upstream SELinux policy module for CRIU ptrace + bpf(2) syscalls | `selinux/podmotion.te` (drafted, needs upstream review + ship) | ⏳ waiting |
| 7 | **GPU checkpoint GA** | NVIDIA | `cuda-checkpoint` public API, stable CLI flags, documentation | `internal/agent/gpu/` — behind `GPUMigration` feature gate (ADR-0032) | ⏳ waiting |
| 8 | **Multi-cluster control plane** | CNCF / community | Standard cross-cluster workload identity and control plane federation | `internal/multicluster/` — `ClusterFederator` interface (ADR-0022, M19+) | 🗓 deferred post-v1.0 |

---

## Status Key

| Symbol | Meaning |
|--------|---------|
| ⏳ waiting | External party has not started; PodMotion extension point is ready |
| 🔄 partial | Some CNIs/distros have what's needed; others don't |
| 🗓 deferred | Intentionally post-v1.0 per ADR-0022 |
| ✅ closed | Gap closed — link to PR/release |

---

## Mitigations Available Today

| Gap | Mitigation (works now, without ecosystem change) |
|-----|--------------------------------------------------|
| VPC CNI TCP continuity | Switch EKS node groups to Calico or Cilium in BGP mode; or deploy Istio/App Mesh for connection-level retries (ADR-0021) |
| CRIU 4.x not in repos | Use `ppa:criu/ppa` (Ubuntu), build from source in Ansible role (RHEL/AL), or use kind node image with CRIU baked in |
| SELinux blocking CRIU | Set `container_manage_cgroup` boolean + permissive mode for `podmotion_agent_t` until policy module ships |
| No kubelet Restore API | PodMotion uses out-of-kubelet containerd task API (ADR-0013) — works today on containerd 1.7+ |

---

## How to Close a Gap

When an ecosystem party ships what's needed:

1. Implement the extension point interface (e.g. `VPCCNIHandoff` in `internal/agent/iphandoff/`)
2. Add a feature gate or auto-detection in `NodeMigrationCapacity` spec
3. Write E2E tests against the real environment
4. Update this table: status → ✅ closed, add link to PR
5. Update ADR-0038 with a note on the closure

No other files need changing — the interface contract was the plan all along.
