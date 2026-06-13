> **See also: [NORTH_STAR_SPRINT_PLAN.md](NORTH_STAR_SPRINT_PLAN.md)** — the authoritative work plan including all ADR pipeline tasks and milestone gate conditions.

# PodMotion Roadmap

This document is the authoritative overview of where PodMotion is going and why. It
covers the path from the proven live-migration foundation to a north-star-complete,
v1.0 product.

Per-milestone implementation detail for **M19–M25** lives in
[`docs/SPRINT_PLAN_M19_M25.md`](./SPRINT_PLAN_M19_M25.md). This document is the
overview; the sprint plan is the work breakdown.

---

## 1. North Star

### Definition

PodMotion exists to deliver **complete bilateral transparency** for live pod
migration across nodes within a single cluster:

- **ALL containers** in the pod are unaware they moved — every app container, every
  sidecar, every log shipper. Not "the main container survives." Every container.
- **ALL clients** with open TCP connections are unaware the pod moved.
- **`seq_delta=0`** — exact TCP sequence number preservation.
- **No RST. No reconnect. No retry. No client-side reconnect logic required.**

This is a distributed-systems guarantee under load, across multi-container pods and
across CNI / storage / load-balancer topologies — not a single-flow point proof.

### What "done" looks like

The north star is **COMPLETE** when, on every release, CI shows green across the full
matrix:

- **Workloads:** multi-container pods including service-mesh sidecars (Envoy/Istio),
  across all 8 beta-gate workload types (stateless web, SQL DB, Redis/KV, message
  broker, mixed multi-container, plus 3 remaining).
- **CNIs:** Calico VXLAN, Cilium eBPF, Flannel VXLAN — each independently re-proving
  N-flow seq preservation and conntrack migration. There is no CNI-generic
  transparency.
- **Clouds:** EKS, self-managed EC2, kubeadm/kind.
- **K8s versions:** N, N-1, N-2.
- **IP families:** IPv4 and IPv6 clients, including Service-routed (ClusterIP /
  NodePort) and external-LB (ALB / NLB) paths.

…with `seq_delta=0`, zero RST, zero reconnect, zero retry, and every container
unaware — validated by **80 randomized zero-error / zero-warning runs** and a **clean
external security audit**, behind a **frozen v1 API**.

The two currently-invisible Tier-0 prerequisites are **multi-container consistent
checkpoint (M22)** and **conntrack/NAT state migration (M23)**. The gate is **INVALID**
if run before both land.

### Scope boundaries

The defensible product claim at v1.0:

> *Live-migrate a running multi-container pod across nodes on EKS or kubeadm with
> Calico / Cilium / Flannel, and neither the containers nor any client with an open
> TCP connection will notice.*

The north star is **single-cluster** and **amd64** by definition for the v1.0 gate.
See [Section 6](#6-explicitly-out-of-scope) for the full out-of-scope list.

---

## 2. Foundation — Proven and Complete

Two results are proven and immutable. All planning builds on these.

### Cold migration proven (2026-06-10, M3/M4)

- nginx HTTP 200, Redis key persistence, PostgreSQL row integrity across nodes.
- Established: the 5-CRD data model, the PodMigration state machine, and CRIU
  dump/restore mechanics.

### Live TCP migration proven (2026-06-11, M18.5 NS#4 spike)

- `seq_delta=0`. sent=576, received=576, errors=0, gaps=[]. 94ms CRIU dump.
- Overlay-native FDB / neighbor injection. Stock Ubuntu 24.04, kernel 6.8. **No kernel
  patches.**
- Established: the mechanism is real and achievable in production.

**Critical framing:** the M18.5 spike proved the *mechanism* for **one** TCP flow,
**one** container, **one** client, on a clean overlay. It removed *physics risk*, not
*engineering risk*. Multi-container CRIU consistency and N-flow simultaneous seq
preservation are **not** proven and are **not** trivially implied by the single-flow
result. The distance from that spike to the north star is the entire remaining
roadmap.

---

## 3. Milestone Overview

| ID | Title | Theme | Status | Size | North star after |
|----|-------|-------|--------|------|------------------|
| M22 | Multi-Container Consistent Checkpoint Correctness + Scope Matrix + Security Baseline | Checkpoint correctness + admission enforcement + security hardening (Gap 1, Gap 4) | NEW | L | ~45% |
| M23 | Conntrack/NAT State Migration + N-Flow Transparency + Controller Test Gate | Network transparency — "every client" half + behavior test coverage (Gap 2) | NEW | L | ~65% |
| M24 | CNI Matrix to Production + LB Connection Tracking | Per-CNI transparency parity | IN_PLAN | XL | ~80% |
| M25 | IPv6 + Encrypted Overlay Transparency | Network transparency across IP families / encryption | NEW | XL | ~88% |
| M26 | Observability + Scheduler/Descheduler E2E + **CI Matrix Gate + Release Hygiene** | Provability, orchestration, deterministic CI (Gap 3, Gap 6) | IN_PLAN | L | ~90% |
| M27 | First True-North-Star AWS Gate Run + **Chaos Gate** | Pre-beta validation + fault injection empirical verification (Gap 5) | NEW | M | ~92% |
| M28 | Beta Gate — 80 Runs, Zero Errors/Warnings | Production hardening gate | IN_PLAN | L | ~95% |
| M29 | CNCF Sandbox + External Security Audit + Public Launch | Community launch | IN_PLAN | M | ~95% |
| M30 | API Stabilization + v1.0 Matrix Freeze | API maturity and v1.0 | NEW | L | 100% (amd64 scope) |

Tier-0 prerequisites: **M22 and M23 must both land before any north-star gate run.**

**Pre-production hardening note (2026-06-12 CNCF quorum):** 6 pre-production gap ADRs
reviewed. 1 accepted (ADR-0079 — E2E CI Matrix). 5 rejected and require revision.
Hardening tasks have been folded into M22 (scope matrix, security baseline), M23
(controller test gate), M26 (CI matrix implementation, release hygiene), and M27
(chaos gate). All 5 rejected ADRs must be revised, re-reviewed, and accepted before
their respective milestone gates can be declared passed. See
`docs/PRE_PROD_CHECKLIST.md` and `docs/adr/CNCF_AUDIT_REJECTED.md`.

**Milestone-count realism:** this synthesized plan is 9 net milestones (M22–M30) vs.
the 4 originally planned (M22–M25). If M22 reveals deep CRIU shared-namespace ordering
problems, expect 1–2 more (realistic range 10–11). This is the ADR-0045-compliant
timeline — slip the date rather than weaken the definition.

---

## 4. Milestone Detail (NEW milestones)

IN_PLAN milestones (M24, M26, M28, M29) already have detail in the sprint plan; their
gate conditions and unlocks are summarized in [Section 5](#5-north-star-progress-by-milestone).

### M22 — Multi-Container Consistent Checkpoint Correctness `NEW · L`

**Theme:** the "every container" half — the single largest currently-unproven
capability.

**Work items:**

- Define and implement consistent freeze / dump / restore ordering across ALL
  containers in a pod (app + sidecars + log shipper).
- Handle shared-namespace coupling: shared netns, IPC, PID, and shared-volume handling
  during coordinated freeze.
- Preserve per-container in-flight state — open FDs, threads, timers, process trees —
  for every container, not just main.
- Prove a 3-container pod (app + Envoy/Istio sidecar + log shipper) migrates with all
  three containers unaware.
- Validate service-mesh sidecar transparency specifically (Envoy/Istio mesh-internal
  connections survive).
- Kick off external security-audit procurement (8–12 week lead time; **start now**, not
  at the gate).
- Start v1alpha2 / WorkloadRef conversion-webhook design (ADR-0075).

**Gate condition:** a 3-container pod with a real service-mesh sidecar migrates across
nodes with all containers reporting zero internal disruption and `seq_delta=0` on every
container's connections, reproduced 10× clean.

**Risk:** highest-risk milestone. May reveal deep CRIU shared-namespace ordering
problems requiring a follow-on.

### M23 — Conntrack/NAT State Migration + N-Flow Transparency `NEW · L`

**Theme:** the "every client" half — the kernel-state path. Retires the second
invisible Tier-0 killer: overlay seq preservation does **not** survive kernel conntrack
for Service paths.

**Work items:**

- Migrate kernel conntrack / NAT state on **both** source and destination nodes.
- Prove `seq_delta=0` for Service-routed traffic (ClusterIP / NodePort; kube-proxy
  iptables and IPVS paths), not just pod-to-pod overlay.
- Prove `seq_delta=0` for N≥100 concurrent flows with independent seq / ack / window /
  SACK state across the 94ms blackout.
- Integrate storage cutover (RWX / Longhorn / Ceph RBD) here, since open-fd offset and
  lock state couple to the freeze window.
- Preserve open file handle / inode / fd-offset / advisory-lock state across volume
  cutover (D3).
- Land v1alpha2 conversion webhook so subsequent beta ships on a near-stable API.

**Gate condition:** `seq_delta=0`, zero RST, zero reconnect for ≥100 concurrent
Service-routed (ClusterIP + NodePort) flows under load across a live migration, with
storage fd / lock state preserved.

### M25 — IPv6 + Encrypted Overlay Transparency `NEW · XL`

**Theme:** completing "ALL clients" across IP families and encryption.

**Work items:**

- AF_INET6 FDB / neighbor injection — dual-stack and v6-only client transparency
  (ADR-0048).
- Encrypted overlay support: WireGuard / IPSec VTEP MAC discovery, where the spiked
  plaintext MAC discovery does not apply (ADR-0057).
- Validate `seq_delta=0` for v6 clients and encrypted-datapath clusters.
- Each needs a dedicated network specialist / second maintainer (touches every network
  code path).

**Gate condition:** `seq_delta=0` live migration proven for an IPv6 client and for a
WireGuard-encrypted overlay cluster.

**Open scope conflict:** the PM scopes both as post-v1.0 epics; the architect scopes
both as north-star-blocking. **UNRESOLVED — flagged for quorum** (see
[Section 7](#7-open-questions-requiring-quorum)).

### M27 — First True-North-Star AWS Gate Run `NEW · M`

**Theme:** pre-beta validation against the real definition (not the weaker M18.5
single-flow definition).

**Work items:**

- First randomized AWS gate run (EKS + self-managed EC2) against the TRUE north-star
  workload set: multi-container + service-mesh sidecar + Service-routed + dual-stack.
- Exercise all 8 beta-gate workload types.
- Surface flakiness in cloud LB conntrack and storage cutover before the scored gate.
- Harness hardening and reproducibility.

**Gate condition:** one full randomized AWS gate run completes against the
multi-container + Service + dual-stack workload set with zero unexplained failures.

### M30 — API Stabilization + v1.0 Matrix Freeze `NEW · L`

**Theme:** API maturity and v1.0. Fills the gap both reviewers flagged: there was no
v0.x → v1.0 API-stabilization milestone.

**Work items:**

- Implement and freeze the API: v1alpha1 / v0.x → v1beta1 (with conversion webhook) →
  v1.
- Land ADR-0075 (WorkloadRef + conversion webhook + CEL validation) fully.
- ADR-0076 cold-mode admission rejection (live-only product posture).
- Full north-star matrix green in CI on every release (workloads × CNIs × clouds × K8s
  N/N-1/N-2).
- Releases: v0.2.0 (stabilization / adopter onboarding) → v0.3.0 → v1beta1 → v1.0.0.
- Recruit a second maintainer; convert deferred items (flannel host-gw, ARM64, LB
  matrices, dashboards) into labeled first-big-issue contribution on-ramps.
- Document 3+ public production adopters to seed an incubation application.

**Gate condition:** v1.0.0 released with frozen v1 API, full north-star matrix green in
CI, clean re-audit, and a proven conversion path from the earliest public release.

**Note:** the path to incubation is structurally non-solo — requires a second
maintainer and documented adopters.

---

## 5. North Star Progress by Milestone

| Milestone | Progress | What it unlocks |
|-----------|----------|-----------------|
| **M22** | ~25% → ~45% | The defining "every container, every sidecar" clause — the largest unproven capability. Proves the pod-as-a-unit guarantee. Tier-0 risk retired. |
| **M23** | → ~65% | "All real clients" (which traverse Services) and N-flow scale. Retires the second invisible Tier-0 killer (conntrack for Service paths). |
| **M24** | → ~80% | The dominant production CNI footprint and north-south client paths. Without Cilium the north star is false for a huge share of production. |
| **M25** | → ~88% | The literal "all clients" gap: v6 clients and default-encrypted clusters. Converts the north star from "conditionally true" to "unconditionally true." |
| **M26** | → ~90% | No raw capability, but makes the guarantee PROVABLE and self-driving — prerequisite for a meaningful gate. |
| **M27** | → ~92% | Validates the assembled mechanism on real cloud topology against the literal north-star definition. |
| **M28** | → ~95% (amd64) | Converts "demonstrated" into a statistically defensible guarantee. The empirical north-star certification. |
| **M29** | ~95% | No new mechanism; makes the north star public and credible (sandbox, audit, public v0.1.0). |
| **M30** | 100% (amd64 scope) | Completes the PRODUCT north star: promised matrix green in CI on every release behind a stable v1 API. |

The gate conditions for IN_PLAN milestones:

- **M24:** `seq_delta=0` multi-container migration green on Calico VXLAN, Cilium eBPF,
  and Flannel VXLAN independently, plus one external-LB (ALB or NLB) north-south flow
  surviving migration.
- **M26:** observability stack emits per-migration `seq_delta`, flow-loss,
  blackout-duration, and per-container consistency metrics; scheduler / descheduler
  drives an unattended multi-migration run clean.
- **M28:** 80 consecutive randomized runs with zero errors and zero warnings against
  the full north-star workload matrix on amd64.
- **M29:** CNCF sandbox application submitted with a clean external audit, public
  v0.1.0 released, and a credibility demo (live `seq_delta=0` tcpdump + sidecar
  migration) published.

---

## 6. Explicitly Out of Scope

State these loudly so the community does not expect them and does not file them as
graduation blockers. A scope-boundaries doc (out-of-scope list) and the full ADR
archive ship publicly on day one (M29).

### Deferred (named post-v1.0 epics; may re-enter scope)

| Item | ADR | Status / note |
|------|-----|---------------|
| GPU / device-attached container migration | ADR-0032 | Permanently feature-gated. RE-ENTERS scope (adds 2+ milestones) only if leadership rules "every container" literally includes GPU sidecars. |
| IPv6 / encrypted-overlay transparency | ADR-0048 / ADR-0057 | Scoped as M25. PM: post-v1.0. Architect: north-star-blocking. UNRESOLVED. |
| flannel host-gw backend | — | Different injection strategy from VXLAN; post-v1.0 community-contributor candidate. |
| ARM64 production validation | — | amd64 only through the v1.0 gate; ARM64 is a fast-follow. |
| Live-storage v1.2 (dual-engine / concurrent) | — | Future epic. |
| Argo Rollouts / Flagger integration | ADR-0055 | Document the divergence; not core transparency. |
| StatefulSet N-pod coordinated rolling migration | — | Operator-on-top, not the core transparency guarantee. |
| sig-node KEP upstream effort | — | Future ecosystem work. |

### Never (permanently out)

| Item | Note |
|------|------|
| Windows containers / nodes | No scope anywhere; stays out. |
| Multi-cluster / cross-cluster migration | ADR-0034. Distinct VNI/VTEP networking problem; a separate future product line. The north star is single-cluster by definition. |
| Cold-mode migration as a product posture | ADR-0076 admission rejection; PodMotion is live-only. (Cold migration remains the proven foundation, not a shipped mode.) |

---

## 7. Open Questions Requiring Quorum

These require an explicit leadership / quorum ruling before scope is frozen.

1. **GPU sidecars.** Does the literal phrase "every container" include GPU /
   device-attached sidecars? If yes, GPU migration (ADR-0032) re-enters scope and adds
   2+ milestones. Architect and PM both demand an explicit ruling before scope freeze.

2. **IPv6 + encrypted overlays (M25).** Architect classifies both as
   north-star-**blocking** ("all clients" includes v6 and default-encrypted clusters);
   PM classifies both as **post-v1.0** epics needing a second maintainer. Direct
   conflict on whether the north star is "complete" without them.

3. **ARM64 boundary.** The north star is empirically certified amd64-only at the beta
   gate (M28), but the literal "all containers / all clients" could be read to require
   ARM64 production parity. Is amd64-only an acceptable north-star scope boundary for
   v1.0?

4. **Cilium production sizing.** PM warns Cilium eBPF is treated as a flag-flip but is
   realistically a multi-quarter epic and a likely v1.0-gating item. Is a second
   maintainer / funded contributor committed **before** M24, or does Cilium scope
   dominate the post-launch roadmap?

5. **Bus factor / second maintainer.** Sandbox (M29) is reachable solo, but incubation
   and the v1.0 matrix (M30) are structurally impossible solo — CNCF requires documented
   adopters and a second maintainer org. The "no git push until launch" posture cannot
   generate adoption signals before M29. Who owns the non-engineering path from sandbox
   to incubation, and when does maintainer recruitment start?

6. **Service-mesh sidecar claim timing.** Is sidecar transparency proven (M22) **before**
   the public "every sidecar" claim is published at launch (M29)? Publishing the claim
   before validation risks credibility collapse if Envoy/Istio mesh-internal
   connections do not survive at `seq_delta=0`.

7. **Beta gate definition.** Confirm the M28 gate runs against the TRUE north-star
   workload set (multi-container + Service + dual-stack), **not** the weaker M18.5
   single-flow / single-container definition. The architect asserts the gate is invalid
   otherwise.

8. **Milestone-count realism.** The synthesized plan is 9 net milestones (M22–M30) vs.
   the 4 originally planned (M22–M25). If M22 reveals deep CRIU shared-namespace
   ordering problems, add 1–2 more (realistic range 10–11). Is leadership aligned on the
   longer, ADR-0045-compliant timeline over the faster but weaker-definition path?

---

## 8. Where to Go Next

- **Implementation detail for M19–M25:** [`docs/SPRINT_PLAN_M19_M25.md`](./SPRINT_PLAN_M19_M25.md).
- **This document** is the overview: north star, foundation, milestone map, and open
  questions. Update it when a milestone lands or a quorum ruling resolves an open
  question.
