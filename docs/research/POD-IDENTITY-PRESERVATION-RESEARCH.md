# Pod Identity Preservation — Opus Research Quorum Findings
**Date:** 2026-06-14  
**Quorum:** 7 Opus domain experts + 1 Opus lead architect synthesizer  
**Question:** Can PodMotion be developed to the point where `kubectl watch pod <name>` shows ONLY `spec.nodeName` changing during a live migration — same pod UID, same pod name, same pod IP, same everything?

---

## The Honest Answer: No on Stock Kubernetes — But Closer Than You Think

True KVM-equivalent identity preservation on stock Kubernetes today is **architecturally impossible**. Three independent invariants block it:

1. **`spec.nodeName` is immutable after binding** — enforced in `pkg/apis/core/validation/validation.go` → `ValidatePodUpdate`; the `pods/binding` subresource is write-once and rejects rebind with a conflict
2. **`metadata.uid` is server-minted on create** — no API path accepts a caller-chosen UID; `BeforeCreate` in the apiserver registry mints it
3. **Kubelet ownership is welded to `spec.nodeName`** — each kubelet watches `fieldSelector=spec.nodeName=self`; losing ownership means terminate and GC; no two-kubelet handoff protocol exists

**Root cause vs KVM:** libvirt/Nova store "host" as a *mutable column* on a host-agnostic domain record. In Kubernetes the Pod object *is* its own binding — no indirection. To move the node you must create a new object; a new object gets a new UID; the watch stream shows DELETE+ADD, never a single MODIFY. The single field the question wants to be "the only change" is the single field Kubernetes most specifically forbids changing.

---

## What IS Achievable Today (No Upstream Changes)

Reframe the North Star: not *control-plane object-identity transparency* but **datapath + workload-facing identity transparency** — which is exactly what KVM peers actually observe. A VM's libvirt UUID is invisible to its network peers.

| Facet | Achievable today? | Mechanism |
|---|---|---|
| Pod IP | Yes (Calico/Cilium) | IPAM pin + datapath handoff — already partially built |
| MAC address | Yes | CRIU restores veth/netns; pin container-side MAC |
| TCP connections | Yes | TCP_REPAIR + eBPF zero-window hold — already built |
| Memory state | Yes | CRIU iterative pre-copy — already built |
| Storage | Yes | 4-tier PVC re-attach — already built |
| Pod name | Yes, sequentially | Reuse after source delete; cleanest for StatefulSet `<set>-<ordinal>` |
| DNS (StatefulSet) | Yes | Same ordinal name = same headless DNS entry |
| Pod UID / object continuity | **No** | Server-minted, immutable — requires upstream KEP |

### Five Specific Builds to Close the Gap

**1. `podmotion-ipam` chainable CNI meta-plugin**
On source `DEL` with in-flight migration annotation, *suppress IP release*. On dest `ADD`, *adopt* the pinned `SourcePodIP` without re-allocating. Closes the release/reacquire race that exists in the current implementation — today conditions verify datapath reachability but Flannel's IPAM store still believes the IP belongs to the old node. Makes IP preservation consistent in the IPAM store, not just on the wire.

**2. Kubelet container-adoption exploit**
Restore CRIU containers via the existing NRI `CreateContainer`/`StartContainer` hooks with the exact `pod-uid`/container-name labels and container-spec-hash the destination kubelet expects, so `computePodActions`/`computeContainerActions` treats SyncPod as a **no-op adopt** instead of starting a fresh copy. Eliminates the double-start and `restartCount` bump — highest-leverage kubelet trick available without upstream changes.

**3. StatefulSet-aware path via scheduling gates (KEP-3521, GA in 1.30)**
For StatefulSet-owned pods, drive the replacement through the StatefulSet controller: recreate `<set>-N` held in `SchedulingGated` pinned to the destination node, restore state + re-attach PVC + pin IP into its sandbox, then ungate. Yields same name, ordinal, PVC, DNS entry, and IP — only UID and a brief transition differ. This is the closest to identity transparency achievable on stock clusters.

**4. Lineage + ownerRef propagation**
Stamp `migration.podmotion.io/predecessor-uid` and `predecessor-name` annotations and copy source `ownerReferences` *before* deleting the source pod. Critical: if the ownerReferences are not propagated before source deletion, the ReplicaSet controller spawns a third pod during the gap. This is entirely within PodMotion's control via the mutating webhook.

**5. `IPAMOwnershipTransferred` condition**
Add a new PodMigration condition proving the IP is *recorded* as owned by the destination in Calico `WorkloadEndpoint` / Cilium `CiliumEndpoint`, not merely reachable on the wire. Today conditions verify datapath reachability only — that gap is how the next scheduler cycle can double-allocate a phantom IP.

---

## IP Preservation Verdict: Yes — CNI-Dependent

| CNI | IP Preservation | Notes |
|---|---|---|
| **Calico** | Clean | Pod IP as `/32 host route via BGP` from each node — no per-node CIDR aggregation required. Request specific IP via `cni.projectcalico.org/ipAddrs`. The /32 moves nodes and BGP reconverges. Direct L3 analog of QEMU gratuitous ARP failover. Caveat: cross-node /32 fragments block affinity (default /26 blocks) and grows BGP route table by one /32 per migrated pod |
| **Cilium** | Partial | Works in `multi-pool` mode or via `io.cilium.ip` annotation with BGP Control Plane (GoBGP) or ipcache update mapping IP → new tunnel endpoint. Node-scoped (`cluster-pool`/`kubernetes`) modes **cannot** move an IP |
| **Flannel** | Datapath-only | Strict per-node /24 IPAM; pod IP is definitionally inside the source node's subnet. PodMotion's VXLAN-FDB injection (ADR-0048, ADR-0133) preserves it at the wire level but Flannel's IPAM store still believes the IP belongs to the old node. Document as datapath-override-only, not true IP mobility |
| **AWS VPC CNI** | See ADR-0036 | Per existing ADR — EKS-specific path already partially scoped |

## UID Preservation Verdict: No — Requires Upstream API Change

UID is load-bearing far beyond `kubectl -o yaml`:
- kubelet pod-dir paths: `/var/lib/kubelet/pods/<uid>/`
- cgroup pod-slice names
- CRI sandbox `pod-uid` label
- CSI volume annotation: `csi.storage.k8s.io/pod.uid`
- `ownerReferences` chains from child resources

The only way to keep a UID is to never create a new object — i.e., the in-place rebind described in the upstream path below, which does not exist yet.

---

## The Upstream Path: KEPs to Advocate For

Frame the entire campaign as: ***"what `virDomainMigrate` does for libvirt domains, for Pods."***

### KEP-1: `pods/relocation` subresource (highest leverage)
Atomically mutate `spec.nodeName` on a bound, Running pod, gated by a `PodRelocation` feature gate + RBAC verb `relocate`. Model directly on **KEP-1287** (in-place pod resize), which already proved a previously-immutable spec field can be made mutable via a dedicated subresource + conditional `ValidatePodUpdate` carve-out. This single change preserves UID for free — no new object, no DELETE+ADD on the watch stream. Target: SIG-Node + SIG-API-Machinery.

### KEP-2: Kubelet ownership-handoff + CRI `RestoreContainer`
Source kubelet relinquishes without SIGTERM/teardown; destination kubelet *adopts* the existing UID's pod directory and CRIU-restored sandbox instead of running fresh. Frame as the symmetric *restore* half of **KEP-2008** (Forensic Container Checkpointing), which deliberately scoped restore-as-same-pod *out* of scope. PodMotion's existing NRI + agent handoff is the natural reference implementation to bring to SIG-Node.

### KEP-3: CNI `MIGRATE`/handoff verb at cni.dev
Paired `ADD --reserve-from` + `DEL --no-release` so an endpoint's IPAM allocation transfers atomically across nodes without the IP returning to the free pool. CNI today has only ADD/DEL/CHECK/GC/STATUS — no MOVE primitive. PodMotion can prototype this as the `podmotion-ipam` meta-plugin (see build #1 above), then drive standardization at cni.dev once proven in production.

---

## Recommended Nav Point for Consideration

**"Workload-Facing Identity Transparency"**

Scope: prove that from the perspective of every peer, client, and dependent — network, TCP connections, DNS, storage — a migrated pod is indistinguishable from the original. The control-plane UID difference becomes an implementation detail visible only to tooling that inspects UIDs directly.

Candidate sprint work:
- `podmotion-ipam` meta-plugin: IP release suppression on source DEL, IP adoption on dest ADD (Calico-first)
- `IPAMOwnershipTransferred` condition: proves IPAM store consistency, not just datapath reachability
- Kubelet container-adoption via NRI: eliminate `restartCount` bump, achieve no-op SyncPod adopt
- StatefulSet-gated path: same name, ordinal, PVC, DNS, IP via SchedulingGate pin
- Predecessor lineage annotations: ownerRef + predecessor-uid stamped before source delete
- Calico /32 BGP convergence proof artifact: `kubectl watch` shows only node field transition; seq_delta=0 on all TCP connections through the migration; IP unchanged in `kubectl get pod -o wide`

**Gate criterion (provable):**
```
kubectl get pod <name> -o wide --watch
```
Output during migration: a single line where only the NODE column changes. IP column unchanged. Pod name unchanged. (UID difference remains — but is not visible in this view, which is what operators actually watch.)

---

## Relation to Existing ADRs

| Existing ADR | Relationship |
|---|---|
| ADR-0048 (overlay-native L3 IP identity) | Foundation — destination netns pre-staged with correct IP. IPAM meta-plugin extends this to IPAM-store consistency |
| ADR-0082 (Calico/Cilium overlay injection strategy) | Directly relevant — Calico /32 BGP path is the recommended CNI for IP preservation |
| ADR-0085 (PVC identity rebinding) | StoratSS path builds on this |
| ADR-0033 (StatefulSet ordinal order) | StatefulSet-gated scheduling path must honor this |
| ADR-0119 (NRI hook annotation propagation) | Kubelet adoption exploit extends the NRI hook path |
| docs/kep/kep-XXXX-kubelet-restore-api.md | Upstream KEP draft already in repo — aligns with KEP-2 above |

---

*Generated from an 8-agent Opus research quorum on 2026-06-14. All seven domain experts (KVM/QEMU, etcd/API server, CNI/IPAM, kubelet, CRI/container runtime, scheduler/admission, StatefulSet) reached unanimous consensus on the UID preservation verdict. IP preservation and the three upstream KEPs represent the synthesis architect's recommended path forward.*
