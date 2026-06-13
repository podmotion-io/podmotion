# Headless Service & Direct Pod-IP Migration Matrix — All CNIs and K8s Distributions

- Status: Research / Design recommendation
- Date: 2026-06-13
- Author: Network architecture sweep (Opus)
- Supersedes parts of: ADR-0129 (Headless Service / direct pod IP migration)
- Related: ADR-0125 (CRIU `--join-ns net:<path>` restore), ADR-0122 (restored-process pod network wiring), ADR-0046 (no mutation of workload objects), ADR-0001 (ValidatingAdmissionWebhook pre-flight gate)

## 1. Purpose and framing

PodMotion's in-cluster IP-handoff toolkit — gratuitous ARP, eBPF XDP bridge,
TCP_REPAIR socket export, and (per ADR-0125) restoring the process *into the
replacement pod's already-CNI-wired netns* — all assume that after migration the
client can still reach the workload at an address it already holds.

That assumption is satisfied in exactly two ways:

1. **A stable indirection layer absorbs the IP change.** ClusterIP Services: the
   client talks to a VIP, and kube-proxy / eBPF (Cilium, kube-proxy iptables/IPVS)
   rewrites the destination to the current pod IP. The pod IP can change freely.
2. **The pod IP itself is preserved across the move.** This is only possible when the
   CNI's data plane allows a specific /32 (or /128) to be *re-homed* to a different
   node — via route advertisement, alias-IP reassignment, or secondary-IP move.

Headless Services (`clusterIP: None`) and direct-pod-IP access patterns have **no
indirection layer**. The client resolves to, caches, and connects to the raw pod IP.
For those scenarios PodMotion's only correctness lever is option (2) — actual IP
preservation — and whether (2) is achievable is **entirely a function of the CNI and
the cloud substrate**, not of anything PodMotion can do in-cluster.

This document catalogues every such scenario, decides Block/Warn/Support per
CNI/platform, and sketches the v2.0 `NetworkProvider` interface that would unlock the
supportable cases.

---

## 2. The decision matrix

Legend for **PodMotion Action**:
- **BLOCK** — ValidatingAdmissionWebhook rejects the PodMigration in v1.0.
- **WARN** — allowed, but surfaces a `.status.conditions` warning + docs caveat
  (used where the IP *is* preserved or the pattern is indirection-backed).
- **SUPPORT (v2.0)** — blocked in v1.0; unlockable by a `NetworkProvider` plugin.

| # | Scenario | CNI / Platform | IP moveable cross-node? | Mechanism if moveable | PodMotion Action | Notes |
|---|----------|----------------|--------------------------|------------------------|-------------------|-------|
| 1 | Headless Svc + StatefulSet per-pod DNS | Any CNI | No (in-cluster); depends on substrate | EndpointSlice/CoreDNS only re-point; IP itself not preserved | **BLOCK** (v1.0) | CoreDNS TTL window + client cache = unbounded gap. See §4.1. |
| 2 | Headless + ExternalDNS → public DNS | AWS VPC CNI | **No (cross-AZ impossible)**; same-AZ only via API | `ec2:AssignPrivateIpAddresses` (same-AZ ENI) | **BLOCK** (v1.0) / SUPPORT same-AZ (v2.0) | Cross-AZ is architecturally impossible. §5. |
| 2 | Headless + ExternalDNS → public DNS | Azure CNI Overlay / GKE DPv2 / Cilium overlay | **Yes** | Route injection / alias-IP / BGP /32 | SUPPORT (v2.0) | Overlay IP not subnet-pinned. §4.2, §4.4–4.6. |
| 3 | Direct pod IP (VPC-routable) | AWS VPC CNI (non-overlay) | Cross-AZ **No**; same-AZ via API | ENI secondary IP reassign | **BLOCK** / SUPPORT same-AZ (v2.0) | §4.3, §5. |
| 3 | Direct pod IP, custom networking | EKS VPC CNI custom networking | Same as above; subnet-per-ENI not per-AZ | Still ENI/AZ-pinned subnet | **BLOCK** | Custom networking changes which subnet, not the AZ pinning. §4.3. |
| 4 | Direct pod IP (VNet-routable) | Azure CNI (non-overlay) | **Yes (same VNet)** | Azure NIC secondary IP move (`az network nic ip-config`) | SUPPORT (v2.0) | Azure allows moving secondary IPs between NICs in a VNet — unlike AWS cross-AZ. §4.4. |
| 4 | Direct pod IP | Azure CNI Overlay | **Yes** | Route injection (CIDR not in VNet) | SUPPORT (v2.0) | Most migration-friendly Azure mode. §4.4. |
| 5 | Direct pod IP | GKE Dataplane V2 (Cilium) | **Yes** | Alias IP range move / Andromeda route + Cilium BGP /32 | SUPPORT (v2.0) | Andromeda is a virtual network; alias IPs are reassignable. §4.5. |
| 6 | Direct pod IP | Flannel VXLAN | **No** (per-node CIDR) | Would need VXLAN FDB + ARP injection cross-node | **BLOCK** | Pod CIDR is partitioned per node; /32 cannot leave its node CIDR without FDB surgery. §4.6. |
| 6 | Direct pod IP | Calico BGP | **Yes** | Inject /32 host route advertised from dest node | SUPPORT (v2.0); WARN if user pre-wires | Calico's native /32 advertisement is the cleanest in-cluster preservation. §4.6. |
| 6 | Direct pod IP | Cilium + BGP Control Plane | **Yes** | /32 announced via Cilium BGP from dest node | SUPPORT (v2.0) | Same /32 model as Calico. §4.6. |
| 6 | Direct pod IP | Cilium overlay (VXLAN/Geneve, no BGP) | Conditional | Tunnel endpoint remap (ipcache) | SUPPORT (v2.0, risky) | Cilium ipcache could be steered but is internal/unstable. §4.6. |
| 7 | StatefulSet stable identity | Any | N/A (name cannot be duplicated) | — | **BLOCK** | Use StatefulSet rolling update, not PodMotion. §4.7. |
| 8 | HostNetwork: true | Any | No ("IP" is the node IP) | — | **BLOCK** | Migrating changes the node → changes the IP. §4.8. |
| 9 | hostPort | Any | No (node IP:port) | — | **BLOCK** | Same root cause as HostNetwork. §4.9. |
| 10 | `externalTrafficPolicy: Local` (NodePort/LB) | Any | N/A (not a pod-IP problem) | LB health-check reconverge | WARN | Traffic-cutover gap, not an addressing failure. §4.10. |

---

## 3. Why ClusterIP is the baseline (and why headless is different)

For a ClusterIP Service the client connects to a stable VIP. The dataplane
(kube-proxy iptables/IPVS DNAT, or Cilium's eBPF service backend map) holds the
VIP→pod-IP mapping and is updated from EndpointSlices. PodMotion changes the pod IP;
the dataplane re-points the VIP to the new pod IP; the client never learns the pod IP
at all. **This is the case PodMotion fully supports today.** TCP connections to the
VIP are preserved by TCP_REPAIR + eBPF bridge because the conntrack/CT entry can be
rewritten to the new backend.

Headless Services delete that indirection on purpose — their entire reason for
existing is to expose individual pod IPs (for StatefulSet identity, peer discovery,
client-side load balancing, gossip protocols). The client holds the pod IP. There is
nothing for PodMotion to rewrite on the client side. The only fix is to make the old
pod IP answer from the new node — i.e. IP preservation — which is a CNI/substrate
capability question.

---

## 4. Per-scenario analysis

### 4.1 Generic headless Service (clusterIP: None) — any CNI

A StatefulSet's headless Service publishes `pod-0.svc.ns.svc.cluster.local` →
pod-0's IP via EndpointSlices, which CoreDNS serves. When PodMotion migrates pod-0,
Kubernetes assigns the replacement a new IP, the EndpointSlice is updated, and
CoreDNS begins serving the new IP — but only after its record TTL (default 30s for
the kubernetes plugin, often 5s in tuned clusters) expires, and only for clients that
re-resolve. Clients that cached the old A record (Java's default `networkaddress.
cache.ttl`, glibc nscd, application-level connection pools pinned to an IP) keep
hitting the dead address. The window is **unbounded** because client-side cache TTLs
are not observable or controllable by PodMotion.

Could PodMotion patch the EndpointSlice to keep the old IP during migration? It can
write the bytes, but that does not make packets to the old IP arrive at the new pod —
the EndpointSlice is just a routing-table input for CoreDNS, not a forwarding rule.
Unless the underlying CNI also preserves the IP (§4.3–4.6), patching the EndpointSlice
publishes a lie. And mutating EndpointSlices that a StatefulSet controller co-owns
risks fighting the endpoint controller (ADR-0046 territory). **Verdict: BLOCK in v1.0
regardless of CNI**, because the generic case cannot assume an IP-preserving substrate.
The CNI-specific SUPPORT paths in §4.3–4.6 are what relax this.

### 4.2 ExternalDNS + Headless → public DNS (generic)

ExternalDNS watches Services/EndpointSlices and writes pod IPs into Route 53 / Azure
DNS / Google Cloud DNS as A records. This is the same TTL-window problem as §4.1 but
worse on two axes: (a) public-DNS TTLs are often 60–300s and resolvers across the
internet honor them independently; (b) ExternalDNS's own reconcile interval (default
1m) adds latency before the record even changes. The migration-correctness question
still reduces to "is the pod IP preserved?": if yes (overlay route injection on Azure
Overlay / GKE / Cilium-BGP), the DNS record is still *correct* after migration and the
window is irrelevant; if no (AWS VPC CNI cross-AZ), no DNS trick closes the gap.
ADR-0129 Option B (TTL drain) is rejected for the same unbounded-window reasons and is
reaffirmed here. **Verdict: BLOCK in v1.0**; SUPPORT only where the CNI preserves the IP.

### 4.3 AWS VPC CNI (non-overlay)

Pod IPs are secondary private IPs on a node's ENI, drawn from the **subnet that ENI is
attached to**. In a standard EKS layout there is one subnet per Availability Zone, so
a pod IP is, in practice, an AZ-pinned address. Same-AZ moves *can* preserve the IP via
`ec2:AssignPrivateIpAddresses` on the destination node's ENI plus VPC CNI coordination
to wire that secondary IP to the new pod's veth, then `ec2:UnassignPrivateIpAddresses`
on the source ENI. This is ADR-0129 Option C and is genuinely viable — but only
same-AZ, only with IAM permissions, only within ENI per-instance IP limits, and with a
tight, unstable coupling to the aws-node DaemonSet. **EKS VPC CNI custom networking**
changes *which* subnet a pod draws from (a dedicated pod subnet per ENI/node rather
than the node's primary subnet) but does **not** lift the AZ pinning — those pod
subnets are still per-AZ. Custom networking therefore does not change the verdict.
**Verdict: BLOCK in v1.0; SUPPORT same-AZ via v2.0 AWS provider plugin.**

### 4.4 Azure CNI (non-overlay) vs Azure CNI Overlay

**Azure CNI (non-overlay)** assigns pod IPs from the VNet subnet as secondary IP
configurations on the node's NIC. Crucially — and unlike AWS cross-AZ — **Azure
supports moving a secondary IP configuration between NICs within the same VNet** via
the Azure network API (`az network nic ip-config delete` on the source NIC then
`create` on the destination NIC, or the equivalent ARM call). Azure VNets are not
AZ-partitioned the way AWS subnets are; a VNet subnet spans the region and IPs are not
hard-pinned to one AZ's ENI. This makes Azure non-overlay *more* migration-friendly
than AWS: same-VNet IP preservation is API-achievable and not AZ-constrained. **Azure
CNI Overlay** is the friendliest: pod IPs come from a private CIDR that is *not part of
the VNet* and is reached via host routing on each node. Preserving the IP is then a
route-injection problem (advertise the /32 from the destination node) rather than a
cloud-API problem. **Verdict: both SUPPORT (v2.0); Overlay is the lower-risk target.**

### 4.5 GKE (Dataplane V2 / Cilium-based)

GKE pod IPs are alias IP ranges assigned to the VM's NIC and routed by Google's
Andromeda SDN; Dataplane V2 uses Cilium for the in-node dataplane. Two preservation
levers exist: (a) Andromeda alias-IP ranges/routes can be reprogrammed so a specific
/32 routes to a different VM, and (b) with Cilium's BGP control plane a /32 can be
advertised from the destination node. Because Andromeda is a virtual network (no
physical AZ subnet ownership like AWS ENIs), the IP is not substrate-pinned to one
node. **Verdict: SUPPORT (v2.0)** via a GCP provider plugin (alias-IP move) and/or the
generic Cilium-BGP path.

### 4.6 Flannel / Calico / Cilium on bare-metal / self-managed

- **Flannel (VXLAN):** each node owns a slice of the pod CIDR (e.g. `10.244.1.0/24` on
  node-1, `10.244.2.0/24` on node-2). A pod IP is structurally part of its node's
  subnet; routing to it is driven by the VXLAN FDB and the per-node route that says
  "10.244.1.0/24 is behind node-1's VTEP." Moving a single /32 to another node would
  require injecting host-specific FDB + ARP/neighbor entries cluster-wide and a /32
  route override on every node — fragile, racy, and not something Flannel exposes.
  **Verdict: BLOCK.**
- **Calico (BGP):** Calico advertises routes per node and *natively supports /32 host
  routes*. You can have the destination node advertise the specific pod /32 via BGP, so
  the fabric routes that exact IP to the new node — clean, well-supported IP
  preservation. This is the canonical in-cluster preservation mechanism and the model
  the v2.0 provider interface should target first. **Verdict: SUPPORT (v2.0); WARN if a
  user has already wired the /32 advertisement themselves.**
- **Cilium + BGP Control Plane:** same /32-announcement model as Calico via Cilium's
  BGP control plane. **Verdict: SUPPORT (v2.0).**
- **Cilium overlay (VXLAN/Geneve, no BGP):** the pod IP→node mapping lives in Cilium's
  ipcache (a distributed map). Re-homing a /32 means steering ipcache to point the IP
  at the destination node's tunnel endpoint. Technically possible but reaches into
  Cilium internals with no stable contract. **Verdict: SUPPORT (v2.0, flagged risky).**

### 4.7 StatefulSet-specific stable-identity patterns

A StatefulSet guarantees a *stable network identity*: `name-ordinal.svc` resolves to
that ordinal's pod, and the **pod name itself is part of the contract**. PodMotion
restores the workload into a *replacement pod* (ADR-0125: join the replacement pod's
netns). A replacement pod cannot reuse the original's name — Kubernetes forbids two
pods with the same name in a namespace, and the StatefulSet controller owns the naming.
So even if the IP were preserved, the DNS name `name-0.svc` would point at the
controller's own pod-0, not PodMotion's replacement. PodMotion and the StatefulSet
controller would fight over identity. The correct tool for moving a StatefulSet pod is
the StatefulSet's own rolling-update / delete-and-reschedule mechanism, which the
controller coordinates. **Verdict: BLOCK pods owned by a StatefulSet** (detected via
`ownerReferences` kind=StatefulSet), independent of the headless-Service check.

### 4.8 Pod with `hostNetwork: true`

The pod shares the node's network namespace and uses the **node IP** — there is no
pod IP and no per-pod veth/CNI allocation. "Preserving the IP" would mean preserving
the source node's IP on the destination node, which is nonsensical (the destination is
a different node with a different IP). Per ADR-0125 the restore joins the replacement
pod's netns, but a hostNetwork pod's netns *is* the host netns, so the entire
join-netns model does not apply. **Verdict: BLOCK** at the webhook.

### 4.9 Pod with `hostPort`

A hostPort publishes a port on the **node's IP** (via a CNI portmap plugin / iptables
DNAT from nodeIP:port → podIP:port). Clients connect to `nodeIP:hostPort`. After
migration the workload lives on a different node with a different node IP; the old
`nodeIP:hostPort` mapping is gone and the new node's mapping is a different address.
Same root cause as hostNetwork — the externally-meaningful address is the node's, and
the node changed. **Verdict: BLOCK** at the webhook.

### 4.10 Service with `externalTrafficPolicy: Local`

Not a headless / pod-IP addressing failure — included because it is a related cutover
hazard. With `externalTrafficPolicy: Local`, a NodePort/LoadBalancer only forwards to
pods *on the receiving node* and the cloud LB uses node health checks to decide which
nodes get traffic. When PodMotion moves the only local pod off the source node, that
node fails its health check and the LB stops sending it traffic — but only after the
health-check interval (typically several seconds to tens of seconds) detects the
change. In that window the source node may receive traffic with no local backend and
drop it. This converges on its own once the LB reconciles; it does not produce a
permanent failure. **Verdict: WARN** — surface the expected cutover gap; optionally, a
future enhancement could pre-drain by failing the source node's health check before the
pod is removed.

---

## 5. Cross-AZ constraint (AWS VPC CNI) — explicit statement

**For AWS VPC CNI in the standard one-subnet-per-AZ layout, preserving a pod IP across
a cross-AZ migration is architecturally impossible.** A pod IP is a secondary private
IP owned by an ENI, and an ENI is attached to a single subnet, and that subnet belongs
to exactly one Availability Zone. The IP is part of that AZ's subnet CIDR. There is no
AWS API to serve that IP from a node in a different AZ, and ENIs cannot migrate across
AZs. No in-cluster technique (gratuitous ARP, eBPF XDP, BGP /32) can announce a VPC
subnet IP from outside its subnet's AZ, because the VPC fabric routes by subnet/AZ
ownership, not by ARP.

**Same-AZ is the only AWS preservation case** and even then it is conditional:
- Requires `ec2:AssignPrivateIpAddresses` / `ec2:UnassignPrivateIpAddresses` IAM on the
  migration operator.
- Requires coordination with the aws-node (VPC CNI) DaemonSet to wire the reassigned
  secondary IP to the replacement pod's veth.
- Bounded by per-instance-type ENI secondary-IP limits (parallelism cap).
- Coupled to VPC CNI internals with no stable contract.

Consequently the AWS path is **scoped to v2.0 behind an explicit AWS provider plugin**,
restricted to same-AZ migrations, and gated by an IAM/permission pre-check. The
scheduler must additionally constrain destination-node selection to the **same AZ** as
the source whenever IP preservation is requested for an AWS VPC CNI pod; a cross-AZ
destination must hard-fail the preservation request rather than silently fall back.

---

## 6. Recommended webhook pre-flight checks

PodMotion's `ValidatingAdmissionWebhook` should evaluate the following before admitting
a `PodMigration`. Each check is independent; any BLOCK denies with a specific reason
code surfaced in the webhook response and `.status.conditions`.

```
# Check 1 — Headless Service selector match
for svc in services(pod.namespace):
    if svc.spec.clusterIP == "None" and selectorMatches(svc.spec.selector, pod.labels):
        if not providerSupportsIPPreservation(pod):   # v2.0 NetworkProvider, see §7
            DENY PodMigrationReasonHeadlessService
        # exception path: Calico-BGP /32 / future provider plugin → ALLOW (WARN)

# Check 2 — HostNetwork
if pod.spec.hostNetwork == true:
    DENY PodMigrationReasonHostNetwork

# Check 3 — hostPort
for c in pod.spec.containers:
    for p in c.ports:
        if p.hostPort != 0:
            DENY PodMigrationReasonHostPort

# Check 4 — StatefulSet ownership
for ref in pod.metadata.ownerReferences:
    if ref.kind == "StatefulSet" and ref.controller == true:
        DENY PodMigrationReasonStatefulSetOwned
        # message: use StatefulSet rolling update; PodMotion cannot preserve pod identity
```

Reason-code set (extend the existing `PodMigrationReason*` constants):
`PodMigrationReasonHeadlessService`, `PodMigrationReasonHostNetwork`,
`PodMigrationReasonHostPort`, `PodMigrationReasonStatefulSetOwned`.

The headless-Service check is the only one with an exception path: when a registered
`NetworkProvider` (§7) reports `CanPreserveIP(pod) == true` for the source/destination
pair, the migration is admitted with a WARN condition rather than denied. All four
denials must carry an actionable message and a link to this document.

The existing ADR-0129 `podmotion.io/bypass-headless-check: "true"` escape hatch remains
**unsupported** and should additionally be logged at WARN with the pod identity for
audit; consider gating it behind an operator-level feature flag so it cannot be enabled
by a namespace user alone.

---

## 7. v2.0 `NetworkProvider` plugin interface (sketch)

The IP-preservation capability is per-CNI/per-cloud and must not leak into the
CNI-agnostic core. Model it as a pluggable provider the operator selects at install
time (Helm value `networkProvider: none|aws|azure|gcp|calico-bgp|cilium-bgp`).

```go
// internal/agent/network/provider.go
package network

import (
    "context"
    corev1 "k8s.io/api/core/v1"
)

// PreserveRequest describes a single pod-IP preservation across a migration.
type PreserveRequest struct {
    Pod         *corev1.Pod // source pod (holds the IP to preserve)
    PodIP       string      // the /32 (or /128) to keep alive
    SourceNode  string
    DestNode    string
    SourceZone  string      // cloud AZ/zone of source node ("" if N/A)
    DestZone    string      // cloud AZ/zone of dest node
    DestNetnsPath string    // ADR-0125 resolved replacement-pod netns path
}

// PreserveHandle is returned by Preserve and must be released after cutover.
type PreserveHandle interface {
    // Release tears down the preservation (e.g. unassign source ENI IP,
    // withdraw the /32 BGP advertisement) once the destination is serving.
    Release(ctx context.Context) error
}

// NetworkProvider is implemented per CNI/cloud. Registered with the operator;
// nil/none provider => headless & direct-pod-IP migrations are BLOCKED (v1.0 behavior).
type NetworkProvider interface {
    // Name identifies the provider ("aws-vpc-cni", "azure-cni", "gcp-alias",
    // "calico-bgp", "cilium-bgp").
    Name() string

    // CanPreserveIP returns whether THIS request is preservable, plus a human
    // reason when it is not. AWS returns false for any cross-AZ request
    // (req.SourceZone != req.DestZone). The webhook (§6) consults this to decide
    // whether to lift the headless-Service block.
    CanPreserveIP(ctx context.Context, req PreserveRequest) (ok bool, reason string)

    // Preserve makes req.PodIP routable to the destination node/pod. Called after
    // the replacement pod's netns is wired (ADR-0125) and before the source pod is
    // deleted. Idempotent; must be safe to retry.
    Preserve(ctx context.Context, req PreserveRequest) (PreserveHandle, error)
}
```

Per-provider mechanics behind this interface:

| Provider | `CanPreserveIP` constraint | `Preserve` action | `Release` action |
|----------|----------------------------|-------------------|-------------------|
| `aws-vpc-cni` | same-AZ only; IAM present; ENI IP limit not hit | `ec2:AssignPrivateIpAddresses` on dest ENI + VPC CNI wire to veth | `ec2:UnassignPrivateIpAddresses` on source ENI |
| `azure-cni` | same VNet | move secondary ipconfig src NIC → dest NIC | (move is the release; ensure src ipconfig removed) |
| `azure-cni-overlay` | same cluster CIDR | inject /32 host route to dest node | withdraw route |
| `gcp-alias` | same VPC/subnet alias range reachable | reassign alias IP /32 to dest VM (or Cilium BGP) | reassign back / withdraw |
| `calico-bgp` | BGP mesh covers dest node | advertise pod /32 from dest node (Calico API/route) | withdraw /32 advertisement |
| `cilium-bgp` | Cilium BGP CP enabled | announce /32 from dest node | withdraw announcement |

The core controller stays provider-agnostic: it calls `CanPreserveIP` during validation
and `Preserve`/`Release` around the existing IP-handoff step (migration sequence step 9
in CLAUDE.md), bracketing the ADR-0125 restore.

---

## 8. Recommended amendments to ADR-0129

ADR-0129 is correct but **scoped too narrowly** — it frames the problem as "EKS +
ExternalDNS + Route 53." This sweep shows the problem is general and the *resolution
varies by CNI*. Recommended changes:

1. **Re-title / re-scope.** ADR-0129's title should drop the EKS-specific framing; the
   block applies to all headless / direct-pod-IP cases on any CNI. Reference this
   matrix as the authoritative per-CNI breakdown.
2. **Generalize Option C.** ADR-0129 Option C is AWS-ENI-specific. Replace it with the
   `NetworkProvider` interface (§7), of which AWS same-AZ ENI preservation is one
   implementation alongside Azure secondary-IP move, GCP alias-IP, and Calico/Cilium
   BGP /32. AWS is *not* the privileged path — Calico/Cilium BGP and Azure Overlay are
   actually lower-risk and should likely ship first in v2.0.
3. **Add the cross-AZ impossibility statement** (§5) explicitly into ADR-0129's
   Consequences: AWS cross-AZ IP preservation is architecturally impossible, not merely
   deferred. Option C is **same-AZ-only**, requires `ec2:AssignPrivateIpAddresses`, and
   the scheduler must pin the destination to the source AZ when preservation is
   requested.
4. **Promote the non-headless blocks.** ADR-0129 only specifies the headless-Service
   webhook check. Add HostNetwork, hostPort, and StatefulSet-ownership as first-class
   pre-flight denials (§6) — they share the "no preservable pod IP" root cause and
   belong in the same gate.
5. **Reaffirm Option B (TTL drain) and Option D (endpoint surgery) as rejected**, now
   with the generalized reasoning: both are moot where the IP *is* preserved and
   useless where it is not, so neither is ever the right lever.
6. **Cross-reference ADR-0125.** The preservation providers operate around the
   ADR-0125 `--join-ns net:<path>` restore — `Preserve` runs after the replacement
   pod's netns is wired and before source-pod deletion. Note this ordering in 0129.

---

## 9. Summary of verdicts

- **BLOCK in v1.0, all CNIs:** generic headless Service, ExternalDNS-published pod IP,
  AWS VPC CNI direct pod IP, Flannel direct pod IP, StatefulSet-owned pods,
  HostNetwork, hostPort.
- **WARN in v1.0:** `externalTrafficPolicy: Local` (cutover gap, self-healing).
- **SUPPORT in v2.0 via `NetworkProvider`:** AWS same-AZ (ENI reassign), Azure
  non-overlay (NIC secondary-IP move), Azure Overlay (route injection), GKE/Andromeda
  (alias-IP / Cilium BGP), Calico BGP (/32), Cilium BGP (/32). Cilium-overlay-no-BGP is
  possible but flagged risky.
- **Architecturally impossible, never supportable:** AWS VPC CNI cross-AZ IP
  preservation.
