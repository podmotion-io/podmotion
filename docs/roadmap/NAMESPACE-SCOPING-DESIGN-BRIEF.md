# PodMotion Namespace-Scoping — Feasibility Design Brief

Status: Draft / feasibility design
Author: Platform architecture (Opus)
Date: 2026-06-14
Surface tag: `multitenancy / scoping`
Related: ADR-0012 (TrafficVerified gate), ADR-0118 (agent cache), ADR-0146 (checkpoint tmpfs)

---

## 1. Executive Summary

Yes, namespace scoping is feasible and worth doing — the **operator's control-plane reach** (which PodMigration/MigrationPolicy CRs it acts on, which pods it can read/delete, which pod admissions it intercepts) can be cleanly confined to an allow-listed set of namespaces using a combination of a controller-runtime namespaced cache, webhook `namespaceSelector`, and per-namespace RBAC Roles instead of a ClusterRole. The core mechanism is a **namespace label (`podmotion.io/enabled: "true"`) plus optional `MigrationScope` CRD for declarative auditability**, with the operator filtering cache + webhooks + RBAC to matching namespaces. The hard limit: the **node agent's host privileges (hostPID, CAP_SYS_PTRACE, CAP_SYS_ADMIN, CAP_NET_ADMIN) are node-scoped, not namespace-scoped** — there is no kernel mechanism to grant "ptrace only processes in namespace X," so agent-side namespace enforcement is *policy-in-software defense-in-depth*, not a kernel-enforced boundary. Scoping therefore bounds the **operator's blast radius and authority**, but does not reduce the agent's inherent node-level capability.

---

## 2. Component-by-component scoping analysis

### Can be scoped (control-plane authority)

| Component | Current behavior | Scoping mechanism | Confidence |
|-----------|------------------|-------------------|------------|
| **Operator informer cache** | `ctrl.NewManager` with no `Cache.DefaultNamespaces` → watches all namespaces (cmd/main.go:171) | `cache.Options{DefaultNamespaces: map[string]cache.Config{...}}` limits PodMigration / MigrationPolicy / MigrationCheckpoint / Pod / PVC / EndpointSlice informers to allowed namespaces | High |
| **PodMigration reconciler** | Reconciles PodMigration CRs in any namespace | Naturally follows the namespaced cache — it only sees CRs the cache delivers | High |
| **Pod delete / read authority** | ClusterRole grants cluster-wide `pods [delete,get,list,watch]` (clusterrole.yaml:13-15) | Replace ClusterRole pod rules with per-namespace **Roles + RoleBindings** generated for each allowed namespace | High |
| **Pod mutating webhook** (injects scheduling gate / IPAM into replacement pods) | Fires for ALL pod CREATE (pod_webhook.go:47) | `namespaceSelector` on the MutatingWebhookConfiguration keyed to `podmotion.io/enabled` | High |
| **Eviction interceptor webhook** (denies eviction mid-migration) | Fires for ALL pod eviction subresource | Same `namespaceSelector` | High |
| **PodMigration validating/mutating webhook** | Fires on `podmigrations` CR ops in any namespace | `namespaceSelector` — but lower value (CR creation is already RBAC-gated) | Medium |
| **MigrationPolicy reconciler** | Namespaced CRD; triggers automated migrations | Follows namespaced cache; only evaluates policies in allowed namespaces | High |
| **MigrationCheckpoint reconciler / GC** | Namespaced CRD | Follows namespaced cache | High |

### Must stay cluster-scoped (architectural)

| Component | Why it cannot be namespace-scoped |
|-----------|-----------------------------------|
| **NodeMigrationCapacity (NMC)** | Cluster-scoped CRD; one per node; agent-authored. Nodes are not namespaced — capacity advertisement is inherently cluster-wide. The operator must read NMC across the cluster to schedule destinations. Keep NMC RBAC cluster-scoped (it is *node* data, not *tenant* data). |
| **Node objects** | `nodes [get,list,watch]` — nodes are cluster-scoped resources; required for destination scheduling and IP/route handoff. |
| **Webhook configurations themselves** | `validatingwebhookconfigurations / mutatingwebhookconfigurations` are cluster-scoped admission objects; the operator patches CA bundles. Cluster RBAC required, but the *effect* of the webhooks is namespace-filtered by `namespaceSelector`. |
| **The node agent DaemonSet** | Runs on every node by definition (it must be present wherever a migratable pod could land). Its host capabilities are node-level. See §5. |

### Cannot be meaningfully scoped at the kernel level

The **agent's host privileges**. hostPID + CAP_SYS_PTRACE let CRIU attach to *any* PID on the node; CAP_NET_ADMIN/CAP_SYS_ADMIN let it load BPF and manipulate any netns/mount. The kernel grants these per-process, not per-target-namespace. A pod from namespace X and a pod from namespace Z on the same node are *both* reachable by the same agent process. See §5.

---

## 3. Recommended design

**Option D (Hybrid): namespace label selector + `MigrationScope` CRD for declarative source-of-truth, with Helm-generated per-namespace RBAC.**

Rationale for choosing D over the alternatives:

- **Option A (label-only)** is the right *enforcement* primitive (webhooks and cache both consume namespace labels efficiently) but gives no declarative, auditable, cluster-visible answer to "what is PodMotion allowed to touch?" A reviewer or platform team has to `kubectl get ns -l podmotion.io/enabled` and trust nobody mislabeled.
- **Option B (CRD-only)** gives auditability but a CRD field alone does not enforce anything — the operator would still need to translate it into a cache filter and into RBAC, and RBAC cannot be driven by a CRD at admission time (the API server authorizes against Roles, not against your CRD).
- **Option C (Helm-only)** produces correctly scoped RBAC and webhook selectors at install time, but is static — adding a namespace means a `helm upgrade`, and there is no in-cluster object describing current scope.
- **Option D** combines them: the **label is the enforcement key** (cache + webhook selector + RBAC RoleBinding target), the **`MigrationScope` CRD is the declarative intent + audit record + status reconciliation surface**, and **Helm generates the initial RBAC/selectors**. The operator's `MigrationScope` reconciler can label namespaces, generate/prune per-namespace RoleBindings, and report drift in `status`.

`MigrationScope` (cluster-scoped CRD) shape:

```yaml
apiVersion: migration.podmotion.io/v1alpha1
kind: MigrationScope
metadata:
  name: default          # singleton, like MigrationWebhookConfig
spec:
  mode: AllowList        # AllowList | LabelSelector
  namespaces: [team-a, team-b, payments]   # explicit allow-list
  # OR
  namespaceSelector:
    matchLabels: { podmotion.io/enabled: "true" }
status:
  resolvedNamespaces: [team-a, team-b, payments]
  rbacReady: true
  cacheRestartRequired: false
  conditions: [...]
```

**Important constraint on the cache:** controller-runtime resolves `DefaultNamespaces` at manager construction time (cmd/main.go:171, *before* `mgr.Start`). It is **not hot-reloadable**. So `MigrationScope`-driven cache changes require an operator restart (or a rollout). The recommended pattern: the `MigrationScope` reconciler manages **labels + RBAC live**, but a change to the *set of cached namespaces* sets `status.cacheRestartRequired: true` and the operator self-restarts (or the Helm chart drives the namespace list and a `helm upgrade` rolls the Deployment). For v1, drive the cached set from Helm values and use `MigrationScope` to manage labels/RBAC/audit; treat cache as install-time config. This is honest and avoids pretending the cache is dynamic.

---

## 4. Implementation outline

### Operator (`cmd/main.go`)
- Add `--watch-namespaces` (comma-list) and/or `--scope-label-selector` flags, OR read a `SCOPE_NAMESPACES` env from the chart.
- Build `cache.Options.DefaultNamespaces` (or `Cache.DefaultLabelSelector` on Namespace) and pass into `ctrl.Options{Cache: ...}`. Leave NMC and Node informers cluster-scoped via `cache.Config{}` per-object overrides (controller-runtime supports per-object namespace config via `Cache.ByObject`).
- Add a `MigrationScopeReconciler` (new controller, cluster-scoped) that: resolves `spec` → namespace set, ensures `podmotion.io/enabled` labels, ensures per-namespace `RoleBinding`s to a shared `podmotion-namespace-role`, prunes stale bindings, writes `status`.

### Webhooks (chart `webhook.yaml`)
- Add `namespaceSelector` to the **pod mutating** and **eviction** webhook configurations (these are the ones that fire on tenant workloads). Key on `podmotion.io/enabled`.
- Leave the PodMigration CR webhooks unselected or selected — low risk either way; CR creation is RBAC-gated.

### Agent (`cmd/agent/main.go`, `internal/agent/server`)
- Add **RPC-layer namespace validation** (defense-in-depth): on `Checkpoint` / `Restore` / `PrepareSource`, the agent already fetches the PodMigration CR (lines 201-212) — extend that to refuse the RPC if `pmCR.Spec.SourcePodNamespace` is not in the agent's configured allow-list (passed via env `SCOPE_NAMESPACES`).
- This is **policy enforcement in software**, not a kernel boundary. Document it as such. It defends against an operator bug/typo, not a compromised operator with valid mTLS (a compromised operator could lie about the namespace, since the agent trusts the CR/RPC).
- More valuable hardening: scope the agent's *Kubernetes RBAC* (the agent's own ClusterRole, clusterrole.yaml:62) so the agent's ServiceAccount can only `get pods` in allowed namespaces — this limits what a compromised agent can *enumerate* via the API, though not what it can *ptrace* on the node.

### Helm chart
- New values block:
  ```yaml
  scope:
    enabled: false
    mode: cluster          # cluster | namespaced
    namespaces: []         # used when mode: namespaced
  ```
- When `scope.mode: namespaced`: template emits per-namespace `Role` + `RoleBinding` for pod/PVC/endpointslice verbs instead of the cluster-wide pod rules in the ClusterRole; emits `namespaceSelector` on pod/eviction webhooks; sets operator `--watch-namespaces`; sets agent `SCOPE_NAMESPACES` env.
- Keep NMC/Node/webhook-config rules in the (smaller) ClusterRole unconditionally.

---

## 5. The privilege boundary problem (honest statement)

The agent is, by design, a **blind, privileged RPC executor**. It needs:
- `hostPID: true` + `CAP_SYS_PTRACE` so CRIU can attach to the target container's PID in the host PID namespace.
- `CAP_SYS_ADMIN` for mount-namespace manipulation and BPF program load.
- `CAP_NET_ADMIN` for XDP/TC/iptables datapath surgery.

These are **node-level capabilities**. The Linux kernel has no primitive for "ptrace only processes belonging to Kubernetes namespace X" — Kubernetes namespaces are an API-server abstraction with no kernel representation. Once a process holds `CAP_SYS_PTRACE` and shares the host PID namespace, every PID on that node is reachable.

Therefore:

- **What scoping provides:** It confines the *operator's authority* — which CRs it reconciles, which pods it is RBAC-permitted to delete/read, which admissions it intercepts. A correctly scoped operator will *never issue* a Checkpoint RPC for a pod in an out-of-scope namespace. This bounds the blast radius of **operator bugs, misconfigured MigrationPolicies, and the descheduler creating unwanted PodMigration CRs**.
- **What scoping does NOT provide:** It does not reduce the agent's *capability*. A compromised agent, or a compromised operator that forges an in-scope CR pointing at an out-of-scope PID, can still reach any process on the node. Agent-side namespace checks are **defense-in-depth against accidents, not a security boundary against a determined adversary with cluster footing.**

This is the same honest posture as kubelet itself, node-problem-detector, or any CSI node plugin: node-level privileged DaemonSets are *trusted node components*. The correct framing is: **PodMotion scoping is a tenancy-of-authority story for the control plane, layered on a trusted privileged node agent** — not a claim that the node agent is sandboxed per-namespace.

---

## 6. CNCF sandbox value proposition

A namespace-scoping story materially strengthens the submission, *if framed honestly*.

**Questions it answers well (TAG-Security):**
- *"Does the operator follow least-privilege?"* — Yes: optional per-namespace RBAC replaces a cluster-wide pod-delete ClusterRole; the operator can be confined to a tenant subset.
- *"Can a platform team bound which workloads PodMotion can act on?"* — Yes, declaratively via `MigrationScope` + namespace labels, auditable with `kubectl get migrationscope`.
- *"What is the blast radius of an operator bug / runaway MigrationPolicy?"* — Bounded to in-scope namespaces.
- *"Is admission interception minimized?"* — Yes: `namespaceSelector` means out-of-scope pods are never sent to the webhook, reducing both attack surface and availability risk (a webhook outage cannot block pod creation in unrelated namespaces).

**Questions it does NOT answer (be upfront — reviewers respect candor):**
- *"Is the node agent's privilege namespace-confined?"* — No. The agent is a trusted privileged node component (like a CSI node plugin or kubelet). Document the threat model explicitly: scoping confines *control-plane authority*, the agent remains node-trusted.
- *"Can a compromised operator be prevented from reaching other namespaces' processes?"* — Not by namespace labels alone; the agent trusts the operator over mTLS. Mitigations to *mention* as roadmap, not claim as done: mTLS SPIFFE identity per operator, RPC request signing tied to the CR's RBAC-authorized creator, and an admission-time check that the RPC's target PID actually belongs to the claimed pod.

**Net framing for the sandbox application:** "PodMotion supports namespace-scoped operation: platform teams declare an allow-list of namespaces (`MigrationScope`), and the operator's cache, RBAC, and admission interception are confined accordingly, bounding control-plane blast radius. The node agent remains a trusted privileged DaemonSet — consistent with the CSI/CRI node-component model — and we document this boundary explicitly rather than overclaiming per-namespace kernel isolation." That is a *more* credible posture than a hand-wavy "fully multi-tenant" claim a reviewer would immediately puncture.

---

## 7. ADR recommendation

**Yes — promote to an ADR.** Suggested: **ADR-0150 (or next free number) "Namespace Scoping of Control-Plane Authority."**

- **Surface tag:** `multitenancy / scoping` (control-plane), with an explicit cross-ref to `security / node-agent-trust`.
- **Blast radius:** Medium. Touches `cmd/main.go` (cache options — manager-construction risk, not hot-reloadable), the Helm RBAC templates (ClusterRole → conditional Role/RoleBinding), webhook configs (`namespaceSelector`), a new `MigrationScope` CRD + reconciler, and an agent RPC guard. No change to the migration state machine, CRIU path, or datapath. Default OFF (`scope.enabled: false`) preserves current cluster-wide behavior — backward compatible.
- **Key decisions the ADR must record:**
  1. Cache namespace set is **install-time** (Helm-driven), not hot-reloadable; `MigrationScope` manages labels/RBAC live but flags `cacheRestartRequired`.
  2. NMC and Node access remain **cluster-scoped** (node data is not tenant data).
  3. Agent-side namespace check is **defense-in-depth (anti-accident), explicitly NOT a security boundary**.
  4. Default OFF for backward compatibility.
- **Chaos assessment (required):** must cover (a) operator behavior when a `MigrationScope`-listed namespace is deleted mid-migration, (b) RBAC RoleBinding prune race vs. in-flight reconcile, (c) webhook `namespaceSelector` label removed from a namespace with an active PodMigration.
