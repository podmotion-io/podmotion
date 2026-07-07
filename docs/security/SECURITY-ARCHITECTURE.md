# PodMotion Security Architecture & Remediation Plan

**Author:** the Lead Architect, K8s OSS Security reviewer
**Date:** 2026-06-14
**Status:** Draft for architecture review
**Design principle:** Solid remediation designs OR better primitives that mitigate risk. Every open finding below carries a concrete design or a lower-level primitive, not generic advice.

---

## Executive Summary

The submitted report is **directionally correct but materially out of date on the parts the codebase has already addressed, and materially understated on the parts it has not.** The single most important finding is this:

> **ADR-0106 ("Security Hardening Baseline") — the ADR that specifies the discrete-capability agent, the custom seccomp profile, fail-closed webhooks, node-pool taints, and the supply-chain gates — was REJECTED in security audit review (`docs/adr/CNCF_AUDIT_REJECTED.md`) and is NOT implemented.** The shipping Helm chart still runs the agent with blanket `privileged: true` (`charts/podmotion/templates/daemonset.yaml:65`), no seccomp profile, no dropped capabilities, and `hostPID: true`. The security design exists on paper, was found non-viable (the `SeccompGuard.Engage()` model is architecturally wrong — see below), and the rejection was never followed by a corrected, accepted ADR. **This is the central gap and the spine of the remediation plan.**

Two further "implemented-on-paper, absent-in-code" gaps compound it:

1. **Checkpoint encryption is dead code.** `internal/agent/encryption/encrypt.go` exists, but `grep` for `agent/encryption` across the whole tree returns **only the package's own test file**. It is wired into nothing — not the CRIU writer, not the P2P transfer, not the registry push. ADR-0029 ("encryption on by default") is unimplemented. Full process-memory checkpoints are written and transferred **in plaintext** today.
2. **mTLS silently fails open.** `internal/agent/tls/tls.go:33-38` returns `nil, nil` (insecure) when cert files are absent, and `cmd/agent/main.go:144` passes that straight to `ListenAndServe`, which logs "without TLS" and serves the **unauthenticated checkpoint/restore gRPC API** (`server.go:1179-1181`). There is no production guard preventing this — exactly the failure ADR-0106 [process rule] was meant to close, and that guard is unimplemented because ADR-0106 was rejected.

The good news: several report claims are **already mitigated**. `failurePolicy: Fail` is set on both webhooks in the chart (`webhook.yaml:67,94`); NetworkPolicy templates exist and isolate agent/operator (`networkpolicy.yaml`); the validating webhook has real, substantial admission logic (`podmigration_webhook.go`); RBAC is reasonably scoped (no wildcards, no cluster-admin); checkpoint dirs are `0700` on tmpfs-intent paths; the agent gRPC server *supports* `RequireAndVerifyClientCert` + TLS 1.3 when certs are present.

**RuntimeClass privilege confusion (report threat #4) does not apply** — PodMotion uses NRI + a DaemonSet agent, not a RuntimeClass. There is no RuntimeClass anywhere in the Go or YAML (`grep` confirms). That threat surface is a non-issue as architected; do not spend a milestone on it.

---

## Part 1 — Current State Assessment

### Threat Surface 1 — Privileged DaemonSet (SYS_ADMIN/SYS_PTRACE/NET_ADMIN)

**What the code does:** `charts/podmotion/templates/daemonset.yaml:64-65` sets `securityContext: { privileged: true }` with `hostPID: true` (line 27) and mounts the host containerd socket **read-write** (lines 69-70, 78-81) and host `/sys` (lines 71-72, 82-84). ADR-0013 documents the full blast radius of containerd-socket compromise (arbitrary container start, exec into any tenant, cross-tenant lateral movement) and **accepts it for v0.1**.

**Already mitigated:** Threat *documented* (ADR-0013 threat model is excellent). NetworkPolicy limits which pods can reach the agent. RBAC is least-privilege at the K8s API layer.

**Genuinely open:**
- `privileged: true` grants ~18 capabilities (SYS_RAWIO, SYS_TIME, NET_RAW, IPC_LOCK, MKNOD, etc.) that CRIU/eBPF never use. ADR-0106 §6 explicitly says "privileged: true is NEVER set" — the chart violates the project's own (rejected, thus unenforced) baseline.
- No seccomp profile (`seccompProfile` absent from chart) — the agent can call **any** syscall.
- containerd socket mounted RW into the steady-state container, not isolated to a restore-only path (ADR-0013 mitigation #1 unimplemented).
- `hostPID: true` exposes every host PID; combined with `process_vm_readv` this is full host-memory read.
- No node-pool isolation: the DaemonSet tolerates **all** taints (`operator: Exists`, lines 32-36), so it lands on control-plane and every tenant node.

**Severity: CRITICAL.** This is full node + cross-tenant compromise on agent breakout, and the agent runs an (optionally) unauthenticated gRPC API (surface #3).

### Threat Surface 2 — CRIU Checkpoint Archives (secrets in memory dumps)

**What the code does:** Checkpoint images written `0o700` to `opts.ImagesDir` (`criu_checkpointer.go:74,141,349`). `zeroizeCheckpoints` (`multi_container_freeze.go:348-355`) removes dirs on exit paths — but is **`os.RemoveAll` only**, with a comment explicitly disclaiming byte-level zeroing. ADR-0002 mandates UID path sanitization via `filepath.Base` + RFC-4122 validation.

**Already mitigated:** Root-only dir perms; removal on documented exit paths; path-traversal hardening per ADR-0002.

**Genuinely open:**
- **Checkpoints are plaintext.** ADR-0029's encryption is unimplemented (see Exec Summary). Full process memory — secrets, JWTs, TLS session keys, KMS creds — lands on disk and on the wire unencrypted.
- "Zeroize" is `RemoveAll`, which on a journaling/overlay fs or a non-tmpfs fallback leaves recoverable blocks. ADR-0106 [process rule] mandates a **tmpfs** mount so removal is RAM-backed, but the chart does not mount a tmpfs `emptyDir` for the checkpoint path — it relies on the host `/run` being tmpfs, which is not guaranteed and not asserted.
- No replay/clone defense: a checkpoint archive is a complete, restorable workload identity. Nothing binds an archive to a single restore (no nonce, no one-time token), so a captured archive can be cloned to an attacker node.

**Severity: CRITICAL** (plaintext secrets at rest + in transit) / **HIGH** (replay-clone).

### Threat Surface 3 — eBPF Programs

**What the code does:** Programs in `bpf/` (pm_relay.c, pm_xdp_vtep.c, xdp_bridge.c, zero_window.c, pm_sk_lookup.c) are TC/XDP programs that rewrite TCP seq/ack and redirect frames. Loaded via cilium/ebpf `spec.LoadAndAssign(objs, opts)` (`bpfloader/*_bpfel.go`). They are compiled CO-RE objects embedded in the binary.

**Already mitigated:** Programs pass the in-kernel **eBPF verifier** at load (memory-safety, bounded-loop, no arbitrary kernel write) — this is a real, strong primitive already in force. Bounded option scans (`pm_relay.c:288` `#pragma unroll` ≤10) are verifier-friendly. Map is a fixed `BPF_MAP_TYPE_HASH` max 4096, not attacker-growable.

**Genuinely open:**
- **No integrity/attestation of the loaded program vs. a known-good hash.** A compromised agent (or a tampered image layer) can load *different* eBPF that the verifier still accepts — the verifier proves safety, not provenance. The XDP/TC datapath programs see every VXLAN frame on the node; a swapped program is a stealth tap.
- **No map pinning ACL.** No `bpffs` pin path with restricted mode; any process with CAP_BPF on the node can `bpf_obj_get` the pinned maps if pinned, or attach competing programs.
- The "periodic manifest verification" the report proposes is the wrong primitive (see Part 3).

**Severity: MEDIUM** (verifier blocks the catastrophic class; provenance/stealth-tap is the residual).

### Threat Surface 4 — RuntimeClass Privilege Confusion

**Not applicable.** No RuntimeClass exists in the codebase. PodMotion targets workloads via NRI hooks + DaemonSet agent keyed on the `podmotion.io/checkpoint-ref` annotation, not a runtime handler. **Severity: N/A.** Recommend the report author re-scope this to "NRI hook scoping" (covered under surface 5/admission).

### Threat Surface 5 — CRD / Controller API Abuse

**What the code does:** `podmigration_webhook.go` enforces ~10 real rules (pod existence, UID match, userfaultfd, NMC readiness/capacity, Tier-4 storage block, hard-affinity conflict, IPv6/IPSec rejection). `failurePolicy: Fail` on both webhooks (`webhook.yaml:67,94`). RBAC restricts who manages CRDs.

**Already mitigated:** Fail-closed admission; capacity gate caps concurrent migrations per node (a real DoS brake); webhook validates the CR refers to a real, matching pod.

**Genuinely open:**
- **No node-trust gate.** Nothing stops a `PodMigration` targeting an arbitrary `targetNodeName` as long as that node has a healthy NMC. There is no `podmotion.io/trusted-node` allowlist — a migration can be steered to any node running the agent, including one an attacker controls.
- **No per-subject authorization on *who* may migrate *which* workload.** Anyone with `create podmigrations` in a namespace can forcibly migrate (and thus checkpoint = dump the memory of) any pod in that namespace. Migration is an implicit `pods/exec`-equivalent power but is not gated like one.
- **Topology leakage:** NodeMigrationCapacity is cluster-readable and advertises kernel version, CRIU version, capacity — a recon map for an attacker. RBAC currently allows broad read.

**Severity: HIGH** (forced-migration-as-dump is a confidentiality break; node-steering enables surface 1/2 escalation).

### Threat Surface 6 — Checkpoint Data At Rest / In Transit

**What the code does:** ADR-0006 mandates mTLS for both P2P and registry transfer; the agent gRPC server supports mTLS (`tls.go:50-56`). ADR-0029 mandates encryption-at-rest.

**Already mitigated (design only):** mTLS *capability* is present and correct (TLS 1.3, `RequireAndVerifyClientCert`).

**Genuinely open:**
- **mTLS fails open** (`tls.go:33-38` → insecure nil config when certs missing; no production assertion). The checkpoint-control + restore API is reachable unauthenticated in that state.
- **Payload itself is unencrypted** independent of TLS (encryption package unwired). If TLS is downgraded/absent, the wire carries plaintext memory.
- **No per-workload storage isolation / auto-delete TTL** for any registry-staged checkpoint (ADR-0034 WAN path). Registry images persist with no enforced GC binding to migration completion.

**Severity: CRITICAL** (fail-open mTLS on a memory-dump API).

---

## Part 2 — Remediation Designs (specific)

### R-1 — Replace `privileged: true` with a discrete capability + seccomp + node-isolation contract

This is the corrected, *viable* version of rejected ADR-0106 §1 and §6. The rejection (`CNCF_AUDIT_REJECTED.md` ADR-0106 crit #2/#3) found the `SeccompGuard.Engage()` model wrong and the `allowPrivilegeEscalation` value disputed (citations to the rejection record retained for traceability). Resolve both:

**Capability set (agent container `securityContext`, replacing `privileged: true`):**
```yaml
securityContext:
  privileged: false
  capabilities:
    drop: ["ALL"]
    add: ["SYS_PTRACE", "SYS_ADMIN", "NET_ADMIN", "BPF", "PERFMON"]
  allowPrivilegeEscalation: true   # REQUIRED: CRIU PTRACE_SEIZE of a more-privileged
                                   # target needs no-new-privs cleared; kernel evidence:
                                   # ptrace of a target with caps the tracer lacks fails
                                   # under no_new_privs. This resolves CNCF crit #3 with
                                   # the kernel-level rationale the panel demanded.
  runAsUser: 0                     # CRIU parasite injection requires uid 0
  readOnlyRootFilesystem: true
  seccompProfile:
    type: Localhost
    localhostProfile: profiles/podmotion-agent.json
```
On kernel ≥5.8, `CAP_BPF`+`CAP_PERFMON` split out the eBPF load/perf rights from the `CAP_SYS_ADMIN` blanket; keep `SYS_ADMIN` only for CRIU's `mount(CLONE_NEWNS)` + tmpfs. This is strictly narrower than `privileged`.

**Seccomp profile** (`charts/podmotion/profiles/podmotion-agent.json`): ship the ADR-0106 [process rule] allowlist **with the corrections from CNCF crit #4** — the prose/JSON `pivot_root` contradiction must be resolved by *removing* `pivot_root`, `kexec_load`, `init_module`/`finit_module`, `delete_module`, `chroot` from the allow list (default `SCMP_ACT_ERRNO`). Validate the allowlist against a real CRIU dump+restore syscall trace (`strace -f criu dump`) in CI rather than hand-curating.

**Node isolation:** replace the catch-all tolerations (`daemonset.yaml:32-36`) with a dedicated taint contract:
```yaml
nodeSelector: { podmotion.io/migration-node: "true" }
tolerations:
  - key: podmotion.io/migration-node
    operator: Equal
    value: "true"
    effect: NoSchedule
```
The agent runs **only** on labeled migration nodes, not control-plane, not every tenant node. This shrinks the blast radius of surface 1 from "whole cluster" to "the migration node pool."

- **ADR:** new **ADR-0148** ("Agent Privilege Containment — supersedes the rejected ADR-0106 §1/§6"). Must explicitly supersede, not re-decide (the rejection reason was corpus conflict).
- **Blast radius:** every node, every workload — high-impact change requiring full architecture review.
- **Files:** `charts/podmotion/templates/daemonset.yaml`, `charts/podmotion/profiles/podmotion-agent.json`, `charts/podmotion/values.yaml`.

### R-2 — Isolate the containerd socket to a restore-only path

Implement ADR-0013 mitigation #1/#3 concretely: mount the containerd socket **read-only** for the steady-state agent container; move task `Create/Start` (the only write ops) behind a separate, short-lived restore invocation that the NRI plugin already mediates. Ship the AppArmor profile that already exists at `images/ubuntu-22.04/apparmor/podmotion-agent` *as a chart-applied annotation* (`container.apparmor.security.beta.kubernetes.io/agent`) so the containerd gRPC method allowlist in ADR-0013 mitigation #2 is actually enforced, not just documented.

- **ADR:** amend **ADR-0013** (move from "accepted risk" to "mitigated"). Files: `daemonset.yaml`, chart AppArmor wiring.

### R-3 — Wire checkpoint encryption into the CRIU write + transfer path (close the plaintext gap)

The package exists; the integration does not. **Better primitive than the report's "encrypt at rest" generic:** encrypt-on-write streaming with an in-RAM session key, never a plaintext spill.

Design:
1. At `PrepareSource`, the operator generates an **ECDH P-256 ephemeral keypair per migration** (the `encryption.GenerateEphemeralKey` that already exists) and threads the destination agent's public key through the existing gRPC `PrepareSource`/`Restore` flow. No persistent key material.
2. Derive an AES-256-GCM key via ECDH (`deriveSharedSecret`, already implemented). Hold it in a `mlock`'d buffer (`IPC_LOCK` is already in the privileged set; add it explicitly under R-1 only if needed) so it never swaps.
3. **Pipe CRIU output through the cipher before it touches the filesystem.** CRIU writes images to `opts.ImagesDir`; wrap that with an encrypt-on-write `io.Writer` so what lands on tmpfs is ciphertext. Concretely: add `internal/agent/criu/encwriter.go` and have `CRIUCheckpointer.Dump` write through it. This eliminates the TOCTOU window where plaintext images exist on disk between dump and encrypt.
4. **Bind the archive to one restore (anti-replay):** the GCM AAD includes `migrationUID || destNodeName || monotonic-nonce`. A captured archive cannot be decrypted on any other node or reused for a second restore — the AAD won't match.
5. Zeroize the GCM key on every exit path (success/error/panic) via `defer` + explicit buffer wipe; the existing `zeroizeCheckpoints` becomes correct-by-construction because the on-disk bytes are ciphertext.

- **ADR:** implement **ADR-0029** (status moves to Implemented); new **ADR-0149** for the AAD anti-replay binding. High-impact (touches the freeze-window critical path + key handling). Files: `internal/agent/criu/criu_checkpointer.go`, new `encwriter.go`, `internal/agent/transfer/*`, operator threading in `internal/controller/podmigration_controller.go`.

### R-4 — Make mTLS fail-closed in production

Implement rejected-ADR-0106 [process rule] as a standalone, accepted decision:
```go
// internal/agent/tls/tls.go — add a production guard
func LoadServerConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
    if !filesExist(certFile, keyFile, caFile) {
        if isProductionCluster() {           // node label podmotion.io/env=production
            return nil, errors.New("TLS certs absent and cluster is production: " +
                "plaintext gRPC is prohibited (ADR-0150)")
        }
        log.Info("TLS certs absent — dev mode insecure")
        return nil, nil
    }
    ...
}
```
`cmd/agent/main.go` must `os.Exit(1)` (not warn-and-serve) when prod + no TLS. Forbid `InsecureSkipVerify` in the WAN transfer path (`wan.go:36`) on production via the same guard.

- **ADR:** new **ADR-0150** ("mTLS default-secure, no insecure fallback in production"). Files: `internal/agent/tls/tls.go`, `cmd/agent/main.go`, `internal/agent/transfer/wan.go`.

### R-5 — eBPF integrity: pin to bpffs with mode 0600 + load-time SHA-256 self-check

**Better primitive than the report's "periodic external checker":** the periodic checker has a TOCTOU window and adds a privileged daemon. Use load-time integrity + kernel pinning instead.
1. Embed the **SHA-256 of each compiled `.o`** at build time (ldflag) and verify the embedded `spec`'s raw bytes against it *before* `LoadAndAssign`. A tampered object fails to load — provenance check the verifier doesn't provide.
2. **Pin maps/programs to a restricted bpffs path** (`/sys/fs/bpf/podmotion/`, dir mode `0700`) so no other CAP_BPF process can `bpf_obj_get` the seq-translation map. cilium/ebpf supports `LoadAndAssignOpts{Maps: ebpf.MapOptions{PinPath: ...}}`.
3. On kernel ≥5.15 with `CONFIG_BPF_LSM`, optionally attach a thin `BPF_PROG_TYPE_LSM` hook on `bpf` that denies program load by any cgroup other than the agent's — eliminating the "competing program attach" class entirely.

- **ADR:** new **ADR-0151** ("eBPF load-time integrity + bpffs pinning"). Files: `internal/agent/network/bpfloader/*`, `bpf/Makefile` (emit per-object hashes), `internal/agent/network/ebpf_linux.go`.

### R-6 — Admission: node-trust gate + migration authorization

Add to `podmigration_webhook.go validate()`:
```go
// Rule 11: targetNodeName must carry the trusted-node label.
if pm.Spec.TargetNodeName != "" {
    node := &corev1.Node{}
    if err := v.client.Get(ctx, types.NamespacedName{Name: pm.Spec.TargetNodeName}, node); err == nil {
        if node.Labels["podmotion.io/trusted-node"] != "true" {
            allErrs = append(allErrs, field.Forbidden(
                field.NewPath("spec","targetNodeName"),
                fmt.Sprintf("node %q is not labeled podmotion.io/trusted-node=true", pm.Spec.TargetNodeName)))
        }
    }
}
```
And a **SubjectAccessReview** check: because creating a PodMigration is equivalent in power to dumping a pod's memory, the webhook performs an SSAR for `get pods/exec` (or a new `podmotion.io/migrate` virtual verb) on the source pod by `req.UserInfo`, denying if the subject lacks it. This makes "who can migrate X" equal to "who can already read X's memory" — closing the privilege-laundering path.

- **ADR:** new **ADR-0152** ("Migration authorization = pod-memory-read equivalence; trusted-node gate"). File: `internal/webhook/podmigration_webhook.go`.

### R-7 — Checkpoint tmpfs enforcement + registry TTL/auto-delete

Mount the checkpoint staging path as a **chart-declared `emptyDir{ medium: Memory, sizeLimit }`** rather than relying on host `/run` being tmpfs; if the medium is not Memory, fail the migration (ADR-0106 [process rule], "no host-dir fallback"). For registry-staged checkpoints (ADR-0034), set an OCI annotation TTL and have `pm-checkpoint-gc` delete the registry artifact when the owning `MigrationCheckpoint` reaches `Consumed`/`Failed` — binding artifact lifetime to migration lifetime.

- **ADR:** amend **ADR-0029**/**ADR-0053**. Files: `daemonset.yaml`, `internal/agent/criu/staging.go` (new), GC binary.

### R-8 — Audit logging of migration events

`internal/agent/audit/` is an **empty directory**. Implement structured, tamper-evident audit events for every migration lifecycle transition (PrepareSource, seccomp-weaken, checkpoint, transfer, restore, source-delete) as Kubernetes Events **and** a structured JSON audit log, including subject (`req.UserInfo`), source/dest node, and outcome. ADR-0009 already requires `SeccompWeakened`/`SeccompRestored` Warning events — implement them (currently the seccomp manager is an M11 stub, `manager.go:64-72`, that hardcodes `profile := "runtime/default"` and does not actually swap or emit events).

- **ADR:** amend **ADR-0009**. Files: `internal/agent/audit/*` (new), `internal/agent/seccomp/manager.go`.

---

## Part 3 — Better Primitives (eliminate, don't mitigate)

| Threat | Report's mitigation | Better primitive (this report) | Why it eliminates the class |
|---|---|---|---|
| Secrets in checkpoint at rest | "Encrypt at rest" (userspace, post-write) | **Encrypt-on-write stream + GCM AAD = migrationUID‖destNode‖nonce** (R-3) | No plaintext ever touches disk (closes TOCTOU); AAD binding makes a stolen archive undecryptable elsewhere and un-replayable — kills the clone class, not just the read class. |
| CRIU needs SYS_ADMIN | "It's required, accept it" | **Split to CAP_BPF+CAP_PERFMON (k≥5.8) + SYS_ADMIN only for mount; custom seccomp allowlist validated against a real CRIU strace** (R-1) | Drops ~13 unused capabilities and every unused syscall; the residual is provably the minimum CRIU/eBPF actually invoke. |
| eBPF tampering/stealth tap | "Sign + periodic external manifest check" | **Build-time per-object SHA-256 verified pre-load + bpffs 0700 pin + optional BPF-LSM load gate** (R-5) | Load-time check has no TOCTOU window the periodic checker has; BPF-LSM denies competing loads in-kernel — the tap can't be installed at all. |
| Unauthenticated/MITM gRPC | "Enable mTLS" | **Fail-closed guard keyed on `podmotion.io/env=production` node label; binary exits rather than serving plaintext** (R-4) | Removes the silent-insecure state entirely; you cannot accidentally run the memory-dump API open in prod. |
| Forced-migration-as-dump | "RBAC on PodMigration create" | **SubjectAccessReview equating migrate-rights to pods/exec-rights at admission** (R-6) | Migration power can never exceed existing memory-read power for the subject — laundering is structurally impossible, not policy-dependent. |
| Memory-encryption residual | (not in report) | **Confidential-computing: AMD SME/SEV-SNP or Intel TDX migration nodes** so even a host-root attacker on the migration node cannot read CRIU's plaintext working set in RAM during dump/restore | Future project milestone: protects the one window R-3 can't (plaintext in agent RAM mid-dump). Document as a deployment option, not a hard dependency. |

---

## Part 4 — Milestone Plan (risk-adjusted priority order)

| Milestone | Title | Surfaces | Deliverables | ADR(s) | Depends | Size | Target release/audit stage |
|---|---|---|---|---|---|---|---|
| **M-SEC-1** | Agent privilege containment | 1 | Drop `privileged:true` → discrete caps; seccomp profile (CRIU-strace-validated, pivot_root/module-load denied); node taint+label isolation; readOnlyRootFs | **ADR-0148** (supersedes rejected 0106 §1/§6) | — | L | **CNCF incubating + Beta** |
| **M-SEC-2** | mTLS fail-closed + checkpoint plaintext closure | 6,2,3-wire | Prod guard in `tls.go`+`main.go`; forbid `InsecureSkipVerify` in WAN; **wire encryption package into CRIU writer + transfer** (encrypt-on-write) | **ADR-0150**, implement **ADR-0029** | M-SEC-1 | L | **CNCF incubating + Beta** |
| **M-SEC-3** | Anti-replay archive binding + tmpfs hardening | 2 | GCM AAD = migrationUID‖destNode‖nonce; key in mlock'd buffer, zeroized; checkpoint path = `emptyDir{Memory}` no host fallback | **ADR-0149**, amend 0029 | M-SEC-2 | M | Beta |
| **M-SEC-4** | Migration authorization + node-trust gate | 5 | Webhook rule: `targetNode` must be `trusted-node=true`; SSAR equating migrate↔pods/exec; restrict NMC read (topology leak) | **ADR-0152** | — | M | **CNCF incubating** |
| **M-SEC-5** | containerd socket isolation | 1 | RO socket steady-state; write only on restore path; apply existing AppArmor profile via chart; containerd method allowlist | amend **ADR-0013** | M-SEC-1 | M | CNCF incubating |
| **M-SEC-6** | eBPF load-time integrity + bpffs pinning | 3 | Per-`.o` SHA-256 verified pre-load; bpffs 0700 pin; optional BPF-LSM load gate (k≥5.15) | **ADR-0151** | — | M | CNCF incubating |
| **M-SEC-7** | Audit logging + real seccomp swap | all | Implement empty `internal/agent/audit/`; structured JSON + K8s Events per transition w/ subject; replace M11 seccomp stub w/ real swap + `SeccompWeakened`/`Restored` events | amend **ADR-0009** | M-SEC-1 | M | Beta |
| **M-SEC-8** | Supply chain gates | (xchain) | SBOM (CycloneDX per ADR-0077), cosign keyless signing, Trivy/Grype HIGH/CRITICAL release gate, RBAC CI lint (kube-linter+allowlist) | **ADR-0077/0103** (impl) | — | M | **CNCF sandbox→incubating** |
| **M-SEC-9** | Registry checkpoint TTL/GC + per-workload isolation | 6 | OCI TTL annotation; GC binds artifact delete to MigrationCheckpoint terminal state | amend **ADR-0034/0053** | M-SEC-2 | S | GA |

Ordering rationale: M-SEC-1/2 are CRITICAL **and** CNCF-blocking → first. M-SEC-4 is the highest-leverage confidentiality fix that is cheap and standalone. M-SEC-8 (supply chain) is the cheapest CNCF-graduation lever and has no code deps, so it can run in parallel from day one.

---

## Part 5 — TAG-stripped Security Posture Gap (sandbox → incubating)

CNCF graduation requires a completed **Security Self-Assessment** and (for incubating) a clean or remediated **third-party security audit**. Delta against current state:

**Unmet self-assessment criteria:**
1. **Secure defaults.** Self-assessment requires the project be secure *out of the box*. PodMotion currently ships `privileged: true`, optional-and-fail-open mTLS, and unencrypted checkpoints. → **M-SEC-1, M-SEC-2** are hard prerequisites.
2. **Cryptography in use, documented.** The self-assessment asks what crypto protects data at rest/in transit. Today: checkpoint crypto is dead code; the honest answer is "none enforced." → **M-SEC-2/3**.
3. **Least privilege / capability justification.** TAG-Security expects a per-component privilege table with justification and a minimization roadmap. ADR-0106 §6 *wrote* this table but the ADR was rejected and the chart doesn't match it. → **M-SEC-1** (re-accept as ADR-0148).
4. **Supply chain (SLSA, SBOM, signed artifacts).** No SBOM, no signing, no vuln-scan gate are wired (ADR-0077/0103 unimplemented). This is a standard incubating bar. → **M-SEC-8**.
5. **Authorization model documentation.** The self-assessment requires describing how privileged operations are authorized. "Anyone with `create podmigrations` can dump any pod's memory in the namespace" is a finding an auditor will flag. → **M-SEC-4**.
6. **Roles & isolation (multi-tenancy).** ADR-0013's accepted cross-tenant lateral-movement risk via the shared containerd socket is exactly what a TAG-Security reviewer probes. → **M-SEC-5**.
7. **Audit/observability of security-relevant events.** Empty `audit/` package; seccomp events specified (ADR-0009) but stubbed. → **M-SEC-7**.

**Already meeting bar (cite as strengths in the self-assessment):** documented threat models (ADR-0013 is exemplary), coordinated-disclosure `SECURITY.md` with SLA, fail-closed admission webhooks, NetworkPolicy isolation, no-wildcard/no-cluster-admin RBAC, in-kernel eBPF verifier as a memory-safety control, ADR-paired governance with a Security veto role (ADR-0009).

**Net:** the project has the *governance and documentation* maturity of an incubating project but the *runtime security defaults* of an early sandbox project. Closing M-SEC-1, -2, -4, and -8 moves the runtime posture to match the paperwork and clears the four criteria most likely to block an incubating audit.

---

## Appendix — Report Claim Disposition

| Report claim | Verdict | Evidence |
|---|---|---|
| Privileged DaemonSet = node compromise | **CONFIRMED, CRITICAL** | `daemonset.yaml:65` `privileged:true`, `:27` hostPID, RW containerd sock `:69-81` |
| Secrets in checkpoint dumps, unencrypted | **CONFIRMED, CRITICAL** | encryption pkg unwired (grep: test-only); `zeroizeCheckpoints` = RemoveAll only |
| eBPF stealth/exfil/kernel instability | **PARTIAL** — verifier blocks instability; provenance/tap open | `bpfloader/*` plain `LoadAndAssign`, no pin/hash |
| RuntimeClass privilege confusion | **NOT APPLICABLE** | no RuntimeClass in repo (grep) |
| CRD/controller forced-migration DoS + topology leak | **CONFIRMED, HIGH** | capacity gate exists (good) but no node-trust/SSAR; NMC cluster-readable |
| Checkpoint data at rest/in transit unencrypted | **CONFIRMED, CRITICAL** | mTLS fail-open `tls.go:33-38`; payload crypto unwired |
| Mitigation: dedicated node pools + taints | **VALID, not implemented** | chart tolerates all taints |
| Mitigation: OPA/Kyverno for runtimeClass | **MISDIRECTED** — use SSAR+trusted-node label (R-6) | — |
| Mitigation: eBPF signing + periodic check | **PARTIALLY MISDIRECTED** — load-time hash + bpffs pin + BPF-LSM beats periodic (R-5) | — |
| Mitigation: audit logging | **VALID, not implemented** | `internal/agent/audit/` empty |
