# Security Policy

PodMotion is a privileged Kubernetes operator that invokes CRIU as a subprocess, loads eBPF programs, manipulates kernel namespaces, and transfers checkpoint data across node boundaries. Security issues in this project can affect workload confidentiality, cluster integrity, and host kernel stability. We take security reports seriously and are committed to coordinated disclosure.

## Security Posture (current)

This section states what PodMotion enforces **today**, so a reviewer's expectations match the code.
A fuller treatment — including the agent privilege/host-mount table and the residual trust boundary —
is in [docs/security-model.md](docs/security-model.md).

**What is enforced by default:**

- **Fail-closed mTLS on the agent gRPC server.** In the default (production) build the agent refuses
  to start if TLS material is absent — it never serves plaintext. A plaintext path exists only in a
  dedicated developer build and only when `PODMOTION_INSECURE_GRPC=true` is explicitly set (ADR-SEC-A).
- **Deny-by-default per-RPC authorization.** Caller identity is the verified mTLS leaf's SPIFFE ID;
  an interceptor classifies it to an operator or peer-agent role, applies a per-method allow policy
  (a method not in the policy is denied), and binds the caller to the named migration. The trusted
  edge is operator → agent (ADR-SEC-A/C).
- **Checkpoint provenance verified before extraction.** The destination agent verifies wire hash,
  a signed manifest, anti-replay migration binding, and per-file digests before promoting a received
  checkpoint — fail-closed, no bypass when a signature is absent (ADR-SEC-B).
- **De-privileged main agent.** The long-lived agent container runs `privileged: false` with a
  discrete capability set; only a single long-lived `netns-broker` container remains privileged for an
  irreducible host mount-namespace operation (ADR-0148).
- **Checkpoints on zeroized tmpfs.** Checkpoint images live on a size-capped `tmpfs` (mode 0700) and
  are zeroized on every exit path.

**Known gaps disclosed deliberately (alpha):**

- **At-rest checkpoint encryption is off by default.** It exists and is opt-in per migration via a
  Kubernetes secret (ECDH P-256 + AES-256-GCM, ADR-0029); absent that secret, checkpoints are
  plaintext on tmpfs, protected by 0700 + zeroization + in-transit mTLS + signed integrity only.
- **Migration has no per-subject / per-node authorization.** Anyone able to `create podmigrations` in
  a namespace can force a full process-memory dump of any pod in that namespace and steer the restore
  to any capable node. There is no `SubjectAccessReview` on migrate and no trusted-node gate on the
  target node. Restrict `PodMigration` RBAC to trusted namespaces/subjects as a mitigation.
- **Node-level surface remains.** The agent pod uses `hostPID` and `hostNetwork`, mounts the host
  containerd socket **read-write** (root-equivalent on the node; an accepted `v0.1` risk, ADR-0013),
  and tolerates all taints (no node-pool isolation). See docs/security-model.md for the full table.

## Supported Versions

| Version | Supported |
|---|---|
| `main` branch (latest) | Yes |
| Active pre-release tags (e.g., `v0.x.y-alpha`, `v0.x.y-beta`) | Yes, during active development |
| Older release tags | No — please upgrade |

If you are running an older tag, upgrade to `main` or the latest pre-release before filing a report. We will not backport fixes to unsupported versions.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security findings.** Public disclosure before a patch is available puts all PodMotion users at risk.

### Preferred path — GitHub Private Security Advisory

Use GitHub's built-in private advisory workflow:

1. Navigate to [https://github.com/podmotion-io/podmotion/security/advisories/new](https://github.com/podmotion-io/podmotion/security/advisories/new)
2. Fill in the advisory form with as much detail as possible (see template below).
3. Submit. Only project maintainers can see the draft advisory.

### Fallback — Email

If you cannot use GitHub advisories, email **security@podmotion.io**.

Encrypt sensitive details using the maintainer PGP key published at [https://podmotion.io/security-pgp.asc](https://podmotion.io/security-pgp.asc) (key fingerprint will be posted when the project reaches public beta).

### What to include in your report

```
Summary:        One sentence description
Component:      e.g., CRIU subprocess invocation, eBPF loader, gRPC agent, CRD webhook
Affected versions:  e.g., main @ <commit SHA>
Attack vector:  Network / Local / Physical
Privileges required: None / Low / High
Impact:         Confidentiality / Integrity / Availability
Steps to reproduce:
  1. ...
  2. ...
Proof-of-concept (if available):
Suggested fix (if known):
```

### Response SLA

| Milestone | Target |
|---|---|
| Initial acknowledgment | Within **72 hours** of receipt |
| Triage and severity assessment | Within **7 days** |
| Patch for Critical / High severity | Within **90 days** (sooner when possible) |
| Patch for Medium / Low severity | Best effort, next scheduled release |

If you do not receive acknowledgment within 72 hours, follow up via email or ping `@podmotion-security` on the project's GitHub Discussions.

## Scope

### In Scope

The following attack surfaces are explicitly in scope for PodMotion's security program:

| Area | Example findings |
|---|---|
| **CRIU checkpoint file exposure** | Checkpoint archives written to world-readable paths; secrets, private keys, or tokens recoverable from checkpoint images; insecure tmpfs mount options during checkpoint/restore |
| **eBPF privilege escalation** | eBPF programs loaded by PodMotion that can be abused to escape cgroup/namespace boundaries; BTF verifier bypasses introduced by PodMotion's eBPF code; misuse of `BPF_PROG_TYPE_LSM` or `BPF_PROG_TYPE_CGROUP_SOCK` hooks |
| **gRPC agent-to-controller authentication bypass** | Missing or bypassable mTLS on the migration agent gRPC server; unauthenticated endpoints on the pm-agent that allow arbitrary checkpoint or restore commands |
| **CRD RBAC misconfigurations** | Overly broad ClusterRole rules on `PodMigration`, `MigrationPolicy`, `NodeMigrationCapacity`, `MigrationCheckpoint`, or `MigrationWebhookConfig` resources that allow privilege escalation within a cluster |
| **Container escape via migration path** | Host path traversal during checkpoint image transfer; symlink attacks in the image staging directory; unsafe deserialization of checkpoint metadata that allows code execution on the destination node |
| **Admission webhook bypass** | Bypassing `MigrationWebhookConfig` validation to migrate workloads that should be blocked; webhook TLS configuration weaknesses |
| **Operator RBAC over-privilege** | The PodMotion controller ServiceAccount holding permissions beyond what live migration requires, enabling lateral movement within the cluster |

### Out of Scope

The following are **not** in scope for this project's security program:

- Vulnerabilities in upstream CRIU (https://github.com/checkpoint-restore/criu) that are not specific to how PodMotion invokes or packages it. Please report those upstream.
- Vulnerabilities in the Linux kernel itself (CRIU namespaces, netlink, eBPF verifier) that are not caused by PodMotion code. Report those to the Linux kernel security team.
- Vulnerabilities in `go-criu`, `cilium/ebpf`, or `vishvananda/netlink` that are not introduced or amplified by PodMotion's integration. Report those to the respective upstream projects.
- Denial-of-service attacks that require cluster-admin credentials already.
- Issues in third-party Kubernetes distributions, managed Kubernetes services (EKS, GKE, AKS), or CNI plugins outside PodMotion's code.
- Social engineering of maintainers.

If you are unsure whether an issue is in scope, report it anyway — we would rather triage a borderline report than miss a real vulnerability.

## Disclosure Policy

PodMotion follows **coordinated disclosure** (also called responsible disclosure):

1. **Reporter submits** a private advisory or email report.
2. **Maintainers acknowledge** within 72 hours and begin triage.
3. **Maintainers and reporter** agree on a disclosure timeline (default: 90 days from initial report for critical issues, extendable by mutual agreement).
4. **Patch is developed** in a private fork or branch. The reporter is invited to review and validate the fix.
5. **CVE is requested** by the maintainers via MITRE or GitHub's CVE assignment workflow. The reporter will be credited in the CVE description unless they request anonymity.
6. **Coordinated public release**: patch, release notes, and CVE advisory are published simultaneously.
7. **Reporter credit**: reporters who responsibly disclose valid security issues will be acknowledged in the release notes, the GitHub advisory, and PodMotion's `SECURITY_ACKNOWLEDGEMENTS.md` (unless they request anonymity).

We will not pursue legal action against researchers who discover and report vulnerabilities in good faith, consistent with this policy.

## Security Hardening Notes

For operators deploying PodMotion while the project is pre-1.0, note first what is **already
enforced by default** (see the Security Posture section above): fail-closed mTLS on the agent gRPC
server, deny-by-default per-RPC authorization, checkpoint provenance verification on ingest, a
de-privileged main agent, and checkpoint images on a zeroized, size-capped tmpfs. Those are not
operator opt-ins — they are on by default.

The following are still operator responsibilities or off-by-default and are recommended:

- Run the operator and agent with dedicated ServiceAccounts; do not reuse the `default` ServiceAccount.
- **Restrict `PodMigration` create/update RBAC to trusted namespaces and subjects.** This is the
  primary mitigation for the un-gated migration-as-memory-dump surface (there is no per-subject
  `SubjectAccessReview` or trusted-node gate yet — see the Security Posture section).
- **Enable at-rest checkpoint encryption** by provisioning a per-migration key secret; it is off by
  default (ADR-0029). Absent it, checkpoints rest as plaintext on tmpfs, protected by mode 0700 +
  zeroization + in-transit mTLS + signed integrity only.
- Treat the read-write host containerd socket mount as root-equivalent on the node (accepted `v0.1`
  risk, ADR-0013) and isolate the node pool accordingly; the agent currently tolerates all taints.
- The agent uses discrete Linux capabilities rather than blanket privilege (ADR-0148); it still
  requires `CAP_SYS_ADMIN` for CRIU mount-namespace operations in addition to `BPF`/`PERFMON` on
  kernels ≥ 5.8. Review these against your policy.

Default-on at-rest encryption and node/socket isolation are targeted for a future release.
