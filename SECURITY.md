# Security Policy

PodMotion is a privileged Kubernetes operator that invokes CRIU as a subprocess, loads eBPF programs, manipulates kernel namespaces, and transfers checkpoint data across node boundaries. Security issues in this project can affect workload confidentiality, cluster integrity, and host kernel stability. We take security reports seriously and are committed to coordinated disclosure.

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

For operators deploying PodMotion in production, the following mitigations are recommended while the project is pre-1.0:

- Run the `pm-controller` and `pm-agent` pods with a dedicated ServiceAccount; do not reuse the `default` ServiceAccount.
- Mount checkpoint staging directories on an encrypted, size-limited `emptyDir` or dedicated PersistentVolume, not on the host filesystem.
- Restrict `PodMigration` create/update RBAC to trusted namespaces only.
- Enable mTLS between `pm-controller` and `pm-agent` gRPC endpoints (mTLS configuration is tracked in ADR-0159 and ADR-0161).
- Review eBPF program permissions; PodMotion should not require `CAP_SYS_ADMIN` beyond the specific `BPF` capability in kernels >= 5.8.

These recommendations will be enforced by default in a future release.
