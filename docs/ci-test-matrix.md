# PodMotion CI Test Matrix

This document defines the CI test coverage plan for PodMotion node image
readiness across distros, kernel versions, CRIU versions, and CNI plugins.

---

## 1. Matrix Axes

### Distro x Kernel
| ID | Distro | Kernel | Notes |
|----|--------|--------|-------|
| A | Ubuntu 22.04 LTS | 5.15 (GA HWE minimum) | Most common GKE/EKS base |
| B | Ubuntu 22.04 LTS | 6.5 (HWE backport) | HWE latest on 22.04 |
| C | Ubuntu 24.04 LTS | 6.8 | Primary development baseline |
| D | Amazon Linux 2023 | 6.1-aws | EKS strategic distro |
| E | Rocky Linux 9 | 5.14 | Open enterprise stand-in for RHEL 9 |
| F | Debian 12 (Bookworm) | 6.1 | GCP default node OS option |
| G | kind (Ubuntu 22.04 base) | host kernel | Local dev and CI baseline — always tested |

### CRIU Versions
| ID | Version | Notes |
|----|---------|-------|
| 1 | CRIU 4.0 | Minimum supported |
| 2 | CRIU 4.2 | Target — go-criu v7.2 protocol match |

### CNI Plugins
| ID | Plugin | Notes |
|----|--------|-------|
| X | Kindnet | kind default — local E2E, no IP mobility |
| Y | Cilium 1.15+ | BGP Control Plane for IP mobility |
| Z | Calico 3.27+ | BGP for IP mobility |

---

## 2. v0.1 Release Matrix

### Priority 1 — Must Pass (release gate)

| Cell | Distro | CRIU | CNI | What It Validates |
|------|--------|------|-----|-------------------|
| G x 1 x X | kind + CRIU 4.0 + kindnet | 4.0 | kindnet | Local dev baseline, cold migration only |
| G x 2 x X | kind + CRIU 4.2 + kindnet | 4.2 | kindnet | Local dev target, cold migration + pre-copy |
| C x 2 x Y | Ubuntu 24.04 + CRIU 4.2 + Cilium | 4.2 | Cilium | Primary AWS PoC target, full feature set |
| D x 2 x Y | Amazon Linux 2023 + CRIU 4.2 + Cilium | 4.2 | Cilium | EKS production target |

### Priority 2 — Should Pass (strong recommendation, not gate)

| Cell | Distro | CRIU | CNI | Notes |
|------|--------|------|-----|-------|
| A x 2 x Y | Ubuntu 22.04 + CRIU 4.2 + Cilium | 4.2 | Cilium | LTS support path |
| C x 2 x Z | Ubuntu 24.04 + CRIU 4.2 + Calico | 4.2 | Calico | BGP alternative CNI |
| D x 2 x Z | Amazon Linux 2023 + CRIU 4.2 + Calico | 4.2 | Calico | EKS Calico variant |
| E x 2 x Z | Rocky 9 + CRIU 4.2 + Calico | 4.2 | Calico | Enterprise — SELinux validation |

### Priority 3 — Best Effort (tracked, not gated)

| Cell | Distro | CRIU | CNI | Notes |
|------|--------|------|-----|-------|
| A x 1 x X | Ubuntu 22.04 + CRIU 4.0 + kindnet | 4.0 | kindnet | Version floor test |
| B x 2 x Y | Ubuntu 22.04 HWE-6.5 + CRIU 4.2 + Cilium | 4.2 | Cilium | HWE kernel path |
| F x 2 x Z | Debian 12 + CRIU 4.2 + Calico | 4.2 | Calico | GCP node OS |
| E x 2 x Y | Rocky 9 + CRIU 4.2 + Cilium | 4.2 | Cilium | SELinux + Cilium validation |

---

## 3. What Each Cell Tests

### Unit Tests (fast — run on every PR, no cluster required)

These run in GitHub Actions on `ubuntu-24.04` runners:

| Test Suite | Command | Coverage |
|-----------|---------|----------|
| Go unit tests | `make test` | Controller logic, migration state machine, checkpoint GC TTL |
| eBPF program compilation | `make bpf-build` | XDP and TC BPF programs compile against target kernel headers |
| Probe JSON schema | `go test ./internal/agent/probe/...` | NodeMigrationCapacitySpec field mapping |
| Webhook validation | `go test ./internal/webhook/...` | PodMigration admission, userns rejection |

### Preflight Script Tests (per-distro, fast)

Run as part of Dockerfile build validation:

```yaml
- docker buildx build --platform linux/amd64 -f images/<distro>/Dockerfile .
- docker run --privileged <image> /usr/local/bin/podmotion-node-preflight --json
- jq -e '.ready == true' <output>
- jq -e '[.checks[] | select(.pass == false and .required == true)] | length == 0' <output>
```

### E2E Tests (slow — per cell, kind cluster)

Run via `make test-e2e` on `ubuntu-24.04` GitHub Actions runner (or EC2 for
non-kind cells):

| Test | Kind cells | Distro cells | Description |
|------|-----------|-------------|-------------|
| Preflight probe ready | all | all | `podmotion-agent probe --json \| jq .ready == true` |
| Cold migration | all | all | nginx pod, 2-node cluster, PodMigration reaches `Complete` |
| Pre-copy rounds | G, C, D | all | Stateful HTTP server with 100MB heap; verify < 2 pre-copy rounds at 100ms threshold |
| TCP continuity | C x 2 x Y, D x 2 x Y | C, D cells with Cilium/Calico | netcat client holds connection through migration; 0 packet loss |
| Checkpoint GC | all | all | MigrationCheckpoint CR deleted after TTL expires |
| CRIU version gate | all | all | Agent startup fails gracefully on node with CRIU < 4.0 |
| NodeMigrationCapacity | all | all | NMC CR created at agent startup; `.status.ready` matches probe |

### Matrix Exclusions for v0.1

- Post-copy lazy pages (M13 / CONFIG_USERFAULTFD path): excluded, tested in v0.2
- GPU migration: excluded — separate matrix
- Windows containers: not supported
- arm64 nodes: tracked but not gated; add as Priority 2 in v0.2

---

## 4. CI Infrastructure

### Kind-based cells (G)

Runner: `ubuntu-24.04` GitHub Actions (free tier)

```yaml
steps:
  - uses: actions/checkout@v4
  - name: Build kind node image
    run: make kind-node-image
  - name: Create kind cluster
    run: make kind-create
  - name: Run E2E tests
    run: make test-e2e
```

### Multi-distro cells (A–F)

Infrastructure: AWS EC2 instances launched per cell via Terraform at
`test/ci/matrix/`.

- Instance type: `t3.medium` (2 nodes per cell), spot pricing
- Spot interruption handling: Terraform marks cell as SKIP (not FAIL) on reclaim
- Provisioning: Ansible role from `images/capi/ansible/roles/podmotion-node/`
- Gate: `podmotion-agent probe --json` must return `ready: true` before E2E
- Estimated runtime: 8–12 minutes per cell including AMI provisioning
- Parallelism: up to 8 cells in parallel

### GitHub Actions Matrix Strategy

```yaml
# .github/workflows/test-e2e.yml excerpt
strategy:
  fail-fast: false
  matrix:
    include:
      # Priority 1 (required)
      - distro: kind
        criu: "4.0"
        cni: kindnet
        required: true
      - distro: kind
        criu: "4.2"
        cni: kindnet
        required: true
      - distro: ubuntu-24.04
        criu: "4.2"
        cni: cilium
        required: true
      - distro: al2023
        criu: "4.2"
        cni: cilium
        required: true
      # Priority 2 (non-blocking)
      - distro: ubuntu-22.04
        criu: "4.2"
        cni: cilium
        required: false
      - distro: rocky9
        criu: "4.2"
        cni: calico
        required: false
```

### CI Status Gates

A PR may not merge if:

1. Any Priority 1 cell fails
2. `go build ./...` fails
3. `make lint` fails
4. Unit test coverage for `internal/controller/` drops below 70%

---

## 5. Version Drift Tracking

The following table is updated each release cycle. Cells marked HIGH require
active mitigation before the release.

| Package | Ubuntu 22.04 | Ubuntu 24.04 | AL2023 | Rocky 9 | Risk |
|---------|-------------|-------------|--------|---------|------|
| criu | 3.17 (LOW — need PPA) | 4.0+ (OK) | none (CRITICAL — build from source) | 3.x (HIGH — build from source) | HIGH |
| libbpf | 0.5 (LOW — need upgrade) | 1.3+ (OK) | 1.1+ (OK) | 1.0+ (OK) | MEDIUM |
| bpftool | bundled in linux-tools | standalone (OK) | standalone (OK) | standalone (OK) | MEDIUM |
| containerd NRI | 1.7+ (OK) | 1.7+ (OK) | EKS-managed (MEDIUM) | 1.7+ (OK) | MEDIUM |
| iproute2 | 5.15 (OK) | 6.x (OK) | 5.18+ (OK) | 5.18+ (OK) | LOW |

### 5.1 Substrate Kubernetes Version Cross-Check

The table above tracks OS-package drift by hand, each release cycle. It does
not cover a different, machine-checkable kind of drift: **go.mod's
`k8s.io/kubernetes` entry silently outrunning what a deploy substrate's own
pinned Kubernetes version actually serves.**

**Origin incident (2026-09-03):** `go.mod` was bumped to `k8s.io/kubernetes
v1.35.0`, which builds the scheduler against the `DynamicResourceAllocation`
API — GA and locked-on (cannot be disabled) as of Kubernetes 1.35.
`images/kind/Dockerfile` was still pinned to `kindest/node:v1.32.0`, which
does not serve that API at all. The scheduler binary started and connected
to the API server normally, then silently never scheduled anything — no
crash, no error, just a hang. Nothing in the repo cross-checked go.mod's
floor requirement against any substrate's actual served version, on kind or
otherwise, so the mismatch shipped undetected until it was hit live.

**The check:** `hack/check-substrate-k8s-versions.sh` (wired into CI as the
`substrate-version-check` job in `.github/workflows/ci.yaml`, and available
standalone via `make check-substrate-versions`) parses go.mod's
`k8s.io/kubernetes` minor version as the floor requirement, then parses each
substrate's own pinned/documented Kubernetes minor version out of its actual
config file:

| Substrate | Source of truth |
|---|---|
| kind | `images/kind/Dockerfile` — `ARG KIND_BASE=kindest/node:vX.Y.Z` |
| KVM/RKE2 standing cluster | `hack/kvm-cluster.sh` header doc comment ("Kubernetes vX.Y.x") — RKE2 itself has no static version pin (`RKE2_VERSION` defaults to empty = get.rke2.io's current-stable channel), so the header's documented version of the actually-running standing cluster is this substrate's source of truth |
| kubeadm-EC2 AMI | `images/capi/packer/kubeadm-ubuntu.pkrvars.hcl` — `kubernetes_version` (the apt package itself has no exact-version pin; this sets the `pkgs.k8s.io` channel minor that package installs pull from) |
| EKS | `terraform/eks-cluster/variables.tf` — `variable "kubernetes_version" { default = ... }` |

A substrate below go.mod's floor minor is a hard failure (non-zero exit,
names the substrate, its pinned version, the required floor, and the gap in
minor versions). A substrate at or above the floor passes — this is a floor
check, not an exact-match check, so a substrate ahead of go.mod is not
flagged.

As of this check's introduction, it also caught (beyond the kind incident
that motivated it) a live, unfixed instance of the same class of gap: EKS's
terraform default (`kubernetes_version = "1.31"`) and the kubeadm-EC2 AMI's
packer pin (`kubernetes_version = "1.32"`) are both behind go.mod's v1.35
floor. Neither has been bumped as of this writing — the check will fail in
CI until they are.
