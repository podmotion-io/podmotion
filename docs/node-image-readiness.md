# PodMotion Node Image Readiness

This document defines what a Linux node must provide to run the PodMotion agent
and participate in live pod migrations. It covers kernel configuration, packages,
system configuration, per-distro support tiers, the node validation probe, and
the CI test matrix summary.

---

## 1. Overview

PodMotion live-migrates Kubernetes pods between nodes without restarting
workloads. The three subsystems that drive requirements are:

- **CRIU** — checkpoints and restores process state (memory, file descriptors,
  network sockets). Invoked as a subprocess via go-criu RPC (ADR-0002).
- **eBPF / XDP** — zero-window hold and packet bridge during the cutover window.
  Programs are loaded via bpftool and attached to veth pairs using XDP and TC BPF.
- **containerd NRI** — lifecycle hooks that let the agent intercept container
  start/stop events without patching containerd.

All three subsystems place hard requirements on the kernel, installed packages,
and runtime configuration described in sections 2–4.

---

## 2. Kernel Requirements

Minimum supported kernel: **5.10** (for veth XDP support — the single most
critical gate). Recommended minimum for production: **5.15**.

### 2.1 Required Kernel Config Options

| Config | Why Required | Min Kernel | U22 | U24 | AL2 | AL2023 | RHEL8 | RHEL9/Rocky9 | Debian12 |
|--------|-------------|-----------|-----|-----|-----|--------|-------|--------------|---------|
| `CONFIG_CHECKPOINT_RESTORE` | CRIU process freeze and memory image creation | 4.14 | y | y | y | y | y | y | y |
| `CONFIG_MEM_SOFT_DIRTY` | Iterative pre-copy dirty-page tracking | 3.13 (x86_64), 5.15 (arm64) | y | y | y* | y | **NO** | y | y |
| `CONFIG_USERFAULTFD` | Post-copy lazy pages (M13) | 5.7 (UFFD_FEATURE_THREAD_ID) | y | y | y | y | y | y | y |
| `CONFIG_BPF_SYSCALL` | Load eBPF programs | 3.18 | y | y | y | y | y | y | y |
| `CONFIG_BPF_JIT` | Native-speed eBPF execution | 3.18 (x86), 4.15 (arm64) | y | y | y | y | y | y | y |
| `CONFIG_XDP_SOCKETS` | AF_XDP sockets for zero-window hold | 5.10 (veth) | y | y | y | y | **NO** | y | y |
| `CONFIG_NET_SCH_INGRESS` | TC ingress qdisc for packet bridge | 2.6.17 | y/m | y/m | y/m | y/m | y/m | y/m | y/m |
| `CONFIG_NET_CLS_BPF` | TC BPF classifier (eBPF direct action) | 4.4 | y/m | y/m | y/m | y/m | y/m | y/m | y/m |
| `CONFIG_CGROUP_FREEZER` / cgroup v2 freezer | Atomic container freeze before checkpoint | 5.2 (v2) | y | y | y | y | v1 only | y | y |
| `CONFIG_UNIX_DIAG` | CRIU Unix socket state snapshot | 3.3 | y | y | y | y | y | y | y |
| `CONFIG_INET_DIAG` | CRIU TCP socket state snapshot | 3.5 | y | y | y | y | y | y | y |
| `CONFIG_NET_NS` | Network namespace isolation | 2.6.24 | y | y | y | y | y | y | y |
| `CONFIG_VETH` | Virtual Ethernet pairs for pod networking | 2.6.24 | y/m | y/m | y/m | y/m | y/m | y/m | y/m |
| `CONFIG_NETFILTER_XT_MATCH_CGROUP` | Per-pod firewall rules scoped to cgroup | 3.14 | y/m | y/m | y/m | y/m | y/m | y/m | y/m |
| `CONFIG_TUN` | TUN/TAP for CNI and some CRIU restore paths | 2.6.0 | y/m | y/m | y/m | y/m | y/m | y/m | y/m |
| `CONFIG_FHANDLE` | File descriptor restoration across mounts | 2.6.39 | y | y | y | y | y | y | y |
| `CONFIG_EVENTFD` | eventfd descriptor checkpoint | 2.6.22 | y | y | y | y | y | y | y |

`*` AL2 kernel 5.10 — CONFIG_MEM_SOFT_DIRTY presence must be validated at
runtime with the preflight script; not publicly documented in AWS kernel config.

`y` = compiled in, `y/m` = compiled in or as loadable module (both acceptable),
**NO** = not available on this distro/version.

### 2.2 Runtime Kernel Checks

Beyond static config options, the following runtime states must be verified:

```
# BPF JIT enabled
cat /proc/sys/net/core/bpf_jit_enable            # must be 1 or 2

# cgroup v2 active
stat -f -c %T /sys/fs/cgroup                     # must print cgroup2fs

# cgroup v2 freezer controller available
grep freezer /sys/fs/cgroup/cgroup.controllers   # must match

# veth XDP runtime gate (5.10+)
# -- performed by preflight script's veth XDP probe
```

---

## 3. Package Requirements

### 3.1 Required Packages

| Package | Min Version | Ubuntu 22.04 Source | Ubuntu 24.04 Source | AL2023 Source | Rocky/RHEL 9 Source |
|---------|------------|--------------------|--------------------|---------------|---------------------|
| `criu` | **4.0** (target 4.2) | ppa:criu/ppa | ppa:criu/ppa (4.0 in main, 4.2 from PPA) | build from source | build from source (EPEL has 3.x) |
| `bpftool` | >= 7.3 (match kernel) | linux-tools-$(uname -r) | bpftool (standalone) | bpftool | bpftool |
| `iproute2` | >= 5.15 | iproute2 (main) | iproute2 (main) | iproute | iproute |
| `containerd` | >= 1.7.0 | containerd.io (Docker repo) | containerd.io (Docker repo) | EKS AMI / Docker repo | containerd.io (Docker repo) |
| `buildah` | >= 1.33 | kubic/opensuse repo | buildah (main) | buildah | buildah (AppStream) |
| `skopeo` | >= 1.14 | kubic/opensuse repo | skopeo (main) | skopeo | skopeo (AppStream) |
| `jq` | >= 1.6 | jq | jq | jq | jq |
| `libbpf` | >= 1.2 | kubic repo or build | libbpf-dev (main, 1.3) | libbpf-devel | libbpf-devel |
| `nftables` | >= 0.9.6 | nftables | nftables | nftables | nftables |

### 3.2 CRIU Version Gap (Critical)

`go-criu v7.2` (in `go.mod`) requires the CRIU **4.x RPC protocol**. Nodes with
CRIU 3.x will fail at agent startup with an RPC version mismatch enforced by the
`criuVersion` check in `NodeMigrationCapacitySpec`.

Default CRIU versions in distro repos:

| Distro | Default Repo Version | Status | Fix |
|--------|---------------------|--------|-----|
| Ubuntu 22.04 | 3.17 (universe) | INSUFFICIENT | Add ppa:criu/ppa |
| Ubuntu 24.04 | 4.0 (main) | Acceptable; 4.2 recommended | Add ppa:criu/ppa |
| Amazon Linux 2023 | 3.x (base) | INSUFFICIENT | Build from source |
| Amazon Linux 2 | 3.x (EPEL) | INSUFFICIENT | Build from source |
| RHEL/Rocky 9 | 3.18 (AppStream/EPEL) | INSUFFICIENT | Build from source |
| Debian 12 | 3.17 (main) | INSUFFICIENT | Build from source or backports |

**Recommended production approach**: bake CRIU 4.2 into the node image during
the Ansible role / image-builder phase so there is no external repo dependency.

### 3.3 CRIU Post-Install Verification

```sh
criu check --extra      # exits 0 if all kernel features present
# Expected non-fatal warning inside Docker/kind: "Devices cgroup is not found"
mkdir -p /var/lib/podmotion/checkpoints && chmod 700 /var/lib/podmotion/checkpoints
```

---

## 4. System Configuration

### 4.1 sysctl Settings

Write to `/etc/sysctl.d/99-podmotion.conf` and apply with `sysctl --system`.

| Setting | Required Value | Default | Why |
|---------|---------------|---------|-----|
| `kernel.perf_event_paranoid` | <= 2 (1 recommended) | 3 (Ubuntu), 2 (RHEL) | bpftool perf event access |
| `kernel.unprivileged_bpf_disabled` | 1 | 0 (Ubuntu), 1 (RHEL) | Security hardening; agent has CAP_BPF |
| `net.core.rmem_max` | 134217728 | 212992 | Large checkpoint image TCP transfers |
| `net.core.wmem_max` | 134217728 | 212992 | Same |
| `net.core.bpf_jit_enable` | 1 | 1 (most distros) | XDP JIT required for performance |
| `net.ipv4.tcp_rmem` | 4096 87380 134217728 | distro default | Per-socket TCP buffer scaling |
| `net.ipv4.tcp_wmem` | 4096 65536 134217728 | distro default | Same |
| `vm.unprivileged_userfaultfd` | 1 | 0 (RHEL 9, AL2023) | CRIU post-copy lazy pages |
| `kernel.pid_max` | 4194304 | 32768 (legacy) | CRIU must restore with original PIDs |
| `fs.inotify.max_user_watches` | 1048576 | 8192 | NRI plugin and agent inotify |
| `fs.inotify.max_user_instances` | 8192 | 128 | Per-pod file descriptor tracking |
| `net.core.bpf_jit_harden` | 0 | 0 | Must not be 2; blocks XDP program load |

### 4.2 Containerd NRI Configuration

Drop-in at `/etc/containerd/conf.d/nri.toml`:

```toml
[plugins."io.containerd.nri.v1.nri"]
  disable = false
  disable_connections = false
  plugin_registration_timeout = "5s"
  plugin_request_timeout = "2s"
  socket_path = "/var/run/nri/nri.sock"
  plugin_path = "/usr/local/lib/nri"
```

After updating: `systemctl restart containerd`

Verify: `containerd config dump | grep -A 10 nri`

The PodMotion NRI plugin symlink must exist:
`/usr/local/lib/nri/podmotion-nri -> /usr/local/bin/podmotion-agent`

**EKS managed node groups**: containerd config is managed by EKS bootstrap.
A privileged DaemonSet init container that patches the config and restarts
containerd is required (see GAP-5 in section 7).

**NRI version gate**: containerd < 1.7.0 does NOT support NRI. Amazon Linux 2
(containerd 1.6.x on EKS) falls back to exec-based CRIU invocation with no NRI
lifecycle hooks.

### 4.3 bpffs Mount

The BPF filesystem must be mounted at `/sys/fs/bpf` for eBPF program pinning.

Systemd unit at `/etc/systemd/system/sys-fs-bpf.mount`:

```ini
[Unit]
Description=BPF filesystem mount
DefaultDependencies=no
Before=network.target

[Mount]
What=bpffs
Where=/sys/fs/bpf
Type=bpf
Options=rw,nosuid,nodev,noexec,relatime,mode=700

[Install]
WantedBy=multi-user.target
```

Enable: `systemctl enable --now sys-fs-bpf.mount`

Verify: `mount | grep bpf && ls /sys/fs/bpf`

### 4.4 AppArmor (Ubuntu / Debian)

Profile at `/etc/apparmor.d/podmotion-agent` grants `SYS_PTRACE`, `NET_ADMIN`,
`SYS_ADMIN` to the agent with child profiles for criu, bpftool, buildah, and
skopeo subprocesses.

Load at node startup: `apparmor_parser -r /etc/apparmor.d/podmotion-agent`

Verify: `aa-status | grep podmotion`

The default containerd AppArmor profile (`docker-default`) blocks several CRIU
operations. The custom profile must be loaded before the agent starts.

### 4.5 SELinux (RHEL / Rocky / Amazon Linux 2023)

RHEL 9, Rocky 9, and Amazon Linux 2023 run SELinux in **enforcing** mode by
default. CRIU's ptrace-based checkpoint triggers AVC denials under the default
`container_t` domain.

PodMotion ships a Type Enforcement policy at `selinux/podmotion.te`.

Build and load on the target node:
```sh
checkmodule -M -m -o podmotion.mod selinux/podmotion.te
semodule_package -o selinux/podmotion.pp -m podmotion.mod
semodule -i selinux/podmotion.pp
```

Required booleans (persistent):
```sh
setsebool -P container_manage_cgroup 1
setsebool -P domain_can_mmap_files 1
setsebool -P selinuxuser_execmod 1
```

**This SELinux module is incomplete and blocks all RHEL/Rocky/AL2023 enterprise
deployments** until `selinux/podmotion.te` is finalized and tested. See
Critical Findings (section 7).

### 4.6 cgroup v2 Requirement

PodMotion requires cgroup v2 (unified hierarchy) on all nodes. cgroup v1 nodes
will appear as `ready: false` in their `NodeMigrationCapacity` and will be
filtered out by the scheduler plugin.

Verify: `stat -f -c %T /sys/fs/cgroup` — must print `cgroup2fs`

Migration from cgroup v1: append `systemd.unified_cgroup_hierarchy=1` to kernel
command line, then drain + reboot the node.

### 4.7 podmotion-agent systemd Unit

Installed at `/etc/systemd/system/podmotion-agent.service`. Required capabilities:

```
CAP_SYS_PTRACE CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_CHOWN
```

Full root (UID 0) is not required. `NoNewPrivileges=no` is set because CRIU
forks child processes that inherit ptrace capabilities.

---

## 5. Per-Distro Support Tiers

### Tier 1 — Fully Supported

All PodMotion features available: cold migration, iterative pre-copy, post-copy
lazy pages, full eBPF bridge with XDP zero-window hold.

| Distro | Kernel | Key Notes |
|--------|--------|-----------|
| **Ubuntu 24.04 LTS** | 6.8 (GA), 6.11 (HWE) | Primary development baseline. All packages at target versions in main. |
| **Ubuntu 22.04 LTS HWE** | 5.15 (GA), 6.5+ (HWE) | CRIU PPA required. libbpf upgrade required. Most common GKE/EKS base. |
| **Amazon Linux 2023** | 6.1-aws | Strategic EKS distro (supported until 2028). CRIU must be built from source. SELinux module required. |

### Tier 2 — Supported With Caveats

Core migrations work; specific features require workarounds or are restricted.

| Distro | Kernel | Caveats |
|--------|--------|---------|
| **Amazon Linux 2** | 5.10-aws | EOL June 30 2025. NRI unavailable (containerd 1.6.x). No NRI lifecycle hooks; agent falls back to exec-based CRIU. arm64 (Graviton2): no iterative pre-copy (kernel < 5.15). Treat as transitional. |
| **Rocky Linux 9** | 5.14 | SELinux module required. CRIU must be built from source (EPEL has 3.x). arm64: iterative pre-copy uncertain on 5.14 (soft-dirty arm64 backport status unconfirmed). |
| **RHEL 9** | 5.14 | Same as Rocky 9 plus requires Red Hat subscription for containerd.io. EKS managed node groups require self-managed node groups. |

### Tier 3 — Cold Migration Only

Iterative pre-copy and eBPF bridge are unavailable. Basic checkpoint/restore works.

| Distro | Kernel | Reason |
|--------|--------|--------|
| **RHEL 8** | 4.18 | `CONFIG_MEM_SOFT_DIRTY` not backported. `CONFIG_XDP_SOCKETS` present but veth XDP requires 5.10+. cgroup v1 by default. CRIU 3.x from EPEL (4.x requires source build). No iterative pre-copy, no eBPF bridge. |

### Unsupported

Any node running kernel < 5.10 is unsupported. veth XDP support (added in 5.10)
is a hard requirement for the eBPF bridge. Nodes with kernel < 5.10 will be
rejected by the agent with `ready: false`.

---

## 6. Node Validation Probe

### 6.1 Design

The probe is implemented as `internal/agent/probe/probe.go` and invoked via:

```
podmotion-agent probe --json
```

It outputs structured JSON to stdout and exits:
- `0` — all required checks pass (node is migration-ready)
- `1` — one or more required checks failed
- `2` — required checks pass but optional checks fail (cold-migration-only mode)

A shell fallback for bootstrapping (before the Go binary is available) is at
`hack/verify-kernel-config.sh` (extend with `--json` flag).

### 6.2 Output Schema

The JSON output maps directly to `NodeMigrationCapacitySpec` fields in
`api/v1alpha1/nodemigrationcapacity_types.go`:

```json
{
  "nodeName": "worker-1",
  "timestamp": "2026-06-10T12:00:00Z",
  "criuVersion": "4.2",
  "nriEnabled": true,
  "ready": true,
  "kernelVersion": "6.8.0-50-generic",
  "kernelFeatures": {
    "checkpointRestore": true,
    "memSoftDirty": true,
    "userfaultfd": true,
    "bpfEnabled": true,
    "xdpSupported": true
  },
  "networkCapability": {
    "cniPlugin": "cilium",
    "ipMobilitySupported": true,
    "ipMobilityMode": "BGPHostRoute",
    "xdpBridgeCapable": true
  },
  "storageCapability": {
    "cephRBDAvailable": false,
    "longhornAvailable": true,
    "localPVMigratable": true
  },
  "checks": [
    {"name": "CONFIG_CHECKPOINT_RESTORE", "required": true,  "pass": true,  "detail": "=y"},
    {"name": "CONFIG_MEM_SOFT_DIRTY",     "required": true,  "pass": true,  "detail": "=y"},
    {"name": "CONFIG_USERFAULTFD",        "required": false, "pass": true,  "detail": "=y"},
    {"name": "CONFIG_BPF_SYSCALL",        "required": false, "pass": true,  "detail": "=y"},
    {"name": "CONFIG_XDP_SOCKETS",        "required": false, "pass": true,  "detail": "=y"},
    {"name": "CONFIG_NET_SCH_INGRESS",    "required": false, "pass": true,  "detail": "=m"},
    {"name": "CONFIG_NET_CLS_BPF",        "required": false, "pass": true,  "detail": "=m"},
    {"name": "CONFIG_CGROUP_FREEZER",     "required": true,  "pass": true,  "detail": "cgroup2 freezer active"},
    {"name": "CONFIG_UNIX_DIAG",          "required": true,  "pass": true,  "detail": "=y"},
    {"name": "CONFIG_INET_DIAG",          "required": true,  "pass": true,  "detail": "=y"},
    {"name": "CONFIG_NET_NS",             "required": true,  "pass": true,  "detail": "=y"},
    {"name": "CONFIG_VETH",               "required": true,  "pass": true,  "detail": "=m (loaded)"},
    {"name": "criu-version",              "required": true,  "pass": true,  "detail": "4.2"},
    {"name": "criu-check",                "required": true,  "pass": true,  "detail": "criu check --extra: OK"},
    {"name": "bpffs-mounted",             "required": true,  "pass": true,  "detail": "/sys/fs/bpf type bpf"},
    {"name": "containerd-nri",            "required": true,  "pass": true,  "detail": "NRI socket present"},
    {"name": "cgroup-v2",                 "required": true,  "pass": true,  "detail": "cgroup2fs"},
    {"name": "kernel-version-min",        "required": true,  "pass": true,  "detail": "6.8.0 >= 5.15.0"},
    {"name": "veth-xdp",                  "required": false, "pass": true,  "detail": "kernel 5.10+ veth XDP confirmed"},
    {"name": "unprivileged-uffd",         "required": false, "pass": false, "detail": "vm.unprivileged_userfaultfd=0 (agent is privileged, OK)"}
  ],
  "failedRequired": [],
  "failedOptional": ["unprivileged-uffd"]
}
```

### 6.3 Kernel Config Resolution Order

1. `/proc/config.gz` (if `CONFIG_IKCONFIG_PROC=y`)
2. `/boot/config-$(uname -r)`
3. `/lib/modules/$(uname -r)/config` (Flatcar, some distros)
4. If none found: mark all kernel config checks as `"unknown"` (not fail) and warn

### 6.4 Key Probe Implementation Notes

- **CRIU version**: `criu --version`, parse `Version: X.Y`, compare >= 4.0
- **CRIU check**: `criu check --extra` exit code 0 = pass
- **NRI**: check `/var/run/nri/nri.sock` existence + `containerd config dump`
- **cgroup v2**: `statfs /sys/fs/cgroup`, Type == `CGROUP2_SUPER_MAGIC` (0x63677270)
- **bpffs**: `statfs /sys/fs/bpf`, Type == `BPF_FS_MAGIC` (0xcafe4a11)
- **veth XDP**: create temp veth pair, attach trivial XDP pass program, clean up

---

## 7. Critical Findings and Known Gaps

### GAP-1: CRIU 4.x Not in Distro Repos (HIGH RISK)

All distros except Ubuntu 24.04 ship CRIU 3.x. go-criu v7.2 requires 4.x RPC
protocol. This blocks all migration functionality on those nodes.

**Mitigations** (in priority order):
1. CRIU PPA for Ubuntu: `add-apt-repository ppa:criu/ppa`
2. Pre-built RPM from criu.org for AL2023 / RHEL
3. Bake CRIU 4.2 into node image during Ansible role execution (recommended for
   production — hermetic, version-pinned, no external repo dependency)

**Action required**: Update `images/kind/Dockerfile` to add the CRIU PPA before
installing criu (currently installs 3.17 from Ubuntu 22.04 universe).

### GAP-2: SELinux Policy Incomplete (HIGH RISK)

No finalized SELinux policy module (`selinux/podmotion.te`) exists for
RHEL/Rocky/AL2023. CRIU's ptrace, `/proc/<pid>/mem` reads, network namespace
creation, and eBPF syscalls all generate AVC denials in enforcing mode.

**Blocks**: all enterprise RHEL/Rocky 9 and Amazon Linux 2023 deployments.

**Action required**: Complete `selinux/podmotion.te`, add `make selinux-policy`
target to build the `.pp` binary on a Rocky 9 builder container.

### GAP-3: EKS Containerd NRI Init Container (MEDIUM RISK)

EKS managed node groups use Amazon-provided AMIs with a bootstrap-managed
containerd config. The NRI drop-in cannot be placed directly.

**Mitigation**: privileged DaemonSet init container that patches
`/etc/containerd/config.toml` and restarts containerd. Similar to the Intel
Resource Management Framework approach.

### GAP-4: VPC CNI IP Mobility Gap on EKS (CRITICAL for EKS)

VPC CNI assigns pod IPs from the node's ENI pool. Pod IPs cannot follow a pod
to a different node — a migrated pod receives a new IP from the destination
node's ENI. This breaks PodMotion's core TCP-continuity guarantee:

- All active TCP connections break at cutover regardless of eBPF bridge duration
- The eBPF bridge cannot redirect traffic to a new IP

**Mitigation options**:
1. Deploy a service mesh (Istio, AWS App Mesh) for connection-level retry and
   pod-IP abstraction
2. Switch to Calico or Cilium with BGP /32 host routes on EKS custom networking

This is documented in ADR-0036 (new, see section 8).

### GAP-5: libbpf Version Drift on Ubuntu 22.04 (MEDIUM RISK)

Ubuntu 22.04 ships libbpf 0.5 which does not support BPF CO-RE/BTF fully.
Ring buffers and newer map types used by PodMotion's eBPF programs will fail to
load.

**Mitigation**: statically link libbpf 1.2+ in the agent CGO build, or install
from kubic/opensuse repo.

### GAP-6: arm64 MEM_SOFT_DIRTY (LOW RISK for v0.1)

`CONFIG_MEM_SOFT_DIRTY` on arm64 was added upstream in 5.15. Any arm64 node on
kernel < 5.15 (Graviton2 EKS with AL2 5.10) silently lacks iterative pre-copy.
The probe sets `kernelFeatures.memSoftDirty = false` and the migration controller
falls back to single-round checkpoint.

---

## 8. Related ADRs

- ADR-0002: CRIU as subprocess via go-criu RPC
- ADR-0005: Node image targets (kind dev + AWS AMI PoC)
- ADR-0027: AWS ALB target group discovery for EKS IP mobility
- ADR-0035: Spot reclamation via IMDS poller
- ADR-0036: VPC CNI IP mobility model and EKS traffic continuity (new)
