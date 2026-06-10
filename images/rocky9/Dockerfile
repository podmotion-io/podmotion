# PodMotion node image — Rocky Linux 9 (open stand-in for RHEL 9 in CI).
# Kernel: 5.14 (RHEL 9 baseline).  Full PodMotion feature set supported.
#
# Build:
#   docker build -t podmotion-node-rocky9:dev \
#     --build-arg AGENT_ARCH=amd64 \
#     -f images/rocky9/Dockerfile .
#
# Runtime requirements:
#   - cgroup v2 (default on Rocky 9 / RHEL 9)
#   - SELinux: either enforcing with podmotion.pp loaded, or permissive for dev
#   - containerd 1.7+ with NRI enabled

ARG ROCKY_VERSION=9
FROM rockylinux:${ROCKY_VERSION}

LABEL org.opencontainers.image.title="podmotion-node-rocky9" \
      org.opencontainers.image.description="PodMotion-ready Rocky Linux 9 node image" \
      org.opencontainers.image.source="https://github.com/podmotion-io/podmotion"

# ---------------------------------------------------------------------------
# 1. Base packages + EPEL
# ---------------------------------------------------------------------------
RUN dnf install -y epel-release && \
    dnf install -y \
      # CRIU 3.18+ available in EPEL 9; 4.x when available
      criu \
      # BPF tooling
      bpftool \
      kernel-tools \
      # Network utilities required by agent and CRIU restore
      iproute \
      iproute-tc \
      iptables \
      nftables \
      # TUN/veth modules (usually compiled in but ensure module utils present)
      kmod \
      # General utilities
      jq \
      curl \
      ca-certificates \
      # OCI tools (image inspection for checkpoint manifest)
      skopeo \
    && dnf clean all

# ---------------------------------------------------------------------------
# 2. Install containerd
#    RHEL/Rocky does not ship containerd in default repos.
#    Use Docker's official RPM repository (provides containerd.io).
#    CRI-O is an alternative but uses CRIU differently (NRI path differs).
# ---------------------------------------------------------------------------
RUN dnf install -y yum-utils && \
    yum-config-manager --add-repo \
      https://download.docker.com/linux/rhel/docker-ce.repo && \
    dnf install -y containerd.io && \
    dnf clean all

# ---------------------------------------------------------------------------
# 3. Configure containerd with NRI enabled
# ---------------------------------------------------------------------------
RUN mkdir -p /etc/containerd/conf.d /var/run/nri /var/lib/nri /usr/local/lib/nri

COPY images/capi/ansible/roles/podmotion-node/files/nri.toml \
     /etc/containerd/conf.d/nri.toml

# Ensure containerd config.toml imports the conf.d drop-in directory
RUN containerd config default > /etc/containerd/config.toml && \
    sed -i 's|config_path = ""|config_path = "/etc/containerd/conf.d"|' \
        /etc/containerd/config.toml

# ---------------------------------------------------------------------------
# 4. bpffs mount unit
# ---------------------------------------------------------------------------
COPY images/capi/ansible/roles/podmotion-node/files/sys-fs-bpf.mount \
     /etc/systemd/system/sys-fs-bpf.mount
RUN systemctl enable sys-fs-bpf.mount 2>/dev/null || true

# ---------------------------------------------------------------------------
# 5. SELinux — load PodMotion policy module if available.
#    The .pp binary is built separately via: make selinux-policy
#    In dev/CI you can skip this and run with permissive mode.
# ---------------------------------------------------------------------------
# COPY selinux/podmotion.pp /usr/share/selinux/packages/podmotion.pp
# RUN semodule -i /usr/share/selinux/packages/podmotion.pp

# ---------------------------------------------------------------------------
# 6. sysctl overrides required by CRIU/eBPF on RHEL 9
#    - unprivileged_userfaultfd: RHEL 9 defaults to 0; must be 1 for post-copy
#    - bpf_jit_enable: ensure JIT is on (should be 1 by default but be explicit)
# ---------------------------------------------------------------------------
RUN mkdir -p /etc/sysctl.d
COPY <<EOF /etc/sysctl.d/99-podmotion.conf
# Required for CRIU post-copy lazy pages (CONFIG_USERFAULTFD unprivileged use)
vm.unprivileged_userfaultfd = 1
# Ensure BPF JIT is enabled for XDP performance
net.core.bpf_jit_enable = 1
EOF

# ---------------------------------------------------------------------------
# 7. CRIU smoke test (kernel warnings inside container build are expected)
# ---------------------------------------------------------------------------
RUN criu --version || true

# ---------------------------------------------------------------------------
# 8. Install PodMotion agent binary
# ---------------------------------------------------------------------------
ARG AGENT_ARCH=amd64
COPY bin/agent-linux-${AGENT_ARCH} /usr/local/bin/podmotion-agent
RUN chmod +x /usr/local/bin/podmotion-agent && \
    ln -sf /usr/local/bin/podmotion-agent /usr/local/lib/nri/podmotion-nri
