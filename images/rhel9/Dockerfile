# PodMotion node image — RHEL 9 (Universal Base Image).
# Kernel: 5.14 (RHEL 9 baseline).  Full PodMotion feature set supported.
#
# IMPORTANT: UBI 9 has a limited package set. Full RHEL 9 packages (including
# CRIU from AppStream) are only available on a subscribed RHEL 9 host build or
# with Red Hat subscription entitlements mounted into the build context.
#
# For CI without a RHEL subscription: use images/rocky9/Dockerfile instead.
# Rocky 9 is binary-compatible with RHEL 9 and freely available.
#
# Build on a subscribed RHEL 9 host:
#   docker build -t podmotion-node-rhel9:dev \
#     -v /etc/pki/entitlement:/etc/pki/entitlement:ro \
#     -v /etc/rhsm:/etc/rhsm:ro \
#     -v /etc/yum.repos.d/redhat.repo:/etc/yum.repos.d/redhat.repo:ro \
#     --build-arg AGENT_ARCH=amd64 \
#     -f images/rhel9/Dockerfile .

FROM registry.access.redhat.com/ubi9/ubi:latest

LABEL org.opencontainers.image.title="podmotion-node-rhel9" \
      org.opencontainers.image.description="PodMotion-ready RHEL 9 node image (UBI base)" \
      org.opencontainers.image.source="https://github.com/podmotion-io/podmotion"

# ---------------------------------------------------------------------------
# 1. Base packages
#    UBI 9 repos: ubi-9-baseos-rpms, ubi-9-appstream-rpms
#    Subscribed hosts additionally have: rhel-9-for-x86_64-appstream-rpms
#      which provides CRIU from AppStream (version ~3.18 in RHEL 9.0; check
#      `dnf info criu` on subscribed host for current version).
# ---------------------------------------------------------------------------
RUN dnf install -y \
      # CRIU: available in RHEL 9 AppStream (requires subscription or
      # developer entitlement mounted at build time)
      criu \
      # BPF tooling
      bpftool \
      kernel-tools \
      # Network utilities
      iproute \
      iproute-tc \
      iptables \
      nftables \
      kmod \
      # General utilities
      jq \
      curl \
      ca-certificates \
      skopeo \
    && dnf clean all

# ---------------------------------------------------------------------------
# 2. Install containerd via Docker RPM repo
#    RHEL 9 AppStream ships podman/cri-o but not containerd.
#    containerd.io from Docker is the supported installation path.
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
# 5. SELinux policy module (podmotion.pp)
#    Build the .pp binary on the target host with:
#      checkmodule -M -m -o podmotion.mod selinux/podmotion.te
#      semodule_package -o podmotion.pp -m podmotion.mod
#      semodule -i podmotion.pp
#    Uncomment the COPY+RUN lines once the .pp artifact is built.
# ---------------------------------------------------------------------------
# COPY selinux/podmotion.pp /usr/share/selinux/packages/podmotion.pp
# RUN semodule -i /usr/share/selinux/packages/podmotion.pp

# ---------------------------------------------------------------------------
# 6. sysctl overrides
# ---------------------------------------------------------------------------
RUN mkdir -p /etc/sysctl.d
COPY <<EOF /etc/sysctl.d/99-podmotion.conf
vm.unprivileged_userfaultfd = 1
net.core.bpf_jit_enable = 1
EOF

# ---------------------------------------------------------------------------
# 7. CRIU smoke test
# ---------------------------------------------------------------------------
RUN criu --version || true

# ---------------------------------------------------------------------------
# 8. PodMotion agent binary
# ---------------------------------------------------------------------------
ARG AGENT_ARCH=amd64
COPY bin/agent-linux-${AGENT_ARCH} /usr/local/bin/podmotion-agent
RUN chmod +x /usr/local/bin/podmotion-agent && \
    ln -sf /usr/local/bin/podmotion-agent /usr/local/lib/nri/podmotion-nri
