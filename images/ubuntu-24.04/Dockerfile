# PodMotion node image — Ubuntu 24.04 LTS (Noble)
#
# Ubuntu 24.04 ships kernel 6.8, CRIU 4.0+ in main (PPA still recommended
# for pinning 4.2+), containerd 1.7+ in the Docker repo, and libbpf 1.3.
# This is the preferred production node image for fresh clusters.
#
# Build:
#   docker build -f images/ubuntu-24.04/Dockerfile -t podmotion-node:ubuntu-24.04 .
#
# NOTE: kindest/node:v1.32.0 is Ubuntu 22.04-based. For a true Ubuntu 24.04
# kind node, use kindest/node:v1.33.0 or build with image-builder targeting
# ubuntu-2404 and the cluster-api provider. For AWS AMI this is the primary target.

ARG UBUNTU_BASE=ubuntu:24.04
FROM ${UBUNTU_BASE}

LABEL org.opencontainers.image.title="podmotion-node-ubuntu-24.04"
LABEL org.opencontainers.image.description="PodMotion-ready Kubernetes node image (Ubuntu 24.04 Noble)"
LABEL org.opencontainers.image.source="https://github.com/podmotion-io/podmotion"

# -------------------------------------------------------------------------
# 1. Base apt setup
# -------------------------------------------------------------------------
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    software-properties-common \
    systemd \
    systemd-sysv \
  && rm -rf /var/lib/apt/lists/*

# Docker repo — containerd.io 1.7+ with NRI support
RUN install -m 0755 -d /etc/apt/keyrings \
  && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
       | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
  && chmod a+r /etc/apt/keyrings/docker.gpg \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
       https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
       > /etc/apt/sources.list.d/docker.list

# CRIU PPA — Noble has CRIU 4.0 in main; PPA provides 4.2+ pinned release
# Recommended to ensure version alignment with go-criu v7.2+ RPC protocol.
RUN add-apt-repository -y ppa:criu/ppa

# -------------------------------------------------------------------------
# 2. Install all required packages
# -------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    # CRIU 4.2+ from PPA — Noble main has 4.0 but PPA ensures 4.2+
    criu \
    # containerd.io 1.7+ from Docker repo (NRI plugin support)
    containerd.io \
    # bpftool — Noble ships bpftool as a standalone package (no uname-r needed)
    # Also install linux-tools-common for the wrapper fallback
    bpftool \
    linux-tools-common \
    # iproute2 >= 6.1 ships with Noble (well above the 5.15 minimum)
    iproute2 \
    # OCI checkpoint image management
    buildah \
    skopeo \
    # JSON parsing
    jq \
    # libbpf 1.3 in Noble main — sufficient for full CO-RE + BTF + ring buffer
    libbpf-dev \
    libbpf1 \
    # nftables + iptables-nft for CNI rules
    nftables \
    iptables \
    # CRIU TLS (GnuTLS backend)
    libgnutls28-dev \
    # protobuf (useful if custom CRIU build needed)
    libprotobuf-dev \
    # socket/network debugging
    socat \
    # pycriu for checkpoint image inspection in dev
    python3-protobuf \
    # AppArmor utilities for loading profile at runtime
    apparmor \
    apparmor-utils \
  && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------------
# 3. Post-install verification
# -------------------------------------------------------------------------
RUN criu --version \
  && CRIU_MAJ=$(criu --version | awk '/Version/{print $2}' | cut -d. -f1) \
  && echo "CRIU major version: ${CRIU_MAJ}" \
  && [ "${CRIU_MAJ}" -ge 4 ] || (echo "ERROR: CRIU < 4.0 — RPC mismatch with go-criu v7" && exit 1)

RUN bpftool version

# -------------------------------------------------------------------------
# 4. Containerd NRI configuration
# -------------------------------------------------------------------------
RUN mkdir -p /etc/containerd/conf.d /usr/local/lib/nri /var/run/nri /var/lib/nri

COPY images/capi/ansible/roles/podmotion-node/files/nri.toml /etc/containerd/conf.d/nri.toml

# -------------------------------------------------------------------------
# 5. bpffs systemd mount unit
# -------------------------------------------------------------------------
COPY images/capi/ansible/roles/podmotion-node/files/sys-fs-bpf.mount /etc/systemd/system/sys-fs-bpf.mount
RUN systemctl enable sys-fs-bpf.mount 2>/dev/null || true

# -------------------------------------------------------------------------
# 6. sysctl configuration
# -------------------------------------------------------------------------
# Noble defaults: unprivileged_userfaultfd=0 (same as Jammy).
# Setting to 1 here; agent startup will also enforce via sysctl -w at runtime.
RUN echo "vm.unprivileged_userfaultfd=1" > /etc/sysctl.d/90-podmotion.conf \
  && echo "net.core.bpf_jit_enable=1"   >> /etc/sysctl.d/90-podmotion.conf \
  && echo "net.core.bpf_jit_harden=0"   >> /etc/sysctl.d/90-podmotion.conf

# -------------------------------------------------------------------------
# 7. AppArmor profile
# -------------------------------------------------------------------------
RUN mkdir -p /etc/apparmor.d
# Reuse the same profile — capability requirements are identical on 24.04.
COPY images/ubuntu-22.04/apparmor/podmotion-agent /etc/apparmor.d/podmotion-agent

# -------------------------------------------------------------------------
# 8. CRIU runtime directories
# -------------------------------------------------------------------------
RUN mkdir -p /var/lib/podmotion/checkpoints \
  && chmod 700 /var/lib/podmotion/checkpoints

# -------------------------------------------------------------------------
# 9. iptables-nft backend
# -------------------------------------------------------------------------
RUN update-alternatives --set iptables  /usr/sbin/iptables-nft  2>/dev/null || true \
  && update-alternatives --set ip6tables /usr/sbin/ip6tables-nft 2>/dev/null || true

# -------------------------------------------------------------------------
# 10. Preflight script
# -------------------------------------------------------------------------
COPY scripts/podmotion-preflight-ubuntu.sh /usr/local/bin/podmotion-preflight
RUN chmod +x /usr/local/bin/podmotion-preflight

# -------------------------------------------------------------------------
# 11. Agent binary + NRI symlink
# -------------------------------------------------------------------------
COPY bin/agent-linux-amd64 /usr/local/bin/podmotion-agent
RUN chmod +x /usr/local/bin/podmotion-agent \
  && ln -sf /usr/local/bin/podmotion-agent /usr/local/lib/nri/podmotion-nri

# Final smoke-test
RUN criu --version && bpftool version
