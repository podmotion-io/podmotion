# PodMotion node image — Ubuntu 22.04 LTS (Jammy)
#
# Target: kind dev/E2E clusters and AWS AMI PoC (Ubuntu 22.04 base).
# CRIU 4.2 is obtained from the CRIU PPA because Ubuntu 22.04 universe ships 3.17,
# which is incompatible with go-criu v7.2+ RPC protocol.
# CRIU is invoked as a subprocess (never statically linked) per ADR-0002.
#
# Build:
#   docker build -f images/ubuntu-22.04/Dockerfile -t podmotion-node:ubuntu-22.04 .
# Or via kind:
#   kind build node-image --image podmotion-node:ubuntu-22.04 images/ubuntu-22.04/

ARG KIND_BASE=kindest/node:v1.32.0
FROM ${KIND_BASE}

LABEL org.opencontainers.image.title="podmotion-node-ubuntu-22.04"
LABEL org.opencontainers.image.description="PodMotion-ready Kubernetes node image (Ubuntu 22.04 Jammy)"
LABEL org.opencontainers.image.source="https://github.com/podmotion-io/podmotion"

# -------------------------------------------------------------------------
# 1. Base apt setup + Docker repo for containerd 1.7+ (NRI support)
# -------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    software-properties-common \
  && rm -rf /var/lib/apt/lists/*

# Docker repo — provides containerd.io >= 1.7 with NRI support
RUN install -m 0755 -d /etc/apt/keyrings \
  && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
       | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
  && chmod a+r /etc/apt/keyrings/docker.gpg \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
       https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
       > /etc/apt/sources.list.d/docker.list

# CRIU PPA — Ubuntu 22.04 universe ships CRIU 3.17; PPA provides 4.2+
# Required: go-criu v7.2+ (in go.mod) needs CRIU RPC protocol 4.x.
RUN add-apt-repository -y ppa:criu/ppa

# Kubic repo — provides buildah 1.33+ and skopeo 1.14+ for Ubuntu 22.04
RUN echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_22.04/ /" \
      > /etc/apt/sources.list.d/libcontainers.list \
  && curl -fsSL "https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_22.04/Release.key" \
       | gpg --dearmor -o /etc/apt/keyrings/libcontainers.gpg \
  && chmod a+r /etc/apt/keyrings/libcontainers.gpg

# -------------------------------------------------------------------------
# 2. Install all required packages
# -------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    # CRIU 4.2+ from PPA (3.17 from universe is insufficient for go-criu v7)
    criu \
    # containerd 1.7+ from Docker repo (NRI support required for NRI plugin)
    containerd.io \
    # bpftool matched to kernel (linux-tools-common provides the wrapper that
    # dispatches to linux-tools-$(uname -r); kernel-version package must be
    # installed separately at runtime if not baked from a specific kernel base)
    linux-tools-common \
    linux-tools-virtual \
    # iproute2 >= 5.15 — tc BPF actions for packet bridge
    iproute2 \
    # OCI checkpoint image push/pull
    buildah \
    skopeo \
    # JSON parsing in agent scripts and preflight
    jq \
    # eBPF CO-RE: libbpf 0.5 from Ubuntu 22.04 is insufficient.
    # libbpf-dev from Kubic/backports provides >= 1.2 for full CO-RE + BTF support.
    libbpf-dev \
    # nftables + iptables-nft for CNI network rules
    nftables \
    iptables \
    # TUN/TAP for CNI and WireGuard-based CNIs
    # (module only — loaded at runtime)
    # CRIU TLS (GnuTLS backend for secure checkpoint transfer between nodes)
    libgnutls28-dev \
    # protobuf required if CRIU is rebuilt; pre-built package bundles it
    # but headers are useful for debugging
    libprotobuf-dev \
    # socket debugging (optional but valuable for migration troubleshooting)
    socat \
    # python3-protobuf for pycriu image inspection during development
    python3-protobuf \
  && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------------
# 3. Post-install verification
# -------------------------------------------------------------------------
# Verify CRIU version is 4.x (kernel feature warnings in Docker are expected)
RUN criu --version \
  && CRIU_MAJ=$(criu --version | awk '/Version/{print $2}' | cut -d. -f1) \
  && echo "CRIU major version: ${CRIU_MAJ}" \
  && [ "${CRIU_MAJ}" -ge 4 ] || (echo "ERROR: CRIU < 4.0 detected — RPC mismatch with go-criu v7" && exit 1)

# Verify iproute2 version
RUN ip -V | grep -oP 'iproute2-\K[0-9.]+' | awk -F. '{if($1*100+$2 >= 515) exit 0; else exit 1}' \
  || echo "WARNING: iproute2 < 5.15 — tc BPF actions may be limited"

# -------------------------------------------------------------------------
# 4. Containerd NRI configuration
# -------------------------------------------------------------------------
RUN mkdir -p /etc/containerd/conf.d /usr/local/lib/nri /var/run/nri /var/lib/nri

# NRI enable snippet — containerd merges files from conf.d
COPY images/capi/ansible/roles/podmotion-node/files/nri.toml /etc/containerd/conf.d/nri.toml

# -------------------------------------------------------------------------
# 5. bpffs systemd mount unit
# -------------------------------------------------------------------------
COPY images/capi/ansible/roles/podmotion-node/files/sys-fs-bpf.mount /etc/systemd/system/sys-fs-bpf.mount
RUN systemctl enable sys-fs-bpf.mount 2>/dev/null || true

# -------------------------------------------------------------------------
# 6. sysctl configuration
# -------------------------------------------------------------------------
# Ubuntu 22.04 sets unprivileged_userfaultfd=0 by default.
# CRIU post-copy lazy pages require UFFD; agent runs privileged but we
# set this explicitly for compatibility and to match RHEL 9 workaround parity.
RUN echo "vm.unprivileged_userfaultfd=1" > /etc/sysctl.d/90-podmotion.conf \
  && echo "net.core.bpf_jit_enable=1"   >> /etc/sysctl.d/90-podmotion.conf \
  && echo "net.core.bpf_jit_harden=0"   >> /etc/sysctl.d/90-podmotion.conf

# -------------------------------------------------------------------------
# 7. AppArmor profile for podmotion-agent
# -------------------------------------------------------------------------
# Ubuntu's AppArmor requires SYS_PTRACE, SYS_ADMIN, and NET_ADMIN for CRIU.
# The profile is loaded at runtime by the agent startup script; we bake the
# file into the image so it is available before the agent starts.
RUN mkdir -p /etc/apparmor.d
COPY images/ubuntu-22.04/apparmor/podmotion-agent /etc/apparmor.d/podmotion-agent

# -------------------------------------------------------------------------
# 8. CRIU runtime directories
# -------------------------------------------------------------------------
RUN mkdir -p /var/lib/podmotion/checkpoints \
  && chmod 700 /var/lib/podmotion/checkpoints

# -------------------------------------------------------------------------
# 9. nftables / iptables-nft backend
# -------------------------------------------------------------------------
# Prefer nft backend for iptables — required by Calico, OVN-K, and our
# per-pod firewall rules during IP handoff.
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

# Final smoke-test: ensure criu and bpftool are reachable
RUN criu --version && (bpftool version || linux-tools-virtual --version 2>/dev/null || true)
