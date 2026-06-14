# PodMotion kind node image for local E2E testing.
# Built on top of the upstream kind node image.
# Usage: make kind-node-image
#        kind create cluster --config images/kind/kind-config.yaml

ARG KIND_BASE=kindest/node:v1.32.0
FROM ${KIND_BASE}

# Add CRIU OBS repo to get CRIU 4.x.
# kindest/node:v1.32.0 is Debian Bookworm (12). Debian Bookworm ships CRIU 3.17
# which is incompatible with go-criu v7.2 RPC protocol (requires 4.x).
# Ubuntu PPAs are not compatible with Debian; use the CRIU OpenSUSE Build Service
# repository for Debian 12 instead.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
  && curl -fsSL https://download.opensuse.org/repositories/devel:/tools:/criu/Debian_12/Release.key \
     | gpg --dearmor -o /etc/apt/trusted.gpg.d/criu.gpg \
  && echo "deb https://download.opensuse.org/repositories/devel:/tools:/criu/Debian_12/ /" \
     > /etc/apt/sources.list.d/criu.list \
  && rm -rf /var/lib/apt/lists/*

# Install CRIU 4.x and supporting tools.
# On Debian Bookworm bpftool is a standalone package (unlike Ubuntu 22.04 where
# it required linux-tools-virtual). buildah and skopeo are in Debian Bookworm main.
RUN apt-get update && apt-get install -y --no-install-recommends \
    criu \
    bpftool \
    iproute2 \
    buildah \
    skopeo \
    jq \
  && rm -rf /var/lib/apt/lists/*

# Verify CRIU 4.x is installed. Kernel feature warnings inside Docker are expected.
# A version < 4.0 here means the PPA was not honoured — fail the build explicitly.
RUN criu --version && criu --version | grep -qE "^Version: [4-9]\." || \
    { echo "ERROR: CRIU < 4.0 installed. go-criu v7.2 requires CRIU 4.x RPC protocol."; exit 1; }

# Create required directories
RUN mkdir -p /etc/containerd/conf.d /usr/local/lib/nri

# Enable NRI in containerd
COPY images/capi/ansible/roles/podmotion-node/files/nri.toml /etc/containerd/conf.d/nri.toml

# bpffs systemd mount unit
COPY images/capi/ansible/roles/podmotion-node/files/sys-fs-bpf.mount /etc/systemd/system/sys-fs-bpf.mount
RUN systemctl enable sys-fs-bpf.mount 2>/dev/null || true

# Install compiled zero_window BPF objects for on-disk inspection and manual reload.
# The agent binary embeds these via //go:embed; the on-disk copies allow bpftool
# introspection and are required if the agent needs to reload after an OOM eviction.
RUN mkdir -p /usr/lib/podmotion/bpf
COPY bpf/zero_window_bpfel.o /usr/lib/podmotion/bpf/zero_window_bpfel.o
COPY bpf/zero_window_bpfeb.o /usr/lib/podmotion/bpf/zero_window_bpfeb.o
RUN chmod 644 /usr/lib/podmotion/bpf/zero_window_bpfel.o \
           /usr/lib/podmotion/bpf/zero_window_bpfeb.o

# Install real agent binary (compiled for linux/amd64)
COPY bin/agent-linux-amd64 /usr/local/bin/podmotion-agent
RUN chmod +x /usr/local/bin/podmotion-agent \
  && ln -sf /usr/local/bin/podmotion-agent /usr/local/lib/nri/podmotion-nri
