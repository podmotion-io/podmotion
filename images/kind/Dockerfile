# PodMotion kind node image for local E2E testing.
# Built on top of the upstream kind node image.
# Usage: make kind-node-image
#        kind create cluster --config images/kind/kind-config.yaml

ARG KIND_BASE=kindest/node:v1.32.0
FROM ${KIND_BASE}

# Install CRIU and supporting tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    criu \
    bpftool \
    iproute2 \
    buildah \
    skopeo \
    jq \
  && rm -rf /var/lib/apt/lists/*

# Verify CRIU installed (kernel feature warnings inside Docker are expected)
RUN criu --version || true

# Create required directories
RUN mkdir -p /etc/containerd/conf.d /usr/local/lib/nri

# Enable NRI in containerd
COPY images/capi/ansible/roles/podmotion-node/files/nri.toml /etc/containerd/conf.d/nri.toml

# bpffs systemd mount unit
COPY images/capi/ansible/roles/podmotion-node/files/sys-fs-bpf.mount /etc/systemd/system/sys-fs-bpf.mount
RUN systemctl enable sys-fs-bpf.mount 2>/dev/null || true

# Install real agent binary (compiled for linux/amd64)
COPY bin/agent-linux-amd64 /usr/local/bin/podmotion-agent
RUN chmod +x /usr/local/bin/podmotion-agent \
  && ln -sf /usr/local/bin/podmotion-agent /usr/local/lib/nri/podmotion-nri
