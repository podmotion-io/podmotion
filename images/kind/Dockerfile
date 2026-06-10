# PodMotion kind node image for local E2E testing.
# Built on top of the upstream kind node image base.
# Usage: docker build -t podmotion/kind-node:latest images/kind/
#        kind create cluster --image podmotion/kind-node:latest

ARG KIND_BASE=kindest/base:latest
FROM ${KIND_BASE}

# Install CRIU and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    criu \
    bpftool \
    iproute2 \
    buildah \
    skopeo \
    jq \
  && rm -rf /var/lib/apt/lists/*

# Verify CRIU installed (may warn about missing kernel features inside Docker — expected)
RUN criu --version

# Enable NRI in containerd config (appended; containerd config is finalized at cluster create time)
COPY nri.toml /etc/containerd/conf.d/nri.toml

# bpffs mount unit
COPY sys-fs-bpf.mount /etc/systemd/system/sys-fs-bpf.mount
RUN systemctl enable sys-fs-bpf.mount 2>/dev/null || true

# Placeholder agent binaries — replaced by 'make kind-load' during development
COPY --chown=root:root podmotion-agent-placeholder /usr/local/bin/podmotion-agent
COPY --chown=root:root podmotion-nri-placeholder /usr/local/lib/nri/podmotion-nri
RUN chmod +x /usr/local/bin/podmotion-agent /usr/local/lib/nri/podmotion-nri
