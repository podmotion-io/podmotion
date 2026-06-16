# Use debian-slim so CRIU's shared libraries (libbsd, libnftables, etc.) are available.
# CRIU is mounted from the host node via hostPath volume; the agent calls it as a subprocess.
# Running as root is required for CRIU checkpoint/restore operations (CAP_SYS_PTRACE, SYS_ADMIN).
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbsd0 \
    libnftables1 \
    libprotobuf-c1 \
    libnl-3-200 \
    libnet1 \
    libgnutls30 \
    ca-certificates \
    iproute2 \
    iptables \
    python3 \
    python3-protobuf \
  && rm -rf /var/lib/apt/lists/*
COPY pycriu/ /usr/lib/python3/dist-packages/pycriu/
COPY bin/agent-linux-amd64 /agent
# ADR-0195 Rule A: universal no-op holder binary injected into replacement pods via init-container
# + emptyDir side-load. Staged in the agent image at /podmotion/holder.
# The init-container (podmotion-inject-holder) copies this binary into the replacement pod's
# emptyDir volume at /holder-bin/holder (mounted at /podmotion/holder in the main container).
# Static binary (CGO_ENABLED=0) — resolves in FROM-scratch rootfs; no base-image tool dependency.
# Build: make build-linux → bin/holder-linux-amd64
COPY bin/holder-linux-amd64 /podmotion/holder
# ADR-0181: cgroup fd delivery wrapper — staged in the agent image at /usr/local/bin/podmotion-criu-wrapper.
# nsenter exec-chains into this binary (on the host) before execve-ing criu.
# ADR-0183 r1: the install-criu-wrapper init container copies this binary onto the host node
# filesystem at /opt/podmotion/bin/podmotion-criu-wrapper. Authenticity is established by the
# OCI image digest: containerd verifies the agent image digest on pull (pinned via Helm
# agent.image; ImagePullPolicy=Never on kind), so a digest-verified image yields an authentic
# binary. No co-located .sha256 sidecar is shipped — a checksum stored in the same image layer as
# the binary it validates is integrity theater against an image-poisoning adversary (ADR-0183 S1/C1).
# Roadmap (ADR-0183 C5): cosign/sigstore signing of released agent images with an out-of-band key.
# Build: make build-linux → cp bin/podmotion-criu-wrapper-amd64 bin/criu-wrapper-linux-amd64
COPY bin/criu-wrapper-linux-amd64 /usr/local/bin/podmotion-criu-wrapper
ENTRYPOINT ["/agent"]
