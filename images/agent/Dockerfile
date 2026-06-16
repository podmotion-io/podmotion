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
    python3 \
    python3-protobuf \
  && rm -rf /var/lib/apt/lists/*
COPY pycriu/ /usr/lib/python3/dist-packages/pycriu/
COPY bin/agent-linux-amd64 /agent
# ADR-0181: cgroup fd delivery wrapper — must be present at /usr/local/bin/podmotion-criu-wrapper
# inside the agent image. nsenter exec-chains into this binary before execve-ing criu.
# Build: make build-linux → cp bin/podmotion-criu-wrapper-amd64 bin/criu-wrapper-linux-amd64
COPY bin/criu-wrapper-linux-amd64 /usr/local/bin/podmotion-criu-wrapper
ENTRYPOINT ["/agent"]
