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
  && rm -rf /var/lib/apt/lists/*
COPY bin/agent-linux-amd64 /agent
ENTRYPOINT ["/agent"]
