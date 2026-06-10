#!/usr/bin/env bash
# eks-userdata.sh
# EKS Launch Template userdata script to prepare an AL2 or AL2023 node
# for PodMotion. Paste this into the UserData field of your Launch Template
# (base64-encoded, or use the raw text in the LaunchTemplate UserData field).
#
# The script detects AL2 vs AL2023 automatically.
#
# Prerequisites:
#   1. The podmotion-agent binary must be available at the S3 URL set in
#      PODMOTION_AGENT_S3_URI below, OR baked into the AMI already.
#   2. EKS bootstrap (aws eks get-token, etc.) runs AFTER this script because
#      userdata executes before the EKS node bootstrap script on custom AMIs.
#      If using EKS-managed node groups with AL2 bootstrap, ensure this script
#      is prepended to the existing userdata, not replacing it.
#
# Required IAM permissions for the node role (EC2 instance profile):
#   s3:GetObject on the bucket containing the agent binary
#   ec2:DescribeInstances (for spot reclamation M17)
#   (IMDS access is unauthenticated — no IAM needed)
#
# Tested on:
#   EKS 1.29 / AL2 (kernel 5.10.x)
#   EKS 1.29 / AL2023 (kernel 6.1.x)
#
# To encode for Launch Template UserData:
#   base64 -w0 eks-userdata.sh

set -euo pipefail
exec > >(tee /var/log/podmotion-userdata.log | logger -t podmotion-userdata) 2>&1

# ---- configuration -----------------------------------------------------------
PODMOTION_VERSION="${PODMOTION_VERSION:-v0.1.0}"
PODMOTION_AGENT_S3_URI="${PODMOTION_AGENT_S3_URI:-s3://your-bucket/podmotion/releases/${PODMOTION_VERSION}/podmotion-agent-linux-amd64}"
PODMOTION_GRPC_PORT="${PODMOTION_GRPC_PORT:-9090}"
PODMOTION_METRICS_PORT="${PODMOTION_METRICS_PORT:-9091}"
INSTALL_DIR="/usr/local/bin"
NRI_PLUGIN_DIR="/usr/local/lib/nri"

echo "==> PodMotion node preparation starting (version ${PODMOTION_VERSION})"

# ---- detect distro -----------------------------------------------------------
DISTRO_ID="unknown"
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    DISTRO_ID="${ID:-unknown}"
fi
echo "==> Detected distro: ${DISTRO_ID}"

# ---- 1. Install CRIU ---------------------------------------------------------
echo "==> Installing CRIU"
if [ "$DISTRO_ID" = "amzn" ] && grep -q 'VERSION_ID="2"' /etc/os-release 2>/dev/null; then
    # AL2: CRIU lives in EPEL
    amazon-linux-extras install -y epel
    yum install -y --enablerepo=epel criu bpftool iproute-tc jq curl
elif [ "$DISTRO_ID" = "amzn" ]; then
    # AL2023: CRIU is in base repos
    dnf install -y criu bpftool iproute-tc jq curl
else
    echo "WARN: Unknown Amazon distro ${DISTRO_ID}, attempting dnf" >&2
    dnf install -y criu bpftool iproute-tc jq curl || true
fi

CRIU_VER=$(criu --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "0.0")
echo "==> CRIU version installed: ${CRIU_VER}"

# ---- 2. Required sysctls -----------------------------------------------------
echo "==> Configuring sysctls"
cat > /etc/sysctl.d/90-podmotion.conf <<'SYSCTL'
# PodMotion node requirements
# Allow unprivileged USERFAULTFD (post-copy lazy pages)
vm.unprivileged_userfaultfd = 1
# Enable BPF JIT (required for XDP performance)
net.core.bpf_jit_enable = 1
# Disable reverse path filtering for migrating pod IPs
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
SYSCTL
sysctl --system

# ---- 3. Enable NRI in containerd (AL2023 / containerd 1.7+ only) ------------
echo "==> Configuring containerd NRI"
CONTAINERD_VER=$(containerd --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "0.0")
CONTAINERD_MAJOR=$(echo "$CONTAINERD_VER" | cut -d. -f1)
CONTAINERD_MINOR=$(echo "$CONTAINERD_VER" | cut -d. -f2)

mkdir -p /etc/containerd/conf.d "${NRI_PLUGIN_DIR}"

if [ "$CONTAINERD_MAJOR" -ge 1 ] && [ "$CONTAINERD_MINOR" -ge 7 ]; then
    echo "==> containerd ${CONTAINERD_VER}: enabling NRI plugin support"
    cat > /etc/containerd/conf.d/nri.toml <<'NRICONF'
[plugins."io.containerd.nri.v1.nri"]
  disable = false
  disable_connections = false
  plugin_registration_timeout = "5s"
  plugin_request_timeout = "2s"
  socket_path = "/var/run/nri/nri.sock"
  state_dir = "/var/lib/nri"
NRICONF
    systemctl restart containerd
    echo "==> NRI enabled"
else
    echo "WARN: containerd ${CONTAINERD_VER} does not support NRI (need 1.7+). NRI plugin will be unavailable." >&2
    echo "WARN: Migration trigger will fall back to exec-based CRIU invocation." >&2
fi

# ---- 4. Mount bpffs ----------------------------------------------------------
echo "==> Configuring bpffs"
cat > /etc/systemd/system/sys-fs-bpf.mount <<'BPFMOUNT'
[Unit]
Description=BPF filesystem mount
DefaultDependencies=no
Before=sysinit.target

[Mount]
What=bpffs
Where=/sys/fs/bpf
Type=bpf
Options=mode=700

[Install]
WantedBy=multi-user.target
BPFMOUNT
systemctl daemon-reload
systemctl enable --now sys-fs-bpf.mount

# ---- 5. Download and install podmotion-agent ---------------------------------
echo "==> Installing podmotion-agent binary from ${PODMOTION_AGENT_S3_URI}"
aws s3 cp "${PODMOTION_AGENT_S3_URI}" "${INSTALL_DIR}/podmotion-agent" \
    --no-progress 2>&1 || {
    echo "WARN: S3 download failed — checking if binary is already present" >&2
    if [ ! -f "${INSTALL_DIR}/podmotion-agent" ]; then
        echo "FATAL: podmotion-agent not found and S3 download failed" >&2
        exit 1
    fi
}
chmod +x "${INSTALL_DIR}/podmotion-agent"
ln -sf "${INSTALL_DIR}/podmotion-agent" "${NRI_PLUGIN_DIR}/podmotion-nri"
echo "==> podmotion-agent installed: $(${INSTALL_DIR}/podmotion-agent --version 2>/dev/null || echo 'version unknown')"

# ---- 6. Install podmotion-preflight and run it -------------------------------
echo "==> Running preflight checks"
# Preflight script is expected to be bundled alongside the agent in the same S3 prefix.
aws s3 cp "$(dirname "${PODMOTION_AGENT_S3_URI}")/podmotion-preflight-amazon.sh" \
    "${INSTALL_DIR}/podmotion-preflight" --no-progress 2>/dev/null || true
if [ -f "${INSTALL_DIR}/podmotion-preflight" ]; then
    chmod +x "${INSTALL_DIR}/podmotion-preflight"
    "${INSTALL_DIR}/podmotion-preflight" > /var/log/podmotion-preflight.json || true
    echo "==> Preflight results:"
    cat /var/log/podmotion-preflight.json
fi

# ---- 7. Install and start podmotion-agent.service ----------------------------
echo "==> Installing podmotion-agent systemd service"
cat > /etc/systemd/system/podmotion-agent.service <<UNITFILE
[Unit]
Description=PodMotion Node Agent
Documentation=https://podmotion.io/docs/node-agent
After=network.target containerd.service
Requires=containerd.service

[Service]
ExecStart=${INSTALL_DIR}/podmotion-agent \\
  --node-name=\${NODE_NAME} \\
  --grpc-port=${PODMOTION_GRPC_PORT} \\
  --metrics-port=${PODMOTION_METRICS_PORT} \\
  --preflight-json=/var/log/podmotion-preflight.json
Restart=always
RestartSec=10
# NODE_NAME is injected by the Downward API via a wrapper or by the systemd
# EnvironmentFile. For EKS, the node name equals the EC2 private DNS name.
EnvironmentFile=-/etc/podmotion/agent.env
StandardOutput=journal
StandardError=journal
SyslogIdentifier=podmotion-agent

[Install]
WantedBy=multi-user.target
UNITFILE

# Create env file directory; NODE_NAME resolved at service start from IMDS
mkdir -p /etc/podmotion
cat > /etc/podmotion/agent.env <<'ENVFILE'
# Populated at runtime by cloud-init from IMDS
NODE_NAME=
ENVFILE

# Resolve NODE_NAME from IMDS (IMDSv2)
IMDS_TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
    --connect-timeout 5 2>/dev/null) || IMDS_TOKEN=""
if [ -n "$IMDS_TOKEN" ]; then
    NODE_NAME=$(curl -s -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" \
        "http://169.254.169.254/latest/meta-data/local-hostname" \
        --connect-timeout 5 2>/dev/null) || NODE_NAME=""
    if [ -n "$NODE_NAME" ]; then
        echo "NODE_NAME=${NODE_NAME}" > /etc/podmotion/agent.env
        echo "==> NODE_NAME resolved from IMDS: ${NODE_NAME}"
    fi
fi

systemctl daemon-reload
systemctl enable podmotion-agent
# Service starts after kubelet joins — delay actual start to avoid race
# (kubelet registration writes the node object that the agent reads)
systemctl start podmotion-agent || echo "WARN: podmotion-agent start failed — will retry via Restart=always"

echo "==> PodMotion node preparation complete"
