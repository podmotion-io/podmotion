#!/usr/bin/env bash
# podmotion-preflight-amazon.sh
# Run on every EKS node at agent startup (or as a Kubernetes init container).
# Outputs JSON to stdout so the agent can populate NodeMigrationCapacitySpec.
# Exit 0 always — degraded capability is reported in JSON, not as a hard failure.
#
# Usage:
#   podmotion-preflight-amazon.sh [--json]   (--json is default, kept for compat)
#   PODMOTION_FAIL_ON_MISSING=1 podmotion-preflight-amazon.sh   (fail if mandatory)
set -euo pipefail

KERNEL_VERSION="$(uname -r)"
ARCH="$(uname -m)"
DISTRO_ID="unknown"
DISTRO_VERSION="unknown"

if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_VERSION="${VERSION_ID:-unknown}"
fi

# ---- helpers -----------------------------------------------------------------
kconfig() {
    local cfg="$1"
    local config_file="/boot/config-${KERNEL_VERSION}"
    [ -f "$config_file" ] || config_file="/proc/config.gz"
    if [ -f "/boot/config-${KERNEL_VERSION}" ]; then
        grep -q "^${cfg}=y" "/boot/config-${KERNEL_VERSION}" && echo "true" || echo "false"
    elif [ -f "/proc/config.gz" ]; then
        zcat /proc/config.gz | grep -q "^${cfg}=y" && echo "true" || echo "false"
    else
        echo "unknown"
    fi
}

sysctl_val() {
    sysctl -n "$1" 2>/dev/null || echo "0"
}

cgroup_version() {
    if grep -q "cgroup2" /proc/mounts 2>/dev/null; then
        # Check if it is unified (v2 only)
        if ! grep -q "cgroup " /proc/mounts 2>/dev/null; then
            echo "v2"
        else
            echo "mixed"
        fi
    else
        echo "v1"
    fi
}

cgroup_freezer_ok() {
    local cgv
    cgv="$(cgroup_version)"
    if [ "$cgv" = "v2" ]; then
        grep -q "freezer" /sys/fs/cgroup/cgroup.controllers 2>/dev/null && echo "true" || echo "false"
    elif [ "$cgv" = "v1" ]; then
        [ -d /sys/fs/cgroup/freezer ] && echo "true" || echo "false"
    else
        echo "false"
    fi
}

criu_version() {
    criu --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || echo "absent"
}

containerd_version() {
    containerd --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "absent"
}

nri_enabled() {
    # Check if NRI socket exists or containerd config enables NRI
    if [ -S /var/run/nri/nri.sock ]; then
        echo "true"
    elif grep -r "disable = false" /etc/containerd/conf.d/ 2>/dev/null | grep -q "nri"; then
        echo "true"
    elif containerd config dump 2>/dev/null | grep -A5 'nri' | grep -q 'disable = false'; then
        echo "true"
    else
        echo "false"
    fi
}

imds_reachable() {
    # IMDSv2: get a token then use it
    local token
    token=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 10" \
        --connect-timeout 2 2>/dev/null) || true
    if [ -n "$token" ]; then
        local az
        az=$(curl -s -H "X-aws-ec2-metadata-token: ${token}" \
            "http://169.254.169.254/latest/meta-data/placement/availability-zone" \
            --connect-timeout 2 2>/dev/null) || true
        [ -n "$az" ] && echo "true" || echo "false"
    else
        echo "false"
    fi
}

instance_type() {
    local token
    token=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 10" \
        --connect-timeout 2 2>/dev/null) || true
    [ -n "$token" ] && \
        curl -s -H "X-aws-ec2-metadata-token: ${token}" \
            "http://169.254.169.254/latest/meta-data/instance-type" \
            --connect-timeout 2 2>/dev/null || echo "unknown"
}

is_spot() {
    local token
    token=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 10" \
        --connect-timeout 2 2>/dev/null) || true
    if [ -n "$token" ]; then
        local lc
        lc=$(curl -s -H "X-aws-ec2-metadata-token: ${token}" \
            "http://169.254.169.254/latest/meta-data/instance-life-cycle" \
            --connect-timeout 2 2>/dev/null) || true
        [ "$lc" = "spot" ] && echo "true" || echo "false"
    else
        echo "false"
    fi
}

selinux_mode() {
    getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "disabled"
}

# ---- collect -----------------------------------------------------------------
CR=$(kconfig CONFIG_CHECKPOINT_RESTORE)
MSD=$(kconfig CONFIG_MEM_SOFT_DIRTY)
UFD=$(kconfig CONFIG_USERFAULTFD)
BPF=$(kconfig CONFIG_BPF_SYSCALL)
BPFJIT=$(kconfig CONFIG_BPF_JIT)
XDP=$(kconfig CONFIG_XDP_SOCKETS)
SCH_INGRESS=$(kconfig CONFIG_NET_SCH_INGRESS)
CLS_BPF=$(kconfig CONFIG_NET_CLS_BPF)
VETH=$(kconfig CONFIG_VETH)
NET_NS=$(kconfig CONFIG_NET_NS)
TUN=$(kconfig CONFIG_TUN)
UNIX_DIAG=$(kconfig CONFIG_UNIX_DIAG)
INET_DIAG=$(kconfig CONFIG_INET_DIAG)

CGROUPV=$(cgroup_version)
FREEZER_OK=$(cgroup_freezer_ok)
BPF_JIT_RUNTIME=$(sysctl_val net.core.bpf_jit_enable)
UFD_UNPRIV=$(sysctl_val vm.unprivileged_userfaultfd)
INOTIFY_INSTANCES=$(sysctl_val fs.inotify.max_user_instances)
INOTIFY_WATCHES=$(sysctl_val fs.inotify.max_user_watches)

CRIU_VER=$(criu_version)
CONTAINERD_VER=$(containerd_version)
NRI_ENABLED=$(nri_enabled)
IMDS_OK=$(imds_reachable)
INSTANCE_TYPE=$(instance_type)
SPOT=$(is_spot)
SELINUX=$(selinux_mode)

# ---- derive migration capabilities -------------------------------------------
# cold_migration: requires CHECKPOINT_RESTORE + cgroup freezer + criu present
COLD_MIGRATION="false"
if [ "$CR" = "true" ] && [ "$FREEZER_OK" = "true" ] && [ "$CRIU_VER" != "absent" ]; then
    COLD_MIGRATION="true"
fi

# precopy_iterative: additionally requires MEM_SOFT_DIRTY + arm64 check
PRECOPY="false"
if [ "$COLD_MIGRATION" = "true" ] && [ "$MSD" = "true" ]; then
    # arm64 needs kernel >= 5.15 for MEM_SOFT_DIRTY
    if [ "$ARCH" = "aarch64" ]; then
        KMAJ=$(echo "$KERNEL_VERSION" | cut -d. -f1)
        KMIN=$(echo "$KERNEL_VERSION" | cut -d. -f2)
        if [ "$KMAJ" -gt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -ge 15 ]; }; then
            PRECOPY="true"
        fi
    else
        PRECOPY="true"
    fi
fi

# ebpf_bridge: requires BPF_SYSCALL + BPF_JIT + XDP_SOCKETS + veth XDP (kernel >= 5.10)
EBPF_BRIDGE="false"
if [ "$BPF" = "true" ] && [ "$BPFJIT" = "true" ] && [ "$XDP" = "true" ]; then
    KMAJ=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    KMIN=$(echo "$KERNEL_VERSION" | cut -d. -f2)
    if [ "$KMAJ" -gt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -ge 10 ]; }; then
        EBPF_BRIDGE="true"
    fi
fi

# spot_reclamation: requires IMDS reachable
SPOT_RECLAIM="$IMDS_OK"

# postcopy_lazy: requires USERFAULTFD + unprivileged or agent is privileged
POSTCOPY="false"
if [ "$UFD" = "true" ]; then
    if [ "$UFD_UNPRIV" = "1" ] || [ "$(id -u)" = "0" ]; then
        POSTCOPY="true"
    fi
fi

# ---- output JSON -------------------------------------------------------------
cat <<EOF
{
  "distro": "${DISTRO_ID}",
  "distroVersion": "${DISTRO_VERSION}",
  "kernelVersion": "${KERNEL_VERSION}",
  "arch": "${ARCH}",
  "cgroupVersion": "${CGROUPV}",
  "selinuxMode": "${SELINUX}",
  "criuVersion": "${CRIU_VER}",
  "containerdVersion": "${CONTAINERD_VER}",
  "nriEnabled": ${NRI_ENABLED},
  "imdsReachable": ${IMDS_OK},
  "instanceType": "${INSTANCE_TYPE}",
  "isSpot": ${SPOT},
  "kernelFeatures": {
    "checkpointRestore": ${CR},
    "memSoftDirty": ${MSD},
    "userfaultfd": ${UFD},
    "bpfSyscall": ${BPF},
    "bpfJit": ${BPFJIT},
    "bpfJitRuntimeEnabled": $([ "$BPF_JIT_RUNTIME" = "1" ] || [ "$BPF_JIT_RUNTIME" = "2" ] && echo true || echo false),
    "xdpSockets": ${XDP},
    "netSchIngress": ${SCH_INGRESS},
    "netClsBpf": ${CLS_BPF},
    "veth": ${VETH},
    "netNs": ${NET_NS},
    "tun": ${TUN},
    "unixDiag": ${UNIX_DIAG},
    "inetDiag": ${INET_DIAG},
    "cgroupFreezer": ${FREEZER_OK},
    "userfaultfdUnprivileged": $([ "$UFD_UNPRIV" = "1" ] && echo true || echo false),
    "inotifyMaxUserInstances": ${INOTIFY_INSTANCES},
    "inotifyMaxUserWatches": ${INOTIFY_WATCHES},
    "inotifyLimitsOk": $([ "$INOTIFY_INSTANCES" -ge 8192 ] && [ "$INOTIFY_WATCHES" -ge 1048576 ] && echo true || echo false)
  },
  "migrationCapabilities": {
    "coldMigration": ${COLD_MIGRATION},
    "preCopyIterative": ${PRECOPY},
    "postCopyLazyPages": ${POSTCOPY},
    "ebpfBridge": ${EBPF_BRIDGE},
    "spotReclamation": ${SPOT_RECLAIM}
  }
}
EOF

# ---- hard-fail mode ----------------------------------------------------------
if [ "${PODMOTION_FAIL_ON_MISSING:-0}" = "1" ]; then
    FATAL=0
    [ "$CR" = "true" ] || { echo "FATAL: CONFIG_CHECKPOINT_RESTORE missing" >&2; FATAL=1; }
    [ "$CGROUPV" != "v1" ] || { echo "FATAL: cgroup v1 detected — cgroup v2 required" >&2; FATAL=1; }
    [ "$CRIU_VER" != "absent" ] || { echo "FATAL: CRIU binary not found" >&2; FATAL=1; }
    exit $FATAL
fi
