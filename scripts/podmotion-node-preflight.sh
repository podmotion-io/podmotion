#!/usr/bin/env bash
# podmotion-node-preflight.sh — unified node readiness check for all supported distros.
#
# Usage:
#   podmotion-node-preflight.sh [--json] [--exit-on-fail]
#
# Exit codes:
#   0 — all required checks pass (node is fully migration-ready)
#   1 — one or more required checks failed (node is not ready)
#   2 — required checks pass; optional checks failed (cold-migration-only mode)
#
# Output:
#   stdout — JSON object (when --json is given)
#   stderr — human-readable summary (always)

set -euo pipefail

# ----------------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------------
JSON_MODE=false
EXIT_ON_FAIL=false
for arg in "$@"; do
  case "$arg" in
    --json)         JSON_MODE=true ;;
    --exit-on-fail) EXIT_ON_FAIL=true ;;
  esac
done

# ----------------------------------------------------------------------------
# Distro detection
# ----------------------------------------------------------------------------
DISTRO="unknown"
DISTRO_VERSION="unknown"
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  DISTRO="${ID:-unknown}"
  DISTRO_VERSION="${VERSION_ID:-unknown}"
fi

# Normalise distro names
case "$DISTRO" in
  rhel|rocky|almalinux|centos) DISTRO_FAMILY="rhel" ;;
  amzn)                         DISTRO_FAMILY="amazon" ;;
  ubuntu|debian)                DISTRO_FAMILY="debian" ;;
  *)                             DISTRO_FAMILY="$DISTRO" ;;
esac

KERNEL_VERSION="$(uname -r)"
ARCH="$(uname -m)"
NODE_NAME="${NODE_NAME:-$(hostname -s)}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ----------------------------------------------------------------------------
# Internal state
# ----------------------------------------------------------------------------
declare -a CHECKS=()
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
FAIL_REQUIRED_COUNT=0
FAIL_OPTIONAL_COUNT=0

log_info()  { echo "[INFO]  $*" >&2; }
log_warn()  { echo "[WARN]  $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

# record_check <name> <required:true|false> <pass:true|false> <detail>
record_check() {
  local name="$1" required="$2" pass="$3" detail="$4"
  CHECKS+=("{\"name\":\"${name}\",\"required\":${required},\"pass\":${pass},\"detail\":\"$(echo "$detail" | sed 's/"/\\"/g')\"}")
  if [[ "$pass" == "true" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    log_info "  PASS  [$(if [[ "$required" == "true" ]]; then echo "REQ"; else echo "OPT"; fi)] ${name}: ${detail}"
  elif [[ "$required" == "true" ]]; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAIL_REQUIRED_COUNT=$((FAIL_REQUIRED_COUNT + 1))
    log_error "  FAIL  [REQ] ${name}: ${detail}"
  else
    WARN_COUNT=$((WARN_COUNT + 1))
    FAIL_OPTIONAL_COUNT=$((FAIL_OPTIONAL_COUNT + 1))
    log_warn "  WARN  [OPT] ${name}: ${detail}"
  fi
}

# ----------------------------------------------------------------------------
# Kernel config resolution
# ----------------------------------------------------------------------------
KCONFIG_FILE=""
if [[ -f /proc/config.gz ]]; then
  KCONFIG_TMP=$(mktemp /tmp/kconfig.XXXXXX)
  trap 'rm -f "$KCONFIG_TMP"' EXIT
  zcat /proc/config.gz > "$KCONFIG_TMP"
  KCONFIG_FILE="$KCONFIG_TMP"
elif [[ -f "/boot/config-${KERNEL_VERSION}" ]]; then
  KCONFIG_FILE="/boot/config-${KERNEL_VERSION}"
elif [[ -f "/lib/modules/${KERNEL_VERSION}/config" ]]; then
  KCONFIG_FILE="/lib/modules/${KERNEL_VERSION}/config"
else
  log_warn "Kernel config not found — kernel config checks will be skipped"
fi

check_kconfig() {
  local cfg="$1" required="$2"
  if [[ -z "$KCONFIG_FILE" ]]; then
    record_check "$cfg" "$required" "false" "kernel config not found"
    return
  fi
  local val
  val=$(grep -E "^${cfg}=" "$KCONFIG_FILE" 2>/dev/null | head -1 | cut -d= -f2 || true)
  if [[ "$val" == "y" || "$val" == "m" ]]; then
    record_check "$cfg" "$required" "true" "=${val}"
  elif [[ -z "$val" ]]; then
    record_check "$cfg" "$required" "false" "not set"
  else
    record_check "$cfg" "$required" "false" "=${val} (unexpected)"
  fi
}

# ----------------------------------------------------------------------------
# 1. Kernel version gate (>= 5.10 required, >= 5.15 recommended)
# ----------------------------------------------------------------------------
log_info "--- Kernel version ---"
KVER_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KVER_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2 | grep -oE '^[0-9]+')

if [[ "$KVER_MAJOR" -gt 5 ]] || { [[ "$KVER_MAJOR" -eq 5 ]] && [[ "${KVER_MINOR:-0}" -ge 15 ]]; }; then
  record_check "kernel-version-min" "true" "true" "${KERNEL_VERSION} >= 5.15"
elif [[ "$KVER_MAJOR" -eq 5 ]] && [[ "${KVER_MINOR:-0}" -ge 10 ]]; then
  record_check "kernel-version-min" "true" "true" "${KERNEL_VERSION} >= 5.10 (5.15 recommended)"
else
  record_check "kernel-version-min" "true" "false" "${KERNEL_VERSION} < 5.10 — unsupported"
fi

# ----------------------------------------------------------------------------
# 2. Required kernel configs
# ----------------------------------------------------------------------------
log_info "--- Kernel config checks ---"
check_kconfig "CONFIG_CHECKPOINT_RESTORE" "true"
check_kconfig "CONFIG_MEM_SOFT_DIRTY"     "true"
check_kconfig "CONFIG_USERFAULTFD"        "false"
check_kconfig "CONFIG_BPF_SYSCALL"        "false"
check_kconfig "CONFIG_BPF_JIT"            "false"
check_kconfig "CONFIG_XDP_SOCKETS"        "false"
check_kconfig "CONFIG_NET_SCH_INGRESS"    "false"
check_kconfig "CONFIG_NET_CLS_BPF"        "false"
check_kconfig "CONFIG_UNIX_DIAG"          "true"
check_kconfig "CONFIG_INET_DIAG"          "true"
check_kconfig "CONFIG_NET_NS"             "true"
check_kconfig "CONFIG_VETH"               "true"
check_kconfig "CONFIG_FHANDLE"            "true"
check_kconfig "CONFIG_EVENTFD"            "true"
check_kconfig "CONFIG_TUN"                "false"

# arm64 soft-dirty caveat
if [[ "$ARCH" == "aarch64" ]] && [[ "$KVER_MAJOR" -eq 5 ]] && [[ "${KVER_MINOR:-0}" -lt 15 ]]; then
  log_warn "arm64 node on kernel < 5.15: CONFIG_MEM_SOFT_DIRTY may be absent — iterative pre-copy will be disabled"
fi

# ----------------------------------------------------------------------------
# 3. cgroup v2
# ----------------------------------------------------------------------------
log_info "--- cgroup v2 ---"
CGROUP_TYPE=$(stat -f -c %T /sys/fs/cgroup 2>/dev/null || echo "unknown")
if [[ "$CGROUP_TYPE" == "cgroup2fs" ]]; then
  record_check "cgroup-v2" "true" "true" "cgroup2fs"
else
  record_check "cgroup-v2" "true" "false" "type=${CGROUP_TYPE} (cgroup2fs required)"
fi

# cgroup v2 freezer controller
if grep -q "freezer" /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
  record_check "CONFIG_CGROUP_FREEZER" "true" "true" "cgroup2 freezer controller active"
else
  # acceptable if freezer is available but not listed (some kernels show it differently)
  if [[ "$CGROUP_TYPE" == "cgroup2fs" ]]; then
    record_check "CONFIG_CGROUP_FREEZER" "true" "true" "cgroup2fs present (freezer assumed available)"
  else
    record_check "CONFIG_CGROUP_FREEZER" "true" "false" "cgroup v2 freezer not available"
  fi
fi

# ----------------------------------------------------------------------------
# 4. CRIU
# ----------------------------------------------------------------------------
log_info "--- CRIU ---"
CRIU_VERSION=""
if command -v criu &>/dev/null; then
  CRIU_VERSION=$(criu --version 2>/dev/null | grep -oE 'Version: [0-9]+\.[0-9]+' | awk '{print $2}' || true)
  CRIU_MAJOR=$(echo "$CRIU_VERSION" | cut -d. -f1)
  if [[ -n "$CRIU_MAJOR" ]] && [[ "$CRIU_MAJOR" -ge 4 ]]; then
    record_check "criu-version" "true" "true" "${CRIU_VERSION}"
  else
    record_check "criu-version" "true" "false" "${CRIU_VERSION:-unknown} (need >= 4.0; go-criu v7.2 requires 4.x RPC)"
  fi

  CRIU_CHECK_OUT=$(criu check --extra 2>&1 || true)
  if echo "$CRIU_CHECK_OUT" | grep -q "Looks good"; then
    record_check "criu-check" "true" "true" "criu check --extra: OK"
  else
    # Suppress known-harmless Docker/kind warning
    FILTERED=$(echo "$CRIU_CHECK_OUT" | grep -v "Devices cgroup is not found" || true)
    if [[ -z "$FILTERED" ]]; then
      record_check "criu-check" "true" "true" "criu check --extra: OK (Docker cgroup warning suppressed)"
    else
      record_check "criu-check" "true" "false" "criu check --extra: ${FILTERED//
/ }"
    fi
  fi
else
  record_check "criu-version" "true" "false" "criu binary not found"
  record_check "criu-check"   "true" "false" "criu not installed"
  CRIU_VERSION="0.0"
fi

# ----------------------------------------------------------------------------
# 5. bpffs mount
# ----------------------------------------------------------------------------
log_info "--- bpffs ---"
BPFFS_TYPE=$(stat -f -c %T /sys/fs/bpf 2>/dev/null || echo "none")
if [[ "$BPFFS_TYPE" == "0xcafe4a11" ]] || mount | grep -q "bpf /sys/fs/bpf"; then
  record_check "bpffs-mounted" "true" "true" "/sys/fs/bpf type bpf"
else
  record_check "bpffs-mounted" "true" "false" "/sys/fs/bpf not mounted (type=${BPFFS_TYPE})"
fi

# BPF JIT
BPF_JIT=$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo "unknown")
if [[ "$BPF_JIT" == "1" || "$BPF_JIT" == "2" ]]; then
  record_check "bpf-jit-enabled" "false" "true" "bpf_jit_enable=${BPF_JIT}"
else
  record_check "bpf-jit-enabled" "false" "false" "bpf_jit_enable=${BPF_JIT} (must be 1 or 2)"
fi

BPF_JIT_HARDEN=$(cat /proc/sys/net/core/bpf_jit_harden 2>/dev/null || echo "unknown")
if [[ "$BPF_JIT_HARDEN" == "0" ]]; then
  record_check "bpf-jit-harden" "false" "true" "bpf_jit_harden=0"
else
  record_check "bpf-jit-harden" "false" "false" "bpf_jit_harden=${BPF_JIT_HARDEN} (must be 0 for XDP; CIS hardening conflicts)"
fi

# ----------------------------------------------------------------------------
# 6. containerd NRI
# ----------------------------------------------------------------------------
log_info "--- containerd NRI ---"
NRI_SOCK="/var/run/nri/nri.sock"
NRI_PLUGIN="/usr/local/lib/nri/podmotion-nri"
NRI_ENABLED=false

if [[ -S "$NRI_SOCK" ]]; then
  NRI_ENABLED=true
  record_check "containerd-nri" "true" "true" "NRI socket present at ${NRI_SOCK}"
elif command -v containerd &>/dev/null; then
  # containerd installed but NRI socket not present — check config
  if containerd config dump 2>/dev/null | grep -q '"disable" = false'; then
    record_check "containerd-nri" "true" "false" "NRI configured but socket not present — restart containerd?"
  else
    record_check "containerd-nri" "true" "false" "NRI disabled in containerd config (add nri.toml drop-in)"
  fi
else
  record_check "containerd-nri" "true" "false" "containerd not found"
fi

if [[ -f "$NRI_PLUGIN" || -L "$NRI_PLUGIN" ]]; then
  record_check "nri-plugin-symlink" "true" "true" "${NRI_PLUGIN} exists"
else
  record_check "nri-plugin-symlink" "true" "false" "${NRI_PLUGIN} missing"
fi

# ----------------------------------------------------------------------------
# 7. Required packages
# ----------------------------------------------------------------------------
log_info "--- Package checks ---"
check_binary() {
  local bin="$1" required="$2" version_flag="${3:---version}"
  if command -v "$bin" &>/dev/null; then
    local ver
    ver=$("$bin" "$version_flag" 2>&1 | head -1 || true)
    record_check "pkg-${bin}" "$required" "true" "${ver}"
  else
    record_check "pkg-${bin}" "$required" "false" "${bin} not found in PATH"
  fi
}

check_binary "bpftool"  "false" "version"
check_binary "buildah"  "true"  "--version"
check_binary "skopeo"   "true"  "--version"
check_binary "jq"       "true"  "--version"
check_binary "ip"       "true"  "-V"
check_binary "tc"       "true"  "-V"

# iproute2 version check (>= 5.15)
if command -v ip &>/dev/null; then
  IPROUTE2_VER=$(ip -V 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
  IP_MAJOR=$(echo "$IPROUTE2_VER" | cut -d. -f1)
  IP_MINOR=$(echo "$IPROUTE2_VER" | cut -d. -f2 | grep -oE '^[0-9]+')
  if [[ -n "$IP_MAJOR" ]] && { [[ "$IP_MAJOR" -gt 5 ]] || { [[ "$IP_MAJOR" -eq 5 ]] && [[ "${IP_MINOR:-0}" -ge 15 ]]; }; }; then
    record_check "iproute2-version" "true" "true" "${IPROUTE2_VER} >= 5.15"
  else
    record_check "iproute2-version" "true" "false" "${IPROUTE2_VER:-unknown} (need >= 5.15)"
  fi
fi

# ----------------------------------------------------------------------------
# 8. sysctl values
# ----------------------------------------------------------------------------
log_info "--- sysctl checks ---"
check_sysctl() {
  local key="$1" expected_op="$2" expected_val="$3" required="$4"
  local actual
  actual=$(sysctl -n "$key" 2>/dev/null || echo "unavailable")
  local pass="false"
  case "$expected_op" in
    "=")   [[ "$actual" == "$expected_val" ]] && pass="true" ;;
    ">=")  [[ "$actual" -ge "$expected_val" ]] 2>/dev/null && pass="true" ;;
    "<=")  [[ "$actual" -le "$expected_val" ]] 2>/dev/null && pass="true" ;;
  esac
  record_check "sysctl-${key}" "$required" "$pass" "${key}=${actual} (want ${expected_op} ${expected_val})"
}

check_sysctl "kernel.perf_event_paranoid"    "<="  "2"         "false"
check_sysctl "kernel.unprivileged_bpf_disabled" "=" "1"        "false"
check_sysctl "net.core.bpf_jit_enable"       ">="  "1"         "false"
check_sysctl "vm.unprivileged_userfaultfd"    ">="  "1"         "false"
check_sysctl "fs.inotify.max_user_watches"    ">="  "1048576"   "false"
check_sysctl "fs.inotify.max_user_instances"  ">="  "8192"      "false"
check_sysctl "kernel.pid_max"                 ">="  "4194304"   "false"

# ----------------------------------------------------------------------------
# 9. veth XDP runtime probe (kernel >= 5.10 required)
# ----------------------------------------------------------------------------
log_info "--- veth XDP runtime probe ---"
if [[ "$KVER_MAJOR" -gt 5 ]] || { [[ "$KVER_MAJOR" -eq 5 ]] && [[ "${KVER_MINOR:-0}" -ge 10 ]]; }; then
  # Attempt to create a temporary veth pair
  if ip link add veth-pm-test0 type veth peer name veth-pm-test1 2>/dev/null; then
    ip link delete veth-pm-test0 2>/dev/null || true
    record_check "veth-xdp" "false" "true" "kernel ${KERNEL_VERSION} >= 5.10, veth pair creation OK"
  else
    record_check "veth-xdp" "false" "false" "veth pair creation failed (may lack CAP_NET_ADMIN)"
  fi
else
  record_check "veth-xdp" "false" "false" "kernel ${KERNEL_VERSION} < 5.10 — no veth XDP support"
fi

# ----------------------------------------------------------------------------
# 10. AppArmor / SELinux status
# ----------------------------------------------------------------------------
log_info "--- Security module status ---"
case "$DISTRO_FAMILY" in
  debian)
    if command -v aa-status &>/dev/null; then
      if aa-status 2>/dev/null | grep -q "podmotion"; then
        record_check "apparmor-profile" "false" "true" "podmotion AppArmor profile loaded"
      else
        record_check "apparmor-profile" "false" "false" "podmotion AppArmor profile not loaded (run: apparmor_parser -r /etc/apparmor.d/podmotion-agent)"
      fi
    fi
    ;;
  rhel|amazon)
    if command -v getenforce &>/dev/null; then
      SE_STATUS=$(getenforce 2>/dev/null || echo "unknown")
      if [[ "$SE_STATUS" == "Enforcing" ]]; then
        if semodule -l 2>/dev/null | grep -q "podmotion"; then
          record_check "selinux-policy" "true" "true" "podmotion SELinux module loaded (enforcing)"
        else
          record_check "selinux-policy" "true" "false" "SELinux enforcing but podmotion module NOT loaded — run: semodule -i selinux/podmotion.pp"
        fi
      else
        record_check "selinux-policy" "true" "false" "SELinux=${SE_STATUS} (enforcing required for production; permissive blocks enterprise deployment)"
      fi
    fi
    ;;
esac

# ----------------------------------------------------------------------------
# 11. CNI detection
# ----------------------------------------------------------------------------
log_info "--- CNI detection ---"
CNI_PLUGIN="unknown"
IP_MOBILITY_SUPPORTED="false"
IP_MOBILITY_MODE="none"

for conf in /etc/cni/net.d/*.conf /etc/cni/net.d/*.conflist; do
  [[ -f "$conf" ]] || continue
  if grep -q '"cilium"' "$conf" 2>/dev/null; then CNI_PLUGIN="cilium"; break; fi
  if grep -q '"calico"' "$conf" 2>/dev/null; then CNI_PLUGIN="calico"; break; fi
  if grep -q '"ovn-k8s-cni-overlay"' "$conf" 2>/dev/null; then CNI_PLUGIN="ovn-kubernetes"; break; fi
  if grep -q '"kindnet"' "$conf" 2>/dev/null; then CNI_PLUGIN="kindnet"; break; fi
done

case "$CNI_PLUGIN" in
  cilium)       IP_MOBILITY_SUPPORTED="true"; IP_MOBILITY_MODE="BGPHostRoute" ;;
  calico)       IP_MOBILITY_SUPPORTED="true"; IP_MOBILITY_MODE="BGPHostRoute" ;;
  ovn-kubernetes) IP_MOBILITY_SUPPORTED="false"; IP_MOBILITY_MODE="EgressIP" ;;
  kindnet)      IP_MOBILITY_SUPPORTED="false"; IP_MOBILITY_MODE="none" ;;
esac

log_info "CNI detected: ${CNI_PLUGIN} (IP mobility: ${IP_MOBILITY_SUPPORTED}, mode: ${IP_MOBILITY_MODE})"

# EKS VPC CNI warning
if [[ "$DISTRO_FAMILY" == "amazon" ]] && [[ "$CNI_PLUGIN" == "unknown" ]]; then
  log_warn "Amazon Linux node: if using VPC CNI, pod IPs change post-migration — TCP connections will break. See docs/node-image-readiness.md GAP-4."
fi

# ----------------------------------------------------------------------------
# Determine overall readiness and exit code
# ----------------------------------------------------------------------------
log_info ""
log_info "=== Summary ==="
log_info "  Pass:          ${PASS_COUNT}"
log_info "  Warn (opt):    ${WARN_COUNT}"
log_info "  Fail (req):    ${FAIL_REQUIRED_COUNT}"
log_info "  Fail (opt):    ${FAIL_OPTIONAL_COUNT}"

OVERALL_READY="true"
EXIT_CODE=0
if [[ "$FAIL_REQUIRED_COUNT" -gt 0 ]]; then
  OVERALL_READY="false"
  EXIT_CODE=1
  log_error "Node NOT ready — ${FAIL_REQUIRED_COUNT} required check(s) failed"
elif [[ "$FAIL_OPTIONAL_COUNT" -gt 0 ]]; then
  EXIT_CODE=2
  log_warn "Node ready for cold migration only — ${FAIL_OPTIONAL_COUNT} optional check(s) failed"
else
  log_info "Node is fully migration-ready"
fi

# ----------------------------------------------------------------------------
# JSON output
# ----------------------------------------------------------------------------
if [[ "$JSON_MODE" == "true" ]]; then
  CHECKS_JSON=$(IFS=','; echo "${CHECKS[*]}")
  FAILED_REQ_NAMES=$(for c in "${CHECKS[@]}"; do
    echo "$c" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['name']) if not d['pass'] and d['required'] else None" 2>/dev/null || true
  done | grep -v '^None$' | tr '\n' ',' | sed 's/,$//' || true)
  FAILED_OPT_NAMES=$(for c in "${CHECKS[@]}"; do
    echo "$c" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['name']) if not d['pass'] and not d['required'] else None" 2>/dev/null || true
  done | grep -v '^None$' | tr '\n' ',' | sed 's/,$//' || true)

  cat <<EOF
{
  "nodeName": "${NODE_NAME}",
  "timestamp": "${TIMESTAMP}",
  "criuVersion": "${CRIU_VERSION}",
  "nriEnabled": ${NRI_ENABLED},
  "ready": ${OVERALL_READY},
  "kernelVersion": "${KERNEL_VERSION}",
  "arch": "${ARCH}",
  "distro": "${DISTRO}",
  "distroVersion": "${DISTRO_VERSION}",
  "kernelFeatures": {
    "checkpointRestore": $(grep -q '"name":"CONFIG_CHECKPOINT_RESTORE","required":true,"pass":true' <<< "${CHECKS_JSON}" 2>/dev/null && echo true || echo false),
    "memSoftDirty": $(grep -q '"name":"CONFIG_MEM_SOFT_DIRTY","required":true,"pass":true' <<< "${CHECKS_JSON}" 2>/dev/null && echo true || echo false),
    "userfaultfd": $(grep -q '"name":"CONFIG_USERFAULTFD".*"pass":true' <<< "${CHECKS_JSON}" 2>/dev/null && echo true || echo false),
    "bpfEnabled": $(grep -q '"name":"CONFIG_BPF_SYSCALL".*"pass":true' <<< "${CHECKS_JSON}" 2>/dev/null && echo true || echo false),
    "xdpSupported": $(grep -q '"name":"CONFIG_XDP_SOCKETS".*"pass":true' <<< "${CHECKS_JSON}" 2>/dev/null && echo true || echo false)
  },
  "networkCapability": {
    "cniPlugin": "${CNI_PLUGIN}",
    "ipMobilitySupported": ${IP_MOBILITY_SUPPORTED},
    "ipMobilityMode": "${IP_MOBILITY_MODE}",
    "xdpBridgeCapable": $(grep -q '"name":"veth-xdp".*"pass":true' <<< "${CHECKS_JSON}" 2>/dev/null && echo true || echo false)
  },
  "checks": [${CHECKS_JSON}],
  "summary": {
    "passCount": ${PASS_COUNT},
    "warnCount": ${WARN_COUNT},
    "failRequiredCount": ${FAIL_REQUIRED_COUNT},
    "failOptionalCount": ${FAIL_OPTIONAL_COUNT}
  }
}
EOF
fi

[[ "$EXIT_ON_FAIL" == "true" ]] && exit "$EXIT_CODE" || true
exit "$EXIT_CODE"
