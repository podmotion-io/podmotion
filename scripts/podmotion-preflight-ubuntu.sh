#!/usr/bin/env bash
# /usr/local/bin/podmotion-preflight
#
# PodMotion node readiness preflight check for Ubuntu 22.04 and 24.04.
#
# Checks:
#   - All required kernel CONFIG_ options
#   - Required packages and minimum versions
#   - sysctl runtime values
#   - cgroup v2 availability and freezer controller
#   - NRI socket / containerd config
#   - CRIU RPC connectivity (criu check --extra)
#
# Output modes:
#   Default:     human-readable coloured output + exit 0/1
#   --json:      JSON: {"ready": bool, "checks": [...]}
#   --quiet:     suppress all output, exit code only
#
# Usage:
#   podmotion-preflight              # human output
#   podmotion-preflight --json       # JSON (used by agent startup)
#   podmotion-preflight --json 2>/dev/null | jq .ready
#
# The --json output schema maps directly to NodeMigrationCapacitySpec fields:
#   kernelFeatures, networkCapability, storageCapability, criuVersion, etc.

set -euo pipefail

# ---- option parsing -------------------------------------------------------
JSON_MODE=0
QUIET_MODE=0
for arg in "$@"; do
  case "$arg" in
    --json)  JSON_MODE=1 ;;
    --quiet) QUIET_MODE=1 ;;
  esac
done

# ---- globals --------------------------------------------------------------
CHECKS=()       # accumulated check result objects for JSON
OVERALL_PASS=1  # set to 0 on any failure

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RESET="\033[0m"
[[ $JSON_MODE -eq 1 || $QUIET_MODE -eq 1 ]] && RED="" && GREEN="" && YELLOW="" && RESET=""

log() { [[ $JSON_MODE -eq 1 || $QUIET_MODE -eq 1 ]] || echo -e "$*"; }

# ---- helper: record a check result ----------------------------------------
# record <name> <pass:0|1> <detail>
record() {
  local name="$1" pass="$2" detail="$3"
  # Escape detail for JSON
  local detail_escaped
  detail_escaped=$(printf '%s' "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/' | tr -d '\n' | sed 's/\\n$//')
  CHECKS+=("{\"name\":\"${name}\",\"pass\":$([ "$pass" -eq 1 ] && echo true || echo false),\"detail\":\"${detail_escaped}\"}")
  if [[ $pass -eq 0 ]]; then
    OVERALL_PASS=0
    log "  ${RED}FAIL${RESET}  ${name}: ${detail}"
  else
    log "  ${GREEN}PASS${RESET}  ${name}: ${detail}"
  fi
}

# ---- helper: warn (non-fatal) ---------------------------------------------
warn_record() {
  local name="$1" detail="$2"
  local detail_escaped
  detail_escaped=$(printf '%s' "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g')
  CHECKS+=("{\"name\":\"${name}\",\"pass\":true,\"detail\":\"WARN: ${detail_escaped}\"}")
  log "  ${YELLOW}WARN${RESET}  ${name}: ${detail}"
}

# ===========================================================================
# SECTION 1: Kernel config
# ===========================================================================
log ""
log "=== Kernel Configuration ($(uname -r)) ==="

KCONFIG=""
if [[ -f /proc/config.gz ]]; then
  KCONFIG="gz:/proc/config.gz"
elif [[ -f "/boot/config-$(uname -r)" ]]; then
  KCONFIG="plain:/boot/config-$(uname -r)"
fi

kconfig_get() {
  local key="$1"
  if [[ -z "$KCONFIG" ]]; then echo ""; return; fi
  local src="${KCONFIG%%:*}" path="${KCONFIG#*:}"
  if [[ "$src" == "gz" ]]; then
    zcat "$path" 2>/dev/null | grep "^${key}=" | cut -d= -f2 || echo ""
  else
    grep "^${key}=" "$path" 2>/dev/null | cut -d= -f2 || echo ""
  fi
}

check_kconfig() {
  local key="$1" required="${2:-required}"
  local val
  val=$(kconfig_get "$key")
  if [[ "$val" == "y" || "$val" == "m" ]]; then
    record "kernel/${key}" 1 "${key}=${val}"
  elif [[ "$required" == "required" ]]; then
    record "kernel/${key}" 0 "${key} not set (required for PodMotion)"
  else
    warn_record "kernel/${key}" "${key} not set (optional — some migration modes unavailable)"
  fi
}

# Required — migration does not work without these
check_kconfig CONFIG_CHECKPOINT_RESTORE required
check_kconfig CONFIG_NAMESPACES         required
check_kconfig CONFIG_UTS_NS             required
check_kconfig CONFIG_IPC_NS             required
check_kconfig CONFIG_PID_NS             required
check_kconfig CONFIG_NET_NS             required
check_kconfig CONFIG_UNIX_DIAG          required
check_kconfig CONFIG_INET_DIAG          required
check_kconfig CONFIG_FHANDLE            required
check_kconfig CONFIG_EVENTFD            required
check_kconfig CONFIG_MEM_SOFT_DIRTY     required
check_kconfig CONFIG_CGROUP_FREEZER     required  # cgroup v1 freezer; cgroup v2 uses CONFIG_FREEZER
check_kconfig CONFIG_TUN                required
check_kconfig CONFIG_VETH               required

# Optional but strongly recommended for v0.1 eBPF features
check_kconfig CONFIG_USERFAULTFD        optional
check_kconfig CONFIG_BPF_SYSCALL        optional
check_kconfig CONFIG_BPF_JIT            optional
check_kconfig CONFIG_XDP_SOCKETS        optional
check_kconfig CONFIG_NET_SCH_INGRESS    optional
check_kconfig CONFIG_NET_CLS_BPF        optional
check_kconfig CONFIG_NETFILTER_XT_MATCH_CGROUP optional

# cgroup v2 freezer (kernel 5.2+)
check_kconfig CONFIG_FREEZER            optional

# ===========================================================================
# SECTION 2: Kernel version check
# ===========================================================================
log ""
log "=== Kernel Version ==="

KVER_RAW=$(uname -r | cut -d- -f1)
KVER_MAJ=$(echo "$KVER_RAW" | cut -d. -f1)
KVER_MIN=$(echo "$KVER_RAW" | cut -d. -f2)
KVER_PATCH=$(echo "$KVER_RAW" | cut -d. -f3)
KVER_NUM=$(( KVER_MAJ * 10000 + KVER_MIN * 100 + KVER_PATCH ))
# Minimum: 5.15 (Ubuntu 22.04 HWE / Jammy GA kernel)
MIN_NUM=$(( 5 * 10000 + 15 * 100 ))

if [[ $KVER_NUM -ge $MIN_NUM ]]; then
  record "kernel/version" 1 "$(uname -r) >= 5.15 (minimum)"
else
  record "kernel/version" 0 "$(uname -r) < 5.15 — upgrade to 5.15+ (HWE) or 6.8+ (Noble)"
fi

# arm64 soft-dirty check (added in 5.15)
ARCH=$(uname -m)
if [[ "$ARCH" == "aarch64" ]]; then
  if [[ $KVER_NUM -ge $(( 5 * 10000 + 15 * 100 )) ]]; then
    record "kernel/arm64_soft_dirty" 1 "arm64 on kernel >= 5.15 — CONFIG_MEM_SOFT_DIRTY supported"
  else
    record "kernel/arm64_soft_dirty" 0 "arm64 on kernel < 5.15 — CONFIG_MEM_SOFT_DIRTY not available; iterative pre-copy will fail"
  fi
fi

# ===========================================================================
# SECTION 3: Package checks
# ===========================================================================
log ""
log "=== Package Versions ==="

pkg_version() {
  dpkg-query -W -f='${Version}' "$1" 2>/dev/null || echo ""
}

# CRIU >= 4.0
CRIU_VER=$(criu --version 2>/dev/null | awk '/Version/{print $2}' || echo "")
if [[ -z "$CRIU_VER" ]]; then
  record "pkg/criu" 0 "criu not found in PATH"
else
  CRIU_MAJ=$(echo "$CRIU_VER" | cut -d. -f1)
  if [[ "$CRIU_MAJ" -ge 4 ]]; then
    record "pkg/criu" 1 "criu ${CRIU_VER} >= 4.0"
  else
    record "pkg/criu" 0 "criu ${CRIU_VER} < 4.0 — RPC mismatch with go-criu v7.2+; install from CRIU PPA (ppa:criu/ppa)"
  fi
fi

# containerd >= 1.7
CTD_VER=$(containerd --version 2>/dev/null | awk '{print $3}' | tr -d 'v' || echo "")
if [[ -z "$CTD_VER" ]]; then
  record "pkg/containerd" 0 "containerd not found — install containerd.io from Docker repo"
else
  CTD_MAJ=$(echo "$CTD_VER" | cut -d. -f1)
  CTD_MIN=$(echo "$CTD_VER" | cut -d. -f2)
  if [[ $CTD_MAJ -gt 1 || ( $CTD_MAJ -eq 1 && $CTD_MIN -ge 7 ) ]]; then
    record "pkg/containerd" 1 "containerd ${CTD_VER} >= 1.7 (NRI supported)"
  else
    record "pkg/containerd" 0 "containerd ${CTD_VER} < 1.7 — NRI not available; upgrade to 1.7+ from Docker repo"
  fi
fi

# iproute2 >= 5.15
IP_VER=$(ip -V 2>/dev/null | grep -oP 'iproute2-\K[0-9.]+' || echo "")
if [[ -z "$IP_VER" ]]; then
  record "pkg/iproute2" 0 "ip command not found"
else
  IP_MAJ=$(echo "$IP_VER" | cut -d. -f1)
  IP_MIN=$(echo "$IP_VER" | cut -d. -f2)
  if [[ $IP_MAJ -gt 5 || ( $IP_MAJ -eq 5 && $IP_MIN -ge 15 ) ]]; then
    record "pkg/iproute2" 1 "iproute2 ${IP_VER} >= 5.15"
  else
    warn_record "pkg/iproute2" "iproute2 ${IP_VER} < 5.15 — tc BPF direct-action may be limited"
  fi
fi

# bpftool presence
BPFTOOL_BIN=$(command -v bpftool 2>/dev/null || echo "")
if [[ -n "$BPFTOOL_BIN" ]]; then
  BPFTOOL_VER=$(bpftool version 2>/dev/null | head -1 || echo "unknown")
  record "pkg/bpftool" 1 "${BPFTOOL_VER}"
else
  warn_record "pkg/bpftool" "bpftool not found — install linux-tools-\$(uname -r) or bpftool package (Ubuntu 24.04)"
fi

# buildah >= 1.33
BUILDAH_VER=$(buildah --version 2>/dev/null | awk '{print $3}' || echo "")
if [[ -z "$BUILDAH_VER" ]]; then
  record "pkg/buildah" 0 "buildah not found — required for OCI checkpoint image push"
else
  BUILDAH_MAJ=$(echo "$BUILDAH_VER" | cut -d. -f1)
  BUILDAH_MIN=$(echo "$BUILDAH_VER" | cut -d. -f2)
  if [[ $BUILDAH_MAJ -gt 1 || ( $BUILDAH_MAJ -eq 1 && $BUILDAH_MIN -ge 33 ) ]]; then
    record "pkg/buildah" 1 "buildah ${BUILDAH_VER} >= 1.33"
  else
    record "pkg/buildah" 0 "buildah ${BUILDAH_VER} < 1.33 — upgrade via kubic repo or Docker repo"
  fi
fi

# skopeo >= 1.14
SKOPEO_VER=$(skopeo --version 2>/dev/null | awk '{print $3}' || echo "")
if [[ -z "$SKOPEO_VER" ]]; then
  record "pkg/skopeo" 0 "skopeo not found — required for checkpoint image transfer"
else
  SKOPEO_MAJ=$(echo "$SKOPEO_VER" | cut -d. -f1)
  SKOPEO_MIN=$(echo "$SKOPEO_VER" | cut -d. -f2)
  if [[ $SKOPEO_MAJ -gt 1 || ( $SKOPEO_MAJ -eq 1 && $SKOPEO_MIN -ge 14 ) ]]; then
    record "pkg/skopeo" 1 "skopeo ${SKOPEO_VER} >= 1.14"
  else
    warn_record "pkg/skopeo" "skopeo ${SKOPEO_VER} < 1.14 — upgrade recommended"
  fi
fi

# jq >= 1.6
JQ_VER=$(jq --version 2>/dev/null | tr -d 'jq-' || echo "")
if [[ -z "$JQ_VER" ]]; then
  record "pkg/jq" 0 "jq not found"
else
  record "pkg/jq" 1 "jq ${JQ_VER}"
fi

# libbpf version (via pkg-config)
LIBBPF_VER=$(pkg-config --modversion libbpf 2>/dev/null || echo "")
if [[ -z "$LIBBPF_VER" ]]; then
  warn_record "pkg/libbpf" "libbpf-dev not found via pkg-config — CO-RE eBPF object loading may fail"
else
  LB_MAJ=$(echo "$LIBBPF_VER" | cut -d. -f1)
  LB_MIN=$(echo "$LIBBPF_VER" | cut -d. -f2)
  if [[ $LB_MAJ -gt 1 || ( $LB_MAJ -eq 1 && $LB_MIN -ge 2 ) ]]; then
    record "pkg/libbpf" 1 "libbpf ${LIBBPF_VER} >= 1.2"
  elif [[ $LB_MAJ -eq 1 ]]; then
    warn_record "pkg/libbpf" "libbpf ${LIBBPF_VER} >= 1.0 but < 1.2 — ring buffer API limited; upgrade recommended"
  else
    record "pkg/libbpf" 0 "libbpf ${LIBBPF_VER} < 1.0 — CO-RE not supported; Ubuntu 22.04 needs PPA or source build"
  fi
fi

# ===========================================================================
# SECTION 4: sysctl runtime values
# ===========================================================================
log ""
log "=== sysctl Runtime Values ==="

sysctl_check() {
  local key="$1" expected="$2" fatal="${3:-warn}"
  local val
  val=$(sysctl -n "$key" 2>/dev/null || echo "")
  if [[ "$val" == "$expected" ]]; then
    record "sysctl/${key}" 1 "${key}=${val}"
  else
    if [[ "$fatal" == "required" ]]; then
      record "sysctl/${key}" 0 "${key}=${val:-<unset>} (expected ${expected}); fix: sysctl -w ${key}=${expected}"
    else
      warn_record "sysctl/${key}" "${key}=${val:-<unset>} (expected ${expected}); fix: sysctl -w ${key}=${expected}"
    fi
  fi
}

sysctl_check "vm.unprivileged_userfaultfd" "1" warn   # CRIU post-copy lazy pages
sysctl_check "net.core.bpf_jit_enable"    "1" warn   # eBPF JIT (XDP/TC performance)

# bpf_jit_harden should be 0 for agent — hardening breaks some XDP programs
BPF_HARDEN=$(sysctl -n net.core.bpf_jit_harden 2>/dev/null || echo "0")
if [[ "$BPF_HARDEN" -ne 0 ]]; then
  warn_record "sysctl/net.core.bpf_jit_harden" "bpf_jit_harden=${BPF_HARDEN} (non-zero may cause XDP program load failures)"
else
  record "sysctl/net.core.bpf_jit_harden" 1 "bpf_jit_harden=0 (JIT hardening off)"
fi

# fs.inotify ceilings — CRIU's kerndat probe and inotify-watch restore path need
# headroom above the stock Linux defaults (max_user_instances=128, max_user_watches=8192)
INOTIFY_INSTANCES=$(sysctl -n fs.inotify.max_user_instances 2>/dev/null || echo "0")
if [[ "$INOTIFY_INSTANCES" -ge 8192 ]]; then
  record "sysctl/fs.inotify.max_user_instances" 1 "fs.inotify.max_user_instances=${INOTIFY_INSTANCES} >= 8192"
else
  warn_record "sysctl/fs.inotify.max_user_instances" "fs.inotify.max_user_instances=${INOTIFY_INSTANCES} (expected >= 8192); fix: sysctl -w fs.inotify.max_user_instances=8192"
fi

INOTIFY_WATCHES=$(sysctl -n fs.inotify.max_user_watches 2>/dev/null || echo "0")
if [[ "$INOTIFY_WATCHES" -ge 1048576 ]]; then
  record "sysctl/fs.inotify.max_user_watches" 1 "fs.inotify.max_user_watches=${INOTIFY_WATCHES} >= 1048576"
else
  warn_record "sysctl/fs.inotify.max_user_watches" "fs.inotify.max_user_watches=${INOTIFY_WATCHES} (expected >= 1048576); fix: sysctl -w fs.inotify.max_user_watches=1048576"
fi

# ===========================================================================
# SECTION 5: cgroup v2
# ===========================================================================
log ""
log "=== cgroup v2 ==="

CGROOT="/sys/fs/cgroup"
if [[ -f "${CGROOT}/cgroup.controllers" ]]; then
  record "cgroup/v2_unified" 1 "cgroup v2 unified hierarchy detected at ${CGROOT}"
  # Check freezer controller
  FREEZER_AVAIL=$(grep -c "freezer" "${CGROOT}/cgroup.controllers" 2>/dev/null || echo "0")
  if [[ "$FREEZER_AVAIL" -gt 0 ]]; then
    record "cgroup/freezer" 1 "freezer controller present in cgroup.controllers"
  else
    warn_record "cgroup/freezer" "freezer not in cgroup.controllers — CRIU will fall back to ptrace SIGSTOP (slower, larger race window)"
  fi
elif [[ -d "${CGROOT}/freezer" ]]; then
  warn_record "cgroup/v2_unified" "cgroup v1 detected — mixed-mode or legacy hierarchy. Upgrade to cgroup v2 (systemd.unified_cgroup_hierarchy=1) for best CRIU compat. The scheduler plugin will exclude this node from migration targets."
  record "cgroup/freezer" 1 "cgroup v1 freezer subsystem present"
else
  record "cgroup/v2_unified" 0 "cannot determine cgroup mode — ${CGROOT}/cgroup.controllers and ${CGROOT}/freezer both missing"
fi

# ===========================================================================
# SECTION 6: containerd NRI
# ===========================================================================
log ""
log "=== containerd NRI ==="

NRI_SOCK="/var/run/nri/nri.sock"
NRI_CONF="/etc/containerd/conf.d/nri.toml"

if [[ -f "$NRI_CONF" ]]; then
  NRI_DISABLED=$(grep -c 'disable = true' "$NRI_CONF" 2>/dev/null || echo "0")
  if [[ "$NRI_DISABLED" -eq 0 ]]; then
    record "containerd/nri_config" 1 "NRI config present and not disabled (${NRI_CONF})"
  else
    record "containerd/nri_config" 0 "NRI config found but disable=true — set disable=false in ${NRI_CONF}"
  fi
else
  warn_record "containerd/nri_config" "${NRI_CONF} not found — NRI may not be enabled; check containerd config dump"
fi

if [[ -S "$NRI_SOCK" ]]; then
  record "containerd/nri_socket" 1 "NRI socket exists: ${NRI_SOCK}"
else
  warn_record "containerd/nri_socket" "NRI socket not found at ${NRI_SOCK} — containerd may not be running or NRI not enabled"
fi

# ===========================================================================
# SECTION 7: CRIU deep check
# ===========================================================================
log ""
log "=== CRIU Capability Check ==="

# criu check (basic) — may fail inside container context, non-fatal
CRIU_BASIC=0
if criu check 2>/dev/null; then
  CRIU_BASIC=1
fi
if [[ $CRIU_BASIC -eq 1 ]]; then
  record "criu/basic_check" 1 "criu check passed"
else
  warn_record "criu/basic_check" "criu check failed — expected inside container/kind node due to missing /dev/mem; ignore if running in Docker"
fi

# criu check --extra (soft-dirty, userfaultfd, cgroup freezer)
CRIU_EXTRA=0
if criu check --extra 2>/dev/null; then
  CRIU_EXTRA=1
fi
if [[ $CRIU_EXTRA -eq 1 ]]; then
  record "criu/extra_check" 1 "criu check --extra passed (soft-dirty, userfaultfd, freezer all available)"
else
  warn_record "criu/extra_check" "criu check --extra had failures — check soft-dirty, userfaultfd, and freezer; some migration modes may be unavailable"
fi

# Verify checkpoint directory
CHKPT_DIR="/var/lib/podmotion/checkpoints"
if [[ -d "$CHKPT_DIR" ]]; then
  CHKPT_PERM=$(stat -c '%a' "$CHKPT_DIR" 2>/dev/null || echo "")
  if [[ "$CHKPT_PERM" == "700" ]]; then
    record "criu/checkpoint_dir" 1 "${CHKPT_DIR} exists with mode 700"
  else
    warn_record "criu/checkpoint_dir" "${CHKPT_DIR} exists but mode is ${CHKPT_PERM} (expected 700)"
  fi
else
  record "criu/checkpoint_dir" 0 "${CHKPT_DIR} missing — run: mkdir -p ${CHKPT_DIR} && chmod 700 ${CHKPT_DIR}"
fi

# ===========================================================================
# SECTION 8: AppArmor
# ===========================================================================
log ""
log "=== AppArmor ==="

AA_STATUS=$(command -v aa-status 2>/dev/null || echo "")
if [[ -n "$AA_STATUS" ]]; then
  AA_LOADED=$(aa-status 2>/dev/null | grep -c "podmotion" || echo "0")
  if [[ "$AA_LOADED" -gt 0 ]]; then
    record "apparmor/profile_loaded" 1 "podmotion-agent AppArmor profile loaded"
  else
    warn_record "apparmor/profile_loaded" "podmotion-agent AppArmor profile not loaded — run: apparmor_parser -r /etc/apparmor.d/podmotion-agent"
  fi
else
  warn_record "apparmor/aa_status" "aa-status not found — cannot verify AppArmor profile status"
fi

# ===========================================================================
# SECTION 9: bpffs
# ===========================================================================
log ""
log "=== bpffs ==="

if mount | grep -q "bpffs\|/sys/fs/bpf"; then
  record "bpffs/mounted" 1 "bpffs mounted at /sys/fs/bpf"
else
  warn_record "bpffs/mounted" "/sys/fs/bpf not mounted — mount: mount -t bpf bpf /sys/fs/bpf || systemctl start sys-fs-bpf.mount"
fi

# ===========================================================================
# SECTION 10: distro detection (informational)
# ===========================================================================
DISTRO_ID=$(. /etc/os-release && echo "${ID:-unknown}")
DISTRO_VER=$(. /etc/os-release && echo "${VERSION_ID:-unknown}")
log ""
log "=== Distro: ${DISTRO_ID} ${DISTRO_VER} ==="
record "distro/detected" 1 "${DISTRO_ID} ${DISTRO_VER} on $(uname -r) ($(uname -m))"

# ===========================================================================
# OUTPUT
# ===========================================================================
log ""
log "=== Summary ==="

# Build JSON
CHECKS_JSON=$(IFS=,; echo "${CHECKS[*]}")
READY_VAL=$( [[ $OVERALL_PASS -eq 1 ]] && echo "true" || echo "false" )
CRIU_VERSION_JSON="\"${CRIU_VER:-unknown}\""

JSON_OUTPUT=$(cat <<EOF
{
  "ready": ${READY_VAL},
  "distro": "${DISTRO_ID} ${DISTRO_VER}",
  "kernel": "$(uname -r)",
  "arch": "$(uname -m)",
  "criuVersion": ${CRIU_VERSION_JSON},
  "checks": [${CHECKS_JSON}]
}
EOF
)

if [[ $JSON_MODE -eq 1 ]]; then
  echo "$JSON_OUTPUT"
else
  TOTAL=${#CHECKS[@]}
  FAILED=$(echo "$JSON_OUTPUT" | grep -o '"pass":false' | wc -l || echo 0)
  PASSED=$(( TOTAL - FAILED ))
  if [[ $OVERALL_PASS -eq 1 ]]; then
    log "${GREEN}Node is PodMotion-ready (${PASSED}/${TOTAL} checks passed)${RESET}"
  else
    log "${RED}Node is NOT PodMotion-ready (${FAILED} check(s) failed — see above)${RESET}"
  fi
fi

[[ $OVERALL_PASS -eq 1 ]] && exit 0 || exit 1
