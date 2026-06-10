#!/usr/bin/env bash
# Verifies kernel config options required by PodMotion on the current node.
# Run on each node after provisioning to confirm the image is correct.
set -euo pipefail

PASS=0; WARN=0; FAIL=0
KCONFIG="/boot/config-$(uname -r)"
[ -f /proc/config.gz ] && KCONFIG="/proc/config.gz"

check() {
  local name=$1 required=$2
  local val
  if [[ "$KCONFIG" == *.gz ]]; then
    val=$(zcat "$KCONFIG" 2>/dev/null | grep "^${name}=" | cut -d= -f2 || echo "")
  else
    val=$(grep "^${name}=" "$KCONFIG" 2>/dev/null | cut -d= -f2 || echo "")
  fi
  if [[ "$val" == "y" || "$val" == "m" ]]; then
    echo "  ✓ ${name}=${val}"
    ((PASS++))
  elif [[ "$required" == "required" ]]; then
    echo "  ✗ ${name} MISSING (required — migration will not work)"
    ((FAIL++))
  else
    echo "  ⚠ ${name} MISSING (optional — some migration modes unavailable)"
    ((WARN++))
  fi
}

echo "=== PodMotion Kernel Config Check ($(uname -r)) ==="
echo "--- Required ---"
check CONFIG_CHECKPOINT_RESTORE required
check CONFIG_NAMESPACES          required
check CONFIG_UTS_NS              required
check CONFIG_IPC_NS              required
check CONFIG_PID_NS              required
check CONFIG_NET_NS              required
check CONFIG_UNIX_DIAG           required
check CONFIG_INET_DIAG           required
check CONFIG_FHANDLE             required
check CONFIG_EVENTFD             required
echo "--- Pre-copy (iterative memory sync) ---"
check CONFIG_MEM_SOFT_DIRTY      required
echo "--- Post-copy (lazy pages, v0.2+) ---"
check CONFIG_USERFAULTFD         optional
echo "--- eBPF packet bridge (v0.2+) ---"
check CONFIG_BPF                 optional
check CONFIG_BPF_SYSCALL         optional
check CONFIG_BPF_JIT             optional
check CONFIG_XDP_SOCKETS         optional
check CONFIG_NET_SCH_INGRESS     optional
check CONFIG_NET_CLS_BPF         optional

echo ""
echo "Result: ${PASS} pass, ${WARN} warn, ${FAIL} fail"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
