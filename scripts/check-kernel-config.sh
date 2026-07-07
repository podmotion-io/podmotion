#!/usr/bin/env bash
# scripts/check-kernel-config.sh
# Validates that the 5 kernel CONFIG options required by PodMotion are enabled
# on the current node. Called from:
#   - make kind-create (CI node-image build step)
#   - CI matrix setup step (before each matrix cell run)
#
# Exit 0 if all required configs are present.
# Exit 1 if any are missing, with a list of missing options.
#
# Required configs (ADR-0098 / ADR-0093 §1.1 / the project conventions doc):
#   CONFIG_CHECKPOINT_RESTORE — CRIU (mandatory)
#   CONFIG_MEM_SOFT_DIRTY     — iterative pre-copy dirty-page tracking
#   CONFIG_USERFAULTFD        — post-copy lazy page fault handling
#   CONFIG_BPF_SYSCALL        — eBPF XDP bridge
#   CONFIG_XDP_SOCKETS        — eBPF XDP socket fast-path

set -euo pipefail

REQUIRED_CONFIGS=(
    CONFIG_CHECKPOINT_RESTORE
    CONFIG_MEM_SOFT_DIRTY
    CONFIG_USERFAULTFD
    CONFIG_BPF_SYSCALL
    CONFIG_XDP_SOCKETS
)

# Locate kernel config. Try the canonical locations in order.
find_kernel_config() {
    local kver
    kver="$(uname -r)"

    local candidates=(
        "/boot/config-${kver}"
        "/proc/config.gz"
        "/proc/config"
        "/lib/modules/${kver}/build/.config"
    )

    for candidate in "${candidates[@]}"; do
        if [[ -f "${candidate}" ]]; then
            echo "${candidate}"
            return 0
        fi
    done

    return 1
}

# Read a config file, transparently decompressing .gz if needed.
read_config() {
    local path="$1"
    if [[ "${path}" == *.gz ]]; then
        zcat "${path}"
    else
        cat "${path}"
    fi
}

# Check whether a CONFIG option is set to =y or =m.
config_enabled() {
    local config_content="$1"
    local option="$2"
    # Match: CONFIG_FOO=y or CONFIG_FOO=m
    echo "${config_content}" | grep -qE "^${option}=[ym]$"
}

main() {
    echo "PodMotion kernel config check"
    echo "Kernel: $(uname -r)"
    echo ""

    local config_path
    if ! config_path="$(find_kernel_config)"; then
        echo "ERROR: kernel config file not found." >&2
        echo "Tried: /boot/config-\$(uname -r), /proc/config.gz, /proc/config," >&2
        echo "       /lib/modules/\$(uname -r)/build/.config" >&2
        echo ""
        echo "On Ubuntu/Debian: sudo apt-get install linux-headers-\$(uname -r)" >&2
        exit 1
    fi

    echo "Config source: ${config_path}"
    echo ""

    local config_content
    config_content="$(read_config "${config_path}")"

    local missing=()
    local present=()

    for opt in "${REQUIRED_CONFIGS[@]}"; do
        if config_enabled "${config_content}" "${opt}"; then
            present+=("${opt}")
            printf "  %-40s  OK\n" "${opt}"
        else
            missing+=("${opt}")
            printf "  %-40s  MISSING\n" "${opt}" >&2
        fi
    done

    echo ""

    if [[ ${#missing[@]} -eq 0 ]]; then
        echo "All ${#REQUIRED_CONFIGS[@]} required kernel config options are present."
        echo "Kernel is compatible with PodMotion CRIU + eBPF requirements."
        exit 0
    else
        echo "ERROR: ${#missing[@]} required kernel config option(s) are missing:" >&2
        for opt in "${missing[@]}"; do
            echo "  - ${opt}" >&2
        done
        echo "" >&2
        echo "These options are required for:" >&2
        for opt in "${missing[@]}"; do
            case "${opt}" in
                CONFIG_CHECKPOINT_RESTORE)
                    echo "  ${opt}: CRIU checkpoint/restore (mandatory)" >&2 ;;
                CONFIG_MEM_SOFT_DIRTY)
                    echo "  ${opt}: iterative pre-copy dirty-page tracking" >&2 ;;
                CONFIG_USERFAULTFD)
                    echo "  ${opt}: post-copy lazy page fault handling" >&2 ;;
                CONFIG_BPF_SYSCALL)
                    echo "  ${opt}: eBPF XDP bridge for TCP transparency" >&2 ;;
                CONFIG_XDP_SOCKETS)
                    echo "  ${opt}: eBPF XDP socket fast-path" >&2 ;;
            esac
        done
        echo "" >&2
        echo "Minimum supported kernel: 5.15 (Ubuntu 22.04 HWE)." >&2
        echo "Preferred kernel: 6.8 (Ubuntu 24.04)." >&2
        exit 1
    fi
}

main "$@"
