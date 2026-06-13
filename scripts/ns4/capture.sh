#!/usr/bin/env bash
# scripts/ns4/capture.sh
#
# Start tcpdump on flannel.1 on BOTH cluster nodes capturing PostgreSQL traffic
# (tcp port 5432) and any RST segments.  Captures run in the background on each
# node via SSH; pcap files land in /tmp on the remote node and are pulled back to
# a local output directory when capture is stopped with Ctrl-C or SIGTERM.
#
# Usage:
#   SOURCE_NODE=pm-worker DEST_NODE=pm-control OUT_DIR=./captures \
#     ./scripts/ns4/capture.sh
#
#   # Override capture filter:
#   FILTER="tcp port 5432" ./scripts/ns4/capture.sh
#
# Environment variables:
#   SOURCE_NODE   SSH hostname of the source node (default: pm-worker)
#   DEST_NODE     SSH hostname of the destination node (default: pm-control)
#   SSH_USER      SSH username (default: ubuntu)
#   IFACE         Interface to capture on (default: flannel.1)
#   FILTER        tcpdump BPF filter (default: tcp port 5432 or tcp[tcpflags] & tcp-rst != 0)
#   OUT_DIR       Local directory to write pcap files into (default: ./captures/ns4)
#   MAX_PKTS      Stop after this many packets per node (default: unlimited)
#
# Output files (written to OUT_DIR):
#   <node>-flannel1.pcap   raw pcap for each node
#
# Exit codes:
#   0  captures collected successfully
#   1  setup error (missing dependency, bad node name, etc.)

set -euo pipefail

SOURCE_NODE="${SOURCE_NODE:-pm-worker}"
DEST_NODE="${DEST_NODE:-pm-control}"
SSH_USER="${SSH_USER:-ubuntu}"
IFACE="${IFACE:-flannel.1}"
FILTER="${FILTER:-tcp port 5432 or (tcp[tcpflags] & tcp-rst != 0)}"
OUT_DIR="${OUT_DIR:-./captures/ns4}"
MAX_PKTS="${MAX_PKTS:-}"

REMOTE_PCAP_SRC="/tmp/capture-flannel1-src.pcap"
REMOTE_PCAP_DST="/tmp/capture-flannel1-dst.pcap"

info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; }

require_cmd() {
    if ! command -v "$1" &>/dev/null; then
        error "required command not found: $1"
        exit 1
    fi
}

require_cmd ssh
require_cmd scp

mkdir -p "$OUT_DIR"

# Build the remote tcpdump command.
build_tcpdump_cmd() {
    local pcap_path="$1"
    local cmd="sudo tcpdump -i ${IFACE} -w ${pcap_path} -s 0 -n"
    if [[ -n "$MAX_PKTS" ]]; then
        cmd="$cmd -c ${MAX_PKTS}"
    fi
    cmd="$cmd '${FILTER}'"
    echo "$cmd"
}

start_capture() {
    local node="$1"
    local remote_path="$2"
    local cmd
    cmd="$(build_tcpdump_cmd "$remote_path")"
    info "starting capture on $node: $cmd"
    # Run tcpdump in background on the remote node; capture the remote PID.
    ssh "${SSH_USER}@${node}" "nohup ${cmd} </dev/null >/tmp/tcpdump-${node}.log 2>&1 & echo \$!"
}

stop_capture() {
    local node="$1"
    local remote_pid="$2"
    info "stopping capture on $node (pid ${remote_pid})"
    ssh "${SSH_USER}@${node}" "sudo kill -INT ${remote_pid} 2>/dev/null || true"
    # Give tcpdump a moment to flush and close the pcap file.
    sleep 2
}

pull_pcap() {
    local node="$1"
    local remote_path="$2"
    local local_path="$3"
    info "pulling pcap from $node:$remote_path → $local_path"
    scp "${SSH_USER}@${node}:${remote_path}" "$local_path"
}

# Start captures on both nodes.
SRC_PID="$(start_capture "$SOURCE_NODE" "$REMOTE_PCAP_SRC")"
DST_PID="$(start_capture "$DEST_NODE"   "$REMOTE_PCAP_DST")"

info "captures running — SRC pid=${SRC_PID}  DST pid=${DST_PID}"
info "press Ctrl-C or send SIGTERM to stop and pull pcaps"

cleanup() {
    info "stopping captures"
    stop_capture "$SOURCE_NODE" "$SRC_PID"
    stop_capture "$DEST_NODE"   "$DST_PID"
    pull_pcap "$SOURCE_NODE" "$REMOTE_PCAP_SRC" "${OUT_DIR}/${SOURCE_NODE}-flannel1.pcap"
    pull_pcap "$DEST_NODE"   "$REMOTE_PCAP_DST" "${OUT_DIR}/${DEST_NODE}-flannel1.pcap"
    info "pcaps written to $OUT_DIR"
    info "  ${OUT_DIR}/${SOURCE_NODE}-flannel1.pcap"
    info "  ${OUT_DIR}/${DEST_NODE}-flannel1.pcap"
}

trap cleanup INT TERM

# Block until interrupted.
wait
