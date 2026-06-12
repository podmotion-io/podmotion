#!/usr/bin/env bash
# deploy-node.sh — copy podmotion binaries to a node and restart the systemd service.
#
# Usage:
#   NODE_IP=<ip> ARCH=<arm64|amd64> ROLE=<control|worker> ./scripts/deploy-node.sh
#
# Environment variables:
#   NODE_IP   — SSH-reachable IP or hostname of the target node (required)
#   ARCH      — target CPU architecture: arm64 or amd64  (default: amd64)
#   ROLE      — control (deploys manager + agent) or worker (deploys agent only)
#               (default: worker)
#   SSH_USER  — remote user (default: ubuntu)
#   BIN_DIR   — local bin/ directory (default: bin/)
#
# The script assumes:
#   1. SSH access is available (key-based, no password prompt).
#   2. systemd units podmotion-manager.service and/or podmotion-agent.service exist
#      on the remote node (created by the node preflight scripts).

set -euo pipefail

# ── Pre-deploy gate ────────────────────────────────────────────────────────────
# Run the e2e gate before deploying to production nodes unless explicitly skipped.
# Set SKIP_PRE_DEPLOY=true to bypass (e.g. emergency rollback).
if [[ "${SKIP_PRE_DEPLOY:-false}" != "true" ]]; then
  echo "==> Running pre-deploy e2e gate (set SKIP_PRE_DEPLOY=true to bypass)..."
  if ! make -C "$(dirname "$0")/.." pre-deploy; then
    echo ""
    echo "ERROR: pre-deploy gate FAILED. Aborting deploy."
    echo "       Fix the failing tests, then re-run this script."
    echo "       To bypass (emergency only): SKIP_PRE_DEPLOY=true $0"
    exit 1
  fi
  echo "==> Pre-deploy gate passed."
else
  echo "WARNING: pre-deploy gate SKIPPED (SKIP_PRE_DEPLOY=true). Deploy at your own risk."
fi

NODE_IP="${NODE_IP:?NODE_IP must be set}"
ARCH="${ARCH:-amd64}"
ROLE="${ROLE:-worker}"
SSH_USER="${SSH_USER:-ubuntu}"
BIN_DIR="${BIN_DIR:-bin}"

REMOTE="${SSH_USER}@${NODE_IP}"
SSH="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${REMOTE}"
SCP="scp -o StrictHostKeyChecking=no"

echo "==> Deploying to ${REMOTE}  arch=${ARCH}  role=${ROLE}"

# ── agent (always deployed) ────────────────────────────────────────────────────
AGENT_BIN="${BIN_DIR}/podmotion-agent-${ARCH}"
if [[ ! -f "${AGENT_BIN}" ]]; then
  echo "ERROR: agent binary not found: ${AGENT_BIN}"
  echo "       Run: make build-linux"
  exit 1
fi

echo "--> Copying agent binary…"
${SCP} "${AGENT_BIN}" "${REMOTE}:/tmp/podmotion-agent"
${SSH} "sudo install -m 0755 /tmp/podmotion-agent /usr/local/bin/podmotion-agent && rm /tmp/podmotion-agent"

echo "--> Restarting podmotion-agent.service…"
${SSH} "sudo systemctl daemon-reload && sudo systemctl restart podmotion-agent.service && sudo systemctl is-active podmotion-agent.service"

# ── manager/operator (control node only) ──────────────────────────────────────
if [[ "${ROLE}" == "control" ]]; then
  MANAGER_BIN="${BIN_DIR}/podmotion-manager-${ARCH}"
  if [[ ! -f "${MANAGER_BIN}" ]]; then
    echo "ERROR: manager binary not found: ${MANAGER_BIN}"
    echo "       Run: make build-linux"
    exit 1
  fi

  echo "--> Copying manager binary…"
  ${SCP} "${MANAGER_BIN}" "${REMOTE}:/tmp/podmotion-manager"
  ${SSH} "sudo install -m 0755 /tmp/podmotion-manager /usr/local/bin/podmotion-manager && rm /tmp/podmotion-manager"

  echo "--> Restarting podmotion-manager.service…"
  ${SSH} "sudo systemctl daemon-reload && sudo systemctl restart podmotion-manager.service && sudo systemctl is-active podmotion-manager.service"
fi

echo "==> Done."
