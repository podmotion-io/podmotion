#!/usr/bin/env bash
# ── PodMotion standing KVM/libvirt kubeadm cluster lifecycle ──────────────────
#
# The project's dev/test substrate is a STANDING 3-node KVM/libvirt kubeadm
# cluster on the libvirt `default` NAT network (192.168.122.0/24). The three VMs
# are PERMANENT infrastructure:
#
#   pm-cp1  = control-plane
#   pm-w1   = worker
#   pm-w2   = worker
#
# IPs are DHCP (discovered from hosts.env / virsh net-dhcp-leases); the VM NAMES
# are stable. Kubernetes v1.35.x, containerd runtime, Flannel CNI (pod CIDR
# 10.244.0.0/16), CRIU 4.2 pre-installed at /usr/sbin/criu on every node.
#
# HARD PROHIBITION — this script NEVER destroys the VMs. `virsh destroy` and
# `virsh undefine` against a pm-* VM are refused unconditionally. "Rebuilding the
# cluster" means resetting kubeadm ON the existing VMs and re-init/join — the VMs
# persist as standing infrastructure.
#
# Subcommands:
#   verify           3 nodes Ready + API reachable
#   reset-cluster    kubeadm reset on all nodes, re-init cp, Flannel, join workers
#   deploy-podmotion build+import images, mint mTLS, apply CRDs, helm install
#   wipe             clean k8s + PodMotion STATE on the VMs (NOT the VMs themselves)
#   ssh <node|ip>    run a command on a node (helper passthrough)
#
# Grounded in: CLAUDE.md deploy sections, the Makefile (build-linux, agent-certs-dev,
# deploy-crds), charts/podmotion/, images/{operator,agent}/Dockerfile.
set -euo pipefail

# ── Standing infra constants ─────────────────────────────────────────────────
KVM_DIR="${KVM_DIR:-/home/chad/podmotion-kvm}"
SSH_KEY="${SSH_KEY:-$KVM_DIR/id_pmkvm}"
HOSTS_ENV="${HOSTS_ENV:-$KVM_DIR/hosts.env}"
KUBECONFIG_OUT="${KUBECONFIG_OUT:-$KVM_DIR/kubeconfig}"
SSH_USER="${SSH_USER:-chad}"
POD_CIDR="10.244.0.0/16"
FLANNEL_MANIFEST="images/kind/kube-flannel-v0.25.4.yml"   # repo-vendored (CLAUDE.md)

# Stable VM names — PERMANENT, never destroyed/undefined.
CP_VM="pm-cp1"
WORKER_VMS=("pm-w1" "pm-w2")
PM_VMS=("$CP_VM" "${WORKER_VMS[@]}")

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ── IP discovery (DHCP — never hardcode) ─────────────────────────────────────
# Prefer hosts.env (CP1=/W1=/W2=); fall back to virsh net-dhcp-leases default.
load_ips() {
  if [[ -f "$HOSTS_ENV" ]]; then
    # shellcheck disable=SC1090
    source "$HOSTS_ENV"
  fi
  CP1_IP="${CP1:-}"
  W1_IP="${W1:-}"
  W2_IP="${W2:-}"
  if [[ -z "$CP1_IP" || -z "$W1_IP" || -z "$W2_IP" ]]; then
    echo "ERROR: could not resolve all node IPs from $HOSTS_ENV." >&2
    echo "       Discover via: sudo virsh net-dhcp-leases default" >&2
    exit 1
  fi
  WORKER_IPS=("$W1_IP" "$W2_IP")
}

nsh() {   # node ssh: nsh <ip> "<cmd>"
  local ip="$1"; shift
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -o LogLevel=ERROR "$SSH_USER@$ip" "$@"
}

# ── Safety guard: never destroy/undefine a pm-* VM ───────────────────────────
assert_no_vm_destruction() {
  echo "SAFETY: this script never runs 'virsh destroy' or 'virsh undefine' on the standing VMs (${PM_VMS[*]}). The VMs are permanent infrastructure." >&2
}

cmd_verify() {
  load_ips
  echo "==> Verifying KVM kubeadm cluster (control-plane $CP1_IP)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl get nodes -o wide
  local ready
  ready="$(KUBECONFIG="$KUBECONFIG_OUT" kubectl get nodes --no-headers 2>/dev/null | grep -cw Ready || true)"
  if [[ "$ready" -lt 3 ]]; then
    echo "ERROR: expected 3 Ready nodes, found $ready." >&2
    exit 1
  fi
  echo "==> OK: 3 nodes Ready."
}

cmd_reset_cluster() {
  assert_no_vm_destruction
  load_ips
  echo "==> RESET: kubeadm reset on all nodes (VMs are NOT destroyed)..."
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- reset $ip"
    nsh "$ip" "sudo kubeadm reset -f && sudo rm -rf /etc/cni/net.d \$HOME/.kube && sudo rm -rf /etc/kubernetes/manifests/*"
  done

  echo "==> INIT control-plane on $CP_VM ($CP1_IP)..."
  nsh "$CP1_IP" "sudo kubeadm init --pod-network-cidr=$POD_CIDR --apiserver-advertise-address=$CP1_IP"
  nsh "$CP1_IP" "mkdir -p \$HOME/.kube && sudo cp -f /etc/kubernetes/admin.conf \$HOME/.kube/config && sudo chown \$(id -u):\$(id -g) \$HOME/.kube/config"

  echo "==> Applying Flannel CNI ($FLANNEL_MANIFEST)..."
  scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "$FLANNEL_MANIFEST" "$SSH_USER@$CP1_IP:/tmp/kube-flannel.yml"
  nsh "$CP1_IP" "kubectl apply -f /tmp/kube-flannel.yml"

  echo "==> Generating join command..."
  local join_cmd
  join_cmd="$(nsh "$CP1_IP" "sudo kubeadm token create --print-join-command")"
  for ip in "${WORKER_IPS[@]}"; do
    echo "  -- join worker $ip"
    nsh "$ip" "sudo $join_cmd"
  done

  echo "==> Exporting admin kubeconfig to $KUBECONFIG_OUT..."
  nsh "$CP1_IP" "sudo cat /etc/kubernetes/admin.conf" > "$KUBECONFIG_OUT"
  chmod 600 "$KUBECONFIG_OUT"

  echo "==> Waiting for 3 nodes Ready..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl wait --for=condition=Ready nodes --all --timeout=180s
  cmd_verify
}

# ── deploy-podmotion: build → import images → certs → CRDs → helm ────────────
cmd_deploy_podmotion() {
  load_ips
  # TAG carries sprint provenance so consecutive sprints don't collide on one
  # static tag (keeps verifyArtifacts' build-stamp check meaningful). Passed in
  # via env (skeleton passes TAG=<sprintPrefix>-amd64); kvm-dev is last-resort only.
  local TAG="${TAG:-kvm-dev}"
  local OP_IMG="podmotion-operator:$TAG"
  local AGENT_IMG="podmotion-agent:$TAG"

  echo "==> Building binaries (make build-linux)..."
  make build-linux   # emits bin/{manager,agent,criu-wrapper}-linux-amd64 (auto-renamed)

  echo "==> Building operator + agent images..."
  docker build -f images/operator/Dockerfile -t "$OP_IMG" .
  docker build -f images/agent/Dockerfile   -t "$AGENT_IMG" .

  echo "==> Importing images into each node's k8s.io containerd namespace (no registry)..."
  # NOTE: CRIU 4.2 is already installed at /usr/sbin/criu on every node, and the
  # agent DaemonSet's install-criu-wrapper init container copies the criu-wrapper
  # onto the host (/opt/podmotion/bin) — so no manual per-VM binary copy is needed.
  #
  # ctr host-dep: the checkpoint/restore host-mount-ns path invokes ctr at the
  # ABSOLUTE path /usr/local/bin/ctr (server.go FindContainerTaskID / ctrCheckpoint /
  # sandbox task-PID lookup; also the netnsbroker exec allowlist). On these Ubuntu
  # containerd nodes ctr ships at /usr/bin/ctr, so the absolute-path invocation ENOENTs
  # and the containerd-native task-PID lookup silently degrades to the proc-scan fallback
  # (which returns PID 0 mid-restart → "criu dump: Pid is 0"). Durably provision the
  # expected path as a symlink to the real ctr — same "provision host deps on deploy"
  # discipline as CRIU. Idempotent; resolves ctr wherever it actually lives.
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- ensure /usr/local/bin/ctr on $ip"
    nsh "$ip" 'set -e; REAL_CTR="$(command -v ctr || true)"; \
      if [ -z "$REAL_CTR" ]; then echo "ERROR: ctr not found on node" >&2; exit 1; fi; \
      if [ "$REAL_CTR" != "/usr/local/bin/ctr" ]; then \
        sudo ln -sfn "$REAL_CTR" /usr/local/bin/ctr; fi; \
      test -x /usr/local/bin/ctr && echo "    ctr -> $REAL_CTR ok"'
  done
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- import into $ip"
    docker save "$OP_IMG"    | nsh "$ip" "sudo ctr -n k8s.io images import -"
    docker save "$AGENT_IMG" | nsh "$ip" "sudo ctr -n k8s.io images import -"
    # Verify each tag actually landed in this node's k8s.io namespace.
    if ! nsh "$ip" "sudo ctr -n k8s.io images ls -q | grep -q ':$TAG'"; then
      echo "ERROR: image tag ':$TAG' not present in k8s.io containerd namespace on node $ip after import." >&2
      exit 1
    fi
  done

  echo "==> Applying CRDs (chart crds/ is empty — apply manually)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f config/crd/bases/

  echo "==> Ensuring podmotion-system namespace..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl create namespace podmotion-system \
    --dry-run=client -o yaml | KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f -

  echo "==> Minting operator<->agent mTLS secrets (certManager disabled)..."
  KUBECONFIG="$KUBECONFIG_OUT" make agent-certs-dev

  echo "==> Helm install..."
  KUBECONFIG="$KUBECONFIG_OUT" helm upgrade --install podmotion charts/podmotion/ \
    --namespace podmotion-system --create-namespace \
    --set operator.image.repository=podmotion-operator --set operator.image.tag="$TAG" --set operator.image.pullPolicy=IfNotPresent \
    --set agent.image.repository=podmotion-agent --set agent.image.tag="$TAG" --set agent.image.pullPolicy=IfNotPresent \
    --set operator.replicas=1 \
    --set webhook.certManager.enabled=false \
    --set scheduler.enabled=false \
    --set installCRDs=false \
    --set operator.featureGates="TCPPreservation=true"

  echo "==> Waiting for rollout (failure/timeout is a real error, not swallowed)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n podmotion-system rollout status deploy/podmotion-operator --timeout=180s
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n podmotion-system rollout status ds/podmotion-agent --timeout=180s
  echo "==> deploy-podmotion complete."
}

# ── wipe: clean k8s + PodMotion STATE on the VMs, WITHOUT destroying VMs ──────
cmd_wipe() {
  assert_no_vm_destruction
  load_ips
  echo "==> WIPE: removing PodMotion + migration state (VMs persist)..."
  # In-cluster: uninstall helm release, delete PodMigration CRs, namespace.
  KUBECONFIG="$KUBECONFIG_OUT" helm uninstall podmotion -n podmotion-system 2>/dev/null || true
  KUBECONFIG="$KUBECONFIG_OUT" kubectl delete podmigrations.podmotion.io --all -A 2>/dev/null || true
  KUBECONFIG="$KUBECONFIG_OUT" kubectl delete ns podmotion-system 2>/dev/null || true

  # On each VM: clear checkpoint tmpfs debris + wrapper install (datapath artifact
  # cleanup only — never touch the VM definition, disks, or the base OS).
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- clean host state on $ip"
    nsh "$ip" "sudo rm -rf /run/podmotion/checkpoints/* 2>/dev/null || true"
  done
  echo "==> wipe complete (cluster + VMs still up; k8s control-plane untouched)."
}

usage() {
  cat >&2 <<EOF
Usage: hack/kvm-cluster.sh <verify|reset-cluster|deploy-podmotion|wipe|ssh <node-ip> [cmd]>

  verify            assert 3 nodes Ready via $KUBECONFIG_OUT
  reset-cluster     kubeadm reset+reinit+flannel+join ON the standing VMs (NEVER destroys VMs)
  deploy-podmotion  build+import images, mint mTLS, apply CRDs, helm install (TAG=<tag>)
  wipe              clean k8s + PodMotion state on the VMs WITHOUT destroying the VMs

This script REFUSES to 'virsh destroy'/'virsh undefine' any of: ${PM_VMS[*]}.
EOF
  exit 2
}

main() {
  local sub="${1:-}"; shift || true
  case "$sub" in
    verify)           cmd_verify ;;
    reset-cluster)    cmd_reset_cluster ;;
    deploy-podmotion) cmd_deploy_podmotion ;;
    wipe)             cmd_wipe ;;
    ssh)              load_ips; nsh "$@" ;;
    *)                usage ;;
  esac
}
main "$@"
