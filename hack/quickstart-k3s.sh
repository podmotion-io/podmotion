#!/usr/bin/env bash
# quickstart-k3s.sh — one-shot local KVM/libvirt + k3s quickstart for PodMotion.
#
# Sibling of hack/quickstart-kvm.sh (kubeadm) — mirrors its structure exactly,
# swapping only the cluster-bootstrap step (k3s instead of kubeadm) and the
# agent's containerd socket/state-dir overrides (k3s's embedded containerd
# lives at different host paths than a standard kubeadm/containerd install).
#
# Takes a fresh checkout of this repo (plus a sibling checkout of the
# `podmotion-demo` repo) to a working 3-node libvirt/k3s cluster with:
#   - 3 fresh libvirt VMs (1 server + 2 agents), provisioned from scratch via
#     hack/kvm-provision.sh (base cloud image + cloud-init + containerd/
#     kubeadm/CRIU/agent prereqs via the same Ansible roles the AWS AMI build
#     uses — k3s installs its OWN embedded containerd on top; the kubeadm-path
#     containerd/kubelet packages these prereqs install are simply unused on
#     this path, harmless to leave installed)
#   - k3s server + agent join (embedded Flannel CNI), via the generalized
#     hack/kvm-cluster.sh cmd_reset_cluster_k3s (CP_VM/WORKER_VMS/
#     WORKER_HOST_VARS/KVM_DIR overrides point it at THESE VMs instead of
#     Chad's standing pm-cp1/pm-w1/pm-w2 — that standing infra is never
#     touched by this script)
#   - Longhorn (dedicated per-node disk + storage classes)
#   - the PodMotion operator + node-agent DaemonSet, with agent.containerd.
#     socketPath/stateDir pointed at k3s's embedded-containerd paths (NOT the
#     kubeadm defaults) — see the K3S CONTAINERD PATHS note below
#   - the podmotion-demo app (web + api + postgres + redis + jaeger)
#   - the test/e2e/fixtures/{redis,postgres,nginx} workloads
#
# This generalizes the exact command sequence proven live on a throwaway
# "pmqk3s-*" 3-node cluster (reset-cluster-k3s, provision-longhorn,
# deploy-podmotion with k3s containerd paths, demo helm upgrade, fixture
# apply, a real PodMigration reaching Complete, web+Jaeger reachable via
# port-forward with real content) — it does not invent new steps beyond what
# was just verified to work.
#
# ─────────────────────────────────────────────────────────────────────────────
# K3S CONTAINERD PATHS — the one real difference from quickstart-kvm.sh
# ─────────────────────────────────────────────────────────────────────────────
# A standard kubeadm/containerd install uses /run/containerd/containerd.sock
# and /var/lib/containerd (the chart's own defaults). k3s ships its OWN
# embedded containerd at different paths:
#   agent.containerd.socketPath = /run/k3s/containerd/containerd.sock
#   agent.containerd.stateDir   = /var/lib/rancher/k3s/agent/containerd
# These are set here via --set on the SAME charts/podmotion Helm chart
# quickstart-kvm.sh uses (K3S_CONTAINERD_SOCKET / K3S_CONTAINERD_STATE_DIR,
# already defined in hack/kvm-cluster.sh — search "k3s (alternative
# reset-cluster mode" in that file). deploy-podmotion is also told
# CONTAINERD_ADDRESS + AGENT_CONTAINERD_SOCKET_PATH/STATE_DIR so its own `ctr`
# image-import calls target k3s's containerd namespace, not the kubeadm-path
# default. AGENT_CNI_EXTRA_CONF_DIR is set to k3s's own CNI conf directory
# (/var/lib/rancher/k3s/agent/etc/cni/net.d) since k3s does not populate the
# canonical /etc/cni/net.d the agent's CNI plugin detector scans by default.
#
# ─────────────────────────────────────────────────────────────────────────────
# Scheduling-gate binding path (matches the kind/kubeadm quickstarts)
# ─────────────────────────────────────────────────────────────────────────────
# This quickstart delegates to hack/kvm-cluster.sh deploy-podmotion and
# re-enters Helm with --reuse-values, so it inherits that script's
# scheduler.enabled=true / webhook.podMutation.enabled=true pair (matched,
# true since commit 7b2ecb53, 2026-07-27; ADR-0416 brings kind and EC2 to the
# same parity). The REPLACEMENT pod is pinned onto spec.targetNodeName by the
# podmotion scheduler, so the cordon/uncordon workaround this section used to
# document is no longer needed. If a migration still wedges at
# RestoreSocketReattach, or a replacement pod shows Init:CrashLoopBackOff with
# "destinationNode X != this node Y", check that deploy/podmotion-scheduler is
# actually Ready rather than reaching for a cordon.
#
# Usage:
#   hack/quickstart-k3s.sh [VM_PREFIX] [--demo-repo PATH] [--skip-workloads] [--help]
#
# VM_PREFIX defaults to "podmotion-quickstart-k3s". It may also be given as
# --vm-prefix NAME. VM_PREFIX must never be "pm" or empty — hack/kvm-provision.sh
# refuses outright to create/destroy/touch pm-cp1/pm-w1/pm-w2 (Chad's PERMANENT
# standing infra), no matter what is passed here.
#
# Re-running against an already-provisioned VM_PREFIX is safe: VM creation,
# cluster reset, Longhorn, and the Helm installs are all idempotent (each step
# either skips with a message or converges to the same end state).
#
# Requires: virsh/virt-install/qemu-img/xorriso (libvirt + KVM host, `default`
# NAT network + a storage pool named "default" already active), ansible-playbook,
# docker, kubectl, helm, go, make, ssh-keygen, curl on Ubuntu 24.04 (or any Linux
# capable of running libvirt/KVM). No PowerShell — bash only.

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Usage / arg parsing
# ─────────────────────────────────────────────────────────────────────────────

usage() {
  cat <<'EOF'
Usage: hack/quickstart-k3s.sh [VM_PREFIX] [options]

Stand up a fresh 3-node libvirt/k3s cluster with Longhorn, the PodMotion
operator, the podmotion-demo app, and extra test-workload fixtures installed.

Arguments:
  VM_PREFIX               libvirt VM name prefix (default: podmotion-quickstart-k3s).
                           VMs created: <VM_PREFIX>-cp1, <VM_PREFIX>-w1, <VM_PREFIX>-w2.
                           Must not be "pm" or empty (reserved for Chad's standing
                           pm-cp1/pm-w1/pm-w2 infra — hack/kvm-provision.sh refuses it).

Options:
  --vm-prefix NAME        same as the positional VM_PREFIX argument
  --demo-repo PATH        path to a podmotion-demo checkout (default: the
                           sibling directory "../podmotion-demo" next to
                           this repo's root; override with $PODMOTION_DEMO_REPO
                           too)
  --skip-workloads        skip applying test/e2e/fixtures/{redis,postgres,nginx}
  -h, --help              show this help and exit

Examples:
  hack/quickstart-k3s.sh
  hack/quickstart-k3s.sh my-k3s-cluster --demo-repo /path/to/podmotion-demo

Resource footprint: 3 VMs x (4 vCPU, 8GiB RAM, 60G root disk, 250G Longhorn
disk) = 12 vCPU / 24GiB RAM / ~930G disk allocated (thin-provisioned qcow2,
so actual host disk usage grows as data is written). Override per-VM sizing
via VCPUS/RAM_MB/ROOT_DISK_SIZE/LH_DISK_SIZE env vars (see hack/kvm-provision.sh).
EOF
}

VM_PREFIX="podmotion-quickstart-k3s"
SKIP_WORKLOADS=false
DEMO_REPO_OVERRIDE=""

if [[ $# -gt 0 && "${1:-}" != -* ]]; then
  VM_PREFIX="$1"
  shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-prefix)
      VM_PREFIX="$2"; shift 2 ;;
    --demo-repo)
      DEMO_REPO_OVERRIDE="$2"; shift 2 ;;
    --skip-workloads)
      SKIP_WORKLOADS=true; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1 ;;
  esac
done

# ─────────────────────────────────────────────────────────────────────────────
# Paths / derived VM identity (byte-identical convention to hack/kvm-provision.sh)
# ─────────────────────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_REPO_ROOT="${DEMO_REPO_OVERRIDE:-${PODMOTION_DEMO_REPO:-$(dirname "$REPO_ROOT")/podmotion-demo}}"

export VM_PREFIX
KVM_DIR="${KVM_DIR:-$HOME/.podmotion-kvm-${VM_PREFIX}}"
HOSTS_ENV="$KVM_DIR/hosts.env"
KUBECONFIG_FILE="$KVM_DIR/kubeconfig"
SSH_KEY="$KVM_DIR/id_pmkvm"

CP_VM="${VM_PREFIX}-cp1"
WORKER_VMS=("${VM_PREFIX}-w1" "${VM_PREFIX}-w2")

TAG="${VM_PREFIX}"
PODMOTION_NAMESPACE="podmotion-system"
WORKLOADS_NAMESPACE="pm-e2e" # hardcoded in test/e2e/fixtures/*.yaml

# k3s's embedded containerd — see the "K3S CONTAINERD PATHS" header note above.
# Matches K3S_CONTAINERD_SOCKET/K3S_CONTAINERD_STATE_DIR already defined in
# hack/kvm-cluster.sh (search "k3s (alternative reset-cluster mode" there).
K3S_CONTAINERD_SOCKET="/run/k3s/containerd/containerd.sock"
K3S_CONTAINERD_STATE_DIR="/var/lib/rancher/k3s/agent/containerd"
K3S_CNI_CONF_DIR="/var/lib/rancher/k3s/agent/etc/cni/net.d"

section() {
  echo ""
  echo "════════════════════════════════════════════════════════════════════"
  echo "  $1"
  echo "════════════════════════════════════════════════════════════════════"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Preflight checks
# ─────────────────────────────────────────────────────────────────────────────

section "Step 1/9 — Preflight checks"

MISSING=()

check_cmd() {
  local cmd="$1" hint="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "  [ok] $cmd ($(command -v "$cmd"))"
  else
    echo "  [MISSING] $cmd — $hint"
    MISSING+=("$cmd")
  fi
}

check_cmd virsh        "apt install libvirt-clients libvirt-daemon-system"
check_cmd virt-install  "apt install virtinst"
check_cmd qemu-img      "apt install qemu-utils"
check_cmd xorriso       "apt install xorriso"
check_cmd ansible-playbook "apt install ansible (or pipx install ansible-core)"
check_cmd docker   "apt install docker.io  (or https://docs.docker.com/engine/install/ubuntu/)"
check_cmd kubectl  "https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/"
check_cmd helm     "https://helm.sh/docs/intro/install/"
check_cmd go       "https://go.dev/doc/install (this repo targets go $(grep '^go ' "$REPO_ROOT/go.mod" | awk '{print $2}'))"
check_cmd make     "apt install make"
check_cmd ssh-keygen "apt install openssh-client"
check_cmd curl     "apt install curl"

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo ""
  echo "ERROR: missing required tool(s): ${MISSING[*]}" >&2
  echo "Install the tool(s) above, then re-run this script." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker is installed but not usable (daemon not running, or your user" >&2
  echo "       lacks permission — try 'sudo usermod -aG docker \$USER' and re-login)." >&2
  exit 1
fi

if ! virsh -c qemu:///system pool-info default >/dev/null 2>&1; then
  echo "ERROR: libvirt storage pool 'default' does not exist/active." >&2
  echo "       See: virsh pool-define-as default dir --target /var/lib/libvirt/images && virsh pool-start default" >&2
  exit 1
fi
if ! virsh -c qemu:///system net-info default >/dev/null 2>&1; then
  echo "ERROR: libvirt network 'default' does not exist/active (virsh net-start default)." >&2
  exit 1
fi
echo "  [ok] libvirt 'default' storage pool + network are active"

if [[ "$VM_PREFIX" == "pm" || -z "$VM_PREFIX" ]]; then
  echo "ERROR: VM_PREFIX='$VM_PREFIX' is reserved / invalid — choose a different name." >&2
  exit 1
fi
for reserved in pm-cp1 pm-w1 pm-w2; do
  if [[ "$CP_VM" == "$reserved" || "${WORKER_VMS[0]}" == "$reserved" || "${WORKER_VMS[1]}" == "$reserved" ]]; then
    echo "ERROR: VM_PREFIX='$VM_PREFIX' resolves to a reserved standing-infra VM name ($reserved)." >&2
    exit 1
  fi
done
echo "  [ok] VM_PREFIX='$VM_PREFIX' — VMs: $CP_VM ${WORKER_VMS[*]} (hack/kvm-provision.sh's own guard re-checks this too)"

if [[ ! -d "$DEMO_REPO_ROOT" ]]; then
  echo "ERROR: podmotion-demo checkout not found at: $DEMO_REPO_ROOT" >&2
  echo "       Clone it next to this repo (\"\$(dirname $REPO_ROOT)/podmotion-demo\")," >&2
  echo "       or pass --demo-repo PATH / set \$PODMOTION_DEMO_REPO." >&2
  exit 1
fi
for f in deploy/Dockerfile.backend deploy/Dockerfile.frontend backend frontend; do
  if [[ ! -e "$DEMO_REPO_ROOT/$f" ]]; then
    echo "ERROR: podmotion-demo checkout at $DEMO_REPO_ROOT is missing '$f'." >&2
    exit 1
  fi
done
echo "  [ok] podmotion-demo checkout: $DEMO_REPO_ROOT"
echo "  [ok] all preflight checks passed"

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Provision the 3 libvirt VMs (idempotent — reuses existing VMs/hosts.env)
# ─────────────────────────────────────────────────────────────────────────────

section "Step 2/9 — hack/kvm-provision.sh provision (VM_PREFIX=$VM_PREFIX)"

VM_PREFIX="$VM_PREFIX" KVM_DIR="$KVM_DIR" \
  bash "$REPO_ROOT/hack/kvm-provision.sh" provision

if [[ ! -f "$HOSTS_ENV" ]]; then
  echo "ERROR: expected $HOSTS_ENV after provisioning — kvm-provision.sh did not write it." >&2
  exit 1
fi
echo "  [ok] VMs provisioned. hosts.env: $HOSTS_ENV"

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — k3s reset-cluster (server init + agent join, embedded Flannel)
# ─────────────────────────────────────────────────────────────────────────────

section "Step 3/9 — hack/kvm-cluster.sh reset-cluster-k3s (k3s server/agent join)"

KVM_DIR="$KVM_DIR" CP_VM="$CP_VM" WORKER_VMS="${WORKER_VMS[*]}" WORKER_HOST_VARS="W1 W2" \
  bash "$REPO_ROOT/hack/kvm-cluster.sh" reset-cluster-k3s

KVM_DIR="$KVM_DIR" CP_VM="$CP_VM" WORKER_VMS="${WORKER_VMS[*]}" WORKER_HOST_VARS="W1 W2" \
  bash "$REPO_ROOT/hack/kvm-cluster.sh" verify

echo "  [ok] 3-node k3s cluster is up. Kubeconfig: $KUBECONFIG_FILE"

# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Longhorn (per-node disk + storage classes) — identical to the
# kubeadm quickstart; Longhorn does not care which distro owns the kubelet.
# ─────────────────────────────────────────────────────────────────────────────

section "Step 4/9 — hack/kvm-cluster.sh provision-longhorn"

KVM_DIR="$KVM_DIR" CP_VM="$CP_VM" WORKER_VMS="${WORKER_VMS[*]}" WORKER_HOST_VARS="W1 W2" \
  bash "$REPO_ROOT/hack/kvm-cluster.sh" provision-longhorn

echo "  [ok] Longhorn installed (storage classes: longhorn, longhorn-migratable)"

# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — Deploy the PodMotion operator + agent (build, import, CRDs, mTLS,
# helm) — with k3s's containerd socket/state-dir/CNI-conf-dir overrides so the
# agent's checkpoint/restore path and CNI detector target k3s's embedded
# containerd instead of the kubeadm-path defaults.
# ─────────────────────────────────────────────────────────────────────────────

section "Step 5/9 — hack/kvm-cluster.sh deploy-podmotion (TAG=$TAG, k3s containerd paths)"

KVM_DIR="$KVM_DIR" CP_VM="$CP_VM" WORKER_VMS="${WORKER_VMS[*]}" WORKER_HOST_VARS="W1 W2" TAG="$TAG" \
  CONTAINERD_ADDRESS="$K3S_CONTAINERD_SOCKET" \
  AGENT_CONTAINERD_SOCKET_PATH="$K3S_CONTAINERD_SOCKET" \
  AGENT_CONTAINERD_STATE_DIR="$K3S_CONTAINERD_STATE_DIR" \
  AGENT_CNI_EXTRA_CONF_DIR="$K3S_CNI_CONF_DIR" \
  bash "$REPO_ROOT/hack/kvm-cluster.sh" deploy-podmotion

echo "  [ok] operator + agent deployed in namespace '$PODMOTION_NAMESPACE'"
echo "  [ok] agent.containerd.socketPath=$K3S_CONTAINERD_SOCKET  stateDir=$K3S_CONTAINERD_STATE_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — Build + import the podmotion-demo images onto every node (no
# registry, no kind-load equivalent — same "docker save | ctr import" model
# deploy-podmotion already uses for operator/agent, done here for demo images
# too since demo pods can land on any of the 3 nodes). ctr is pointed at k3s's
# containerd socket via -a, same as deploy-podmotion's own image imports.
# ─────────────────────────────────────────────────────────────────────────────

section "Step 6/9 — Build + import podmotion-demo images onto all nodes"

DEMO_API_IMG="podmotion-demo-api:${TAG}"
DEMO_WEB_IMG="podmotion-demo-web:${TAG}"

cd "$DEMO_REPO_ROOT"
docker build -f deploy/Dockerfile.backend  -t "$DEMO_API_IMG" .
docker build -f deploy/Dockerfile.frontend -t "$DEMO_WEB_IMG" .
cd "$REPO_ROOT"

# shellcheck disable=SC1090
source "$HOSTS_ENV"
NODE_IPS=("$CP1" "$W1" "$W2")

SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
for ip in "${NODE_IPS[@]}"; do
  echo "  -- importing demo images into $ip"
  ssh "${SSH_OPTS[@]}" "chad@$ip" "sudo ctr -a '$K3S_CONTAINERD_SOCKET' -n k8s.io images rm '$DEMO_API_IMG' '$DEMO_WEB_IMG' >/dev/null 2>&1 || true"
  docker save "$DEMO_API_IMG" | ssh "${SSH_OPTS[@]}" "chad@$ip" "sudo ctr -a '$K3S_CONTAINERD_SOCKET' -n k8s.io images import -"
  docker save "$DEMO_WEB_IMG" | ssh "${SSH_OPTS[@]}" "chad@$ip" "sudo ctr -a '$K3S_CONTAINERD_SOCKET' -n k8s.io images import -"
done
echo "  [ok] $DEMO_API_IMG and $DEMO_WEB_IMG imported on ${NODE_IPS[*]}"

# ─────────────────────────────────────────────────────────────────────────────
# Step 7 — helm upgrade (add the podmotion-demo subchart on top of the
# operator release deploy-podmotion just installed — --reuse-values keeps
# every operator/agent/webhook/scheduler/containerd setting from Step 5
# untouched)
# ─────────────────────────────────────────────────────────────────────────────

section "Step 7/9 — helm upgrade podmotion (enable podmotion-demo subchart)"

helm dependency update "$REPO_ROOT/charts/podmotion"

KUBECONFIG="$KUBECONFIG_FILE" helm upgrade --install podmotion "$REPO_ROOT/charts/podmotion" \
  --namespace "$PODMOTION_NAMESPACE" --create-namespace \
  --reuse-values \
  --set podmotion-demo.enabled=true \
  --set podmotion-demo.web.image.repository="podmotion-demo-web" \
  --set podmotion-demo.web.image.tag="$TAG" \
  --set podmotion-demo.web.image.pullPolicy=IfNotPresent \
  --set podmotion-demo.api.image.repository="podmotion-demo-api" \
  --set podmotion-demo.api.image.tag="$TAG" \
  --set podmotion-demo.api.image.pullPolicy=IfNotPresent \
  --wait=false

echo "  [ok] podmotion-demo subchart enabled in release 'podmotion'"

# ─────────────────────────────────────────────────────────────────────────────
# Step 8 — Wait for everything to reach Ready
# ─────────────────────────────────────────────────────────────────────────────

section "Step 8/9 — Waiting for pods to become Ready"

wait_for_namespace_ready() {
  local ns="$1" timeout_s="$2"
  echo "  Waiting up to ${timeout_s}s for pods in namespace '$ns' to be Ready..."
  local deadline=$(( SECONDS + timeout_s ))
  while (( SECONDS < deadline )); do
    if KUBECONFIG="$KUBECONFIG_FILE" kubectl get pods -n "$ns" --no-headers 2>/dev/null | grep -q .; then
      if KUBECONFIG="$KUBECONFIG_FILE" kubectl wait --for=condition=Ready pods --all \
           -n "$ns" --timeout=10s >/dev/null 2>&1; then
        echo "  [ok] all pods in '$ns' are Ready."
        return 0
      fi
    fi
    sleep 5
  done
  return 1
}

if ! wait_for_namespace_ready "$PODMOTION_NAMESPACE" 300; then
  echo ""
  echo "ERROR: timed out waiting for pods in namespace '$PODMOTION_NAMESPACE' to become Ready." >&2
  echo "--- kubectl get pods -A ---" >&2
  KUBECONFIG="$KUBECONFIG_FILE" kubectl get pods -A >&2
  echo "--- recent events in $PODMOTION_NAMESPACE ---" >&2
  KUBECONFIG="$KUBECONFIG_FILE" kubectl get events -n "$PODMOTION_NAMESPACE" \
    --sort-by=.lastTimestamp 2>/dev/null | tail -n 40 >&2
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 9 — Apply extra test-workload fixtures
# ─────────────────────────────────────────────────────────────────────────────

if [[ "$SKIP_WORKLOADS" == "true" ]]; then
  section "Step 9/9 — Skipping extra test workloads (--skip-workloads)"
else
  section "Step 9/9 — Applying extra test workloads (test/e2e/fixtures/)"

  # These fixtures hardcode `namespace: pm-e2e` in their metadata, so the
  # namespace they land in is NOT configurable from this script without
  # rewriting the fixture files themselves — create pm-e2e and apply as-is.
  KUBECONFIG="$KUBECONFIG_FILE" kubectl create namespace "$WORKLOADS_NAMESPACE" \
    --dry-run=client -o yaml | KUBECONFIG="$KUBECONFIG_FILE" kubectl apply -f -

  KUBECONFIG="$KUBECONFIG_FILE" kubectl apply -f "$REPO_ROOT/test/e2e/fixtures/redis.yaml"
  KUBECONFIG="$KUBECONFIG_FILE" kubectl apply -f "$REPO_ROOT/test/e2e/fixtures/postgres.yaml"
  KUBECONFIG="$KUBECONFIG_FILE" kubectl apply -f "$REPO_ROOT/test/e2e/fixtures/nginx.yaml"

  echo "  [step] Waiting up to 180s for workloads in '$WORKLOADS_NAMESPACE' to be Ready (best-effort;"
  echo "         postgres needs a bound Longhorn PVC, which can take longer than redis/nginx)..."
  if ! KUBECONFIG="$KUBECONFIG_FILE" kubectl wait --for=condition=Ready pods --all \
       -n "$WORKLOADS_NAMESPACE" --timeout=180s >/dev/null 2>&1; then
    echo "  [warn] not all pods in '$WORKLOADS_NAMESPACE' reached Ready within 180s."
    KUBECONFIG="$KUBECONFIG_FILE" kubectl get pods -n "$WORKLOADS_NAMESPACE"
  else
    echo "  [ok] all workloads in '$WORKLOADS_NAMESPACE' are Ready."
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

WEB_SVC="podmotion-demo-web"
JAEGER_SVC="podmotion-demo-jaeger"

section "Done — k3s cluster '$VM_PREFIX' is ready"

cat <<EOF

Kubeconfig:
  export KUBECONFIG=$KUBECONFIG_FILE

VMs (libvirt, standing until you tear down — see below):
  $CP_VM (k3s server), ${WORKER_VMS[0]}, ${WORKER_VMS[1]} (k3s agents)
  hosts.env: $HOSTS_ENV
  SSH:  ssh -i $SSH_KEY chad@<node-ip>   (IPs in hosts.env: CP1/W1/W2)

These are libvirt VMs on a private NAT network (192.168.122.0/24), not reachable
directly from your workstation browser — use kubectl port-forward, same approach
as the kind/kubeadm quickstarts (run each in its own terminal, then leave it running):

  # PodMotion demo web UI  -> http://localhost:8080
  KUBECONFIG=$KUBECONFIG_FILE kubectl port-forward -n $PODMOTION_NAMESPACE svc/$WEB_SVC 8080:80

  # Jaeger trace UI        -> http://localhost:16686
  KUBECONFIG=$KUBECONFIG_FILE kubectl port-forward -n $PODMOTION_NAMESPACE svc/$JAEGER_SVC 16686:16686

Run your first migration:

  cat <<'YAML' | KUBECONFIG=$KUBECONFIG_FILE kubectl apply -f -
  apiVersion: migration.podmotion.io/v1alpha1
  kind: PodMigration
  metadata:
    name: migrate-my-app
    namespace: pm-e2e
  spec:
    podName: <some-pod-in-pm-e2e-namespace>
    podNamespace: pm-e2e
    targetNodeName: <a-node-name-from-hosts.env>
    mode: PreCopy
  YAML

  KUBECONFIG=$KUBECONFIG_FILE kubectl get podmigration migrate-my-app -n pm-e2e -o yaml

NOTE — this quickstart delegates to hack/kvm-cluster.sh deploy-podmotion and
re-enters Helm with --reuse-values, so it inherits that script's
scheduler.enabled=true / webhook.podMutation.enabled=true pair (matched, true
since commit 7b2ecb53, 2026-07-27; ADR-0416 brings kind and EC2 to the same
parity). The scheduling-gate binding path is live on this 3-node dev deploy:
the replacement pod is pinned onto spec.targetNodeName by the podmotion
scheduler, so the old cordon/uncordon workaround is no longer needed.

k3s-specific containerd paths in use on this cluster (agent.containerd.*):
  socketPath: $K3S_CONTAINERD_SOCKET
  stateDir:   $K3S_CONTAINERD_STATE_DIR
  CNI conf dir (agent.cni.extraConfDir): $K3S_CNI_CONF_DIR

Extra test workloads (redis/postgres/nginx) are running in namespace: $WORKLOADS_NAMESPACE

Tear down when finished (destroys ONLY the $VM_PREFIX-* VMs + their volumes —
refuses unconditionally to touch Chad's standing pm-cp1/pm-w1/pm-w2):

  VM_PREFIX=$VM_PREFIX KVM_DIR=$KVM_DIR bash hack/kvm-provision.sh destroy
  rm -rf $KVM_DIR

EOF
