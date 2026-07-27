#!/usr/bin/env bash
# bootstrap.sh — kubeadm init/join + Longhorn + PodMotion install, driven off
# terraform/kubeadm-ec2-quickstart's own `terraform output -json` (run this
# AFTER `terraform apply` in this directory succeeds).
#
# This module's main.tf deliberately stops at "reachable boxes" — Terraform
# does not run kubeadm. This script picks up from there: same shape as
# hack/kvm-cluster.sh's cmd_reset_cluster (kubeadm init on the control-plane
# with the right pod-CIDR, generate a join token, join workers over SSH,
# export kubeconfig locally), adapted to read node IPs/SSH key path from
# Terraform outputs instead of a static hosts.env, plus:
#   - Longhorn install (same recipe as hack/kvm-cluster.sh's
#     cmd_provision_longhorn: format+mount a dedicated EBS volume per node,
#     open-iscsi prereq, apply the pinned longhorn.yaml manifest, patch the
#     control-plane taint-toleration, create the RWX "longhorn-migratable"
#     StorageClass).
#   - The PodMotion operator + CRDs + podmotion-demo + the
#     test/e2e/fixtures/{redis,postgres,nginx} workloads, using the same
#     Helm value paths already proven in hack/quickstart-kind.sh, with the
#     image-loading mechanism swapped for EC2: `docker save <img> | ssh
#     <node> 'sudo ctr -n k8s.io images import -'` instead of `kind load`
#     (same pattern hack/kvm-cluster.sh's cmd_deploy_podmotion already uses
#     for real VMs, and the one documented for the KVM substrate generally).
#
# Requires a sibling checkout of the podmotion-demo application repo (web +
# api source + Dockerfiles) — same convention as hack/quickstart-kind.sh:
# defaults to "../podmotion-demo" next to this repo's root, override with
# --demo-repo PATH or $PODMOTION_DEMO_REPO.
#
# NOT live-verified end-to-end (no real EC2 boxes were stood up to run this
# against — that requires `terraform apply`, which needs an explicit human
# go-ahead first). Authored and statically checked (bash -n, shellcheck if
# available) against the actual `terraform output` shape this module
# produces and the proven recipes in hack/kvm-cluster.sh / hack/quickstart-kind.sh.
#
# Usage:
#   terraform init && terraform apply   # NOT run by this script
#   ./bootstrap.sh [--demo-repo PATH] [--skip-workloads] [--skip-demo] [--help]

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Arg parsing
# ─────────────────────────────────────────────────────────────────────────────

usage() {
  cat <<'EOF'
Usage: ./bootstrap.sh [options]

Bootstraps kubeadm (init + join) on the EC2 boxes this module's
`terraform apply` created, then installs Longhorn, the PodMotion operator,
the podmotion-demo app, and the test/e2e/fixtures/{redis,postgres,nginx}
workloads. Run from this directory, after `terraform apply` has succeeded.

Options:
  --demo-repo PATH   path to a podmotion-demo checkout (default: the sibling
                      directory "../../../podmotion-demo" next to this repo's
                      root; override with $PODMOTION_DEMO_REPO too)
  --skip-demo         skip building/installing the podmotion-demo app entirely
  --skip-workloads     skip applying test/e2e/fixtures/{redis,postgres,nginx}
  -h, --help          show this help and exit
EOF
}

DEMO_REPO_OVERRIDE=""
SKIP_DEMO=false
SKIP_WORKLOADS=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --demo-repo)
      DEMO_REPO_OVERRIDE="$2"; shift 2 ;;
    --skip-demo)
      SKIP_DEMO=true; shift ;;
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
# Paths
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO_REPO_ROOT="${DEMO_REPO_OVERRIDE:-${PODMOTION_DEMO_REPO:-$(dirname "$REPO_ROOT")/podmotion-demo}}"

cd "$SCRIPT_DIR"

section() {
  echo ""
  echo "════════════════════════════════════════════════════════════════════"
  echo "  $1"
  echo "════════════════════════════════════════════════════════════════════"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 0 — Preflight: local tools + Terraform state/outputs
# ─────────────────────────────────────────────────────────────────────────────

section "Step 0/9 — Preflight checks"

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
check_cmd terraform "https://developer.hashicorp.com/terraform/install"
check_cmd jq        "apt install jq"
check_cmd ssh        "apt install openssh-client"
check_cmd scp        "apt install openssh-client"
check_cmd kubectl    "https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/"
check_cmd helm       "https://helm.sh/docs/intro/install/"
check_cmd docker     "https://docs.docker.com/engine/install/ubuntu/"
check_cmd go         "https://go.dev/doc/install"
check_cmd make       "apt install make"

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "" >&2
  echo "ERROR: missing required tool(s): ${MISSING[*]}" >&2
  exit 1
fi

if [[ ! -f "$SCRIPT_DIR/terraform.tfstate" ]]; then
  echo "ERROR: no terraform.tfstate found in $SCRIPT_DIR." >&2
  echo "       Run 'terraform init && terraform apply' in this directory first." >&2
  exit 1
fi

TF_OUT_JSON="$(terraform output -json)"
CP_IP="$(jq -r '.control_plane_public_ip.value' <<<"$TF_OUT_JSON")"
mapfile -t WORKER_IPS < <(jq -r '.worker_public_ips.value[]' <<<"$TF_OUT_JSON")
SSH_KEY="$SCRIPT_DIR/$(jq -r '.ssh_private_key_path.value' <<<"$TF_OUT_JSON" | xargs basename)"
POD_CIDR="$(jq -r '.pod_cidr.value' <<<"$TF_OUT_JSON")"
DEMO_URL="$(jq -r '.podmotion_demo_url.value' <<<"$TF_OUT_JSON")"

if [[ -z "$CP_IP" || "$CP_IP" == "null" || ${#WORKER_IPS[@]} -eq 0 ]]; then
  echo "ERROR: could not resolve control-plane/worker IPs from 'terraform output -json'." >&2
  echo "       Did 'terraform apply' succeed in $SCRIPT_DIR?" >&2
  exit 1
fi
if [[ ! -f "$SSH_KEY" ]]; then
  echo "ERROR: SSH key not found at $SSH_KEY (from ssh_private_key_path output)." >&2
  exit 1
fi

echo "  [ok] control-plane: $CP_IP"
echo "  [ok] workers: ${WORKER_IPS[*]}"
echo "  [ok] SSH key: $SSH_KEY"
echo "  [ok] pod CIDR: $POD_CIDR"

if [[ "$SKIP_DEMO" == "false" ]]; then
  if [[ ! -d "$DEMO_REPO_ROOT" ]]; then
    echo "ERROR: podmotion-demo checkout not found at: $DEMO_REPO_ROOT" >&2
    echo "       Clone it next to this repo (\"\$(dirname $REPO_ROOT)/podmotion-demo\")," >&2
    echo "       or pass --demo-repo PATH / set \$PODMOTION_DEMO_REPO, or pass --skip-demo." >&2
    exit 1
  fi
  for f in deploy/Dockerfile.backend deploy/Dockerfile.frontend backend frontend; do
    if [[ ! -e "$DEMO_REPO_ROOT/$f" ]]; then
      echo "ERROR: podmotion-demo checkout at $DEMO_REPO_ROOT is missing '$f'." >&2
      exit 1
    fi
  done
  echo "  [ok] podmotion-demo checkout: $DEMO_REPO_ROOT"
fi

nsh() {   # node ssh: nsh <ip> "<cmd>"
  local ip="$1"; shift
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=10 -o LogLevel=ERROR "ubuntu@$ip" "$@"
}

KUBECONFIG_OUT="$SCRIPT_DIR/kubeconfig"
TAG="ec2-quickstart-$(date +%Y%m%d%H%M%S)"
FLANNEL_MANIFEST="$REPO_ROOT/images/kind/kube-flannel-v0.25.4.yml"
PODMOTION_NAMESPACE="podmotion-system"
WORKLOADS_NAMESPACE="pm-e2e"
OPERATOR_IMG="podmotion-operator:$TAG"
AGENT_IMG="podmotion-agent:$TAG"
DEMO_WEB_IMG="podmotion-demo-web:$TAG"
DEMO_API_IMG="podmotion-demo-api:$TAG"
ALL_IPS=("$CP_IP" "${WORKER_IPS[@]}")

echo "  [ok] waiting for SSH on all nodes..."
for ip in "${ALL_IPS[@]}"; do
  for i in $(seq 1 30); do
    nsh "$ip" "true" 2>/dev/null && { echo "    $ip reachable"; break; }
    if [[ "$i" -eq 30 ]]; then
      echo "ERROR: could not SSH to $ip after 30 tries (~2.5min). Is the instance still booting?" >&2
      exit 1
    fi
    sleep 5
  done
done

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — kubeadm init on the control-plane
# ─────────────────────────────────────────────────────────────────────────────

section "Step 1/9 — kubeadm init on control-plane ($CP_IP)"

# apiserver-advertise-address must be an address actually present on the CP's
# own interface (its private IP, from EC2 instance metadata) — the public IP
# is NAT-mapped at the ENI, not bound to any local interface. The public IP is
# added as an extra cert SAN so the kubeconfig we export below (rewritten to
# point at the public IP) is still trusted by the apiserver's TLS cert.
CP_PRIVATE_IP="$(nsh "$CP_IP" bash -s <<'REMOTE'
TOKEN="$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")"
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4
REMOTE
)"
if [[ -z "$CP_PRIVATE_IP" ]]; then
  echo "ERROR: could not discover the control-plane's private IP via instance metadata." >&2
  exit 1
fi
echo "  [ok] control-plane private IP: $CP_PRIVATE_IP"

if nsh "$CP_IP" "test -f /etc/kubernetes/admin.conf"; then
  echo "  [skip] /etc/kubernetes/admin.conf already present on $CP_IP — cluster already initialized, skipping kubeadm init."
else
  nsh "$CP_IP" "sudo kubeadm init --pod-network-cidr=$POD_CIDR --apiserver-advertise-address=$CP_PRIVATE_IP --apiserver-cert-extra-sans=$CP_IP"
fi
nsh "$CP_IP" "mkdir -p \$HOME/.kube && sudo cp -f /etc/kubernetes/admin.conf \$HOME/.kube/config && sudo chown \$(id -u):\$(id -g) \$HOME/.kube/config"

echo "  [step] Applying Flannel CNI ($FLANNEL_MANIFEST)..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$FLANNEL_MANIFEST" "ubuntu@$CP_IP:/tmp/kube-flannel.yml"
nsh "$CP_IP" "kubectl apply -f /tmp/kube-flannel.yml"

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Join workers
# ─────────────────────────────────────────────────────────────────────────────

section "Step 2/9 — Joining workers"

JOIN_CMD="$(nsh "$CP_IP" "sudo kubeadm token create --print-join-command")"
for ip in "${WORKER_IPS[@]}"; do
  if nsh "$ip" "test -f /etc/kubernetes/kubelet.conf"; then
    echo "  [skip] $ip already joined."
    continue
  fi
  echo "  -- join worker $ip"
  nsh "$ip" "sudo $JOIN_CMD"
done

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Export kubeconfig locally, pointed at the public IP
# ─────────────────────────────────────────────────────────────────────────────

section "Step 3/9 — Exporting kubeconfig to $KUBECONFIG_OUT"

nsh "$CP_IP" "sudo cat /etc/kubernetes/admin.conf" \
  | sed "s#server: https://$CP_PRIVATE_IP:6443#server: https://$CP_IP:6443#" \
  > "$KUBECONFIG_OUT"
chmod 600 "$KUBECONFIG_OUT"

echo "  [step] Waiting for nodes Ready (timeout 180s)..."
KUBECONFIG="$KUBECONFIG_OUT" kubectl wait --for=condition=Ready nodes --all --timeout=180s
KUBECONFIG="$KUBECONFIG_OUT" kubectl get nodes -o wide

# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Longhorn: dedicated EBS volume per node + Longhorn install
# ─────────────────────────────────────────────────────────────────────────────

section "Step 4/9 — Longhorn (format+mount EBS volume, iSCSI prereq, install, migratable SC)"

LH_MOUNT="/var/lib/longhorn"
LH_VERSION="v1.9.1"
LH_MANIFEST_URL="https://raw.githubusercontent.com/longhorn/longhorn/${LH_VERSION}/deploy/longhorn.yaml"
LH_NAMESPACE="longhorn-system"
LH_STORAGE_CLASS="longhorn"
LH_MIGRATABLE_SC="longhorn-migratable"

echo "  [step] Format + mount the dedicated Longhorn EBS volume on each node..."
# Nitro instances (t3.*) attach extra EBS volumes as NVMe devices with an
# unpredictable in-guest name (no /dev/sdf-style naming) — main.tf's own
# comment on aws_ebs_volume flags this. Discover it at runtime: it's the one
# top-level disk that is NOT the disk backing the root filesystem.
for ip in "${ALL_IPS[@]}"; do
  echo "  -- prep Longhorn disk on $ip"
  nsh "$ip" "sudo bash -s" <<'REMOTE'
set -e
ROOT_SRC="$(findmnt -no SOURCE /)"
ROOT_DISK="$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null || true)"
if [[ -z "$ROOT_DISK" ]]; then
  ROOT_DISK="$(basename "$ROOT_SRC" | sed -E 's/p?[0-9]+$//')"
fi
DEV=""
while read -r name type; do
  [[ "$type" == "disk" && "$name" != "$ROOT_DISK" ]] || continue
  DEV="/dev/$name"
  break
done < <(lsblk -dno NAME,TYPE)
if [[ -z "$DEV" ]]; then
  echo "ERROR: could not find a non-root disk for Longhorn on $(hostname)." >&2
  lsblk >&2
  exit 1
fi
echo "  Longhorn device on $(hostname): $DEV (root disk: /dev/$ROOT_DISK)"
if ! blkid "$DEV" >/dev/null 2>&1; then mkfs.ext4 -q -L longhorn "$DEV"; fi
mkdir -p /var/lib/longhorn
UUID=$(blkid -s UUID -o value "$DEV")
grep -q "$UUID" /etc/fstab || echo "UUID=$UUID /var/lib/longhorn ext4 defaults 0 2" >> /etc/fstab
mountpoint -q /var/lib/longhorn || mount /var/lib/longhorn
df -h /var/lib/longhorn | tail -1
REMOTE
done

echo "  [step] open-iscsi prereq on each node..."
for ip in "${ALL_IPS[@]}"; do
  nsh "$ip" "sudo bash -c 'export DEBIAN_FRONTEND=noninteractive; dpkg -l open-iscsi 2>/dev/null | grep -q \"^ii\" || { apt-get update -qq && apt-get install -y -qq open-iscsi >/dev/null; }; systemctl enable --now iscsid >/dev/null 2>&1; systemctl is-active iscsid'"
done

echo "  [step] Installing Longhorn $LH_VERSION..."
KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f "$LH_MANIFEST_URL"
KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" rollout status ds/longhorn-manager --timeout=300s

echo "  [step] Tolerating the control-plane taint so Longhorn also uses its disk..."
lh_patch_tries=0
until KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" patch setting taint-toleration \
    --type=merge -p '{"value":"node-role.kubernetes.io/control-plane:NoSchedule"}' 2>/dev/null; do
  lh_patch_tries=$((lh_patch_tries + 1))
  if [[ $lh_patch_tries -ge 30 ]]; then
    echo "ERROR: taint-toleration Setting never became patchable after 30 tries (~60s)." >&2
    exit 1
  fi
  sleep 2
done
KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" patch ds longhorn-manager --type=json \
  -p '[{"op":"add","path":"/spec/template/spec/tolerations","value":[{"key":"node-role.kubernetes.io/control-plane","operator":"Exists","effect":"NoSchedule"}]}]' || true
KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" rollout status ds/longhorn-manager --timeout=300s
echo "  [step] Waiting for all longhorn-system pods Ready..."
KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" wait --for=condition=Ready pods --all --timeout=300s || true

echo "  [step] Creating $LH_MIGRATABLE_SC StorageClass (RWX, live-migration)..."
KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f - <<YAML
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: $LH_MIGRATABLE_SC
provisioner: driver.longhorn.io
allowVolumeExpansion: true
reclaimPolicy: Delete
volumeBindingMode: Immediate
parameters:
  numberOfReplicas: "3"
  staleReplicaTimeout: "30"
  fsType: "ext4"
  dataLocality: "disabled"
  migratable: "true"
  accessMode: "rwx"
YAML
echo "  [ok] Longhorn ready. StorageClasses: $LH_STORAGE_CLASS (RWO), $LH_MIGRATABLE_SC (RWX, live-migratable)."

# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — Build operator/agent binaries + images, import to every node
# ─────────────────────────────────────────────────────────────────────────────

section "Step 5/9 — Build + import PodMotion operator/agent images (docker save | ssh ... ctr import)"

cd "$REPO_ROOT"
make build-linux
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
docker build --build-arg GIT_SHA="$GIT_SHA" -f images/operator/Dockerfile -t "$OPERATOR_IMG" .
docker build --build-arg GIT_SHA="$GIT_SHA" -f images/agent/Dockerfile    -t "$AGENT_IMG"    .

for ip in "${ALL_IPS[@]}"; do
  echo "  -- ensure /usr/local/bin/ctr on $ip"
  # server.go's checkpoint/restore host-mount-ns path invokes ctr at the
  # absolute path /usr/local/bin/ctr; Ubuntu ships it at /usr/bin/ctr — same
  # provisioning gap hack/kvm-cluster.sh's cmd_deploy_podmotion guards
  # against for real (non-kind) VMs. Idempotent.
  nsh "$ip" 'set -e; REAL_CTR="$(command -v ctr || true)"; \
    if [ -z "$REAL_CTR" ]; then echo "ERROR: ctr not found on node" >&2; exit 1; fi; \
    if [ "$REAL_CTR" != "/usr/local/bin/ctr" ]; then \
      sudo ln -sfn "$REAL_CTR" /usr/local/bin/ctr; fi; \
    test -x /usr/local/bin/ctr && echo "    ctr -> $REAL_CTR ok"'
done

for ip in "${ALL_IPS[@]}"; do
  echo "  -- import operator+agent into $ip"
  nsh "$ip" "sudo ctr -n k8s.io images rm '$OPERATOR_IMG' '$AGENT_IMG' >/dev/null 2>&1 || true"
  docker save "$OPERATOR_IMG" | nsh "$ip" "sudo ctr -n k8s.io images import -"
  docker save "$AGENT_IMG"    | nsh "$ip" "sudo ctr -n k8s.io images import -"
  if ! nsh "$ip" "sudo ctr -n k8s.io images ls -q | grep -q ':$TAG'"; then
    echo "ERROR: image tag ':$TAG' not present in k8s.io containerd namespace on node $ip after import." >&2
    exit 1
  fi
done
echo "  [ok] operator + agent images imported on all nodes."

# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — CRDs + namespace + mTLS dev certs
# ─────────────────────────────────────────────────────────────────────────────

section "Step 6/9 — CRDs, namespace, agent-certs-dev"

KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f "$REPO_ROOT/config/crd/bases/"
KUBECONFIG="$KUBECONFIG_OUT" kubectl create namespace "$PODMOTION_NAMESPACE" \
  --dry-run=client -o yaml | KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f -
KUBECONFIG="$KUBECONFIG_OUT" make -C "$REPO_ROOT" agent-certs-dev
echo "  [ok] CRDs applied, namespace ensured, mTLS secrets minted."

# ─────────────────────────────────────────────────────────────────────────────
# Step 7 — podmotion-demo app: build + import images (unless --skip-demo)
# ─────────────────────────────────────────────────────────────────────────────

DEMO_ENABLED="false"
if [[ "$SKIP_DEMO" == "false" ]]; then
  section "Step 7/9 — Build + import podmotion-demo images"
  DEMO_ENABLED="true"
  cd "$DEMO_REPO_ROOT"
  docker build -f deploy/Dockerfile.backend  -t "$DEMO_API_IMG" .
  docker build -f deploy/Dockerfile.frontend -t "$DEMO_WEB_IMG" .
  for ip in "${ALL_IPS[@]}"; do
    echo "  -- import demo web+api into $ip"
    nsh "$ip" "sudo ctr -n k8s.io images rm '$DEMO_API_IMG' '$DEMO_WEB_IMG' >/dev/null 2>&1 || true"
    docker save "$DEMO_API_IMG" | nsh "$ip" "sudo ctr -n k8s.io images import -"
    docker save "$DEMO_WEB_IMG" | nsh "$ip" "sudo ctr -n k8s.io images import -"
  done
  echo "  [ok] podmotion-demo images imported on all nodes."
else
  section "Step 7/9 — Skipping podmotion-demo (--skip-demo)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 8 — helm install (operator + podmotion-demo)
# ─────────────────────────────────────────────────────────────────────────────

section "Step 8/9 — helm upgrade --install podmotion"

cd "$REPO_ROOT"
helm dependency update charts/podmotion

# Same value paths already proven in hack/quickstart-kind.sh (operator/agent
# image refs, the webhook.certManager/scheduler/podMutation trio, and the
# podmotion-demo.* image overrides), with two EC2-specific differences from
# that kind recipe:
#   - pullPolicy=IfNotPresent, not Never: the images were placed into
#     containerd via `ctr images import` (this script's Step 5/7), not
#     `kind load` — IfNotPresent is the same choice hack/kvm-cluster.sh's
#     cmd_deploy_podmotion already makes for real (non-kind) VMs.
#   - no agent.apparmorProfile=unconfined override: that kind-specific
#     fallback exists because kind's docker-in-docker nodes often lack a
#     real AppArmor LSM. These are full Ubuntu 24.04 EC2 VMs (same as the
#     KVM substrate), which do have one, so the chart's default
#     "localhost/podmotion-agent" profile (self-loaded by the
#     install-apparmor-profile init container) is left in effect — matching
#     hack/kvm-cluster.sh's cmd_deploy_podmotion, which also does not
#     override this value.
HELM_ARGS=(
  upgrade --install podmotion charts/podmotion
  --namespace "$PODMOTION_NAMESPACE" --create-namespace
  --set operator.image.repository=podmotion-operator
  --set operator.image.tag="$TAG"
  --set operator.image.pullPolicy=IfNotPresent
  --set agent.image.repository=podmotion-agent
  --set agent.image.tag="$TAG"
  --set agent.image.pullPolicy=IfNotPresent
  --set operator.replicas=1
  --set webhook.certManager.enabled=false
  --set scheduler.enabled=false
  --set webhook.podMutation.enabled=false
  --set installCRDs=false
)
if [[ "$DEMO_ENABLED" == "true" ]]; then
  HELM_ARGS+=(
    --set podmotion-demo.enabled=true
    --set podmotion-demo.web.image.repository=podmotion-demo-web
    --set podmotion-demo.web.image.tag="$TAG"
    --set podmotion-demo.web.image.pullPolicy=IfNotPresent
    --set podmotion-demo.api.image.repository=podmotion-demo-api
    --set podmotion-demo.api.image.tag="$TAG"
    --set podmotion-demo.api.image.pullPolicy=IfNotPresent
  )
fi
KUBECONFIG="$KUBECONFIG_OUT" helm "${HELM_ARGS[@]}"

echo "  [step] Waiting for operator + agent rollout..."
KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$PODMOTION_NAMESPACE" rollout status deploy/podmotion-operator --timeout=180s
KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$PODMOTION_NAMESPACE" rollout status ds/podmotion-agent --timeout=180s
if [[ "$DEMO_ENABLED" == "true" ]]; then
  echo "  [step] Waiting for podmotion-demo pods Ready (best-effort, 300s)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$PODMOTION_NAMESPACE" wait --for=condition=Ready pods \
    -l "app.kubernetes.io/instance=podmotion" --timeout=300s || \
    KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$PODMOTION_NAMESPACE" get pods
fi
echo "  [ok] PodMotion (+ podmotion-demo) installed."

# ─────────────────────────────────────────────────────────────────────────────
# Step 9 — Extra test-workload fixtures
# ─────────────────────────────────────────────────────────────────────────────

if [[ "$SKIP_WORKLOADS" == "true" ]]; then
  section "Step 9/9 — Skipping extra test workloads (--skip-workloads)"
else
  section "Step 9/9 — Applying extra test workloads (test/e2e/fixtures/)"
  KUBECONFIG="$KUBECONFIG_OUT" kubectl create namespace "$WORKLOADS_NAMESPACE" \
    --dry-run=client -o yaml | KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f -
  KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f "$REPO_ROOT/test/e2e/fixtures/redis.yaml"
  KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f "$REPO_ROOT/test/e2e/fixtures/postgres.yaml"
  KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f "$REPO_ROOT/test/e2e/fixtures/nginx.yaml"
  echo "  [step] Waiting up to 120s for workloads in '$WORKLOADS_NAMESPACE' to be Ready (best-effort)..."
  if ! KUBECONFIG="$KUBECONFIG_OUT" kubectl wait --for=condition=Ready pods --all \
       -n "$WORKLOADS_NAMESPACE" --timeout=120s >/dev/null 2>&1; then
    echo "  [warn] not all pods in '$WORKLOADS_NAMESPACE' reached Ready within 120s (not fatal)."
    KUBECONFIG="$KUBECONFIG_OUT" kubectl get pods -n "$WORKLOADS_NAMESPACE"
  else
    echo "  [ok] all workloads in '$WORKLOADS_NAMESPACE' are Ready."
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

section "Done — cluster is ready"

cat <<EOF

Kubeconfig:
  export KUBECONFIG=$KUBECONFIG_OUT

$( [[ "$DEMO_ENABLED" == "true" ]] && echo "podmotion-demo web UI: $DEMO_URL" || echo "podmotion-demo was skipped (--skip-demo)." )

Extra test workloads (redis/postgres/nginx), if not skipped, are running in
namespace: $WORKLOADS_NAMESPACE

Run your first migration:

  cat <<'YAML' | KUBECONFIG=$KUBECONFIG_OUT kubectl apply -f -
  apiVersion: migration.podmotion.io/v1alpha1
  kind: PodMigration
  metadata:
    name: migrate-my-app
    namespace: default
  spec:
    podName: <some-pod-in-default-namespace>
    podNamespace: default
    mode: PreCopy
  YAML

Tear down when finished (this is real, billed AWS infrastructure):

  cd $SCRIPT_DIR
  terraform destroy

EOF
