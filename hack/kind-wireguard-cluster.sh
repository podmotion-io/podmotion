#!/usr/bin/env bash
# kind-wireguard-cluster.sh — M25 WireGuard gate cluster setup for PodMotion
# Creates a kind cluster "podmotion-wg" with Calico WireGuard enabled.
#
# Usage: ./hack/kind-wireguard-cluster.sh

set -euo pipefail

CLUSTER_NAME="podmotion-wg"
KCTX="kind-${CLUSTER_NAME}"
CALICO_VERSION="v3.27.0"
CALICO_MANIFEST="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Prefer the local PodMotion node image if it exists, else fall back to upstream
if docker image inspect podmotion-node:dev &>/dev/null 2>&1; then
  KIND_NODE_IMAGE="podmotion-node:dev"
  echo "[info] Using PodMotion node image: ${KIND_NODE_IMAGE}"
else
  KIND_NODE_IMAGE="kindest/node:v1.31.0"
  echo "[info] PodMotion node image not found, using: ${KIND_NODE_IMAGE}"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 1. Create kind cluster
# ─────────────────────────────────────────────────────────────────────────────
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "[skip] Cluster '${CLUSTER_NAME}' already exists."
else
  echo "[step 1] Creating kind cluster '${CLUSTER_NAME}'..."
  cat <<EOF | kind create cluster --name "${CLUSTER_NAME}" --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
nodes:
  - role: control-plane
    image: ${KIND_NODE_IMAGE}
  - role: worker
    image: ${KIND_NODE_IMAGE}
  - role: worker
    image: ${KIND_NODE_IMAGE}
EOF
  echo "[ok] Cluster created."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. Install Calico CNI
# ─────────────────────────────────────────────────────────────────────────────
echo "[step 2] Installing Calico ${CALICO_VERSION}..."
kubectl --context "${KCTX}" apply -f "${CALICO_MANIFEST}"
echo "[step 2] Waiting for calico-node DaemonSet to roll out (timeout 120s)..."
kubectl --context "${KCTX}" -n kube-system rollout status daemonset/calico-node --timeout=120s
echo "[ok] Calico ready."

# ─────────────────────────────────────────────────────────────────────────────
# 3. Enable WireGuard in Felix
# ─────────────────────────────────────────────────────────────────────────────
echo "[step 3] Enabling WireGuard in FelixConfiguration..."
kubectl --context "${KCTX}" patch felixconfiguration default --type=merge \
  -p '{"spec":{"wireguardEnabled":true}}'

echo "[step 3] Sleeping 15s for Felix to restart with WireGuard enabled..."
sleep 15

echo "[step 3] Verifying WireGuard public key annotations on nodes..."
WG_OK=true
while IFS= read -r node; do
  KEY=$(kubectl --context "${KCTX}" get node "${node}" \
    -o jsonpath='{.metadata.annotations.projectcalico\.org/WireguardPublicKey}' 2>/dev/null || true)
  if [[ -n "${KEY}" ]]; then
    echo "  [ok] ${node}: WireguardPublicKey=${KEY}"
  else
    echo "  [warn] ${node}: WireguardPublicKey annotation is EMPTY — WireGuard may not be supported in this kernel/image"
    WG_OK=false
  fi
done < <(kubectl --context "${KCTX}" get nodes -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n')

if [[ "${WG_OK}" == "false" ]]; then
  echo "[warn] One or more nodes are missing WireGuard public key annotations."
  echo "       This is expected if the kind node image lacks wireguard-tools or kernel module."
  echo "       The gate will proceed; WireGuard tunnels will not be active on those nodes."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. Build and load PodMotion operator image
# ─────────────────────────────────────────────────────────────────────────────
echo "[step 4] Building PodMotion manager binary (linux/amd64)..."
cd "${REPO_ROOT}"
GOOS=linux GOARCH=amd64 go build -o /tmp/podmotion-manager-wg ./cmd/main.go
echo "[ok] Binary built: /tmp/podmotion-manager-wg"

echo "[step 4] Building operator Docker image podmotion/manager:wg-test..."
docker build -t podmotion/manager:wg-test -f - /tmp <<'DOCKERFILE'
FROM ubuntu:24.04
COPY podmotion-manager-wg /usr/local/bin/podmotion-manager
ENTRYPOINT ["/usr/local/bin/podmotion-manager"]
DOCKERFILE
echo "[ok] Image built."

echo "[step 4] Loading image into kind cluster '${CLUSTER_NAME}'..."
kind load docker-image podmotion/manager:wg-test --name "${CLUSTER_NAME}"
echo "[ok] Image loaded."

# ─────────────────────────────────────────────────────────────────────────────
# 5. Apply CRDs
# ─────────────────────────────────────────────────────────────────────────────
echo "[step 5] Applying CRDs from config/crd/bases/..."
kubectl --context "${KCTX}" apply -f "${REPO_ROOT}/config/crd/bases/"

echo "[step 5] Waiting for all CRDs to reach Established condition..."
for CRD in $(kubectl --context "${KCTX}" get crd -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep podmotion); do
  echo "  Waiting for CRD: ${CRD}"
  kubectl --context "${KCTX}" wait crd "${CRD}" \
    --for=condition=Established --timeout=60s
done
echo "[ok] CRDs established."

# ─────────────────────────────────────────────────────────────────────────────
# 6. Create test namespace
# ─────────────────────────────────────────────────────────────────────────────
echo "[step 6] Creating namespace podmotion-wg-test..."
kubectl --context "${KCTX}" create namespace podmotion-wg-test \
  --dry-run=client -o yaml | kubectl --context "${KCTX}" apply -f -
echo "[ok] Namespace ready."

# ─────────────────────────────────────────────────────────────────────────────
# 7. Check NMC records
# ─────────────────────────────────────────────────────────────────────────────
echo "[step 7] Checking NodeMigrationCapacity (NMC) records..."
echo "         (NMC records are created by the operator on startup; operator not yet deployed)"
echo "         Listing any existing NMC records..."
NMC_LIST=$(kubectl --context "${KCTX}" get nmc 2>&1 || true)
echo "${NMC_LIST}"

echo ""
echo "[step 7] NMC wireGuardInterface values:"
NMC_WG=$(kubectl --context "${KCTX}" get nmc \
  -o jsonpath='{range .items[*]}{.metadata.name}{": "}{.spec.networkCapability.wireGuardInterface}{"\n"}{end}' 2>/dev/null || true)
if [[ -n "${NMC_WG}" ]]; then
  echo "${NMC_WG}"
else
  echo "  (no NMC records yet — operator must be deployed and started to create them)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo " M25 WireGuard Gate Cluster — Setup Summary"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Cluster:    ${CLUSTER_NAME}  (context: ${KCTX})"
echo "CNI:        Calico ${CALICO_VERSION}"
echo ""
echo "Nodes:"
kubectl --context "${KCTX}" get nodes -o wide
echo ""
echo "WireGuard public key annotations:"
kubectl --context "${KCTX}" get nodes \
  -o custom-columns='NODE:.metadata.name,WG_KEY:.metadata.annotations.projectcalico\.org/WireguardPublicKey'
echo ""
echo "CRDs installed:"
kubectl --context "${KCTX}" get crd | grep podmotion || echo "  (none)"
echo ""
echo "NMC records:"
kubectl --context "${KCTX}" get nmc 2>/dev/null || echo "  (none — deploy operator to populate)"
echo ""
echo "Next steps:"
echo "  Deploy the operator:  kubectl --context ${KCTX} apply -f config/deploy/"
echo "  Watch NMC:            kubectl --context ${KCTX} get nmc -w"
echo "════════════════════════════════════════════════════════════"
