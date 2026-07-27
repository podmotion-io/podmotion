#!/usr/bin/env bash
# quickstart-kind.sh — one-shot local kind quickstart for PodMotion.
#
# Takes a fresh checkout of this repo (plus a sibling checkout of the
# `podmotion-demo` repo) to a working local kind cluster with:
#   - the PodMotion operator + node-agent DaemonSet installed
#   - the podmotion-demo app (web + api + postgres + redis + jaeger) installed
#   - the test/e2e/fixtures/{redis,postgres,nginx} workloads applied
#
# This generalizes the build+load+helm-install recipe documented in
# docs-site's getting-started page and already proven live (Sprint 53) for
# the `podmotion-demo` kind cluster. It does not invent new Make targets or
# Helm value paths — every command below is grounded in this repo's Makefile,
# charts/podmotion/values.yaml, charts/podmotion-demo/values.yaml, and
# charts/podmotion/Chart.yaml.
#
# Usage:
#   hack/quickstart-kind.sh [CLUSTER_NAME] [--demo-repo PATH] [--skip-workloads] [--help]
#
# CLUSTER_NAME defaults to "podmotion-quickstart". It may also be given as
# --cluster-name NAME. Re-running against an existing cluster of the same
# name is safe (each step is idempotent or explicitly skips with a warning).
#
# Requires: docker, kind, kubectl, helm, go, make on Ubuntu 24.04 (or any
# Linux capable of running kind). No PowerShell — bash only.

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Usage / arg parsing
# ─────────────────────────────────────────────────────────────────────────────

usage() {
  cat <<'EOF'
Usage: hack/quickstart-kind.sh [CLUSTER_NAME] [options]

Stand up a local kind cluster with the PodMotion operator, the
podmotion-demo app, and extra test-workload fixtures installed.

Arguments:
  CLUSTER_NAME            kind cluster name (default: podmotion-quickstart)

Options:
  --cluster-name NAME     same as the positional CLUSTER_NAME argument
  --demo-repo PATH        path to a podmotion-demo checkout (default: the
                           sibling directory "../podmotion-demo" next to
                           this repo's root; override with $PODMOTION_DEMO_REPO
                           too)
  --skip-workloads        skip applying test/e2e/fixtures/{redis,postgres,nginx}
  -h, --help              show this help and exit

Examples:
  hack/quickstart-kind.sh
  hack/quickstart-kind.sh my-cluster --demo-repo /path/to/podmotion-demo
EOF
}

CLUSTER_NAME="podmotion-quickstart"
SKIP_WORKLOADS=false
DEMO_REPO_OVERRIDE=""

# Positional CLUSTER_NAME (only if it doesn't look like a flag).
if [[ $# -gt 0 && "${1:-}" != -* ]]; then
  CLUSTER_NAME="$1"
  shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster-name)
      CLUSTER_NAME="$2"; shift 2 ;;
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
# Paths
# ─────────────────────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_REPO_ROOT="${DEMO_REPO_OVERRIDE:-${PODMOTION_DEMO_REPO:-$(dirname "$REPO_ROOT")/podmotion-demo}}"

KUBECONFIG_FILE="/tmp/${CLUSTER_NAME}.kubeconfig"
KIND_CONFIG_TEMPLATE="${REPO_ROOT}/images/kind/kind-config.yaml"
KIND_CONFIG_GENERATED="/tmp/${CLUSTER_NAME}-kind-config.yaml"
FLANNEL_MANIFEST="${REPO_ROOT}/images/kind/kube-flannel-v0.25.4.yml"

TAG="${CLUSTER_NAME}-quickstart"
KIND_NODE_IMG="podmotion-node:${TAG}"
OPERATOR_IMG="podmotion-operator:${TAG}"
AGENT_IMG="podmotion-agent:${TAG}"
DEMO_WEB_IMG="podmotion-demo-web:${TAG}"
DEMO_API_IMG="podmotion-demo-api:${TAG}"

PODMOTION_NAMESPACE="podmotion-system"
WORKLOADS_NAMESPACE="pm-e2e" # hardcoded in test/e2e/fixtures/*.yaml, see step 11 below

section() {
  echo ""
  echo "════════════════════════════════════════════════════════════════════"
  echo "  $1"
  echo "════════════════════════════════════════════════════════════════════"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Preflight checks
# ─────────────────────────────────────────────────────────────────────────────

section "Step 1/11 — Preflight checks"

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

check_cmd docker   "apt install docker.io  (or https://docs.docker.com/engine/install/ubuntu/)"
check_cmd kind     "go install sigs.k8s.io/kind@latest  (or https://kind.sigs.k8s.io/docs/user/quick-start/#installation)"
check_cmd kubectl  "https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/"
check_cmd helm     "https://helm.sh/docs/intro/install/"
check_cmd go       "https://go.dev/doc/install (this repo targets go $(grep '^go ' "$REPO_ROOT/go.mod" | awk '{print $2}'))"
check_cmd make     "apt install make"

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
# Step 2 — Build operator + agent binaries (linux/amd64, plus arm64)
# ─────────────────────────────────────────────────────────────────────────────

section "Step 2/11 — make build-linux (operator + agent + criu-wrapper + holder binaries)"

cd "$REPO_ROOT"
make build-linux
echo "  [ok] bin/manager-linux-amd64, bin/agent-linux-amd64, bin/criu-wrapper-linux-amd64, bin/holder-linux-amd64 built"

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Build the custom kind node image (CRIU + NRI + bundled agent)
# ─────────────────────────────────────────────────────────────────────────────

section "Step 3/11 — make kind-image (custom kind node image, KIND_NODE_IMG=$KIND_NODE_IMG)"

# images/kind/Dockerfile embeds the just-built agent binary directly into the
# node image (it runs as an NRI plugin, not a separately-loaded pod image) —
# so this step must happen after Step 2 and before cluster creation.
make kind-image KIND_NODE_IMG="$KIND_NODE_IMG"
echo "  [ok] kind node image built: $KIND_NODE_IMG"

# images/kind/kind-config.yaml hardcodes its node `image:` fields to whatever
# tag the last person who edited it was using (currently podmotion-node:sprint53-amd64)
# — this is the documented gotcha from getting-started/page.mdx ("edit
# images/kind/kind-config.yaml to reference podmotion-node:dev"). Rather than
# mutating the tracked file (which would leave the repo dirty and isn't safe
# to run concurrently for two cluster names), generate a scratch copy with
# just the node `image:` and cluster `name:` fields swapped, keeping every
# other field (kubeadmConfigPatches, networking, featureGates) byte-identical.
sed \
  -e "s/^name: .*/name: ${CLUSTER_NAME}/" \
  -e "s/image: podmotion-node:sprint53-amd64/image: ${KIND_NODE_IMG}/" \
  "$KIND_CONFIG_TEMPLATE" > "$KIND_CONFIG_GENERATED"
echo "  [ok] generated kind cluster config: $KIND_CONFIG_GENERATED"

# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Create the kind cluster (idempotent)
# ─────────────────────────────────────────────────────────────────────────────

section "Step 4/11 — kind create cluster (name=$CLUSTER_NAME)"

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "  [skip] kind cluster '$CLUSTER_NAME' already exists — reusing it."
  echo "         (delete it first with 'kind delete cluster --name $CLUSTER_NAME' for a clean rebuild)"
  kind get kubeconfig --name "$CLUSTER_NAME" > "$KUBECONFIG_FILE"
else
  kind create cluster \
    --name "$CLUSTER_NAME" \
    --config "$KIND_CONFIG_GENERATED" \
    --kubeconfig "$KUBECONFIG_FILE"
fi

echo "  [step] Applying Flannel CNI (images/kind/kind-config.yaml sets disableDefaultCNI: true)..."
kubectl --kubeconfig "$KUBECONFIG_FILE" apply -f "$FLANNEL_MANIFEST"
echo "  [step] Waiting for all nodes to be Ready (timeout 120s)..."
kubectl --kubeconfig "$KUBECONFIG_FILE" wait --for=condition=Ready nodes --all --timeout=120s
echo "  [ok] cluster '$CLUSTER_NAME' is up. Kubeconfig: $KUBECONFIG_FILE"

# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — Build + load the operator and agent container images
# ─────────────────────────────────────────────────────────────────────────────

section "Step 5/11 — Build + kind load operator/agent images"

cd "$REPO_ROOT"
docker build -f images/operator/Dockerfile -t "$OPERATOR_IMG" .
docker build -f images/agent/Dockerfile    -t "$AGENT_IMG"    .

kind load docker-image "$OPERATOR_IMG" --name "$CLUSTER_NAME"
kind load docker-image "$AGENT_IMG"    --name "$CLUSTER_NAME"
echo "  [ok] loaded $OPERATOR_IMG and $AGENT_IMG into cluster '$CLUSTER_NAME'"

# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — Apply CRDs
# ─────────────────────────────────────────────────────────────────────────────

section "Step 6/11 — Apply CRDs (config/crd/bases/)"

kubectl --kubeconfig "$KUBECONFIG_FILE" apply -f "$REPO_ROOT/config/crd/bases/"
echo "  [ok] CRDs applied"

# ─────────────────────────────────────────────────────────────────────────────
# Step 7 — mTLS dev certs (required — pods hang on FailedMount without this)
# ─────────────────────────────────────────────────────────────────────────────

section "Step 7/11 — make agent-certs-dev (podmotion-agent-tls / podmotion-operator-agent-client-tls secrets)"

kubectl --kubeconfig "$KUBECONFIG_FILE" create namespace "$PODMOTION_NAMESPACE" \
  --dry-run=client -o yaml | kubectl --kubeconfig "$KUBECONFIG_FILE" apply -f -

KUBECONFIG="$KUBECONFIG_FILE" make -C "$REPO_ROOT" agent-certs-dev
echo "  [ok] agent + operator mTLS secrets created in namespace '$PODMOTION_NAMESPACE'"

# ─────────────────────────────────────────────────────────────────────────────
# Step 8 — Build + load the podmotion-demo images
# ─────────────────────────────────────────────────────────────────────────────

section "Step 8/11 — Build + kind load podmotion-demo images"

cd "$DEMO_REPO_ROOT"
docker build -f deploy/Dockerfile.backend  -t "$DEMO_API_IMG" .
docker build -f deploy/Dockerfile.frontend -t "$DEMO_WEB_IMG" .

kind load docker-image "$DEMO_API_IMG" --name "$CLUSTER_NAME"
kind load docker-image "$DEMO_WEB_IMG" --name "$CLUSTER_NAME"
echo "  [ok] loaded $DEMO_API_IMG and $DEMO_WEB_IMG into cluster '$CLUSTER_NAME'"

# ─────────────────────────────────────────────────────────────────────────────
# Step 9 — helm upgrade --install (operator + podmotion-demo subchart)
# ─────────────────────────────────────────────────────────────────────────────

section "Step 9/11 — helm upgrade --install podmotion (operator + podmotion-demo)"

cd "$REPO_ROOT"
# The podmotion-demo chart is a local file:// dependency of charts/podmotion
# (charts/podmotion/Chart.yaml, condition: podmotion-demo.enabled). Refresh
# the vendored copy so local edits to charts/podmotion-demo are picked up.
helm dependency update charts/podmotion

# agent.apparmorProfile: chart default is "localhost/podmotion-agent" (ADR-0300),
# which requires a real AppArmor LSM on the host to load the profile onto. kind
# nodes run on whatever the Docker host provides, and hosts without AppArmor
# enabled fail the DaemonSet pods ("Cannot enforce AppArmor: AppArmor is not
# enabled on the host", pods stuck in AppArmor/Failed status). values.yaml
# documents agent.apparmorProfile=unconfined as the explicit degraded-but-working
# fallback for exactly this case; the standing podmotion-demo kind cluster
# already runs with this override.
#
# webhook.podMutation.enabled=false: podmotion-coherence-check.yaml (ADR-0359 /
# ADR-0360) fails the render if podMutation is left at its default `true` while
# scheduler.enabled=false — the mutating webhook would bind replacement pods to
# a scheduler that isn't running. Disabling both together is the documented
# full-degradation path (no scheduler pinning, no gate, no IP pins, no node
# binding) and matches hack/kvm-cluster.sh's dev-cluster install.
KUBECONFIG="$KUBECONFIG_FILE" helm upgrade --install podmotion charts/podmotion \
  --namespace "$PODMOTION_NAMESPACE" --create-namespace \
  --set operator.image.repository="podmotion-operator" \
  --set operator.image.tag="$TAG" \
  --set operator.image.pullPolicy=Never \
  --set agent.image.repository="podmotion-agent" \
  --set agent.image.tag="$TAG" \
  --set agent.image.pullPolicy=Never \
  --set agent.apparmorProfile=unconfined \
  --set operator.replicas=1 \
  --set webhook.certManager.enabled=false \
  --set scheduler.enabled=false \
  --set webhook.podMutation.enabled=false \
  --set installCRDs=false \
  --set checkpoint.transferMode="" \
  --set checkpoint.registry.url="" \
  --set podmotion-demo.enabled=true \
  --set podmotion-demo.web.image.repository="podmotion-demo-web" \
  --set podmotion-demo.web.image.tag="$TAG" \
  --set podmotion-demo.web.image.pullPolicy=Never \
  --set podmotion-demo.api.image.repository="podmotion-demo-api" \
  --set podmotion-demo.api.image.tag="$TAG" \
  --set podmotion-demo.api.image.pullPolicy=Never \
  --wait=false

echo "  [ok] helm release 'podmotion' installed/upgraded in namespace '$PODMOTION_NAMESPACE'"

# ─────────────────────────────────────────────────────────────────────────────
# Step 10 — Wait for everything to reach Ready
# ─────────────────────────────────────────────────────────────────────────────

section "Step 10/11 — Waiting for pods to become Ready"

wait_for_namespace_ready() {
  local ns="$1" timeout_s="$2"
  echo "  Waiting up to ${timeout_s}s for pods in namespace '$ns' to be Ready..."
  local deadline=$(( SECONDS + timeout_s ))
  while (( SECONDS < deadline )); do
    if kubectl --kubeconfig "$KUBECONFIG_FILE" get pods -n "$ns" --no-headers 2>/dev/null | grep -q .; then
      if kubectl --kubeconfig "$KUBECONFIG_FILE" wait --for=condition=Ready pods --all \
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
  kubectl --kubeconfig "$KUBECONFIG_FILE" get pods -A >&2
  echo "--- recent events in $PODMOTION_NAMESPACE ---" >&2
  kubectl --kubeconfig "$KUBECONFIG_FILE" get events -n "$PODMOTION_NAMESPACE" \
    --sort-by=.lastTimestamp 2>/dev/null | tail -n 40 >&2
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 11 — Apply extra test-workload fixtures
# ─────────────────────────────────────────────────────────────────────────────

if [[ "$SKIP_WORKLOADS" == "true" ]]; then
  section "Step 11/11 — Skipping extra test workloads (--skip-workloads)"
else
  section "Step 11/11 — Applying extra test workloads (test/e2e/fixtures/)"

  # These fixtures hardcode `namespace: pm-e2e` in their metadata, so the
  # namespace they land in is NOT configurable from this script without
  # rewriting the fixture files themselves — create pm-e2e and apply as-is.
  kubectl --kubeconfig "$KUBECONFIG_FILE" create namespace "$WORKLOADS_NAMESPACE" \
    --dry-run=client -o yaml | kubectl --kubeconfig "$KUBECONFIG_FILE" apply -f -

  kubectl --kubeconfig "$KUBECONFIG_FILE" apply -f "$REPO_ROOT/test/e2e/fixtures/redis.yaml"
  kubectl --kubeconfig "$KUBECONFIG_FILE" apply -f "$REPO_ROOT/test/e2e/fixtures/postgres.yaml"
  kubectl --kubeconfig "$KUBECONFIG_FILE" apply -f "$REPO_ROOT/test/e2e/fixtures/nginx.yaml"

  echo "  [step] Waiting up to 120s for workloads in '$WORKLOADS_NAMESPACE' to be Ready (best-effort)..."
  if ! kubectl --kubeconfig "$KUBECONFIG_FILE" wait --for=condition=Ready pods --all \
       -n "$WORKLOADS_NAMESPACE" --timeout=120s >/dev/null 2>&1; then
    echo "  [warn] not all pods in '$WORKLOADS_NAMESPACE' reached Ready within 120s."
    echo "         (postgres needs a bound PVC — if your kind install has no default"
    echo "         StorageClass this will stay Pending; not fatal to the quickstart.)"
    kubectl --kubeconfig "$KUBECONFIG_FILE" get pods -n "$WORKLOADS_NAMESPACE"
  else
    echo "  [ok] all workloads in '$WORKLOADS_NAMESPACE' are Ready."
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

WEB_SVC="podmotion-demo-web"
JAEGER_SVC="podmotion-demo-jaeger"

section "Done — cluster '$CLUSTER_NAME' is ready"

cat <<EOF

Kubeconfig:
  export KUBECONFIG=$KUBECONFIG_FILE

kind does NOT expose NodePorts to localhost by default, so the most robust
way to reach the demo UI and Jaeger from your machine is kubectl port-forward
(run each in its own terminal, then leave it running):

  # PodMotion demo web UI  -> http://localhost:8080
  KUBECONFIG=$KUBECONFIG_FILE kubectl port-forward -n $PODMOTION_NAMESPACE svc/$WEB_SVC 8080:80

  # Jaeger trace UI        -> http://localhost:16686
  KUBECONFIG=$KUBECONFIG_FILE kubectl port-forward -n $PODMOTION_NAMESPACE svc/$JAEGER_SVC 16686:16686

(The chart also opens NodePort 30080/30686 on every kind node container — reachable via
that container's docker-internal IP, e.g. \`docker inspect ${CLUSTER_NAME}-control-plane
--format '{{.NetworkSettings.Networks.kind.IPAddress}}'\`, but port-forward above is simpler
and works the same way on every machine.)

Run your first migration (see docs-site/app/docs/getting-started/page.mdx, "Your First
Migration" for the full walkthrough):

  cat <<'YAML' | KUBECONFIG=$KUBECONFIG_FILE kubectl apply -f -
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

  KUBECONFIG=$KUBECONFIG_FILE kubectl get podmigration migrate-my-app -o yaml

Extra test workloads (redis/postgres/nginx) are running in namespace: $WORKLOADS_NAMESPACE

Tear down when finished:

  kind delete cluster --name $CLUSTER_NAME
  rm -f $KUBECONFIG_FILE $KIND_CONFIG_GENERATED

EOF
