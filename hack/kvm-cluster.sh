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

# ── Shared RWX storage (NFS re-attach model — same volume on both workers) ────
# Live pod migration re-attaches the SAME persistent volume on the destination
# node (no storage migration); the bytes live on a common NFS pool that pm-w1 and
# pm-w2 both mount identically. NFS server lives on the control-plane VM.
NFS_SERVER_IP="${NFS_SERVER_IP:-}"                          # resolved to CP1 in load_ips-time
NFS_EXPORT_PATH="${NFS_EXPORT_PATH:-/srv/nfs/podmotion}"
NFS_CLIENT_CIDR="${NFS_CLIENT_CIDR:-192.168.122.0/24}"
NFS_STORAGE_CLASS="${NFS_STORAGE_CLASS:-nfs-shared}"
NFS_PROVISIONER_NS="${NFS_PROVISIONER_NS:-nfs-provisioner}"
NFS_PROVISIONER_IMG_TAG="${NFS_PROVISIONER_IMG_TAG:-v4.0.2}"

# Stable VM names — PERMANENT, never destroyed/undefined.
CP_VM="pm-cp1"
WORKER_VMS=("pm-w1" "pm-w2")
PM_VMS=("$CP_VM" "${WORKER_VMS[@]}")

# ── Dedicated block storage + Longhorn ───────────────────────────────────────
# Each VM gets a dedicated 250G virtio disk (target vdb) backing Longhorn, kept
# OFF the 40G root vda. Longhorn provides live-migratable volumes: during a
# PodMotion live migration the volume must attach on the destination node while
# still attached on the source (Longhorn `migratable` volume mode). The disks are
# attached to the standing VMs (non-destructive — attach only, never destroy).
LH_DISK_SIZE="${LH_DISK_SIZE:-250G}"
LH_IMG_DIR="${LH_IMG_DIR:-/var/lib/libvirt/images}"
LH_DISK_TARGET="${LH_DISK_TARGET:-vdb}"          # new disk shows up as /dev/vdb in-guest
LH_MOUNT="${LH_MOUNT:-/var/lib/longhorn}"
LH_VERSION="${LH_VERSION:-v1.9.1}"               # current proven-stable Longhorn tag
LH_MANIFEST="${LH_MANIFEST:-https://raw.githubusercontent.com/longhorn/longhorn/${LH_VERSION}/deploy/longhorn.yaml}"
LH_NAMESPACE="${LH_NAMESPACE:-longhorn-system}"
LH_STORAGE_CLASS="${LH_STORAGE_CLASS:-longhorn}"             # default RWO SC (ships with Longhorn)
LH_MIGRATABLE_SC="${LH_MIGRATABLE_SC:-longhorn-migratable}"  # RWX live-migration SC (created here)

# ── Cilium CNI (eBPF-native, per-endpoint routing) ───────────────────────────
# Cilium replaces Flannel as the CNI. Flannel routes a pod IP by per-node /24
# subnet over VXLAN, so a live-migrated pod that KEEPS its source IP lands on the
# wrong node and cross-node reachability fails. Cilium's per-endpoint /32 routing
# (endpointRoutes.enabled=true + ipcache) makes a preserved pod IP routable to the
# node that actually holds the endpoint — the primitive PodMotion IP-handoff needs.
#
# IPAM=cluster-pool with the EXISTING 10.244.0.0/16 + /24-per-node mask preserves
# the current podCIDRs byte-identically (no kubeadm re-init, no renumbering).
# routingMode=tunnel + geneve wraps every inter-node pod packet in a 192.168.122.x
# outer header — byte-identical traversal to the Flannel VXLAN this substrate has
# already proven (avoids the unproven native-routing chain across the libvirt NAT
# L2). kube-proxy replacement is ON (eBPF service datapath). The Flannel path in
# reset-cluster stays intact as the rollback baseline.
CILIUM_VERSION="${CILIUM_VERSION:-1.17.6}"
CILIUM_CHART_VERSION="${CILIUM_CHART_VERSION:-1.17.6}"
CILIUM_NAMESPACE="${CILIUM_NAMESPACE:-kube-system}"
CILIUM_IMG="${CILIUM_IMG:-quay.io/cilium/cilium:v${CILIUM_VERSION}}"
CILIUM_OPERATOR_IMG="${CILIUM_OPERATOR_IMG:-quay.io/cilium/operator-generic:v${CILIUM_VERSION}}"
CILIUM_APISERVER_HOST="${CILIUM_APISERVER_HOST:-}"   # resolved to CP1_IP at run time
CILIUM_APISERVER_PORT="${CILIUM_APISERVER_PORT:-6443}"


# ── Calico CNI (Tigera Operator, standard iptables/ipvs dataplane) ───────────
# Calico via the Tigera Operator, installed as an ALTERNATIVE CNI candidate
# alongside the existing Cilium path above (this block is purely additive —
# it does not touch any Cilium variable or function). Single non-strict-
# affinity IPPool covering the EXISTING pod CIDR (byte-identical, same
# reasoning as the Cilium block above — no kubeadm re-init, no renumbering),
# VXLAN encapsulation (not IPIP, not pure-BGP) to keep the existing
# VXLAN-FDB link-type-discovery mechanism's assumptions intact
# (internal/agent/network/fdb.go discovers the FDB interface by link type,
# not by a Cilium-specific name, so it does not care which CNI programs the
# VXLAN device). bpfEnabled is explicitly and permanently false: Calico's
# own eBPF dataplane attaches to the same TC clsact hooks PodMotion's
# TC-BPF/XDP bridge needs, with no supported coexistence mechanism — DO NOT
# set this to true, ever, for any performance reason.
CALICO_VERSION="${CALICO_VERSION:-3.28.0}"
CALICO_CHART_VERSION="${CALICO_CHART_VERSION:-$CALICO_VERSION}"
CALICO_OPERATOR_NAMESPACE="${CALICO_OPERATOR_NAMESPACE:-tigera-operator}"
CALICO_NAMESPACE="${CALICO_NAMESPACE:-calico-system}"
# The Tigera Operator versions ITSELF independently of the Calico release it
# ships (confirmed against charts/tigera-operator/values.yaml pinned to the
# projectcalico/calico v3.28.0 tag: tigeraOperator.version there is v1.34.0,
# not v3.28.0). Using CALICO_VERSION for the operator tag produces a
# reference that has never existed on quay.io ("failed to resolve reference
# ...: not found") — this is the actual root cause of the operator
# pre-import failure, not a missing docker-pull step. Keep this pinned
# independently and bump it only alongside CALICO_VERSION, cross-checked
# against that same upstream values.yaml file.
CALICO_OPERATOR_VERSION="${CALICO_OPERATOR_VERSION:-1.34.0}"
CALICO_OPERATOR_IMG="${CALICO_OPERATOR_IMG:-quay.io/tigera/operator:v${CALICO_OPERATOR_VERSION}}"
CALICO_NODE_IMG="${CALICO_NODE_IMG:-docker.io/calico/node:v${CALICO_VERSION}}"
CALICO_KUBE_CONTROLLERS_IMG="${CALICO_KUBE_CONTROLLERS_IMG:-docker.io/calico/kube-controllers:v${CALICO_VERSION}}"
CALICO_CNI_IMG="${CALICO_CNI_IMG:-docker.io/calico/cni:v${CALICO_VERSION}}"
CALICO_CSI_IMG="${CALICO_CSI_IMG:-docker.io/calico/csi:v${CALICO_VERSION}}"
CALICO_CSI_REGISTRAR_IMG="${CALICO_CSI_REGISTRAR_IMG:-docker.io/calico/node-driver-registrar:v${CALICO_VERSION}}"
CALICO_IPPOOL_NAME="${CALICO_IPPOOL_NAME:-default-ipv4-ippool}"

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

  # Post-reset race guard: kubeadm reset disrupts containerd; restart it and wait for the
  # CRI socket to actually serve before init/join, else 'kubeadm init' fails preflight with
  # "containerd.sock: connection refused" (transient, intermittent).
  echo "==> Restarting containerd + waiting for CRI readiness on all nodes (post-reset race guard)..."
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    nsh "$ip" "sudo systemctl restart containerd; for i in \$(seq 1 30); do sudo crictl --runtime-endpoint unix:///run/containerd/containerd.sock info >/dev/null 2>&1 && { echo '  CRI ready on '\$(hostname); break; }; sleep 2; done"
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
  # Stamp images with the git commit they were built from so deployed images can be
  # verified against source provenance. Falls back to "unknown" if git is unavailable.
  local GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  docker build --build-arg GIT_SHA="$GIT_SHA" -f images/operator/Dockerfile -t "$OP_IMG" .
  docker build --build-arg GIT_SHA="$GIT_SHA" -f images/agent/Dockerfile   -t "$AGENT_IMG" .

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
    # A re-deploy within the same sprint reuses the same $TAG (by design — see
    # the TAG provenance note above). `ctr images import` overwriting an
    # already-present tag's digest is undocumented/unverified behavior on this
    # containerd version, and the tag-presence check below only proves the tag
    # string exists, not that it points at the digest we just built (this was
    # confirmed live 2026-07-14: a same-tag re-deploy left a stale binary
    # running despite a clean deploy + rollout restart). Remove the tag first
    # so there is no ambiguity about overwrite semantics — the import that
    # follows is then the ONLY thing that can make the tag resolve.
    nsh "$ip" "sudo ctr -n k8s.io images rm '$OP_IMG' '$AGENT_IMG' >/dev/null 2>&1 || true"
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

  # A re-deploy within the same sprint reuses the same $TAG (see the image
  # import step above), so the rendered Deployment/DaemonSet spec is often
  # byte-identical to what's already applied — helm then sees NO diff and
  # creates no new pods, silently leaving the OLD binary running even though
  # the image tag on the nodes now points at freshly-built content. Force a
  # restart unconditionally so every deploy-podmotion call is guaranteed to
  # produce fresh pods, not just a "diff detected" one (confirmed live
  # 2026-07-14 as the root cause of a stale-binary false-negative gate).
  echo "==> Forcing rollout restart (same-tag deploys are otherwise a silent no-op)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n podmotion-system rollout restart deploy/podmotion-operator ds/podmotion-agent

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

# ── provision-shared-storage: NFS server + clients + dynamic RWX StorageClass ─
# Idempotent. Reproduces:
#   1. NFS server on the control-plane VM exporting $NFS_EXPORT_PATH to the cluster
#      subnet (rw,sync,no_subtree_check,no_root_squash).
#   2. nfs-common on all 3 nodes.
#   3. nfs-subdir-external-provisioner (helm) creating StorageClass
#      "$NFS_STORAGE_CLASS" (RWX, reclaimPolicy Retain) pointed at that export.
# The same RWX PVC then binds a volume that BOTH workers mount identically — the
# re-attach-same-volume model live migration depends on. VMs are never touched.
cmd_provision_shared_storage() {
  assert_no_vm_destruction
  load_ips
  NFS_SERVER_IP="${NFS_SERVER_IP:-$CP1_IP}"
  echo "==> [1/3] NFS server on $CP_VM ($NFS_SERVER_IP), export $NFS_EXPORT_PATH -> $NFS_CLIENT_CIDR ..."
  nsh "$NFS_SERVER_IP" "sudo bash -c '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq nfs-kernel-server >/dev/null
    mkdir -p $NFS_EXPORT_PATH
    chmod 1777 $NFS_EXPORT_PATH
    grep -qF \"$NFS_EXPORT_PATH \" /etc/exports || echo \"$NFS_EXPORT_PATH ${NFS_CLIENT_CIDR}(rw,sync,no_subtree_check,no_root_squash)\" >> /etc/exports
    exportfs -ra
    systemctl enable --now nfs-server >/dev/null 2>&1
    showmount -e localhost
  '"

  echo "==> [2/3] nfs-common on all 3 nodes ..."
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- nfs-common on $ip"
    nsh "$ip" "sudo bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq nfs-common >/dev/null'"
  done

  echo "==> [3/3] nfs-subdir-external-provisioner + StorageClass $NFS_STORAGE_CLASS (RWX, Retain) ..."
  helm repo add nfs-subdir-external-provisioner \
    https://kubernetes-sigs.github.io/nfs-subdir-external-provisioner/ >/dev/null 2>&1 || true
  helm repo update nfs-subdir-external-provisioner >/dev/null 2>&1 || true
  KUBECONFIG="$KUBECONFIG_OUT" helm upgrade --install nfs-subdir-external-provisioner \
    nfs-subdir-external-provisioner/nfs-subdir-external-provisioner \
    --namespace "$NFS_PROVISIONER_NS" --create-namespace \
    --set nfs.server="$NFS_SERVER_IP" \
    --set nfs.path="$NFS_EXPORT_PATH" \
    --set storageClass.name="$NFS_STORAGE_CLASS" \
    --set storageClass.defaultClass=false \
    --set storageClass.reclaimPolicy=Retain \
    --set storageClass.accessModes=ReadWriteMany \
    --set storageClass.archiveOnDelete=true \
    --set image.repository=registry.k8s.io/sig-storage/nfs-subdir-external-provisioner \
    --set image.tag="$NFS_PROVISIONER_IMG_TAG"
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$NFS_PROVISIONER_NS" rollout status \
    deploy/nfs-subdir-external-provisioner --timeout=120s
  echo "==> Shared storage ready. Workloads use an RWX PVC on storageClassName: $NFS_STORAGE_CLASS"
}

# ── provision-longhorn: dedicated 250G disk per node + Longhorn ──────────────
# Idempotent end-to-end: (re)creates+attaches the vdb disk if absent, formats +
# mounts it at $LH_MOUNT with a UUID fstab entry, installs the iSCSI prereq, then
# installs Longhorn and both StorageClasses. Safe to re-run; never destroys a VM.
cmd_provision_longhorn() {
  assert_no_vm_destruction
  load_ips

  echo "==> [1/5] Ensure a $LH_DISK_SIZE $LH_DISK_TARGET disk on each VM (attach only — never destroy)..."
  local vm img
  for vm in "${PM_VMS[@]}"; do
    img="$LH_IMG_DIR/${vm}-longhorn.qcow2"
    if sudo virsh domblklist "$vm" | awk '{print $1}' | grep -qx "$LH_DISK_TARGET"; then
      echo "  -- $vm already has $LH_DISK_TARGET; skipping create+attach"
      continue
    fi
    if ! sudo test -f "$img"; then
      echo "  -- creating $img ($LH_DISK_SIZE)"
      sudo qemu-img create -f qcow2 "$img" "$LH_DISK_SIZE"
      sudo chown libvirt-qemu:kvm "$img"
    fi
    echo "  -- attaching $img to $vm as $LH_DISK_TARGET (persistent + live)"
    sudo virsh attach-disk "$vm" "$img" "$LH_DISK_TARGET" \
      --driver qemu --subdriver qcow2 --targetbus virtio --persistent --live
  done

  echo "==> [2/5] Format + mount /dev/$LH_DISK_TARGET at $LH_MOUNT (UUID fstab) on each node..."
  local ip
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- prep disk on $ip"
    nsh "$ip" "sudo bash -s" <<REMOTE
set -e
DEV=/dev/$LH_DISK_TARGET
MNT=$LH_MOUNT
if ! blkid \$DEV >/dev/null 2>&1; then mkfs.ext4 -q -L longhorn \$DEV; fi
mkdir -p \$MNT
UUID=\$(blkid -s UUID -o value \$DEV)
grep -q "\$UUID" /etc/fstab || echo "UUID=\$UUID \$MNT ext4 defaults 0 2" >> /etc/fstab
mountpoint -q \$MNT || mount \$MNT
df -h \$MNT | tail -1
REMOTE
  done

  echo "==> [3/5] Longhorn iSCSI prereq (open-iscsi + iscsid) on each node..."
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- iscsi prereq on $ip"
    nsh "$ip" "sudo bash -c 'export DEBIAN_FRONTEND=noninteractive; dpkg -l open-iscsi 2>/dev/null | grep -q \"^ii\" || { apt-get update -qq && apt-get install -y -qq open-iscsi >/dev/null; }; systemctl enable --now iscsid >/dev/null 2>&1; systemctl is-active iscsid'"
  done

  echo "==> [4/5] Install Longhorn $LH_VERSION and wait for pods Ready..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f "$LH_MANIFEST"
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" rollout status ds/longhorn-manager --timeout=300s
  # Let Longhorn also use the control-plane node's disk: tolerate the cp taint and
  # add the toleration to the longhorn-manager DaemonSet (the setting alone does not
  # patch the manager DS). Idempotent.
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" patch setting taint-toleration \
    --type=merge -p '{"value":"node-role.kubernetes.io/control-plane:NoSchedule"}' || true
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" patch ds longhorn-manager --type=json \
    -p '[{"op":"add","path":"/spec/template/spec/tolerations","value":[{"key":"node-role.kubernetes.io/control-plane","operator":"Exists","effect":"NoSchedule"}]}]' || true
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" rollout status ds/longhorn-manager --timeout=300s
  echo "  -- waiting for all longhorn-system pods Ready"
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" wait --for=condition=Ready pods --all --timeout=300s || true

  echo "==> [5/5] Ensure StorageClasses ($LH_STORAGE_CLASS default RWO; $LH_MIGRATABLE_SC RWX live-migration)..."
  # The default $LH_STORAGE_CLASS SC ships with the Longhorn manifest. Create the
  # RWX live-migration SC: migratable=true lets the volume attach on the destination
  # node while still attached on the source during a PodMotion live migration.
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

  echo "==> Longhorn ready. Per-node schedulable capacity:"
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" get nodes.longhorn.io
  echo "==> Workloads: use storageClassName: $LH_STORAGE_CLASS (RWO) or $LH_MIGRATABLE_SC (RWX, live-migratable)."
}

# ── provision-cilium: pre-import Cilium images → helm install → status --wait ──
# Idempotent. Installs Cilium as the CNI with the IP-preservation primitive PodMotion
# needs (per-endpoint /32 routing + ipcache), preserving the existing pod CIDR
# (10.244.0.0/16, /24 per node) via cluster-pool IPAM — no kubeadm re-init, no
# renumbering. routingMode=tunnel/geneve gives proven-traversable inter-node encap on
# this libvirt NAT L2; kube-proxy replacement is ON. Images are pre-imported into each
# node's k8s.io containerd namespace (no-registry idiom, same as deploy-podmotion) so a
# stalled pull cannot leave the cluster CNI-less. This does NOT remove Flannel or
# kube-proxy — the operator performs the ordered, recoverable cutover on the live
# cluster; reset-cluster's Flannel path stays the rollback baseline. VMs never touched.
cmd_provision_cilium() {
  assert_no_vm_destruction
  load_ips
  CILIUM_APISERVER_HOST="${CILIUM_APISERVER_HOST:-$CP1_IP}"

  echo "==> [1/3] Pre-importing Cilium images into each node's k8s.io containerd namespace (no registry)..."
  # Pre-import is MANDATORY: removing Flannel before the Cilium images are resident on
  # every node would leave the cluster with no CNI while pods pull — so pull to the
  # host, docker save, and import per node, verifying each tag landed before install.
  local ip
  for img in "$CILIUM_IMG" "$CILIUM_OPERATOR_IMG"; do
    echo "  -- ensure $img present on host"
    docker image inspect "$img" >/dev/null 2>&1 || docker pull "$img"
  done
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- import into $ip"
    docker save "$CILIUM_IMG"          | nsh "$ip" "sudo ctr -n k8s.io images import -"
    docker save "$CILIUM_OPERATOR_IMG" | nsh "$ip" "sudo ctr -n k8s.io images import -"
    if ! nsh "$ip" "sudo ctr -n k8s.io images ls -q | grep -q 'cilium:v${CILIUM_VERSION}'"; then
      echo "ERROR: cilium:v${CILIUM_VERSION} not present in k8s.io containerd namespace on node $ip after import." >&2
      exit 1
    fi
    if ! nsh "$ip" "sudo ctr -n k8s.io images ls -q | grep -q 'operator-generic:v${CILIUM_VERSION}'"; then
      echo "ERROR: operator-generic:v${CILIUM_VERSION} not present in k8s.io containerd namespace on node $ip after import." >&2
      exit 1
    fi
  done

  echo "==> [2/3] helm install cilium/cilium $CILIUM_CHART_VERSION (cluster-pool + tunnel/geneve + kube-proxy-replacement)..."
  helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
  helm repo update cilium >/dev/null 2>&1 || true
  # cluster-pool IPAM with the EXISTING /16 + /24 mask = byte-identical podCIDRs.
  # tunnel/geneve = proven inter-node encap; kubeProxyReplacement + k8sServiceHost/Port
  # (apiserver reachable before the eBPF service map is programmed); bpf.masquerade with
  # ipv4NativeRoutingCIDR = pod CIDR excluded from SNAT so pod<->pod keeps its real
  # source IP (essential for TCP/IP preservation). pullPolicy IfNotPresent picks up the
  # pre-imported images. This is upgrade --install so re-running is safe.
  KUBECONFIG="$KUBECONFIG_OUT" helm upgrade --install cilium cilium/cilium \
    --version "$CILIUM_CHART_VERSION" --namespace "$CILIUM_NAMESPACE" \
    --set ipam.mode=cluster-pool \
    --set ipam.operator.clusterPoolIPv4PodCIDRList="{$POD_CIDR}" \
    --set ipam.operator.clusterPoolIPv4MaskSize=24 \
    --set routingMode=tunnel \
    --set tunnelProtocol=geneve \
    --set endpointRoutes.enabled=true \
    --set kubeProxyReplacement=true \
    --set k8sServiceHost="$CILIUM_APISERVER_HOST" \
    --set k8sServicePort="$CILIUM_APISERVER_PORT" \
    --set bpf.masquerade=true \
    --set enableIPv4Masquerade=true \
    --set ipv4NativeRoutingCIDR="$POD_CIDR" \
    --set image.pullPolicy=IfNotPresent \
    --set operator.image.pullPolicy=IfNotPresent \
    --set operator.replicas=1

  echo "==> [3/3] Waiting for Cilium to come up (cilium status --wait)..."
  if command -v cilium >/dev/null 2>&1; then
    KUBECONFIG="$KUBECONFIG_OUT" cilium status --wait
  else
    echo "  -- cilium-cli not on PATH; waiting on the DaemonSet/Deployment rollout instead"
    KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CILIUM_NAMESPACE" rollout status ds/cilium --timeout=300s
    KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CILIUM_NAMESPACE" rollout status deploy/cilium-operator --timeout=300s
  fi
  echo "==> Cilium ready. CNI swap done at the install layer; run the cutover to remove Flannel/kube-proxy."
}

# ── multi-pool IPAM re-provision (ADR-0324 P-VERIFY-C escalation) ──
# cluster-pool IPAM binds each node's pod CIDR to that node only, so the
# ipam.cilium.io/ip pinning annotation used by CiliumHandoff.AnnotateDestPodIPAM
# to preserve a source pod's IP on a DIFFERENT destination node can never be
# honored (confirmed negative by TestCrossNodeReachability). multi-pool IPAM
# with per-node CiliumPodIPPool CRs lets an IP from ANY pool be requested on
# ANY node, which is required for cross-node IP preservation. This is the
# re-provision step the ADR-0324 escalation path calls for. Idempotent
# (helm upgrade --install + kubectl apply), safe to re-run. VMs never touched.
cmd_provision_cilium_multipool() {
  assert_no_vm_destruction
  load_ips
  CILIUM_APISERVER_HOST="${CILIUM_APISERVER_HOST:-$CP1_IP}"

  echo "==> [1/3] Switching Cilium IPAM mode: cluster-pool -> multi-pool..."
  helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
  helm repo update cilium >/dev/null 2>&1 || true
  KUBECONFIG="$KUBECONFIG_OUT" helm upgrade --install cilium cilium/cilium \
    --version "$CILIUM_CHART_VERSION" --namespace "$CILIUM_NAMESPACE" \
    --set ipam.mode=multi-pool \
    --set routingMode=tunnel \
    --set tunnelProtocol=geneve \
    --set endpointRoutes.enabled=true \
    --set kubeProxyReplacement=true \
    --set k8sServiceHost="$CILIUM_APISERVER_HOST" \
    --set k8sServicePort="$CILIUM_APISERVER_PORT" \
    --set bpf.masquerade=true \
    --set enableIPv4Masquerade=true \
    --set ipv4NativeRoutingCIDR="$POD_CIDR" \
    --set image.pullPolicy=IfNotPresent \
    --set operator.image.pullPolicy=IfNotPresent \
    --set operator.replicas=1

  echo "==> [2/3] Applying CiliumPodIPPool CRs (one /24 pool per node, same CIDRs as before)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f - <<'EOF'
apiVersion: cilium.io/v2alpha1
kind: CiliumPodIPPool
metadata:
  name: pm-cp1-pool
spec:
  ipv4:
    cidrs:
      - 10.244.0.0/24
    maskSize: 24
---
apiVersion: cilium.io/v2alpha1
kind: CiliumPodIPPool
metadata:
  name: pm-w1-pool
spec:
  ipv4:
    cidrs:
      - 10.244.1.0/24
    maskSize: 24
---
apiVersion: cilium.io/v2alpha1
kind: CiliumPodIPPool
metadata:
  name: pm-w2-pool
spec:
  ipv4:
    cidrs:
      - 10.244.2.0/24
    maskSize: 24
EOF

  echo "==> [3/3] Waiting for Cilium to come up (cilium status --wait)..."
  if command -v cilium >/dev/null 2>&1; then
    KUBECONFIG="$KUBECONFIG_OUT" cilium status --wait
  else
    echo "  -- cilium-cli not on PATH; waiting on the DaemonSet/Deployment rollout instead"
    KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CILIUM_NAMESPACE" rollout status ds/cilium --timeout=300s
    KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CILIUM_NAMESPACE" rollout status deploy/cilium-operator --timeout=300s
  fi
  echo "==> Cilium now in multi-pool IPAM mode with per-node CiliumPodIPPool CRs."
  echo "==> Re-run TestCrossNodeReachability (PODMOTION_CILIUM_LIVE_TEST=1) to confirm the ipam.cilium.io/ip pin now honors cross-node placement."
}

# ── provision-calico: pre-import Tigera Operator/Calico images → helm install
#    operator → apply Installation CR → wait for rollout ────────────────────
# Idempotent. Installs Calico (via the Tigera Operator Helm chart) as an
# ALTERNATIVE CNI candidate on this cluster. Mirrors cmd_provision_cilium's
# 3-step shape (pre-import → install → wait) but the install phase is itself
# two-phase: helm install the operator, then apply the Installation CR the
# operator reconciles into the actual calico-node/kube-controllers workloads.
# Preserves the existing pod CIDR (10.244.0.0/16) byte-identically via a
# SINGLE non-strict-affinity IPPool (no per-node nodeSelector — default IPAM,
# not the per-node-pool escalation cmd_provision_cilium_multipool exists to
# work around; only build that variant later if cross-node IP pinning proves
# unreliable under Calico's default IPAM). Encapsulation is VXLAN (matches
# the existing VXLAN-FDB link-type-discovery mechanism's assumptions — see
# internal/agent/network/fdb.go, which discovers the FDB interface by link
# type and does not care which CNI programs it). Images are pre-imported
# into each node's k8s.io containerd namespace (no-registry idiom, same as
# cmd_provision_cilium) so a stalled pull cannot leave the cluster CNI-less.
# This does NOT remove Flannel/Cilium/kube-proxy — cmd_cutover_calico
# performs the ordered, recoverable cutover afterward. Does NOT modify
# cmd_provision_cilium, cmd_provision_cilium_multipool, or cmd_reset_cluster
# in any way — purely additive. VMs never touched.
cmd_provision_calico() {
  assert_no_vm_destruction
  load_ips

  echo "==> [1/3] Pre-importing Tigera Operator + Calico images into each node's k8s.io containerd namespace (no registry)..."
  # Pre-import is MANDATORY, same reasoning as cmd_provision_cilium: removing
  # the currently-active CNI before every Calico image is resident on every
  # node would leave the cluster with no CNI while pods pull.
  local ip
  for img in "$CALICO_OPERATOR_IMG" "$CALICO_NODE_IMG" "$CALICO_KUBE_CONTROLLERS_IMG" \
             "$CALICO_CNI_IMG" "$CALICO_CSI_IMG" "$CALICO_CSI_REGISTRAR_IMG"; do
    echo "  -- ensure $img present on host"
    docker image inspect "$img" >/dev/null 2>&1 || docker pull "$img"
  done
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- import into $ip"
    for img in "$CALICO_OPERATOR_IMG" "$CALICO_NODE_IMG" "$CALICO_KUBE_CONTROLLERS_IMG" \
               "$CALICO_CNI_IMG" "$CALICO_CSI_IMG" "$CALICO_CSI_REGISTRAR_IMG"; do
      docker save "$img" | nsh "$ip" "sudo ctr -n k8s.io images import -"
    done
    for tag in "operator:v${CALICO_OPERATOR_VERSION}" "node:v${CALICO_VERSION}" \
               "kube-controllers:v${CALICO_VERSION}" "cni:v${CALICO_VERSION}" \
               "csi:v${CALICO_VERSION}" "node-driver-registrar:v${CALICO_VERSION}"; do
      if ! nsh "$ip" "sudo ctr -n k8s.io images ls -q | grep -q '${tag}'"; then
        echo "ERROR: ${tag} not present in k8s.io containerd namespace on node $ip after import." >&2
        exit 1
      fi
    done
  done

  echo "==> [2/3] helm install the Tigera Operator, then apply the Installation CR (single non-strict-affinity IPPool, VXLAN, bpfEnabled=false)..."
  helm repo add projectcalico https://docs.tigera.io/calico/charts >/dev/null 2>&1 || true
  helm repo update projectcalico >/dev/null 2>&1 || true
  KUBECONFIG="$KUBECONFIG_OUT" helm upgrade --install calico projectcalico/tigera-operator \
    --version "$CALICO_CHART_VERSION" \
    --namespace "$CALICO_OPERATOR_NAMESPACE" --create-namespace \
    --set installation.enabled=false \
    --set tigeraOperator.image=tigera/operator \
    --set tigeraOperator.version="v${CALICO_OPERATOR_VERSION}" \
    --set tigeraOperator.imagePullPolicy=IfNotPresent

  # Installation CR: single pool, non-strict-affinity (no nodeSelector), VXLAN
  # encapsulation, EXISTING pod CIDR preserved byte-identically. bpfEnabled is
  # explicitly false — SAFETY-CRITICAL, see the header comment on the Calico
  # variable block above. Do not "helpfully" flip this to true for
  # kube-proxy-replacement performance: it puts Calico's own TC-BPF programs
  # in direct, unresolved conflict with PodMotion's zero-window hold and XDP
  # bridge (internal/agent/network/bridge.go CheckXDPHookConflict, bpf/xdp_bridge.c,
  # bpf/zero_window.c).
  KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f - <<YAML
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  cni:
    type: Calico
  calicoNetwork:
    bgp: Disabled
    ipPools:
      - name: $CALICO_IPPOOL_NAME
        cidr: $POD_CIDR
        encapsulation: VXLAN
        natOutgoing: Enabled
        nodeSelector: all()
    # bpfEnabled deliberately OMITTED/false — Calico stays on the standard
    # iptables/ipvs dataplane. NEVER set this to true (see header comment).
YAML

  echo "==> [3/3] Waiting for Calico to come up (rollout status on calico-node / calico-kube-controllers)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CALICO_NAMESPACE" rollout status ds/calico-node --timeout=300s
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CALICO_NAMESPACE" rollout status deploy/calico-kube-controllers --timeout=300s
  echo "==> Calico ready. CNI swap done at the install layer; run cutover-calico to remove the previously-active CNI."
}

# ── cutover-calico: remove the previously-active CNI after Calico is confirmed
#    live, never leaving a window with no active CNI ─────────────────────────
# Mirrors cmd_cutover's discipline exactly, generalized to whichever CNI was
# active before Calico: verifies calico-node is Ready on all nodes FIRST
# (refuses to remove anything if Calico is not confirmed live — that would
# leave the cluster with no CNI), then removes Flannel remnants (if present),
# Cilium remnants (if present — DaemonSet/namespace, NOT the Cilium code
# paths in this script, which are left untouched), and kube-proxy (Calico's
# standard dataplane needs kube-proxy, so kube-proxy is NOT removed here —
# unlike the Cilium cutover, which supersedes it). Finally confirms each
# node's /etc/cni/net.d contains exactly the Calico conflist as the active
# config. Idempotent and safe to re-run. Does NOT modify cmd_cutover,
# cmd_provision_cilium, cmd_provision_cilium_multipool, or cmd_reset_cluster.
# VMs never touched.
cmd_cutover_calico() {
  assert_no_vm_destruction
  load_ips

  echo "==> [1/3] Confirming Calico is Ready on all nodes before removing the previously-active CNI..."
  local ready desired
  ready=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CALICO_NAMESPACE" get ds calico-node -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)
  desired=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CALICO_NAMESPACE" get ds calico-node -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo -1)
  if [[ "$ready" -lt 1 || "$ready" != "$desired" ]]; then
    echo "ERROR: calico-node DaemonSet not fully Ready ($ready/$desired) — refusing to remove the previously-active CNI (cluster would be left with no CNI)." >&2
    exit 1
  fi
  echo "  -- calico-node DaemonSet Ready: $ready/$desired"

  echo "==> [2/3] Removing the previously-active CNI's remnants (Flannel and/or Cilium, whichever is present)..."
  if KUBECONFIG="$KUBECONFIG_OUT" kubectl get ns kube-flannel >/dev/null 2>&1; then
    echo "  -- removing Flannel remnants"
    KUBECONFIG="$KUBECONFIG_OUT" kubectl -n kube-flannel delete daemonset kube-flannel-ds --ignore-not-found
    KUBECONFIG="$KUBECONFIG_OUT" kubectl delete ns kube-flannel --ignore-not-found
  else
    echo "  -- no kube-flannel namespace present"
  fi
  if KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CILIUM_NAMESPACE" get ds cilium >/dev/null 2>&1; then
    echo "  -- removing Cilium remnants (DaemonSet/Deployment only — Cilium script functions in this file are untouched)"
    KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CILIUM_NAMESPACE" delete daemonset cilium --ignore-not-found
    KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CILIUM_NAMESPACE" delete deployment cilium-operator --ignore-not-found
  else
    echo "  -- no active Cilium DaemonSet present"
  fi

  echo "==> [3/3] Verifying each node's CNI conf dir contains only the Calico conflist..."
  local ip confs
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    confs=$(nsh "$ip" "sudo ls /etc/cni/net.d/" 2>/dev/null || echo "UNKNOWN")
    echo "  -- $ip: $confs"
    # Only files with a kubelet-recognized CNI extension are ever read by the
    # CNI plugin manager — same discipline as cmd_cutover's flannel check,
    # generalized to also reject a leftover active flannel or cilium conflist.
    if echo "$confs" | grep -Ei '\.(conf|conflist|json)$' | grep -qiE 'flannel|cilium'; then
      echo "ERROR: node $ip still has an ACTIVE non-Calico CNI conflist present after cutover." >&2
      exit 1
    fi
    if ! echo "$confs" | grep -Ei '\.(conf|conflist|json)$' | grep -qi calico; then
      echo "ERROR: node $ip has no active Calico conflist present after cutover." >&2
      exit 1
    fi
  done
  echo "==> Cutover complete: previously-active CNI removed (or already absent), Calico sole CNI-of-record on all nodes."
}

# ── cutover: remove Flannel/kube-proxy remnants after Cilium is confirmed live ──
# Authored artifact for the Flannel→Cilium CNI cutover step (ADR-0322/ADR-0318
# P-VERIFY-B / P-VERIFY-0 precondition). Idempotent and order-safe: verifies Cilium
# is Ready on all 3 nodes FIRST (refuses to remove Flannel/kube-proxy if Cilium is not
# confirmed live — that would leave the cluster with no CNI), then removes the
# kube-flannel DaemonSet/namespace and kube-proxy DaemonSet/configmap if present, and
# confirms each node's /etc/cni/net.d contains only the Cilium conflist. On this
# standing cluster the install-layer swap (cmd_provision_cilium, cluster-pool IPAM,
# kube-proxy-replacement) already left no Flannel pods and no kube-proxy DaemonSet —
# this command makes that outcome an explicit, re-runnable, checked step rather than
# an implicit side effect, and is safe to re-run (no-ops cleanly when nothing is left
# to remove). VMs never touched.
cmd_cutover() {
  assert_no_vm_destruction
  load_ips

  echo "==> [1/3] Confirming Cilium is Ready on all nodes before removing Flannel/kube-proxy..."
  local ready
  ready=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CILIUM_NAMESPACE" get ds cilium -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)
  local desired
  desired=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CILIUM_NAMESPACE" get ds cilium -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo -1)
  if [[ "$ready" -lt 1 || "$ready" != "$desired" ]]; then
    echo "ERROR: Cilium DaemonSet not fully Ready ($ready/$desired) — refusing to remove Flannel/kube-proxy (cluster would be left with no CNI)." >&2
    exit 1
  fi
  echo "  -- cilium DaemonSet Ready: $ready/$desired"

  echo "==> [2/3] Removing Flannel remnants (if any)..."
  if KUBECONFIG="$KUBECONFIG_OUT" kubectl get ns kube-flannel >/dev/null 2>&1; then
    KUBECONFIG="$KUBECONFIG_OUT" kubectl -n kube-flannel delete daemonset kube-flannel-ds --ignore-not-found
    KUBECONFIG="$KUBECONFIG_OUT" kubectl delete ns kube-flannel --ignore-not-found
  else
    echo "  -- no kube-flannel namespace present (already clean)"
  fi

  echo "==> [3/3] Removing kube-proxy remnants (if any — Cilium kubeProxyReplacement=true supersedes it)..."
  if KUBECONFIG="$KUBECONFIG_OUT" kubectl -n kube-system get ds kube-proxy >/dev/null 2>&1; then
    KUBECONFIG="$KUBECONFIG_OUT" kubectl -n kube-system delete daemonset kube-proxy --ignore-not-found
    KUBECONFIG="$KUBECONFIG_OUT" kubectl -n kube-system delete configmap kube-proxy --ignore-not-found
  else
    echo "  -- no kube-proxy DaemonSet present (already clean)"
  fi

  echo "==> Verifying each node's CNI conf dir contains only the Cilium conflist..."
  local ip
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    local confs
    confs=$(nsh "$ip" "sudo ls /etc/cni/net.d/" 2>/dev/null || echo "UNKNOWN")
    echo "  -- $ip: $confs"
    # Only files with a kubelet-recognized CNI extension (.conf/.conflist/.json) are
    # ever read by the CNI plugin manager to select the active network. Cilium's own
    # install-cni step disables the old Flannel config by renaming it to a
    # *.cilium_bak suffix rather than deleting it (kept as a rollback artifact) — that
    # rename IS the authoritative "inactive" marker, so a substring match on the
    # filename false-positives on it. Check only the extensions kubelet actually scans.
    if echo "$confs" | grep -Ei '\.(conf|conflist|json)$' | grep -qi flannel; then
      echo "ERROR: node $ip still has an ACTIVE flannel CNI conflist present after cutover." >&2
      exit 1
    fi
  done
  echo "==> Cutover complete: Flannel/kube-proxy removed (or already absent), Cilium sole CNI-of-record on all nodes."
}

usage() {
  cat >&2 <<EOF
Usage: hack/kvm-cluster.sh <verify|reset-cluster|deploy-podmotion|provision-shared-storage|provision-longhorn|provision-cilium|cutover|provision-calico|cutover-calico|wipe|ssh <node-ip> [cmd]>

  verify            assert 3 nodes Ready via $KUBECONFIG_OUT
  reset-cluster     kubeadm reset+reinit+flannel+join ON the standing VMs (NEVER destroys VMs)
  deploy-podmotion  build+import images, mint mTLS, apply CRDs, helm install (TAG=<tag>)
  provision-shared-storage  NFS server on cp + nfs-common on all + RWX StorageClass $NFS_STORAGE_CLASS
  provision-longhorn  attach $LH_DISK_SIZE $LH_DISK_TARGET per node + Longhorn + SCs ($LH_STORAGE_CLASS, $LH_MIGRATABLE_SC)
  provision-cilium  pre-import Cilium images + helm install cilium/cilium $CILIUM_CHART_VERSION (cluster-pool/geneve/kube-proxy-replacement)
  cutover           Flannel→Cilium CNI cutover: verify Cilium Ready, remove Flannel/kube-proxy remnants
  provision-calico  pre-import Tigera Operator/Calico images + helm install operator + apply Installation CR (single non-strict-affinity IPPool, VXLAN, bpfEnabled=false)
  cutover-calico    previously-active-CNI→Calico cutover: verify Calico Ready, remove Flannel/Cilium remnants
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
    provision-shared-storage) cmd_provision_shared_storage ;;
    provision-longhorn) cmd_provision_longhorn ;;
    provision-cilium) cmd_provision_cilium ;;
    provision-cilium-multipool) cmd_provision_cilium_multipool ;;
    cutover)          cmd_cutover ;;
    provision-calico) cmd_provision_calico ;;
    cutover-calico)   cmd_cutover_calico ;;
    wipe)             cmd_wipe ;;
    ssh)              load_ips; nsh "$@" ;;
    *)                usage ;;
  esac
}
main "$@"
