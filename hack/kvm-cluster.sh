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
KVM_DIR="${KVM_DIR:-$HOME/podmotion-kvm}"
SSH_KEY="${SSH_KEY:-$KVM_DIR/id_pmkvm}"
HOSTS_ENV="${HOSTS_ENV:-$KVM_DIR/hosts.env}"
KUBECONFIG_OUT="${KUBECONFIG_OUT:-$KVM_DIR/kubeconfig}"
KVM_CONTEXT="${KVM_CONTEXT:-default}"          # standing KVM cluster's kubeconfig context — pin explicitly so a drifted current-context (e.g. a stray kind context) never silently redirects cluster-mutating commands
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
# /var/lib/libvirt/images is 711 root:root — chad cannot write there without
# sudo, even though chad's own libvirt-group membership already grants full
# virsh access to the running VMs (libvirtd runs as root and applies
# dynamic_ownership at attach time, so the source image file does not need to
# be pre-owned by libvirt-qemu). Using a directory chad already owns removes
# the only genuine need for local sudo in this script (confirmed live
# 2026-07-17 — see require_local_sudo()'s history in git log for the prior,
# now-unnecessary, workaround).
LH_IMG_DIR="${LH_IMG_DIR:-$KVM_DIR/longhorn-disks}"
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

# ── CNI leftover-residue registry ────────────────────────────────────────────
# One row per CNI this project's matrix actually supports (Flannel/Cilium/Calico
# per CLAUDE.md), used by cmd_reset_cluster's post-reset purge below. Each row is
# "name|iface_prefixes(space-sep, glob-safe)|iptables_jump_or_chain_regex". A
# future 4th CNI (or a Calico/Cilium version that adds a new interface/chain
# prefix) is a one-line addition here, not a hand-edit of two separate embedded
# shell blocks (confirmed live 2026-07-17: a hardcoded two-CNI list is exactly
# the class of bug that silently repeats when a 3rd/4th CNI is added).
#
# Flannel is intentionally NOT a row: cni0/flannel.1 are the CURRENT/target
# CNI's own interfaces in the reset-TO-Flannel path, not residue from a prior
# CNI — adding it here would delete the interface the cluster is being reset
# INTO. Flannel also installs no custom iptables chains (kube-proxy owns NAT).
CNI_LEFTOVER_REGISTRY=(
  "cilium|cilium_host cilium_net cilium_geneve|CILIUM"
  "calico|vxlan.calico|cali-"
)

# ── k3s (alternative reset-cluster mode, sprint50 k3s compat plan §1) ────────
# k3s ships its own embedded containerd at different host paths than
# kubeadm/standard-containerd (UNVERIFIED-EXTERNAL — not confirmed against a
# live k3s node this round). K3S_CONTAINERD_SOCKET/K3S_CONTAINERD_STATE_DIR
# below are the values a k3s deploy passes to the Helm chart
# (agent.containerd.socketPath / agent.containerd.stateDir — see
# charts/podmotion/values.yaml) and to CONTAINERD_ADDRESS for
# cmd_deploy_podmotion's own `ctr` calls. Override any of these if a real k3s
# install turns out to use a different layout than the UNVERIFIED-EXTERNAL
# defaults below.
K3S_VERSION="${K3S_VERSION:-}"                 # empty = get.k3s.io installs its current stable channel
K3S_INSTALL_EXTRA_ARGS="${K3S_INSTALL_EXTRA_ARGS:-}"   # e.g. "--flannel-backend=none" for Track B (CNI swap)
K3S_TOKEN_FILE="${K3S_TOKEN_FILE:-/var/lib/rancher/k3s/server/node-token}"
K3S_KUBECONFIG_PATH="${K3S_KUBECONFIG_PATH:-/etc/rancher/k3s/k3s.yaml}"
K3S_CONTAINERD_SOCKET="${K3S_CONTAINERD_SOCKET:-/run/k3s/containerd/containerd.sock}"
K3S_CONTAINERD_STATE_DIR="${K3S_CONTAINERD_STATE_DIR:-/var/lib/rancher/k3s/agent/containerd}"

# ── RKE2 (sprint51, alternative reset-cluster mode, sibling of k3s above) ────
# RKE2 ("Rancher Kubernetes Engine 2") is a DIFFERENT distribution from k3s, not
# a variant of it: separate server/agent binaries (rke2), its own install
# script (get.rke2.io, not get.k3s.io), separate systemd units
# (rke2-server.service / rke2-agent.service, not k3s.service/k3s-agent.service),
# its own config mechanism (/etc/rancher/rke2/config.yaml, read by the systemd
# unit at start — RKE2 does NOT take an INSTALL_*_EXEC inline-flags idiom the
# way k3s's installer does), its own embedded containerd under
# /var/lib/rancher/rke2/, and — per docs.rke2.io/reference/server_config
# (fetched live this round, not from training-data memory) — its own default
# CNI: "canal" (a Flannel dataplane + Calico policy-only hybrid), not k3s's
# embedded Flannel. RKE2_CONTAINERD_SOCKET/RKE2_CONTAINERD_STATE_DIR/RKE2_CNI_CONF_DIR below
# were CONFIRMED LIVE against a real RKE2 v1.35.6+rke2r1 node this round (sprint51-rke2,
# pm-cp1/pm-w1/pm-w2), superseding the earlier guessed values:
#   - containerd socket + task-bundle "state" tree: RKE2's containerd config.toml sets
#     state = "/run/k3s/containerd" — RKE2 reuses the EXACT SAME /run/k3s/containerd path
#     k3s uses (both are Rancher's embedded-containerd packaging), confirmed by the running
#     shim/runc processes' --address and --bundle paths. containerd's "root" (persistent
#     image/snapshot store, NOT the runtime task-bundle dir the criu-dump.log fix cares
#     about) is the RKE2-specific /var/lib/rancher/rke2/agent/containerd, but that is not
#     what RKE2_CONTAINERD_STATE_DIR needs to be — the task-bundle/work dir (where runc
#     writes criu-dump.log) lives directly under the run root, so STATE_DIR = same value
#     as SOCKET's directory, matching k3s's already-shipped override exactly. No new Go
#     code path or third distinct value was needed here.
#   - CNI conf dir: RKE2 writes its canal conflist straight to the CANONICAL
#     /etc/cni/net.d/10-canal.conflist — unlike k3s (which writes under
#     /var/lib/rancher/k3s/agent/etc/cni/net.d and needs the extraConfDir override),
#     RKE2 needs NO extraConfDir override at all; nmcregistrar's existing default scan of
#     /etc/cni/net.d already finds it. RKE2_CNI_CONF_DIR is kept as an override knob for
#     completeness but defaults to empty (no extra dir) to reflect this.
RKE2_VERSION="${RKE2_VERSION:-}"                 # empty = get.rke2.io installs the current stable channel
RKE2_CNI="${RKE2_CNI:-}"                          # empty = RKE2's own default (canal) — this sprint's scope is proving RKE2 on its OWN default CNI, not a CNI swap
RKE2_INSTALL_EXTRA_ARGS="${RKE2_INSTALL_EXTRA_ARGS:-}"
RKE2_SUPERVISOR_PORT="${RKE2_SUPERVISOR_PORT:-9345}"   # RKE2 agents join the supervisor API on 9345, NOT the k8s API's 6443
RKE2_TOKEN_FILE="${RKE2_TOKEN_FILE:-/var/lib/rancher/rke2/server/node-token}"
RKE2_KUBECONFIG_PATH="${RKE2_KUBECONFIG_PATH:-/etc/rancher/rke2/rke2.yaml}"
RKE2_DATA_DIR="${RKE2_DATA_DIR:-/var/lib/rancher/rke2}"
RKE2_CONTAINERD_SOCKET="${RKE2_CONTAINERD_SOCKET:-/run/k3s/containerd/containerd.sock}"       # CONFIRMED LIVE 2026-07 against RKE2 v1.35.6+rke2r1
RKE2_CONTAINERD_STATE_DIR="${RKE2_CONTAINERD_STATE_DIR:-/run/k3s/containerd}"                 # CONFIRMED LIVE — same run root as the socket, NOT /var/lib/rancher/rke2/agent/containerd (that's containerd's image/snapshot "root", not the task-bundle/work dir)
RKE2_CNI_CONF_DIR="${RKE2_CNI_CONF_DIR:-}"                                                     # CONFIRMED LIVE — RKE2 writes to canonical /etc/cni/net.d already; no extra scan dir needed

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ── Demo/test apps wired into the standard deploy flow ──────────────────────
# podmotion-demo (C&C/observability portal) and migration-demo-stack
# (nginx/redis/postgres test workload) each live in their own sibling
# checkout next to this repo, not inside it — same "../podmotion-demo"
# sibling convention hack/quickstart-kvm.sh already uses. Override either path
# if your checkouts live somewhere else. Namespaces are independent of
# podmotion-system: both apps are deployed as their OWN standalone Helm
# releases (see cmd_deploy_podmotion_demo's header comment for why, re:
# podmotion-demo's cluster-scoped RBAC objects and the subchart path).
PODMOTION_DEMO_REPO="${PODMOTION_DEMO_REPO:-$(dirname "$REPO_ROOT")/podmotion-demo}"
MIGRATION_DEMO_REPO="${MIGRATION_DEMO_REPO:-$(dirname "$REPO_ROOT")/podmotion-migration-demo-app}"
PODMOTION_DEMO_NAMESPACE="${PODMOTION_DEMO_NAMESPACE:-podmotion-demo}"
MIGRATION_DEMO_NAMESPACE="${MIGRATION_DEMO_NAMESPACE:-migration-demo}"

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

# ── containerd-socket detection primitive (confirmed live 2026-07-22) ───────
# Every `ctr -n k8s.io ...` call in this script MUST target the socket the
# node's actual kubelet reads images from — NOT `ctr`'s compiled-in default
# (/run/containerd/containerd.sock, the plain SYSTEM containerd every Ubuntu
# 24.04 base image ships alongside a distro's own embedded one). Confirmed
# live this round against the standing cluster: it is actually running RKE2
# (v1.35.6+rke2r1), not vanilla kubeadm, and RKE2's kubelet is launched with
# --containerd=/run/k3s/containerd/containerd.sock — a plain `ctr images
# import` (no -a flag) lands the image on the WRONG (system) containerd,
# where kubelet never looks: `ctr -n k8s.io images ls` on the SYSTEM socket
# falsely shows the image present, while the kubelet reports "pull access
# denied" / ErrImageNeverPull trying to actually run it.
#
# Rather than infer which socket is right from which reset-cluster-* command
# was last run (a brittle chain — the caller can forget, exactly what
# happened here) or require CONTAINERD_ADDRESS to be set by hand every time,
# ask the node directly: RKE2 and k3s share the identical embedded-containerd
# socket path (both are Rancher's own packaging — see the RKE2_CONTAINERD_SOCKET
# comment above), so testing for that one socket file's existence on the node
# is a real, general primitive that covers both distros without hardcoding
# which one is active. An explicit CONTAINERD_ADDRESS override always wins
# (e.g. for a distro/layout this detection doesn't yet know about); the
# kubeadm path (no k3s/RKE2 socket present) is unaffected — ctr_addr_flag
# comes back empty and `ctr` keeps using its own compiled-in default, exactly
# the pre-existing behavior.
detect_ctr_addr_flag() {   # detect_ctr_addr_flag <ip>
  local ip="$1"
  if [[ -n "${CONTAINERD_ADDRESS:-}" ]]; then
    echo "-a $CONTAINERD_ADDRESS"
    return
  fi
  if nsh "$ip" "sudo test -S $RKE2_CONTAINERD_SOCKET" 2>/dev/null; then
    echo "-a $RKE2_CONTAINERD_SOCKET"
  else
    echo ""
  fi
}

# ── assert_storageclass_tier1_migratable: ADR-0424 D2 ────────────────────────
# Named, reusable preflight primitive: given the RESOLVED StorageClass name a
# Tier-1-eligible demo workload will actually bind to, fails loudly — before any
# docker build/helm install — if that class is Longhorn-backed but does not
# declare parameters.migratable="true". Without this, Longhorn never starts a
# second engine on the destination node during a live migration attempt, making
# LonghornMigrator.pollUntilSingleOwner (internal/agent/storage/tier1.go)
# structurally unsatisfiable no matter how long it runs — the mechanism-map H6
# finding this ADR closes.
#
# A StorageClass that is not Longhorn-provisioned (provisioner does not contain
# "longhorn.io") is a different tier entirely (e.g. Ceph RBD) and is out of this
# check's evidence base — NOT blocked here; "not migratable=true" is only
# treated as "broken" for a Longhorn-backed class.
#
# No silent auto-correction: on failure this exits non-zero with a named,
# actionable error and two remediations, exactly like the pre-existing
# no-default-StorageClass check below — never quietly substitutes a different
# StorageClass than the one the operator requested.
assert_storageclass_tier1_migratable() {   # assert_storageclass_tier1_migratable <sc-name> <workload-label>
  local sc_name="$1" workload_label="$2"
  local provisioner migratable
  provisioner="$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" get storageclass "$sc_name" \
    -o jsonpath='{.provisioner}' 2>/dev/null || true)"
  if [[ -z "$provisioner" ]]; then
    echo "ERROR: assert_storageclass_tier1_migratable: StorageClass '$sc_name' (workload: $workload_label) not found in the cluster." >&2
    exit 1
  fi
  if [[ "$provisioner" != *longhorn.io* ]]; then
    echo "  -- StorageClass '$sc_name' (workload: $workload_label) is not Longhorn-provisioned (provisioner: $provisioner) — ADR-0424's migratability check does not apply to it."
    return 0
  fi
  migratable="$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" get storageclass "$sc_name" \
    -o jsonpath='{.parameters.migratable}' 2>/dev/null || true)"
  if [[ "$migratable" != "true" ]]; then
    echo "ERROR: assert_storageclass_tier1_migratable: StorageClass '$sc_name' (workload: $workload_label, provisioner: $provisioner) does not set parameters.migratable=\"true\" — PodMotion's Tier1-Longhorn dual-engine live migration requires a migratable Longhorn StorageClass; the default single-attach-only Longhorn class cannot collapse to a second engine on the destination node and AwaitSingleOwner would stall for the full completion budget instead of failing fast (ADR-0424)." >&2
    echo "       Remediation: run 'bash hack/kvm-cluster.sh provision-longhorn' and use its \$LH_MIGRATABLE_SC (default: longhorn-migratable), or set MIGRATION_DEMO_STORAGE_CLASS=<a-migratable-longhorn-class> explicitly." >&2
    exit 1
  fi
  echo "  -- StorageClass '$sc_name' (workload: $workload_label) confirmed Tier1-migratable (provisioner: $provisioner, parameters.migratable=true)"
}

# ── resolve_chart_postgres_storageclass: ADR-0424 D1/D2 fix ──────────────────
# Reads the EFFECTIVE postgres.persistence.storageClassName default straight
# out of the migration-demo-stack chart's own values.yaml, with no
# MIGRATION_DEMO_STORAGE_CLASS override in play. This exists because
# cmd_deploy_migration_demo used to resolve "what StorageClass will postgres
# actually bind to?" as "the override, or else the cluster's default
# StorageClass" — true when values.yaml left storageClassName empty, but
# ADR-0424's D1 fix set it to the fixed value "longhorn-migratable" (see the
# chart's postgres.persistence section), which need not be, and on this
# standing cluster is NOT, the cluster's default StorageClass ("longhorn" is
# default; "longhorn-migratable" is not). Skipping this step made the preflight
# validate the wrong class and fail closed on a correctly-configured deploy.
#
# Prints the resolved value on stdout and returns 0 on success; prints nothing
# and returns 1 if the chart's values.yaml is missing or does not set
# postgres.persistence.storageClassName to a non-empty, non-comment value
# (callers must fall back to the cluster default in that case — an explicitly
# empty chart default legitimately means "use the cluster default").
resolve_chart_postgres_storageclass() {   # resolve_chart_postgres_storageclass <chart-dir>
  local chart_dir="$1"
  local values_file="$chart_dir/values.yaml"
  if [[ ! -f "$values_file" ]]; then
    return 1
  fi
  local val
  val="$(
    awk '/^postgres:/{f=1;next} f && /^[a-zA-Z]/{f=0} f' "$values_file" |
    awk '/^  persistence:/{p=1;next} p && /^  [a-zA-Z]/{p=0} p' |
    grep -v '^[[:space:]]*#' |
    grep -m1 'storageClassName:' |
    sed -E 's/^[[:space:]]*storageClassName:[[:space:]]*"?([^"#[:space:]]*)"?.*/\1/'
  )"
  if [[ -z "$val" ]]; then
    return 1
  fi
  echo "$val"
  return 0
}

# ── Safety guard: never destroy/undefine a pm-* VM ───────────────────────────
assert_no_vm_destruction() {
  echo "SAFETY: this script never runs 'virsh destroy' or 'virsh undefine' on the standing VMs (${PM_VMS[*]}). The VMs are permanent infrastructure." >&2
}

# ── Precondition guard: local sudo must be non-interactively usable ──────────
# Every remote (nsh) sudo call runs on the VMs, where passwordless sudo is
# already provisioned for $SSH_USER — those are safe. cmd_provision_longhorn is
# the one command that also shells out to LOCAL sudo (virsh attach-disk,
# qemu-img create) on the host running this script, to manage libvirt disks.
# A bare `sudo` with no cached credentials and no TTY (e.g. invoked from an
# agent/non-interactive session) does not fail — it BLOCKS indefinitely waiting
# on a password prompt nothing will ever answer (confirmed live 2026-07-17: a
# provisioning run hung with no error output until killed). Fail fast instead,
# with a clear, actionable message, before any local sudo call is attempted.
require_local_sudo() {
  if ! sudo -n true 2>/dev/null; then
    echo "ERROR: this command needs local sudo (for virsh/qemu-img disk management)," >&2
    echo "       but passwordless sudo is not available for this session (no TTY/cached" >&2
    echo "       credentials). Run this command yourself in an interactive terminal where" >&2
    echo "       you can enter your sudo password, e.g.:" >&2
    echo "         $0 ${1:-<subcommand>}" >&2
    exit 1
  fi
}

cmd_verify() {
  load_ips
  echo "==> Verifying KVM kubeadm cluster (control-plane $CP1_IP)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" get nodes -o wide
  local ready
  ready="$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" get nodes --no-headers 2>/dev/null | grep -cw Ready || true)"
  if [[ "$ready" -lt 3 ]]; then
    echo "ERROR: expected 3 Ready nodes, found $ready." >&2
    exit 1
  fi
  echo "==> OK: 3 nodes Ready."
}

# ── sweep_cni_leftovers: purge kernel-level interfaces + iptables chains left ─
# behind by a PRIOR CNI (Cilium/Calico — see CNI_LEFTOVER_REGISTRY) that
# kubeadm/k3s's own reset/uninstall never removes, since those interfaces and
# chains are created directly via netlink/iptables by the CNI's own daemonset,
# not by the kubelet CNI-conf-dir mechanism kubeadm reset clears. Shared by
# cmd_reset_cluster (kubeadm path) and cmd_reset_cluster_k3s (k3s path) — see
# sprint50 k3s compat plan §1 Q1 (this is exactly the primitive
# CNI_LEFTOVER_REGISTRY was built to generalize, not two copies of the sweep).
sweep_cni_leftovers() {
  local cni_ifaces="" cni_iptables_regex=""
  local reg_row reg_name reg_ifaces reg_regex
  for reg_row in "${CNI_LEFTOVER_REGISTRY[@]}"; do
    IFS='|' read -r reg_name reg_ifaces reg_regex <<< "$reg_row"
    cni_ifaces="$cni_ifaces $reg_ifaces"
    if [[ -z "$cni_iptables_regex" ]]; then
      cni_iptables_regex="$reg_regex"
    else
      cni_iptables_regex="$cni_iptables_regex|$reg_regex"
    fi
  done
  cni_ifaces="${cni_ifaces# }"

  echo "==> Purging leftover network interfaces from any prior CNI (${CNI_LEFTOVER_REGISTRY[*]%%|*}, from CNI_LEFTOVER_REGISTRY)..."
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    nsh "$ip" "for l in $cni_ifaces; do sudo ip link del \"\$l\" 2>/dev/null || true; done; sudo ip route flush proto 80 2>/dev/null || true"
  done

  # Same leftover-CNI-residue problem as above, but in iptables rather than
  # netlink: Cilium/Calico each install their own chains (cali-*, CILIUM_*) into
  # raw/mangle/filter/nat, hooked in ahead of kube-proxy's own rules, and
  # kubeadm reset never removes them. Confirmed live 2026-07-17: a stray
  # unconditional MASQUERADE rule left in cali-POSTROUTING (plus assorted
  # Cilium TPROXY/NOTRACK rules in raw/mangle) caused intermittent DNS/Service
  # ClusterIP routing failures hours into a Flannel-only cluster's life —
  # exactly the class of "sometimes works" bug that's expensive to diagnose
  # blind. Purge unconditionally on every reset, same as the interface sweep.
  echo "==> Purging leftover iptables chains from any prior CNI (${CNI_LEFTOVER_REGISTRY[*]%%|*}, from CNI_LEFTOVER_REGISTRY)..."
  local cni_iptables_purge
  cni_iptables_purge='
for table in raw mangle filter nat; do
  iptables-legacy -t "$table" -S 2>/dev/null | grep -E "^-A" | grep -E -- "-j ('"$cni_iptables_regex"')" | sed "s/^-A/-D/" | while read -r cmd; do
    iptables-legacy -t "$table" $cmd 2>/dev/null || true
  done
done
for pass in 1 2 3; do
  for table in raw mangle filter nat; do
    for chain in $(iptables-legacy -t "$table" -S 2>/dev/null | grep -oE -- "-N ('"$cni_iptables_regex"')[^ ]+" | awk "{print \$2}"); do
      iptables-legacy -t "$table" -F "$chain" 2>/dev/null || true
    done
  done
done
for table in raw mangle filter nat; do
  for chain in $(iptables-legacy -t "$table" -S 2>/dev/null | grep -oE -- "-N ('"$cni_iptables_regex"')[^ ]+" | awk "{print \$2}"); do
    iptables-legacy -t "$table" -X "$chain" 2>/dev/null || true
  done
done
'
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    nsh "$ip" "sudo bash -c '$cni_iptables_purge'"
  done
}

cmd_reset_cluster() {
  assert_no_vm_destruction
  load_ips
  echo "==> RESET: kubeadm reset on all nodes (VMs are NOT destroyed)..."
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- reset $ip"
    nsh "$ip" "sudo kubeadm reset -f && sudo rm -rf /etc/cni/net.d \$HOME/.kube && sudo rm -rf /etc/kubernetes/manifests/*"
  done

  # kubeadm reset only clears /etc/cni/net.d — it does NOT remove the kernel-level
  # network interfaces that Cilium/Calico's own daemonsets create directly via
  # netlink (cilium_host/cilium_net/cilium_geneve, vxlan.calico). Those survive
  # every reset and their routes collide with the next CNI's routes for the same
  # pod CIDR (confirmed live 2026-07-17: a stale cilium_host route for 10.244.1.0/24
  # silently shadowed cni0's real Flannel route on that same node, making every pod
  # on the node unreachable — even from the node itself — with no error surfaced
  # anywhere except a generic probe timeout). Sweep every prior-CNI leftover
  # unconditionally, on every reset, regardless of which CNI is being reset FROM.
  sweep_cni_leftovers

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
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" wait --for=condition=Ready nodes --all --timeout=180s
  cmd_verify
}

# ── reset-cluster-k3s: alternative reset-cluster mode, same 3 standing VMs ───
# Sibling of cmd_reset_cluster, not a mode flag inside it — k3s's reset
# sequence diverges from kubeadm's at almost every step (own installer, own
# uninstaller, own token/join mechanism, own kubeconfig path), not just the
# CNI-apply step Calico/Cilium differ at (sprint50 k3s compat plan §1 Q1
# recommendation).
#
# Defaults to a STOCK k3s install (embedded Flannel, no CNI swap) — the plan's
# "Track A" recommendation: exercises k3s's actual out-of-box default and
# isolates the containerd socket/bundle-path fixes (this sprint's other half —
# see internal/agent/server/containerd_paths.go) from any CNI question. Track
# B (live migration — Flannel disabled + Calico/Cilium installed manually) is
# NOT implemented here; it is gated on sprint48's Calico reachability-gate fix
# landing first (plan §1 Q4, §2 Round 3) and gets its own follow-up command
# when that lands. Pass K3S_INSTALL_EXTRA_ARGS="--flannel-backend=none" to
# disable embedded Flannel if you are manually driving Track B against this
# same function.
#
# UNVERIFIED-EXTERNAL warning: every k3s-side path/flag/filename this function
# relies on (K3S_TOKEN_FILE, K3S_KUBECONFIG_PATH, K3S_CONTAINERD_SOCKET,
# K3S_CONTAINERD_STATE_DIR, the k3s-uninstall.sh script names, the
# K3S_URL/K3S_TOKEN agent-install contract) is cited from general k3s project
# knowledge, NOT verified against a live k3s node this round (no cluster was
# touched writing this script — see the sprint50 k3s compat plan's own
# grounding note). Confirm against a real install (the plan's own
# recommended Round 2, ideally on a disposable scratch VM first) before
# trusting a non-default override blind.
cmd_reset_cluster_k3s() {
  assert_no_vm_destruction
  load_ips
  echo "==> RESET (k3s): removing any existing kubeadm OR k3s state on all nodes (VMs are NOT destroyed)..."
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- clean $ip"
    # Symmetric two-way swap: whichever distro was previously installed, run
    # ITS OWN uninstaller before the incoming k3s init (plan §1 Q1) — a stale
    # kubeadm cert/manifest tree and a stale k3s data dir can each collide
    # with the other distro's fresh init if left behind.
    nsh "$ip" '
      set -e
      if command -v kubeadm >/dev/null 2>&1; then
        sudo kubeadm reset -f 2>/dev/null || true
      fi
      sudo rm -rf /etc/cni/net.d "$HOME/.kube" /etc/kubernetes/manifests/* 2>/dev/null || true
      # CNI IPAM lease state (host-local/bridge plugin leases, e.g.
      # /var/lib/cni/networks/cbr0/ from a prior kubeadm+Flannel install)
      # survives both the kubeadm reset above and the k3s uninstall below —
      # neither one clears it. If left behind, the CNI plugin on the incoming
      # k3s install consults these stale lease files for the first pods
      # scheduled after boot and hands them IPs from the OLD pod CIDR
      # (10.244.0.0/16) instead of k3s'"'"'s real one (10.42.0.0/16 by
      # default), breaking their networking (verified live 2026-07-17:
      # coredns/local-path-provisioner/metrics-server all got 10.244.0.x
      # addresses and could not reach the 10.43.0.0/16 service CIDR).
      # Purging it here guarantees every pod gets an IP from the CNI that is
      # actually about to be installed.
      sudo rm -rf /var/lib/cni/networks 2>/dev/null || true
      # k3s installer drops its own uninstall scripts — server and agent variants
      # are named differently and only one is present per node role.
      if [ -x /usr/local/bin/k3s-uninstall.sh ]; then
        sudo /usr/local/bin/k3s-uninstall.sh || true
      fi
      if [ -x /usr/local/bin/k3s-agent-uninstall.sh ]; then
        sudo /usr/local/bin/k3s-agent-uninstall.sh || true
      fi
      sudo rm -rf /etc/rancher/k3s /var/lib/rancher/k3s 2>/dev/null || true
    '
  done

  # Same leftover-interface/iptables-chain problem cmd_reset_cluster guards
  # against — k3s's embedded Flannel and any manually-installed Calico/Cilium
  # from a prior round leave the same netlink/iptables residue kubeadm's own
  # CNIs do. Shared primitive, not a second copy (see sweep_cni_leftovers).
  sweep_cni_leftovers

  echo "==> Restarting containerd + waiting for CRI readiness on all nodes (post-reset race guard)..."
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    nsh "$ip" "sudo systemctl restart containerd 2>/dev/null || true; for i in \$(seq 1 30); do sudo crictl --runtime-endpoint unix:///run/containerd/containerd.sock info >/dev/null 2>&1 && { echo '  CRI ready on '\$(hostname); break; }; sleep 2; done"
  done

  echo "==> Installing k3s server on $CP_VM ($CP1_IP)..."
  # --write-kubeconfig-mode so the non-root SSH_USER can cat it without sudo is
  # NOT relied on here — export step below uses sudo cat, matching the kubeadm
  # path's own admin.conf export idiom (plan §1 Q1 kubeconfig-export note).
  local server_exec="server --node-ip=$CP1_IP --advertise-address=$CP1_IP $K3S_INSTALL_EXTRA_ARGS"
  nsh "$CP1_IP" "curl -sfL https://get.k3s.io | ${K3S_VERSION:+INSTALL_K3S_VERSION=$K3S_VERSION }INSTALL_K3S_EXEC='$server_exec' sh -"

  echo "==> Waiting for k3s node-token on $CP_VM..."
  local i
  for i in $(seq 1 30); do
    if nsh "$CP1_IP" "sudo test -f $K3S_TOKEN_FILE"; then break; fi
    sleep 2
  done
  local k3s_token
  k3s_token="$(nsh "$CP1_IP" "sudo cat $K3S_TOKEN_FILE")"
  if [[ -z "$k3s_token" ]]; then
    echo "ERROR: could not read k3s node-token from $CP1_IP:$K3S_TOKEN_FILE." >&2
    exit 1
  fi

  echo "==> Installing k3s agent on workers, joining $CP1_IP..."
  for ip in "${WORKER_IPS[@]}"; do
    echo "  -- join worker $ip"
    nsh "$ip" "curl -sfL https://get.k3s.io | ${K3S_VERSION:+INSTALL_K3S_VERSION=$K3S_VERSION }K3S_URL='https://$CP1_IP:6443' K3S_TOKEN='$k3s_token' INSTALL_K3S_EXEC='agent --node-ip=$ip' sh -"
  done

  echo "==> Exporting k3s kubeconfig to $KUBECONFIG_OUT..."
  # k3s's generated kubeconfig embeds a loopback server address
  # (https://127.0.0.1:6443, UNVERIFIED-EXTERNAL default) — unlike kubeadm's
  # admin.conf, which already uses the real --apiserver-advertise-address.
  # Rewrite it to the real CP1 IP so KUBECONFIG_OUT is usable off-node,
  # matching every other command in this script's assumption.
  nsh "$CP1_IP" "sudo cat $K3S_KUBECONFIG_PATH" | sed "s#https://127.0.0.1:6443#https://$CP1_IP:6443#" > "$KUBECONFIG_OUT"
  chmod 600 "$KUBECONFIG_OUT"

  echo "==> Waiting for 3 nodes Ready..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" wait --for=condition=Ready nodes --all --timeout=180s
  cmd_verify

  echo "==> reset-cluster-k3s complete."
  echo "    k3s containerd socket:  $K3S_CONTAINERD_SOCKET (UNVERIFIED-EXTERNAL default)"
  echo "    k3s containerd state:   $K3S_CONTAINERD_STATE_DIR (UNVERIFIED-EXTERNAL default)"
  echo "    Deploy PodMotion against this cluster with:"
  echo "      CONTAINERD_ADDRESS=$K3S_CONTAINERD_SOCKET \\"
  echo "      AGENT_CONTAINERD_SOCKET_PATH=$K3S_CONTAINERD_SOCKET \\"
  echo "      AGENT_CONTAINERD_STATE_DIR=$K3S_CONTAINERD_STATE_DIR \\"
  echo "      TAG=<tag> bash hack/kvm-cluster.sh deploy-podmotion"
}

# ── reset-cluster-rke2: alternative reset-cluster mode, same 3 standing VMs ──
# Sibling of cmd_reset_cluster / cmd_reset_cluster_k3s, not a mode flag inside
# either — RKE2 diverges from BOTH kubeadm and k3s at almost every step: own
# server/agent binaries, own installer (get.rke2.io), own systemd unit names
# (rke2-server/rke2-agent), config driven by a file
# (/etc/rancher/rke2/config.yaml) the systemd unit reads at start rather than
# k3s's inline INSTALL_*_EXEC idiom, agents join the SUPERVISOR api on port
# 9345 (not 6443), and — per docs.rke2.io (fetched live this round) — its own
# default CNI is "canal" (Flannel dataplane + Calico policy-only), not k3s's
# embedded Flannel. This function installs RKE2 on its OWN DEFAULT CNI
# (canal) — sprint51's explicit scope is proving the distribution +
# provisioning + a Cold-mode migration first; a Cilium-on-RKE2 CNI swap is a
# separate, later round (see RKE2_CNI above, left empty by default).
cmd_reset_cluster_rke2() {
  assert_no_vm_destruction
  load_ips
  echo "==> RESET (rke2): removing any existing kubeadm/k3s/RKE2 state on all nodes (VMs are NOT destroyed)..."
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- clean $ip"
    # Symmetric N-way swap, same reasoning as the k3s reset: whichever distro
    # was previously installed, run ITS OWN uninstaller before the incoming
    # RKE2 install — a stale kubeadm cert/manifest tree, a stale k3s data dir,
    # or a stale RKE2 data dir can each collide with the other distros' fresh
    # init if left behind.
    nsh "$ip" '
      set -e
      if command -v kubeadm >/dev/null 2>&1; then
        sudo kubeadm reset -f 2>/dev/null || true
      fi
      sudo rm -rf /etc/cni/net.d "$HOME/.kube" /etc/kubernetes/manifests/* 2>/dev/null || true
      if [ -x /usr/local/bin/k3s-uninstall.sh ]; then
        sudo /usr/local/bin/k3s-uninstall.sh || true
      fi
      if [ -x /usr/local/bin/k3s-agent-uninstall.sh ]; then
        sudo /usr/local/bin/k3s-agent-uninstall.sh || true
      fi
      sudo rm -rf /etc/rancher/k3s /var/lib/rancher/k3s 2>/dev/null || true
      # RKE2'"'"'s own uninstallers — separate scripts from k3s'"'"'s, dropped by the
      # RKE2 installer at a fixed path regardless of server/agent role.
      if [ -x /usr/local/bin/rke2-uninstall.sh ]; then
        sudo /usr/local/bin/rke2-uninstall.sh || true
      fi
      if [ -x /usr/local/bin/rke2-killall.sh ]; then
        sudo /usr/local/bin/rke2-killall.sh || true
      fi
      sudo rm -rf /etc/rancher/rke2 /var/lib/rancher/rke2 2>/dev/null || true
      # Same stale CNI IPAM lease problem the k3s reset guards against
      # (cd304e9) — host-local/bridge plugin leases from ANY prior CNI
      # (kubeadm+Flannel, k3s+Flannel, or a prior RKE2+canal run) survive
      # every distro'"'"'s own reset/uninstall and hand the wrong pod-CIDR IPs to
      # the first pods scheduled after the incoming CNI comes up.
      sudo rm -rf /var/lib/cni/networks 2>/dev/null || true
    '
  done

  # Same leftover-interface/iptables-chain problem cmd_reset_cluster and
  # cmd_reset_cluster_k3s guard against. Canal'"'"'s policy component ships the
  # same Calico node/felix binaries as standalone Calico, installing the same
  # cali-* iptables chains — already covered by the existing "calico" row in
  # CNI_LEFTOVER_REGISTRY, no new row needed for that half. Canal'"'"'s dataplane
  # is a Flannel VXLAN device (flannel.1/cni0), which — like the kubeadm/k3s
  # Flannel paths — is the RESET-TARGET's own interface when resetting INTO
  # canal, not prior-CNI residue, so it stays excluded from the registry for
  # the same reason Flannel is excluded there already.
  sweep_cni_leftovers

  echo "==> Restarting containerd + waiting for CRI readiness on all nodes (post-reset race guard)..."
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    nsh "$ip" "sudo systemctl restart containerd 2>/dev/null || true; for i in \$(seq 1 30); do sudo crictl --runtime-endpoint unix:///run/containerd/containerd.sock info >/dev/null 2>&1 && { echo '  CRI ready on '\$(hostname); break; }; sleep 2; done"
  done

  echo "==> Installing RKE2 server on $CP_VM ($CP1_IP)..."
  # RKE2 does not take k3s'"'"'s inline INSTALL_*_EXEC idiom — its systemd unit
  # reads /etc/rancher/rke2/config.yaml at start, so the config must exist
  # BEFORE `systemctl start rke2-server`, not passed as an install-time env var.
  nsh "$CP1_IP" "sudo mkdir -p /etc/rancher/rke2"
  local cp_config="node-ip: $CP1_IP
advertise-address: $CP1_IP
tls-san:
  - $CP1_IP
write-kubeconfig-mode: \"0644\""
  if [[ -n "$RKE2_CNI" ]]; then
    cp_config="$cp_config
cni: $RKE2_CNI"
  fi
  if [[ -n "$RKE2_INSTALL_EXTRA_ARGS" ]]; then
    cp_config="$cp_config
$RKE2_INSTALL_EXTRA_ARGS"
  fi
  printf '%s\n' "$cp_config" | nsh "$CP1_IP" "sudo tee /etc/rancher/rke2/config.yaml >/dev/null"
  nsh "$CP1_IP" "curl -sfL https://get.rke2.io | ${RKE2_VERSION:+INSTALL_RKE2_VERSION=$RKE2_VERSION }sudo sh -"
  nsh "$CP1_IP" "sudo systemctl enable --now rke2-server.service"

  echo "==> Waiting for RKE2 node-token on $CP_VM..."
  local i
  for i in $(seq 1 60); do
    if nsh "$CP1_IP" "sudo test -f $RKE2_TOKEN_FILE"; then break; fi
    sleep 2
  done
  local rke2_token
  rke2_token="$(nsh "$CP1_IP" "sudo cat $RKE2_TOKEN_FILE")"
  if [[ -z "$rke2_token" ]]; then
    echo "ERROR: could not read RKE2 node-token from $CP1_IP:$RKE2_TOKEN_FILE." >&2
    exit 1
  fi

  # RKE2's own kubectl/crictl/ctr live under $RKE2_DATA_DIR/bin, not on the
  # default PATH — wait for the API server to actually answer before joining
  # workers, using RKE2's own bundled kubectl against its own kubeconfig.
  echo "==> Waiting for RKE2 API server to become reachable on $CP_VM..."
  for i in $(seq 1 60); do
    if nsh "$CP1_IP" "sudo $RKE2_DATA_DIR/bin/kubectl --kubeconfig $RKE2_KUBECONFIG_PATH get --raw=/readyz" >/dev/null 2>&1; then
      echo "  API server ready."
      break
    fi
    sleep 2
  done

  echo "==> Installing RKE2 agent on workers, joining $CP1_IP:$RKE2_SUPERVISOR_PORT..."
  for ip in "${WORKER_IPS[@]}"; do
    echo "  -- join worker $ip"
    nsh "$ip" "sudo mkdir -p /etc/rancher/rke2"
    local worker_config="node-ip: $ip
server: https://$CP1_IP:$RKE2_SUPERVISOR_PORT
token: $rke2_token"
    printf '%s\n' "$worker_config" | nsh "$ip" "sudo tee /etc/rancher/rke2/config.yaml >/dev/null"
    nsh "$ip" "curl -sfL https://get.rke2.io | ${RKE2_VERSION:+INSTALL_RKE2_VERSION=$RKE2_VERSION }INSTALL_RKE2_TYPE=agent sudo sh -"
    nsh "$ip" "sudo systemctl enable --now rke2-agent.service"
  done

  echo "==> Exporting RKE2 kubeconfig to $KUBECONFIG_OUT..."
  # RKE2's generated kubeconfig also embeds a loopback server address
  # (https://127.0.0.1:6443), same as k3s — rewrite it to the real CP1 IP so
  # KUBECONFIG_OUT is usable off-node, matching this script's assumption.
  nsh "$CP1_IP" "sudo cat $RKE2_KUBECONFIG_PATH" | sed "s#https://127.0.0.1:6443#https://$CP1_IP:6443#" > "$KUBECONFIG_OUT"
  chmod 600 "$KUBECONFIG_OUT"

  echo "==> Waiting for 3 nodes Ready..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" wait --for=condition=Ready nodes --all --timeout=300s
  cmd_verify

  echo "==> reset-cluster-rke2 complete."
  echo "    RKE2 containerd socket:  $RKE2_CONTAINERD_SOCKET (confirmed live against pm-cp1/pm-w1/pm-w2)"
  echo "    RKE2 containerd state:   $RKE2_CONTAINERD_STATE_DIR (confirmed live — same run root as socket)"
  echo "    RKE2 CNI conf dir:       canonical /etc/cni/net.d — no extraConfDir override needed (confirmed live)"
  echo "    ADR-0370: the agent now self-discovers the authoritative containerd socket at"
  echo "    startup — CONTAINERD_ADDRESS (this script's own ctr calls) is still required, but"
  echo "    AGENT_CONTAINERD_SOCKET_PATH/AGENT_CONTAINERD_STATE_DIR are now OPTIONAL explicit"
  echo "    overrides, not a required workaround. Plain deploy (self-discovering agent):"
  echo "      CONTAINERD_ADDRESS=$RKE2_CONTAINERD_SOCKET \\"
  echo "      TAG=<tag> bash hack/kvm-cluster.sh deploy-podmotion"
  echo "    Forcing an explicit agent-side override instead of self-discovery:"
  echo "      CONTAINERD_ADDRESS=$RKE2_CONTAINERD_SOCKET \\"
  echo "      AGENT_CONTAINERD_SOCKET_PATH=$RKE2_CONTAINERD_SOCKET \\"
  echo "      AGENT_CONTAINERD_STATE_DIR=$RKE2_CONTAINERD_STATE_DIR \\"
  echo "      TAG=<tag> bash hack/kvm-cluster.sh deploy-podmotion"
}

# ── deploy-podmotion: build → import images → certs → CRDs → helm ────────────
cmd_deploy_podmotion() {
  # ADR-0325-remediation Fix 1 (Deploy Provenance Gate, §2.1): --allow-dirty is the ONLY
  # accepted flag. Root cause of the round5-vs-main incident this gate exists to prevent:
  # nothing in this pipeline previously verified that "deployed" meant "matches the git ref
  # you intend to test" — a stale/wrong-branch image tag can silently keep serving traffic
  # indefinitely. This is now a structural build/deploy identity contract, not a one-off check.
  local allow_dirty=0
  local skip_demo_apps=0
  local arg
  for arg in "$@"; do
    case "$arg" in
      --allow-dirty) allow_dirty=1 ;;
      --skip-demo-apps) skip_demo_apps=1 ;;
      *) echo "ERROR: deploy-podmotion: unrecognized argument '$arg' (only --allow-dirty/--skip-demo-apps are accepted)" >&2; exit 2 ;;
    esac
  done

  load_ips
  # TAG carries sprint provenance so consecutive sprints don't collide on one
  # static tag (keeps verifyArtifacts' build-stamp check meaningful). Passed in
  # via env (skeleton passes TAG=<sprintPrefix>-amd64); kvm-dev is last-resort only.
  local TAG="${TAG:-kvm-dev}"
  local OP_IMG="podmotion-operator:$TAG"
  local AGENT_IMG="podmotion-agent:$TAG"
  # ADR-0363/0364 Part B2 follow-up: the podmotion-scheduler Deployment
  # (charts/podmotion/templates/scheduler-deployment.yaml) has been rendered
  # since scheduler.enabled defaults true, but until now nothing in this
  # function pointed it at a locally-built image the way operator/agent are —
  # it fell through to the chart default (ghcr.io/podmotion/podmotion-scheduler:latest,
  # values.yaml scheduler.image.*), a remote image that does not exist, giving
  # ImagePullBackOff/403 on every deploy. Build/import/override it exactly like
  # operator and agent below.
  local SCHEDULER_IMG="podmotion-scheduler:$TAG"

  # ── §2.1 build-time provenance ───────────────────────────────────────────────
  # Compute the revision from the WORKTREE ACTUALLY BEING BUILT (this script's own repo
  # root, not some other checkout), refuse a dirty tree unless --allow-dirty was passed
  # explicitly, and if it was, stamp "<sha>-dirty" rather than a clean sha — a dirty stamp
  # can never be mistaken for a verified, reproducible commit.
  local GIT_SHA GIT_BRANCH GIT_DIRTY=0
  GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  if [[ "$GIT_SHA" == "unknown" ]]; then
    echo "ERROR: deploy-podmotion: could not resolve 'git rev-parse HEAD' for this worktree — refusing to build with unknown provenance." >&2
    exit 1
  fi
  if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
    if [[ "$allow_dirty" -ne 1 ]]; then
      echo "ERROR: deploy-podmotion: worktree is dirty (uncommitted changes). Refusing to build — a dirty deploy cannot be matched back to a git ref later, which is exactly the failure mode this gate exists to prevent." >&2
      echo "       Commit or stash your changes, or re-run with 'deploy-podmotion --allow-dirty' to build anyway (the image will be stamped '<sha>-dirty', never a clean sha)." >&2
      exit 1
    fi
    GIT_DIRTY=1
    GIT_SHA="${GIT_SHA}-dirty"
    echo "WARNING: deploy-podmotion --allow-dirty: building from a dirty worktree; images/annotations will be stamped '$GIT_SHA', not a clean, reproducible commit." >&2
  fi

  # TAG-collision guard: if this TAG already resolves to a locally-built image whose baked-in
  # org.opencontainers.image.revision differs from the revision we are about to build, refuse —
  # this is the most likely mechanism by which a tag silently keeps pointing at stale content
  # across branches (a same-tag re-deploy from a different branch/checkout than intended).
  local existing_rev img
  for img in "$OP_IMG" "$AGENT_IMG" "$SCHEDULER_IMG"; do
    if docker image inspect "$img" >/dev/null 2>&1; then
      existing_rev="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$img" 2>/dev/null || echo "")"
      if [[ -n "$existing_rev" && "$existing_rev" != "$GIT_SHA" ]]; then
        echo "ERROR: deploy-podmotion: image tag '$img' already exists locally, built from revision '$existing_rev', which does not match the revision about to be built ('$GIT_SHA')." >&2
        echo "       Reusing TAG='$TAG' across differing revisions is exactly how a stale image ends up silently serving a different branch than the one under test. Choose a distinct TAG (e.g. TAG=\$(git rev-parse --short HEAD)-amd64), or remove the stale local image first (docker rmi $img)." >&2
        exit 1
      fi
    fi
  done
  # sprint50 (k3s compat, plan §1 Q2 item 1) / ADR-0325-remediation (RKE2, 2026-07-22):
  # this script's own `ctr` calls below (image rm/import/ls, distinct from the
  # agent's own ctr invocations — see internal/agent/server/containerd_paths.go)
  # fall back to ctr's compiled-in default socket (/run/containerd/containerd.sock)
  # when no address is given, which is wrong on a k3s/RKE2 node — see
  # detect_ctr_addr_flag above. Confirmed live 2026-07-22: relying on a caller
  # to remember to export CONTAINERD_ADDRESS by hand is exactly the omission
  # that caused a prior deploy to import operator/agent images onto the wrong
  # (system) containerd, where kubelet never looks. Detect it from the node
  # itself instead (still overridable via CONTAINERD_ADDRESS for a layout this
  # detection doesn't know about); on a plain kubeadm node this comes back
  # empty and ctr keeps using its own default, unchanged from before.
  local ctr_addr_flag
  ctr_addr_flag="$(detect_ctr_addr_flag "$CP1_IP")"
  if [[ -n "$ctr_addr_flag" ]]; then
    echo "  -- detected non-default containerd socket for ctr calls: $ctr_addr_flag"
  fi
  # AGENT_CONTAINERD_SOCKET_PATH / AGENT_CONTAINERD_STATE_DIR: passed straight
  # through to the Helm chart's agent.containerd.socketPath/stateDir values (the
  # containerd-socket + host-var-lib-containerd hostPath VOLUME MOUNTS only —
  # see charts/podmotion/values.yaml). Default to the same standard-containerd
  # paths the chart itself defaults to, so a plain kubeadm deploy-podmotion call
  # is byte-identical to before this sprint.
  #
  # ADR-0370: these two no longer drive the agent's OWN idea of which containerd
  # is authoritative — the agent self-discovers that empirically at startup
  # (internal/agent/server/containerd_discovery.go), fixing exactly the failure
  # mode this script used to require an operator to remember to work around (a
  # deploy-podmotion call that forgot to export AGENT_CONTAINERD_SOCKET_PATH
  # silently wired the agent to the wrong containerd on RKE2/k3s — 100% of
  # restores failed, never loudly). AGENT_CONTAINERD_SOCKET_PATH_WAS_SET /
  # AGENT_CONTAINERD_STATE_DIR_WAS_SET below capture whether the CALLER actually
  # exported an override BEFORE the default fills in below, so the Helm
  # `agent.containerd.override.*` fields (the explicit-override signal
  # discoverContainerdSocket treats as "tried first and exclusively") are only
  # populated when an operator genuinely asked for one — never a byte-for-byte
  # copy of these mount-path values, which would otherwise silently defeat
  # self-discovery on every deploy (mount paths are always non-empty).
  local AGENT_CONTAINERD_SOCKET_PATH_WAS_SET=0
  local AGENT_CONTAINERD_STATE_DIR_WAS_SET=0
  [[ -n "${AGENT_CONTAINERD_SOCKET_PATH:-}" ]] && AGENT_CONTAINERD_SOCKET_PATH_WAS_SET=1
  [[ -n "${AGENT_CONTAINERD_STATE_DIR:-}" ]] && AGENT_CONTAINERD_STATE_DIR_WAS_SET=1
  local AGENT_CONTAINERD_SOCKET_PATH="${AGENT_CONTAINERD_SOCKET_PATH:-/run/containerd/containerd.sock}"
  local AGENT_CONTAINERD_STATE_DIR="${AGENT_CONTAINERD_STATE_DIR:-/var/lib/containerd}"
  local -a AGENT_CONTAINERD_OVERRIDE_SET_ARGS=()
  if [[ "$AGENT_CONTAINERD_SOCKET_PATH_WAS_SET" -eq 1 ]]; then
    AGENT_CONTAINERD_OVERRIDE_SET_ARGS+=(--set "agent.containerd.override.socket=$AGENT_CONTAINERD_SOCKET_PATH")
  fi
  if [[ "$AGENT_CONTAINERD_STATE_DIR_WAS_SET" -eq 1 ]]; then
    AGENT_CONTAINERD_OVERRIDE_SET_ARGS+=(--set "agent.containerd.override.stateRoot=$AGENT_CONTAINERD_STATE_DIR")
  fi
  # AGENT_CNI_EXTRA_CONF_DIR: passed through to agent.cni.extraConfDir (Helm chart
  # values.yaml / daemonset.yaml host-cni-conf-extra mount). Some distros do not
  # populate the canonical /etc/cni/net.d that nmcregistrar.detectCNI() scans by
  # default — k3s writes its embedded-Flannel conflist to
  # /var/lib/rancher/k3s/agent/etc/cni/net.d instead, leaving /etc/cni/net.d empty and
  # NMC's spec.networkCapability.cniPlugin stuck at "unknown". Empty (default) leaves
  # a plain kubeadm deploy byte-identical to before this sprint; a k3s deploy sets this.
  local AGENT_CNI_EXTRA_CONF_DIR="${AGENT_CNI_EXTRA_CONF_DIR:-}"

  echo "==> Building binaries (make build-linux)..."
  make build-linux   # emits bin/{manager,agent,criu-wrapper}-linux-amd64 (auto-renamed)

  echo "==> Building operator + agent + scheduler images..."
  # Stamp images with the git commit they were built from (computed once, above, as the
  # §2.1 provenance gate's GIT_SHA — includes the "-dirty" suffix under --allow-dirty) so
  # deployed images can be verified against source provenance.
  docker build --build-arg GIT_SHA="$GIT_SHA" -f images/operator/Dockerfile  -t "$OP_IMG" .
  docker build --build-arg GIT_SHA="$GIT_SHA" -f images/agent/Dockerfile    -t "$AGENT_IMG" .
  docker build --build-arg GIT_SHA="$GIT_SHA" -f images/scheduler/Dockerfile -t "$SCHEDULER_IMG" .

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
    nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images rm '$OP_IMG' '$AGENT_IMG' '$SCHEDULER_IMG' >/dev/null 2>&1 || true"
    docker save "$OP_IMG"        | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    docker save "$AGENT_IMG"     | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    docker save "$SCHEDULER_IMG" | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    # Verify each tag actually landed in this node's k8s.io namespace.
    if ! nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images ls -q | grep -q ':$TAG'"; then
      echo "ERROR: image tag ':$TAG' not present in k8s.io containerd namespace on node $ip after import." >&2
      exit 1
    fi
  done

  echo "==> Applying CRDs (chart crds/ is empty — apply manually)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" apply -f config/crd/bases/

  echo "==> Ensuring podmotion-system namespace..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" create namespace podmotion-system \
    --dry-run=client -o yaml | KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" apply -f -

  echo "==> Minting operator<->agent mTLS secrets (certManager disabled)..."
  KUBECONFIG="$KUBECONFIG_OUT" make agent-certs-dev

  echo "==> Helm install..."
  KUBECONFIG="$KUBECONFIG_OUT" helm --kube-context="$KVM_CONTEXT" upgrade --install podmotion charts/podmotion/ \
    --namespace podmotion-system --create-namespace \
    --set operator.image.repository=podmotion-operator --set operator.image.tag="$TAG" --set operator.image.pullPolicy=IfNotPresent \
    --set agent.image.repository=podmotion-agent --set agent.image.tag="$TAG" --set agent.image.pullPolicy=IfNotPresent \
    --set scheduler.image.repository=podmotion-scheduler --set scheduler.image.tag="$TAG" --set scheduler.image.pullPolicy=IfNotPresent \
    --set operator.replicas=1 \
    --set webhook.certManager.enabled=false \
    --set scheduler.enabled=true \
    --set webhook.podMutation.enabled=true \
    --set installCRDs=false \
    --set operator.featureGates="TCPPreservation=true" \
    --set agent.containerd.socketPath="$AGENT_CONTAINERD_SOCKET_PATH" \
    --set agent.containerd.stateDir="$AGENT_CONTAINERD_STATE_DIR" \
    "${AGENT_CONTAINERD_OVERRIDE_SET_ARGS[@]}" \
    ${AGENT_CNI_EXTRA_CONF_DIR:+--set agent.cni.extraConfDir="$AGENT_CNI_EXTRA_CONF_DIR"}

  # A re-deploy within the same sprint reuses the same $TAG (see the image
  # import step above), so the rendered Deployment/DaemonSet spec is often
  # byte-identical to what's already applied — helm then sees NO diff and
  # creates no new pods, silently leaving the OLD binary running even though
  # the image tag on the nodes now points at freshly-built content. Force a
  # restart unconditionally so every deploy-podmotion call is guaranteed to
  # produce fresh pods, not just a "diff detected" one (confirmed live
  # 2026-07-14 as the root cause of a stale-binary false-negative gate).
  echo "==> Forcing rollout restart (same-tag deploys are otherwise a silent no-op)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n podmotion-system rollout restart deploy/podmotion-operator ds/podmotion-agent deploy/podmotion-scheduler

  echo "==> Waiting for rollout (failure/timeout is a real error, not swallowed)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n podmotion-system rollout status deploy/podmotion-operator --timeout=180s
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n podmotion-system rollout status ds/podmotion-agent --timeout=180s
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n podmotion-system rollout status deploy/podmotion-scheduler --timeout=180s

  # ── §2.2 deploy-time provenance ──────────────────────────────────────────────
  # Make provenance queryable from the cluster itself, not just from whoever ran the deploy:
  # stamp the resolved {revision, dirty, branch, tag} tuple as annotations on BOTH workloads,
  # and write the same tuple (plus each image's local digest) to deploy-manifest.json
  # alongside the kubeconfig, so a fresh session/orchestrator can read it without re-deploying.
  echo "==> Stamping deploy provenance (podmotion.io/deployed-revision, podmotion.io/deployed-branch)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n podmotion-system annotate deploy/podmotion-operator \
    "podmotion.io/deployed-revision=$GIT_SHA" "podmotion.io/deployed-branch=$GIT_BRANCH" --overwrite
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n podmotion-system annotate ds/podmotion-agent \
    "podmotion.io/deployed-revision=$GIT_SHA" "podmotion.io/deployed-branch=$GIT_BRANCH" --overwrite
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n podmotion-system annotate deploy/podmotion-scheduler \
    "podmotion.io/deployed-revision=$GIT_SHA" "podmotion.io/deployed-branch=$GIT_BRANCH" --overwrite

  local op_digest agent_digest scheduler_digest
  op_digest="$(docker image inspect --format '{{.Id}}' "$OP_IMG" 2>/dev/null || echo unknown)"
  agent_digest="$(docker image inspect --format '{{.Id}}' "$AGENT_IMG" 2>/dev/null || echo unknown)"
  scheduler_digest="$(docker image inspect --format '{{.Id}}' "$SCHEDULER_IMG" 2>/dev/null || echo unknown)"
  local manifest_out="$KVM_DIR/deploy-manifest.json"
  cat > "$manifest_out" <<EOF
{
  "revision": "$GIT_SHA",
  "dirty": $([[ "$GIT_DIRTY" -eq 1 ]] && echo true || echo false),
  "branch": "$GIT_BRANCH",
  "tag": "$TAG",
  "operator_image": "$OP_IMG",
  "operator_image_digest": "$op_digest",
  "agent_image": "$AGENT_IMG",
  "agent_image_digest": "$agent_digest",
  "scheduler_image": "$SCHEDULER_IMG",
  "scheduler_image_digest": "$scheduler_digest",
  "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
  echo "==> Wrote deploy provenance manifest: $manifest_out"

  if [[ "$skip_demo_apps" -eq 1 ]]; then
    echo "==> Skipping demo/test app deploy (--skip-demo-apps)."
  else
    echo "==> Deploying demo/test apps (podmotion-demo + migration-demo-stack)..."
    cmd_deploy_demo_apps "$TAG"
  fi

  echo "==> deploy-podmotion complete."
}

# ── deploy-podmotion-demo: podmotion-demo C&C/observability portal ──────────
# Wired into the standard flow (cmd_deploy_podmotion calls cmd_deploy_demo_apps,
# which calls this) and independently dispatchable as its own subcommand for a
# faster iteration loop while only the demo app itself is changing.
#
# DEVIATION FROM THE ORIGINAL "podmotion-demo as a Helm subchart of the
# podmotion release" plan: charts/podmotion/Chart.yaml lists podmotion-demo as
# a file:// dependency specifically so it CAN ride the same release/namespace
# as the operator (`--set podmotion-demo.enabled=true` on the main `helm
# upgrade --install podmotion ...`) — that is what hack/quickstart-kvm.sh and
# terraform/kubeadm-ec2-quickstart/bootstrap.sh both do, and was this task's
# starting plan. But charts/podmotion-demo/templates/clusterrole.yaml +
# clusterrolebinding.yaml are CLUSTER-SCOPED and NOT release-name-templated
# (literal names "podmotion-demo-api-role" / "podmotion-demo-api-rolebinding").
# CONFIRMED LIVE against the standing cluster this round: it already has a
# STANDALONE "podmotion-demo" Helm release (namespace podmotion-demo) from
# prior manual testing that owns those two cluster-scoped objects, and Helm
# refuses to let a second release (the subchart path runs under the
# "podmotion" release) take them over:
#   Error: UPGRADE FAILED: Unable to continue with update: ClusterRole
#   "podmotion-demo-api-role" in namespace "" exists and cannot be imported
#   into the current release: invalid ownership metadata; annotation
#   validation error: key "meta.helm.sh/release-name" must equal "podmotion":
#   current value is "podmotion-demo"; ... release-namespace ... current
#   value is "podmotion-demo" ...
# Forcing ownership away from that release risks disrupting whatever is
# already using it — possibly the exact live test-orchestration entry point
# CLAUDE.md rule 15 routes through — and is not a call this script gets to
# make unilaterally. charts/podmotion-demo/values.yaml's own header already
# documents standalone installation as a first-class supported mode ("It can
# also be installed standalone"), so that is what this function does: deploy
# it as its OWN release, in its OWN namespace — idempotent (helm
# upgrade --install on the same release name converges, does not duplicate),
# non-destructive, zero ownership conflict with what is already live, and it
# still satisfies "deploys automatically alongside core PodMotion."
cmd_deploy_podmotion_demo() {
  load_ips
  local TAG="${1:-${TAG:-kvm-dev}}"
  local WEB_IMG="podmotion-demo-web:$TAG"
  local API_IMG="podmotion-demo-api:$TAG"

  if [[ ! -d "$PODMOTION_DEMO_REPO" ]]; then
    echo "ERROR: deploy-podmotion-demo: podmotion-demo checkout not found at $PODMOTION_DEMO_REPO (override with PODMOTION_DEMO_REPO=<path>)." >&2
    exit 1
  fi
  local f
  for f in deploy/Dockerfile.backend deploy/Dockerfile.frontend; do
    if [[ ! -e "$PODMOTION_DEMO_REPO/$f" ]]; then
      echo "ERROR: deploy-podmotion-demo: $PODMOTION_DEMO_REPO is missing '$f'." >&2
      exit 1
    fi
  done

  local ctr_addr_flag
  ctr_addr_flag="$(detect_ctr_addr_flag "$CP1_IP")"

  echo "==> [podmotion-demo] Building web+api images from $PODMOTION_DEMO_REPO (TAG=$TAG)..."
  ( cd "$PODMOTION_DEMO_REPO" && \
    docker build -f deploy/Dockerfile.backend  -t "$API_IMG" . && \
    docker build -f deploy/Dockerfile.frontend -t "$WEB_IMG" . )

  echo "==> [podmotion-demo] Importing images into each node's k8s.io containerd namespace (no registry)..."
  local ip
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- import into $ip"
    # Same remove-before-import discipline as deploy-podmotion's own image
    # loop (a same-tag re-import's overwrite semantics are unverified on this
    # containerd version — see that loop's comment).
    nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images rm '$API_IMG' '$WEB_IMG' >/dev/null 2>&1 || true"
    docker save "$API_IMG" | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    docker save "$WEB_IMG" | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    if ! nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images ls -q | grep -q ':$TAG'"; then
      echo "ERROR: deploy-podmotion-demo: image tag ':$TAG' not present in k8s.io containerd namespace on node $ip after import." >&2
      exit 1
    fi
  done

  echo "==> [podmotion-demo] Helm upgrade --install (standalone release, namespace $PODMOTION_DEMO_NAMESPACE)..."
  KUBECONFIG="$KUBECONFIG_OUT" helm --kube-context="$KVM_CONTEXT" upgrade --install podmotion-demo charts/podmotion-demo \
    --namespace "$PODMOTION_DEMO_NAMESPACE" --create-namespace \
    --set enabled=true \
    --set web.image.repository=podmotion-demo-web --set web.image.tag="$TAG" --set web.image.pullPolicy=IfNotPresent \
    --set api.image.repository=podmotion-demo-api --set api.image.tag="$TAG" --set api.image.pullPolicy=IfNotPresent \
    --set api.podmotionNamespace=podmotion-system

  # Same same-tag-is-otherwise-a-silent-no-op reasoning as deploy-podmotion's
  # own forced restart — scoped to web+api only (the two images this function
  # actually rebuilds every call); postgres/redis/jaeger use fixed upstream
  # tags and don't need churning on every re-run.
  echo "==> [podmotion-demo] Forcing rollout restart of web+api (same-tag deploys are otherwise a silent no-op)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$PODMOTION_DEMO_NAMESPACE" rollout restart deploy/podmotion-demo-web deploy/podmotion-demo-api

  echo "==> [podmotion-demo] Waiting for rollout (failure/timeout is a real error, not swallowed)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$PODMOTION_DEMO_NAMESPACE" rollout status deploy/podmotion-demo-web --timeout=180s
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$PODMOTION_DEMO_NAMESPACE" rollout status deploy/podmotion-demo-api --timeout=180s
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$PODMOTION_DEMO_NAMESPACE" rollout status deploy/podmotion-demo-postgres --timeout=180s
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$PODMOTION_DEMO_NAMESPACE" rollout status deploy/podmotion-demo-redis --timeout=180s
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$PODMOTION_DEMO_NAMESPACE" rollout status deploy/podmotion-demo-jaeger --timeout=180s

  # ── Local access: always via the idempotent helper, never a hand-typed
  # `kubectl port-forward` ────────────────────────────────────────────────
  # Recurring bug (hit at least 3 times in one session): a manually-typed port-forward after this
  # function returns has repeatedly ended up pointed at svc/podmotion-demo-api
  # (backend only, 404s on "/") instead of svc/podmotion-demo-web (the
  # frontend, which also reverse-proxies /api/* — the only correct target for
  # localhost:8080). deploy/port-forward-web.sh in the podmotion-demo repo
  # removes that decision entirely: it hardcodes svc/podmotion-demo-web,
  # kills any existing forward pointed at either service (matched on the
  # actual service name + namespace in argv, not on the bare port number, so
  # a stale wrong-target forward can't survive undetected), and verifies with
  # a real curl that the portal's HTML comes back before it returns.
  if [[ -x "$PODMOTION_DEMO_REPO/deploy/port-forward-web.sh" ]]; then
    echo "==> [podmotion-demo] Setting up localhost:8080 -> svc/podmotion-demo-web via deploy/port-forward-web.sh..."
    NAMESPACE="$PODMOTION_DEMO_NAMESPACE" KUBECONFIG="$KUBECONFIG_OUT" \
      "$PODMOTION_DEMO_REPO/deploy/port-forward-web.sh"
  else
    echo "==> [podmotion-demo] Ready. Access:"
    echo "      WARNING: deploy/port-forward-web.sh not found at $PODMOTION_DEMO_REPO/deploy/ — falling back to the raw command."
    echo "      Do NOT substitute svc/podmotion-demo-api here — that Service has no '/' route and 404s (see SESSION-HANDOFF-2026-07-24.md §5)."
    echo "      kubectl port-forward -n $PODMOTION_DEMO_NAMESPACE svc/podmotion-demo-web 8080:80   # portal -> http://localhost:8080"
  fi
  echo "      Jaeger UI is NodePort-reachable directly, no port-forward needed: http://<any-node-ip>:30686"
}

# ── deploy-migration-demo-stack: nginx/redis/postgres test workload ─────────
# Standalone chart living in the sibling podmotion-migration-demo-app repo
# (charts/migration-demo-stack/Chart.yaml is explicit: "NOT the podmotion-demo
# control portal and NOT part of the governed PodMotion operator datapath" —
# there is no subchart relationship to this repo's own charts/podmotion/ to
# preserve, unlike podmotion-demo). Deployed as its own release + namespace,
# matching what is already live on this cluster from prior manual testing.
#
# postgres has a REAL PVC (charts/migration-demo-stack/templates/pvc-postgres.yaml,
# 5Gi hard cap) with no explicit storageClassName set by default
# (values.yaml: storageClassName: "" -> cluster default StorageClass) — hard
# fail before building or deploying anything if no default StorageClass
# exists, rather than let the PVC hang Pending silently (zero-tech-debt: this
# must be a real, visible error). Run 'provision-longhorn' first, or set
# MIGRATION_DEMO_STORAGE_CLASS to an explicit StorageClass name to bypass the
# "must be cluster-default" requirement entirely.
cmd_deploy_migration_demo() {
  load_ips
  local TAG="${1:-${TAG:-kvm-dev}}"
  local WEB_IMG="migration-demo-web:$TAG"
  local BACKEND_IMG="migration-demo-backend:$TAG"

  if [[ ! -d "$MIGRATION_DEMO_REPO" ]]; then
    echo "ERROR: deploy-migration-demo-stack: checkout not found at $MIGRATION_DEMO_REPO (override with MIGRATION_DEMO_REPO=<path>)." >&2
    exit 1
  fi
  local f
  for f in deploy/Dockerfile.backend deploy/Dockerfile.web charts/migration-demo-stack/Chart.yaml; do
    if [[ ! -e "$MIGRATION_DEMO_REPO/$f" ]]; then
      echo "ERROR: deploy-migration-demo-stack: $MIGRATION_DEMO_REPO is missing '$f'." >&2
      exit 1
    fi
  done

  # ADR-0424 D2 (fixed): resolve the EFFECTIVE StorageClass postgres will
  # actually bind to, in the SAME order Helm's own precedence + the chart's
  # values.yaml actually produce it:
  #   1. MIGRATION_DEMO_STORAGE_CLASS override, if set (passed through to helm
  #      via --set postgres.persistence.storageClassName=... below).
  #   2. Else, the chart's OWN postgres.persistence.storageClassName default
  #      (resolve_chart_postgres_storageclass, above) — ADR-0424's D1 fix set
  #      this to the fixed value "longhorn-migratable" in
  #      charts/migration-demo-stack/values.yaml, so with no override postgres
  #      binds to THAT, never to whatever the cluster calls its default.
  #   3. Only if neither of the above yields a value (e.g. a future chart
  #      regression back to storageClassName: "") does this fall back to the
  #      cluster's default StorageClass, which is what postgres would actually
  #      bind to in that case.
  # Validating against the cluster-default StorageClass unconditionally (the
  # pre-fix behavior) is wrong on THIS standing cluster specifically: its
  # default class is "longhorn" (non-migratable), while postgres actually
  # binds to "longhorn-migratable" (migratable, not default) — so the old
  # resolution validated the wrong class and failed closed on an otherwise
  # correctly-configured deploy. This is a real, visible fail-fast for the H6
  # mechanism-map defect: proving A StorageClass merely EXISTS is not the same
  # as proving the one postgres will actually use can support Longhorn's
  # dual-engine live migration.
  local resolved_sc="${MIGRATION_DEMO_STORAGE_CLASS:-}"
  if [[ -z "$resolved_sc" ]]; then
    resolved_sc="$(resolve_chart_postgres_storageclass "$MIGRATION_DEMO_REPO/charts/migration-demo-stack" || true)"
    if [[ -n "$resolved_sc" ]]; then
      echo "  -- no MIGRATION_DEMO_STORAGE_CLASS override; chart default postgres.persistence.storageClassName: $resolved_sc"
    fi
  fi
  if [[ -z "$resolved_sc" ]]; then
    resolved_sc="$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" get storageclass \
      -o jsonpath='{.items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")].metadata.name}' 2>/dev/null || true)"
    if [[ -z "$resolved_sc" ]]; then
      echo "ERROR: deploy-migration-demo-stack: neither MIGRATION_DEMO_STORAGE_CLASS nor the chart's postgres.persistence.storageClassName default is set, and no default StorageClass exists in the cluster — migration-demo-stack's postgres PVC needs one to bind, and would otherwise hang Pending silently." >&2
      echo "       Run 'bash hack/kvm-cluster.sh provision-longhorn' first, or set MIGRATION_DEMO_STORAGE_CLASS=<name> to target an explicit StorageClass." >&2
      exit 1
    fi
    echo "  -- no override and no chart default; falling back to cluster default StorageClass: $resolved_sc"
  fi
  # §P-VERIFY-relevant sanity check: on this standing cluster, with no
  # MIGRATION_DEMO_STORAGE_CLASS override set, this MUST resolve to the
  # chart's current default ("longhorn-migratable"), never to the cluster's
  # separately-configured default StorageClass ("longhorn") — that divergence
  # is exactly the bug this fix closes. This does not hard-fail (a deliberate
  # future chart change is legitimate); it is a visible signal if the
  # resolution path silently reverts to the old, wrong behavior.
  if [[ -z "${MIGRATION_DEMO_STORAGE_CLASS:-}" && "$resolved_sc" != "longhorn-migratable" ]]; then
    echo "  -- NOTE: resolved StorageClass '$resolved_sc' differs from the expected chart default 'longhorn-migratable' — confirm charts/migration-demo-stack/values.yaml postgres.persistence.storageClassName if this is unexpected."
  fi
  assert_storageclass_tier1_migratable "$resolved_sc" "migration-demo-stack postgres"

  local ctr_addr_flag
  ctr_addr_flag="$(detect_ctr_addr_flag "$CP1_IP")"

  echo "==> [migration-demo-stack] Building web(nginx)+backend images from $MIGRATION_DEMO_REPO (TAG=$TAG)..."
  ( cd "$MIGRATION_DEMO_REPO" && \
    docker build -f deploy/Dockerfile.backend -t "$BACKEND_IMG" . && \
    docker build -f deploy/Dockerfile.web      -t "$WEB_IMG" . )

  echo "==> [migration-demo-stack] Importing images into each node's k8s.io containerd namespace (no registry)..."
  local ip
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- import into $ip"
    nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images rm '$BACKEND_IMG' '$WEB_IMG' >/dev/null 2>&1 || true"
    docker save "$BACKEND_IMG" | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    docker save "$WEB_IMG"     | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    if ! nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images ls -q | grep -q ':$TAG'"; then
      echo "ERROR: deploy-migration-demo-stack: image tag ':$TAG' not present in k8s.io containerd namespace on node $ip after import." >&2
      exit 1
    fi
  done

  echo "==> [migration-demo-stack] Helm upgrade --install (standalone chart+release, namespace $MIGRATION_DEMO_NAMESPACE)..."
  KUBECONFIG="$KUBECONFIG_OUT" helm --kube-context="$KVM_CONTEXT" upgrade --install migration-demo "$MIGRATION_DEMO_REPO/charts/migration-demo-stack" \
    --namespace "$MIGRATION_DEMO_NAMESPACE" --create-namespace \
    --set web.nginx.image.repository=migration-demo-web --set web.nginx.image.tag="$TAG" --set web.nginx.image.pullPolicy=IfNotPresent \
    --set web.app.image.repository=migration-demo-backend --set web.app.image.tag="$TAG" --set web.app.image.pullPolicy=IfNotPresent \
    ${MIGRATION_DEMO_STORAGE_CLASS:+--set postgres.persistence.storageClassName="$MIGRATION_DEMO_STORAGE_CLASS"}

  echo "==> [migration-demo-stack] Forcing rollout restart of web (same-tag deploys are otherwise a silent no-op; redis/postgres use fixed upstream images and don't need churning)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$MIGRATION_DEMO_NAMESPACE" rollout restart deploy/migration-demo-web

  echo "==> [migration-demo-stack] Waiting for rollout (failure/timeout is a real error, not swallowed)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$MIGRATION_DEMO_NAMESPACE" rollout status deploy/migration-demo-web --timeout=180s
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$MIGRATION_DEMO_NAMESPACE" rollout status deploy/migration-demo-redis --timeout=180s
  echo "  -- waiting for postgres (PVC bind can take longer than redis/web)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$MIGRATION_DEMO_NAMESPACE" rollout status deploy/migration-demo-postgres --timeout=240s

  echo "==> [migration-demo-stack] Ready. Access:"
  echo "      kubectl port-forward -n $MIGRATION_DEMO_NAMESPACE svc/migration-demo-web 8080:8080   # -> http://localhost:8080 (basic auth user 'demo', default password 'migration-demo')"
}

# ── deploy-demo-apps: both demo/test apps, in the proven order (podmotion-demo ──
# then migration-demo-stack — matches quickstart-kvm.sh/bootstrap.sh: core
# first, demo apps after core is healthy). This is what cmd_deploy_podmotion
# calls automatically; also dispatchable standalone for a faster iteration
# loop when only the demo apps are changing (skips the operator/agent/
# scheduler build+deploy entirely).
cmd_deploy_demo_apps() {
  local TAG="${1:-${TAG:-kvm-dev}}"
  cmd_deploy_podmotion_demo "$TAG"
  cmd_deploy_migration_demo "$TAG"
}

# ── verify-deployed-revision: ADR-0325-remediation Fix 1 §2.3 test-orchestration-time gate ────
# The mechanical fix for "every reproduction this session ran against the wrong code without
# anyone noticing": read podmotion.io/deployed-revision off the LIVE operator Deployment and
# compare it against 'git rev-parse HEAD' of the branch under test (this worktree). A mismatch
# is a hard precondition failure — report it the same way a dirty tree or a not-Ready node
# would be, BEFORE any migration is attempted through the podmotion-demo API. Intended to be
# run by the orchestrator as the third precondition clause (alongside "main clean" and
# "3/3 Ready"), and callable standalone for manual verification.
cmd_verify_deployed_revision() {
  load_ips
  local expect_dirty_ok=0
  local arg
  for arg in "$@"; do
    case "$arg" in
      --allow-dirty) expect_dirty_ok=1 ;;
      *) echo "ERROR: verify-deployed-revision: unrecognized argument '$arg' (only --allow-dirty is accepted)" >&2; exit 2 ;;
    esac
  done

  local want_sha
  want_sha="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if [[ "$want_sha" == "unknown" ]]; then
    echo "ERROR: verify-deployed-revision: could not resolve 'git rev-parse HEAD' for this worktree." >&2
    exit 1
  fi
  if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
    if [[ "$expect_dirty_ok" -ne 1 ]]; then
      echo "ERROR: verify-deployed-revision: worktree under test is dirty — the deployed image (if any) cannot be honestly matched to uncommitted source. Commit/stash, or pass --allow-dirty to compare against '<sha>-dirty' semantics." >&2
      exit 1
    fi
    want_sha="${want_sha}-dirty"
  fi

  local got_sha
  got_sha="$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n podmotion-system get deploy/podmotion-operator \
    -o jsonpath='{.metadata.annotations.podmotion\.io/deployed-revision}' 2>/dev/null || echo "")"
  if [[ -z "$got_sha" ]]; then
    echo "ERROR: verify-deployed-revision: live operator Deployment has no podmotion.io/deployed-revision annotation — it was deployed by a version of this script predating the provenance gate, or deploy-podmotion has never run against this cluster. Re-run 'deploy-podmotion'." >&2
    exit 1
  fi
  if [[ "$got_sha" != "$want_sha" ]]; then
    echo "ERROR: verify-deployed-revision: MISMATCH — cluster is serving revision '$got_sha' but the worktree under test is '$want_sha'. This is precisely the failure mode that produced false migration-failure reproductions before (a stale/wrong-branch image on the cluster). Re-run 'deploy-podmotion' against this worktree before testing." >&2
    exit 1
  fi
  echo "==> OK: cluster-deployed revision '$got_sha' matches worktree HEAD."
}

# ── wipe: clean k8s + PodMotion STATE on the VMs, WITHOUT destroying VMs ──────
cmd_wipe() {
  assert_no_vm_destruction
  load_ips
  echo "==> WIPE: removing PodMotion + migration state (VMs persist)..."
  # In-cluster: uninstall helm release, delete PodMigration CRs, namespace.
  KUBECONFIG="$KUBECONFIG_OUT" helm --kube-context="$KVM_CONTEXT" uninstall podmotion -n podmotion-system 2>/dev/null || true
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" delete podmigrations.podmotion.io --all -A 2>/dev/null || true
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" delete ns podmotion-system 2>/dev/null || true

  # Demo/test apps wired into the standard deploy flow (cmd_deploy_demo_apps)
  # are their own standalone releases in their own namespaces (see
  # cmd_deploy_podmotion_demo's header comment for why podmotion-demo is NOT
  # part of the podmotion release/namespace above) — clean them symmetrically
  # so a wipe leaves no PodMotion-adjacent state behind, matching this
  # command's existing "state on the VMs, not the VMs" contract.
  echo "==> WIPE: removing demo/test app releases (podmotion-demo, migration-demo)..."
  KUBECONFIG="$KUBECONFIG_OUT" helm --kube-context="$KVM_CONTEXT" uninstall podmotion-demo -n "$PODMOTION_DEMO_NAMESPACE" 2>/dev/null || true
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" delete ns "$PODMOTION_DEMO_NAMESPACE" 2>/dev/null || true
  KUBECONFIG="$KUBECONFIG_OUT" helm --kube-context="$KVM_CONTEXT" uninstall migration-demo -n "$MIGRATION_DEMO_NAMESPACE" 2>/dev/null || true
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" delete ns "$MIGRATION_DEMO_NAMESPACE" 2>/dev/null || true

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
  KUBECONFIG="$KUBECONFIG_OUT" helm --kube-context="$KVM_CONTEXT" upgrade --install nfs-subdir-external-provisioner \
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
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$NFS_PROVISIONER_NS" rollout status \
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
  mkdir -p "$LH_IMG_DIR"

  echo "==> [1/5] Ensure a $LH_DISK_SIZE $LH_DISK_TARGET disk on each VM (attach only — never destroy)..."
  local vm img
  for vm in "${PM_VMS[@]}"; do
    img="$LH_IMG_DIR/${vm}-longhorn.qcow2"
    if virsh domblklist "$vm" | awk '{print $1}' | grep -qx "$LH_DISK_TARGET"; then
      echo "  -- $vm already has $LH_DISK_TARGET; skipping create+attach"
      continue
    fi
    if [[ ! -f "$img" ]]; then
      echo "  -- creating $img ($LH_DISK_SIZE)"
      qemu-img create -f qcow2 "$img" "$LH_DISK_SIZE"
    fi
    echo "  -- attaching $img to $vm as $LH_DISK_TARGET (persistent + live)"
    # No chown needed: libvirtd runs as root and applies dynamic_ownership at
    # attach time (Ubuntu default), so it re-owns the file for the qemu
    # process itself — chad only needs to be able to create/read it first.
    virsh attach-disk "$vm" "$img" "$LH_DISK_TARGET" \
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
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" apply -f "$LH_MANIFEST"
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$LH_NAMESPACE" rollout status ds/longhorn-manager --timeout=300s
  # Let Longhorn also use the control-plane node's disk: tolerate the cp taint and
  # add the toleration to the longhorn-manager DaemonSet (the setting alone does not
  # patch the manager DS). Idempotent.
  #
  # The taint-toleration Setting object is only created by longhorn-manager itself
  # after it starts, as part of seeding its default settings from its ConfigMap —
  # there is a real race between "DaemonSet rollout reports Ready" and "the Setting
  # CR actually exists yet." The old `|| true` here silently swallowed that race: a
  # NotFound patch failure left the setting permanently empty, which made Longhorn's
  # replica scheduler refuse to place ANY replica on pm-cp1 for EVERY future volume
  # (not a transient error — durable and silent) even though pm-cp1's disk was
  # perfectly healthy and schedulable. Confirmed live 2026-07-17: a volume stuck
  # "degraded" from the moment it was created, unrelated to disk space or the disk's
  # own Ready/Schedulable conditions. Retry with a real wait instead of swallowing.
  local lh_patch_tries=0
  until KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$LH_NAMESPACE" patch setting taint-toleration \
      --type=merge -p '{"value":"node-role.kubernetes.io/control-plane:NoSchedule"}' 2>/dev/null; do
    lh_patch_tries=$((lh_patch_tries + 1))
    if [[ $lh_patch_tries -ge 30 ]]; then
      echo "ERROR: taint-toleration Setting never became patchable after 30 tries (~60s)." >&2
      echo "       Longhorn replicas will silently refuse to schedule onto pm-cp1 without this." >&2
      exit 1
    fi
    sleep 2
  done
  local lh_applied
  lh_applied="$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$LH_NAMESPACE" get setting taint-toleration -o jsonpath='{.value}')"
  if [[ "$lh_applied" != "node-role.kubernetes.io/control-plane:NoSchedule" ]]; then
    echo "ERROR: taint-toleration Setting patch reported success but value is '$lh_applied', not the expected toleration." >&2
    exit 1
  fi
  echo "  -- taint-toleration setting confirmed: $lh_applied"
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$LH_NAMESPACE" patch ds longhorn-manager --type=json \
    -p '[{"op":"add","path":"/spec/template/spec/tolerations","value":[{"key":"node-role.kubernetes.io/control-plane","operator":"Exists","effect":"NoSchedule"}]}]' || true
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$LH_NAMESPACE" rollout status ds/longhorn-manager --timeout=300s
  echo "  -- waiting for all longhorn-system pods Ready"
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$LH_NAMESPACE" wait --for=condition=Ready pods --all --timeout=300s || true

  echo "==> [5/5] Ensure StorageClasses ($LH_STORAGE_CLASS default RWO; $LH_MIGRATABLE_SC RWX live-migration)..."
  # The default $LH_STORAGE_CLASS SC ships with the Longhorn manifest. Create the
  # RWX live-migration SC: migratable=true lets the volume attach on the destination
  # node while still attached on the source during a PodMotion live migration.
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" apply -f - <<YAML
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
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$LH_NAMESPACE" get nodes.longhorn.io
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
    # Same containerd-socket detection as cmd_deploy_podmotion's ctr_addr_flag
    # (see detect_ctr_addr_flag above) — a plain `ctr images import` with no
    # -a flag lands on the wrong (system) containerd on a k3s/RKE2 node,
    # leaving the CNI images invisible to kubelet even though `ctr images ls`
    # on the wrong socket falsely shows them present.
    local ctr_addr_flag
    ctr_addr_flag="$(detect_ctr_addr_flag "$ip")"
    docker save "$CILIUM_IMG"          | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    docker save "$CILIUM_OPERATOR_IMG" | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    if ! nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images ls -q | grep -q 'cilium:v${CILIUM_VERSION}'"; then
      echo "ERROR: cilium:v${CILIUM_VERSION} not present in k8s.io containerd namespace on node $ip after import." >&2
      exit 1
    fi
    if ! nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images ls -q | grep -q 'operator-generic:v${CILIUM_VERSION}'"; then
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
  KUBECONFIG="$KUBECONFIG_OUT" helm --kube-context="$KVM_CONTEXT" upgrade --install cilium cilium/cilium \
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
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" rollout status ds/cilium --timeout=300s
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" rollout status deploy/cilium-operator --timeout=300s
  fi
  echo "==> Cilium ready. CNI swap done at the install layer; run the cutover to remove Flannel/kube-proxy."
}

# ── multi-pool IPAM re-provision (ADR-0324 verification check C escalation) ──
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
  KUBECONFIG="$KUBECONFIG_OUT" helm --kube-context="$KVM_CONTEXT" upgrade --install cilium cilium/cilium \
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
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" apply -f - <<'EOF'
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
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" rollout status ds/cilium --timeout=300s
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" rollout status deploy/cilium-operator --timeout=300s
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
    # Same containerd-socket detection as cmd_deploy_podmotion/cmd_provision_cilium
    # (see detect_ctr_addr_flag above) — required on k3s/RKE2 nodes.
    local ctr_addr_flag
    ctr_addr_flag="$(detect_ctr_addr_flag "$ip")"
    for img in "$CALICO_OPERATOR_IMG" "$CALICO_NODE_IMG" "$CALICO_KUBE_CONTROLLERS_IMG" \
               "$CALICO_CNI_IMG" "$CALICO_CSI_IMG" "$CALICO_CSI_REGISTRAR_IMG"; do
      docker save "$img" | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    done
    for tag in "operator:v${CALICO_OPERATOR_VERSION}" "node:v${CALICO_VERSION}" \
               "kube-controllers:v${CALICO_VERSION}" "cni:v${CALICO_VERSION}" \
               "csi:v${CALICO_VERSION}" "node-driver-registrar:v${CALICO_VERSION}"; do
      if ! nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images ls -q | grep -q '${tag}'"; then
        echo "ERROR: ${tag} not present in k8s.io containerd namespace on node $ip after import." >&2
        exit 1
      fi
    done
  done

  echo "==> [2/3] helm install the Tigera Operator, then apply the Installation CR (single non-strict-affinity IPPool, VXLAN, bpfEnabled=false)..."
  helm repo add projectcalico https://docs.tigera.io/calico/charts >/dev/null 2>&1 || true
  helm repo update projectcalico >/dev/null 2>&1 || true
  KUBECONFIG="$KUBECONFIG_OUT" helm --kube-context="$KVM_CONTEXT" upgrade --install calico projectcalico/tigera-operator \
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
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" apply -f - <<YAML
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

  echo "==> [3/3] Waiting for the Tigera Operator to reconcile the Installation CR (namespace $CALICO_NAMESPACE)..."
  # The Installation CR apply above only asks the Tigera Operator to act; the
  # operator creates the $CALICO_NAMESPACE namespace (and everything in it)
  # asynchronously as it reconciles. Running rollout-status before that
  # namespace exists fails with a hard NotFound instead of waiting, so poll
  # for the namespace first. Bounded wait, not a fixed sleep and not an
  # infinite wait.
  local waited=0
  local calico_ns_timeout=120
  until KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" get namespace "$CALICO_NAMESPACE" >/dev/null 2>&1; do
    if (( waited >= calico_ns_timeout )); then
      echo "ERROR: namespace $CALICO_NAMESPACE did not appear within ${calico_ns_timeout}s — Tigera Operator has not reconciled the Installation CR. Check 'kubectl -n $CALICO_OPERATOR_NAMESPACE logs deploy/tigera-operator'." >&2
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo "  -- namespace $CALICO_NAMESPACE present after ${waited}s"

  echo "==> Waiting for Calico to come up (rollout status on calico-node / calico-kube-controllers)..."
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CALICO_NAMESPACE" rollout status ds/calico-node --timeout=300s
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CALICO_NAMESPACE" rollout status deploy/calico-kube-controllers --timeout=300s
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
# unlike the Cilium cutover, which supersedes it).
#
# Removing the Cilium/Flannel Kubernetes API objects does NOT remove the
# files Cilium's/Flannel's own install-cni init containers already wrote to
# each host's /etc/cni/net.d/ — those persist on disk independently, so a
# per-node SSH cleanup step is required (step [3/4] below). Two host-level
# conditions have been observed on this standing cluster and both are
# handled: (a) a leftover ACTIVE (non-.cilium_bak) cilium/flannel conflist
# left behind after the k8s objects are gone, which must be removed so it
# stops shadowing Calico's, and (b) Cilium's install-cni logic renames
# *any* pre-existing conflist it finds to a *.cilium_bak suffix before
# writing its own active file — including, if Calico was provisioned
# before Cilium's objects were deleted, Calico's OWN conflist. That leaves
# Calico's real conflist sitting inactive as e.g.
# "10-calico.conflist.cilium_bak", so simply deleting the stale Cilium file
# would leave the node with NO active CNI conflist at all. Step [3/4]
# restores it (strips the .cilium_bak suffix) only when no active Calico
# conflist is already present, and never touches genuine Flannel/Cilium
# backups. Finally step [4/4] confirms each node's /etc/cni/net.d contains
# exactly the Calico conflist as the active config. Idempotent and safe to
# re-run. Does NOT modify cmd_cutover, cmd_provision_cilium,
# cmd_provision_cilium_multipool, or cmd_reset_cluster. VMs never touched
# (no virsh destroy/undefine — only files under /etc/cni/net.d/ on each
# node are touched, via SSH).
cmd_cutover_calico() {
  assert_no_vm_destruction
  load_ips

  echo "==> [1/4] Confirming Calico is Ready on all nodes before removing the previously-active CNI..."
  local ready desired
  ready=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CALICO_NAMESPACE" get ds calico-node -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)
  desired=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CALICO_NAMESPACE" get ds calico-node -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo -1)
  if [[ "$ready" -lt 1 || "$ready" != "$desired" ]]; then
    echo "ERROR: calico-node DaemonSet not fully Ready ($ready/$desired) — refusing to remove the previously-active CNI (cluster would be left with no CNI)." >&2
    exit 1
  fi
  echo "  -- calico-node DaemonSet Ready: $ready/$desired"

  echo "==> [2/4] Removing the previously-active CNI's remnants (Flannel and/or Cilium, whichever is present)..."
  if KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" get ns kube-flannel >/dev/null 2>&1; then
    echo "  -- removing Flannel remnants"
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n kube-flannel delete daemonset kube-flannel-ds --ignore-not-found
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" delete ns kube-flannel --ignore-not-found
  else
    echo "  -- no kube-flannel namespace present"
  fi
  if KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" get ds cilium >/dev/null 2>&1; then
    echo "  -- removing Cilium remnants (DaemonSet/Deployment only — Cilium script functions in this file are untouched)"
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" delete daemonset cilium --ignore-not-found
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" delete deployment cilium-operator --ignore-not-found
  else
    echo "  -- no active Cilium DaemonSet present"
  fi

  echo "==> [3/4] Cleaning up stale previously-active-CNI conflist files left on-disk on each node (K8s object deletion above does not remove these)..."
  # Deliberately narrow: only ever removes a file matching *cilium*.conflist or
  # *flannel*.conflist that is NOT already a .cilium_bak/.bak backup (i.e. would
  # still be read by the CNI plugin manager), and only ever restores Calico's own
  # conflist from a *calico*.conflist.cilium_bak backup when no active Calico
  # conflist is already present. Never touches any other file in the directory
  # (genuine Flannel .cilium_bak backups, calico-kubeconfig, etc. are preserved).
  local cni_cleanup_script
  cni_cleanup_script='
set -e
cd /etc/cni/net.d
shopt -s nullglob
echo "     -- before cleanup:"; sudo ls -la | sed "s/^/     /"
for f in *cilium*.conflist *flannel*.conflist; do
  case "$f" in
    *.cilium_bak|*.bak) continue ;;
  esac
  echo "     -- removing stale active conflist: $f"
  sudo rm -f -- "$f"
done
active_calico=0
for f in *calico*.conflist; do
  case "$f" in
    *.cilium_bak|*.bak) continue ;;
  esac
  active_calico=1
done
if [[ "$active_calico" -eq 0 ]]; then
  for f in *calico*.conflist.cilium_bak; do
    newname="${f%.cilium_bak}"
    echo "     -- restoring Calico conflist from backup: $f -> $newname"
    sudo mv -f -- "$f" "$newname"
  done
fi
# Remove stray calico-kubeconfig duplicates (e.g. calico-kubeconfig.bak/.orig)
# left behind by a previous run. Never matches the canonical "calico-kubeconfig"
# file itself (glob requires a further suffix), so the file the Calico
# conflist references is never touched.
for f in calico-kubeconfig.*; do
  echo "     -- removing stray calico-kubeconfig duplicate: $f"
  sudo rm -f -- "$f"
done
echo "     -- after cleanup:"; sudo ls -la | sed "s/^/     /"
'
  local ip
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    echo "  -- $ip: cleaning /etc/cni/net.d/"
    # /etc/cni/net.d is root-owned (chad cannot even 'cd' into it), so the whole
    # compound script must run as root in one go. sudo does not carry across
    # shell operators like && or across a persistent 'cd' in a later command, so
    # individual 'sudo rm'/'sudo mv' calls after an unprivileged 'cd' still fail —
    # the entire script body is wrapped in a single 'sudo bash -c' invocation.
    nsh "$ip" "sudo bash -c '$cni_cleanup_script'"
  done

  echo "==> [4/4] Verifying each node's CNI conf dir contains only the Calico conflist..."
  local confs
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
# verification check B / verification check 0 precondition). Idempotent and order-safe: verifies Cilium
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
  ready=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" get ds cilium -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)
  local desired
  desired=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" get ds cilium -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo -1)
  if [[ "$ready" -lt 1 || "$ready" != "$desired" ]]; then
    echo "ERROR: Cilium DaemonSet not fully Ready ($ready/$desired) — refusing to remove Flannel/kube-proxy (cluster would be left with no CNI)." >&2
    exit 1
  fi
  echo "  -- cilium DaemonSet Ready: $ready/$desired"

  echo "==> [2/3] Removing Flannel remnants (if any)..."
  if KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" get ns kube-flannel >/dev/null 2>&1; then
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n kube-flannel delete daemonset kube-flannel-ds --ignore-not-found
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" delete ns kube-flannel --ignore-not-found
  else
    echo "  -- no kube-flannel namespace present (already clean)"
  fi

  echo "==> [3/3] Removing kube-proxy remnants (if any — Cilium kubeProxyReplacement=true supersedes it)..."
  if KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n kube-system get ds kube-proxy >/dev/null 2>&1; then
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n kube-system delete daemonset kube-proxy --ignore-not-found
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n kube-system delete configmap kube-proxy --ignore-not-found
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

# ── provision-cilium-rke2 / cutover-canal-rke2 (sprint52, RKE2-specific) ────
# RKE2 ships its own default CNI (canal) via a server-side --cni flag and its
# addon-manager (HelmChart CRs reconciled from /var/lib/rancher/rke2/server/
# manifests/, NOT the same install path cmd_provision_cilium/cmd_cutover use
# on the kubeadm substrate). Confirmed LIVE this round against a real RKE2
# v1.35.6+rke2r1 cluster (sprint52-rke2-cilium), not assumed from k3s's
# --flannel-backend=none idiom (a DIFFERENT distribution, per the RKE2 header
# comment above RKE2_VERSION):
#   - RKE2's own mechanism to disable the built-in CNI is `cni: none` in
#     /etc/rancher/rke2/config.yaml on the SERVER node, followed by a
#     `systemctl restart rke2-server`. On restart, RKE2's addon-manager
#     regenerates the desired manifest set, drops rke2-canal.yaml (since
#     canal is no longer selected), deletes the owned HelmChart CR, and the
#     helm-controller runs a real `helm uninstall` — this is the clean,
#     RKE2-native equivalent of cmd_cutover_calico's k8s-object-removal step,
#     not a manual `kubectl delete ds`.
#   - kube-proxy on RKE2 is a PER-NODE static pod (not a DaemonSet — unlike
#     kubeadm), controlled independently by each node's OWN config.yaml via
#     `disable-kube-proxy: true` + a restart of that node's own rke2-server
#     (control-plane) or rke2-agent (workers) service. Must be set on ALL
#     THREE nodes, not just the server.
#   - RKE2's own pod CIDR default is 10.42.0.0/16 (/24 per node) — DIFFERENT
#     from the kubeadm substrate's hardcoded $POD_CIDR (10.244.0.0/16).
#     RKE2_CILIUM_POD_CIDR below is intentionally a SEPARATE variable, not a
#     rebind of the kubeadm-only $POD_CIDR global, to avoid silently breaking
#     the kubeadm path.
# Same install-then-verify-then-cutover discipline as cmd_provision_cilium/
# cmd_cutover_calico: Cilium is installed and confirmed Ready BEFORE canal is
# touched, so a stalled Cilium rollout never leaves the cluster CNI-less.
# Does NOT modify cmd_provision_cilium, cmd_cutover, cmd_provision_calico,
# cmd_cutover_calico, or cmd_reset_cluster_rke2. VMs never touched.
RKE2_CILIUM_POD_CIDR="${RKE2_CILIUM_POD_CIDR:-10.42.0.0/16}"

cmd_provision_cilium_rke2() {
  assert_no_vm_destruction
  load_ips
  CILIUM_APISERVER_HOST="${CILIUM_APISERVER_HOST:-$CP1_IP}"

  echo "==> [1/2] helm install cilium/cilium $CILIUM_CHART_VERSION on RKE2 (cluster-pool over RKE2's OWN pod CIDR $RKE2_CILIUM_POD_CIDR, geneve, kube-proxy-replacement)..."
  # Images are expected to already be resident (imported by an earlier
  # provision-cilium run on this same standing cluster, or pre-import them
  # the same way cmd_provision_cilium does before running this). This
  # function does not repeat the pre-import loop to avoid a second silent
  # image-provenance path; run provision-cilium's [1/3] step manually first
  # if starting from a node that has never pulled Cilium images.
  helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
  helm repo update cilium >/dev/null 2>&1 || true
  KUBECONFIG="$KUBECONFIG_OUT" helm --kube-context="$KVM_CONTEXT" upgrade --install cilium cilium/cilium \
    --version "$CILIUM_CHART_VERSION" --namespace "$CILIUM_NAMESPACE" \
    --set ipam.mode=cluster-pool \
    --set ipam.operator.clusterPoolIPv4PodCIDRList="{$RKE2_CILIUM_POD_CIDR}" \
    --set ipam.operator.clusterPoolIPv4MaskSize=24 \
    --set routingMode=tunnel \
    --set tunnelProtocol=geneve \
    --set endpointRoutes.enabled=true \
    --set kubeProxyReplacement=true \
    --set k8sServiceHost="$CILIUM_APISERVER_HOST" \
    --set k8sServicePort="$CILIUM_APISERVER_PORT" \
    --set bpf.masquerade=true \
    --set enableIPv4Masquerade=true \
    --set ipv4NativeRoutingCIDR="$RKE2_CILIUM_POD_CIDR" \
    --set image.pullPolicy=IfNotPresent \
    --set operator.image.pullPolicy=IfNotPresent \
    --set operator.replicas=1

  echo "==> [2/2] Waiting for Cilium to come up (cilium status --wait)..."
  if command -v cilium >/dev/null 2>&1; then
    KUBECONFIG="$KUBECONFIG_OUT" cilium status --wait
  else
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" rollout status ds/cilium --timeout=300s
    KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" rollout status deploy/cilium-operator --timeout=300s
  fi
  echo "==> Cilium ready alongside canal (both active — canal's install-cni already renamed its own conflist to *.cilium_bak on each node). Run cutover-canal-rke2 to disable canal via RKE2's own mechanism."
}

cmd_cutover_canal_rke2() {
  assert_no_vm_destruction
  load_ips

  echo "==> [1/4] Confirming Cilium is Ready on all nodes before disabling canal..."
  local ready desired
  ready=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" get ds cilium -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)
  desired=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n "$CILIUM_NAMESPACE" get ds cilium -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo -1)
  if [[ "$ready" -lt 1 || "$ready" != "$desired" ]]; then
    echo "ERROR: cilium DaemonSet not fully Ready ($ready/$desired) — refusing to disable canal (cluster would be left with no CNI)." >&2
    exit 1
  fi
  echo "  -- cilium DaemonSet Ready: $ready/$desired"

  echo "==> [2/4] Disabling canal via RKE2's own mechanism (cni: none in server config.yaml, restart rke2-server)..."
  nsh "$CP1_IP" "sudo cp /etc/rancher/rke2/config.yaml /etc/rancher/rke2/config.yaml.bak-canal-\$(date +%s) 2>/dev/null || true; grep -q '^cni: none' /etc/rancher/rke2/config.yaml || sudo bash -c 'echo \"cni: none\" >> /etc/rancher/rke2/config.yaml'"
  nsh "$CP1_IP" "sudo systemctl restart rke2-server.service"
  echo "  -- waiting for apiserver to come back..."
  local waited=0
  until KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" get nodes >/dev/null 2>&1; do
    if (( waited >= 150 )); then
      echo "ERROR: apiserver did not come back within 150s of rke2-server restart." >&2
      exit 1
    fi
    sleep 5; waited=$((waited + 5))
  done

  echo "==> [3/4] Disabling kube-proxy static pods on all nodes (disable-kube-proxy: true, per-node — RKE2 kube-proxy is NOT a DaemonSet)..."
  nsh "$CP1_IP" "grep -q '^disable-kube-proxy: true' /etc/rancher/rke2/config.yaml || sudo bash -c 'echo \"disable-kube-proxy: true\" >> /etc/rancher/rke2/config.yaml'"
  nsh "$CP1_IP" "sudo systemctl restart rke2-server.service"
  local ip
  for ip in "${WORKER_IPS[@]}"; do
    nsh "$ip" "grep -q '^disable-kube-proxy: true' /etc/rancher/rke2/config.yaml || sudo bash -c 'echo \"disable-kube-proxy: true\" >> /etc/rancher/rke2/config.yaml'"
    nsh "$ip" "sudo systemctl restart rke2-agent.service"
  done
  waited=0
  until KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" get nodes >/dev/null 2>&1; do
    if (( waited >= 150 )); then
      echo "ERROR: apiserver did not come back within 150s of rke2-server restart (kube-proxy disable step)." >&2
      exit 1
    fi
    sleep 5; waited=$((waited + 5))
  done
  local kp
  kp=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n kube-system get pods -o name 2>/dev/null | grep -c '^pod/kube-proxy-' || true)
  if [[ "$kp" -ne 0 ]]; then
    echo "ERROR: $kp kube-proxy static pod(s) still present after disable-kube-proxy on all nodes." >&2
    exit 1
  fi
  echo "  -- kube-proxy fully removed on all nodes"

  echo "==> [4/4] Recreating pods still wired to canal's now-dead dataplane, then sweeping leftover canal/calico interfaces + iptables (CNI_LEFTOVER_REGISTRY 'calico' row — canal's policy component is Calico's felix/node binaries) and calico-kubeconfig..."
  # Pods created before the cutover keep their existing (canal) netns/veth
  # wiring undisturbed — same no-forced-restart discipline as cmd_cutover —
  # so any Deployment/DaemonSet-managed workload that must move onto Cilium's
  # CNI needs an explicit rollout restart. This step handles the RKE2-bundled
  # in-cluster components only; caller is responsible for restarting their
  # own workloads the same way if IP-mobility/Cilium-only invariants matter.
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n kube-system rollout restart deploy/rke2-coredns-rke2-coredns deploy/rke2-coredns-rke2-coredns-autoscaler deploy/rke2-metrics-server deploy/rke2-snapshot-controller 2>/dev/null || true
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n kube-system rollout restart daemonset/rke2-ingress-nginx-controller 2>/dev/null || true
  KUBECONFIG="$KUBECONFIG_OUT" kubectl --context="$KVM_CONTEXT" -n kube-system rollout status deploy/rke2-coredns-rke2-coredns --timeout=120s 2>/dev/null || true
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    nsh "$ip" "sudo ip link del flannel.1 2>/dev/null || true; sudo rm -f /etc/cni/net.d/calico-kubeconfig"
  done
  sweep_cni_leftovers

  echo "==> [verify] each node's CNI conf dir contains only the active Cilium conflist (canal's is the inactive *.cilium_bak)..."
  local confs
  for ip in "$CP1_IP" "${WORKER_IPS[@]}"; do
    confs=$(nsh "$ip" "sudo ls /etc/cni/net.d/" 2>/dev/null || echo "UNKNOWN")
    echo "  -- $ip: $confs"
    if echo "$confs" | grep -Ei '\.(conf|conflist|json)$' | grep -qiE 'canal|calico|flannel'; then
      echo "ERROR: node $ip still has an ACTIVE non-Cilium CNI conflist present after cutover." >&2
      exit 1
    fi
    if ! echo "$confs" | grep -Ei '\.(conf|conflist|json)$' | grep -qi cilium; then
      echo "ERROR: node $ip has no active Cilium conflist present after cutover." >&2
      exit 1
    fi
  done
  echo "==> Cutover complete: canal + kube-proxy disabled via RKE2's own mechanism, Cilium sole CNI-of-record on all nodes. Restart the podmotion-agent DaemonSet (rollout restart) to re-run nmcregistrar detection against the new CNI."
}

usage() {
  cat >&2 <<EOF
Usage: hack/kvm-cluster.sh <verify|reset-cluster|reset-cluster-k3s|reset-cluster-rke2|deploy-podmotion|deploy-demo-apps|deploy-podmotion-demo|deploy-migration-demo-stack|provision-shared-storage|provision-longhorn|provision-cilium|cutover|provision-calico|cutover-calico|provision-cilium-rke2|cutover-canal-rke2|wipe|ssh <node-ip> [cmd]>

  verify            assert 3 nodes Ready via $KUBECONFIG_OUT
  reset-cluster     kubeadm reset+reinit+flannel+join ON the standing VMs (NEVER destroys VMs)
  reset-cluster-k3s k3s install (stock, embedded Flannel) ON the standing VMs (NEVER destroys VMs) — sprint50
  reset-cluster-rke2 RKE2 install (stock, default canal CNI) ON the standing VMs (NEVER destroys VMs) — sprint51
  deploy-podmotion  build+import images, mint mTLS, apply CRDs, helm install, then deploy-demo-apps (TAG=<tag>; --allow-dirty; --skip-demo-apps to opt out; CONTAINERD_ADDRESS/AGENT_CONTAINERD_SOCKET_PATH/AGENT_CONTAINERD_STATE_DIR for k3s/RKE2)
  deploy-demo-apps  deploy-podmotion-demo + deploy-migration-demo-stack, in that order (TAG=<tag>; standalone re-run / faster iteration loop)
  deploy-podmotion-demo      build+import podmotion-demo web+api images, helm upgrade --install standalone release in ns $PODMOTION_DEMO_NAMESPACE (PODMOTION_DEMO_REPO=<path> override)
  deploy-migration-demo-stack build+import migration-demo-stack web images, helm upgrade --install standalone release in ns $MIGRATION_DEMO_NAMESPACE (MIGRATION_DEMO_REPO=<path>/MIGRATION_DEMO_STORAGE_CLASS=<sc> override; requires a default StorageClass)
  provision-shared-storage  NFS server on cp + nfs-common on all + RWX StorageClass $NFS_STORAGE_CLASS
  provision-longhorn  attach $LH_DISK_SIZE $LH_DISK_TARGET per node + Longhorn + SCs ($LH_STORAGE_CLASS, $LH_MIGRATABLE_SC)
  provision-cilium  pre-import Cilium images + helm install cilium/cilium $CILIUM_CHART_VERSION (cluster-pool/geneve/kube-proxy-replacement)
  cutover           Flannel→Cilium CNI cutover: verify Cilium Ready, remove Flannel/kube-proxy remnants
  provision-calico  pre-import Tigera Operator/Calico images + helm install operator + apply Installation CR (single non-strict-affinity IPPool, VXLAN, bpfEnabled=false)
  cutover-calico    previously-active-CNI→Calico cutover: verify Calico Ready, remove Flannel/Cilium remnants
  provision-cilium-rke2  helm install cilium/cilium on RKE2 (cluster-pool over RKE2's own pod CIDR $RKE2_CILIUM_POD_CIDR) alongside canal — sprint52
  cutover-canal-rke2     RKE2-native canal→Cilium cutover: verify Cilium Ready, disable canal via cni:none + restart rke2-server, disable kube-proxy per-node, sweep leftovers — sprint52
  wipe              clean k8s + PodMotion state on the VMs WITHOUT destroying the VMs
  verify-deployed-revision  ADR-0325-remediation deploy-provenance gate: compare the
                    live operator Deployment's podmotion.io/deployed-revision annotation
                    against 'git rev-parse HEAD' of the current worktree; exits non-zero
                    on any mismatch (or on a dirty deployed revision) so a stale/wrong-branch
                    image can never silently be mistaken for the code under test

This script REFUSES to 'virsh destroy'/'virsh undefine' any of: ${PM_VMS[*]}.
EOF
  exit 2
}

main() {
  local sub="${1:-}"; shift || true
  case "$sub" in
    verify)           cmd_verify ;;
    reset-cluster)    cmd_reset_cluster ;;
    reset-cluster-k3s) cmd_reset_cluster_k3s ;;
    reset-cluster-rke2) cmd_reset_cluster_rke2 ;;
    deploy-podmotion) cmd_deploy_podmotion "$@" ;;
    deploy-demo-apps) cmd_deploy_demo_apps "$@" ;;
    deploy-podmotion-demo) cmd_deploy_podmotion_demo "$@" ;;
    deploy-migration-demo-stack) cmd_deploy_migration_demo "$@" ;;
    verify-deployed-revision) cmd_verify_deployed_revision "$@" ;;
    provision-shared-storage) cmd_provision_shared_storage ;;
    provision-longhorn) cmd_provision_longhorn ;;
    provision-cilium) cmd_provision_cilium ;;
    provision-cilium-multipool) cmd_provision_cilium_multipool ;;
    cutover)          cmd_cutover ;;
    provision-calico) cmd_provision_calico ;;
    cutover-calico)   cmd_cutover_calico ;;
    provision-cilium-rke2) cmd_provision_cilium_rke2 ;;
    cutover-canal-rke2)    cmd_cutover_canal_rke2 ;;
    wipe)             cmd_wipe ;;
    ssh)              load_ips; nsh "$@" ;;
    *)                usage ;;
  esac
}
main "$@"
