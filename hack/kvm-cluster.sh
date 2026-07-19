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
# live k3s node this round; see docs/sprints/sprint50-k3s/K3S-COMPATIBILITY-PLAN.md
# §0 items 1-4 and §2 Round 2). K3S_CONTAINERD_SOCKET/K3S_CONTAINERD_STATE_DIR
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
  KUBECONFIG="$KUBECONFIG_OUT" kubectl get nodes -o wide
  local ready
  ready="$(KUBECONFIG="$KUBECONFIG_OUT" kubectl get nodes --no-headers 2>/dev/null | grep -cw Ready || true)"
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
  KUBECONFIG="$KUBECONFIG_OUT" kubectl wait --for=condition=Ready nodes --all --timeout=180s
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
  KUBECONFIG="$KUBECONFIG_OUT" kubectl wait --for=condition=Ready nodes --all --timeout=180s
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
  KUBECONFIG="$KUBECONFIG_OUT" kubectl wait --for=condition=Ready nodes --all --timeout=300s
  cmd_verify

  echo "==> reset-cluster-rke2 complete."
  echo "    RKE2 containerd socket:  $RKE2_CONTAINERD_SOCKET (confirmed live against pm-cp1/pm-w1/pm-w2)"
  echo "    RKE2 containerd state:   $RKE2_CONTAINERD_STATE_DIR (confirmed live — same run root as socket)"
  echo "    RKE2 CNI conf dir:       canonical /etc/cni/net.d — no extraConfDir override needed (confirmed live)"
  echo "    Deploy PodMotion against this cluster with:"
  echo "      CONTAINERD_ADDRESS=$RKE2_CONTAINERD_SOCKET \\"
  echo "      AGENT_CONTAINERD_SOCKET_PATH=$RKE2_CONTAINERD_SOCKET \\"
  echo "      AGENT_CONTAINERD_STATE_DIR=$RKE2_CONTAINERD_STATE_DIR \\"
  echo "      TAG=<tag> bash hack/kvm-cluster.sh deploy-podmotion"
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
  # sprint50 (k3s compat, plan §1 Q2 item 1): this script's own `ctr` calls below
  # (image rm/import/ls, distinct from the agent's own ctr invocations — see
  # internal/agent/server/containerd_paths.go) fall back to ctr's compiled-in
  # default socket (/run/containerd/containerd.sock) when no address is given,
  # which is wrong on a k3s node. Set CONTAINERD_ADDRESS (e.g. to
  # $K3S_CONTAINERD_SOCKET after a reset-cluster-k3s run) to target the right
  # socket; empty (the kubeadm-path default) leaves ctr's own default in effect,
  # unchanged from before this sprint.
  local CONTAINERD_ADDRESS="${CONTAINERD_ADDRESS:-}"
  local ctr_addr_flag=""
  if [[ -n "$CONTAINERD_ADDRESS" ]]; then
    ctr_addr_flag="-a $CONTAINERD_ADDRESS"
  fi
  # AGENT_CONTAINERD_SOCKET_PATH / AGENT_CONTAINERD_STATE_DIR: passed straight
  # through to the Helm chart's agent.containerd.* values (the containerd-socket
  # hostPath mount + the agent's env-driven path roots — see
  # charts/podmotion/values.yaml and internal/agent/server/containerd_paths.go).
  # Default to the same standard-containerd paths the chart itself defaults to,
  # so a plain kubeadm deploy-podmotion call is byte-identical to before this
  # sprint; a k3s deploy sets both (reset-cluster-k3s prints the exact values).
  local AGENT_CONTAINERD_SOCKET_PATH="${AGENT_CONTAINERD_SOCKET_PATH:-/run/containerd/containerd.sock}"
  local AGENT_CONTAINERD_STATE_DIR="${AGENT_CONTAINERD_STATE_DIR:-/var/lib/containerd}"
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
    nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images rm '$OP_IMG' '$AGENT_IMG' >/dev/null 2>&1 || true"
    docker save "$OP_IMG"    | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    docker save "$AGENT_IMG" | nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images import -"
    # Verify each tag actually landed in this node's k8s.io namespace.
    if ! nsh "$ip" "sudo ctr $ctr_addr_flag -n k8s.io images ls -q | grep -q ':$TAG'"; then
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
    --set operator.featureGates="TCPPreservation=true" \
    --set agent.containerd.socketPath="$AGENT_CONTAINERD_SOCKET_PATH" \
    --set agent.containerd.stateDir="$AGENT_CONTAINERD_STATE_DIR" \
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
  KUBECONFIG="$KUBECONFIG_OUT" kubectl apply -f "$LH_MANIFEST"
  KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" rollout status ds/longhorn-manager --timeout=300s
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
  until KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" patch setting taint-toleration \
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
  lh_applied="$(KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$LH_NAMESPACE" get setting taint-toleration -o jsonpath='{.value}')"
  if [[ "$lh_applied" != "node-role.kubernetes.io/control-plane:NoSchedule" ]]; then
    echo "ERROR: taint-toleration Setting patch reported success but value is '$lh_applied', not the expected toleration." >&2
    exit 1
  fi
  echo "  -- taint-toleration setting confirmed: $lh_applied"
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

  echo "==> [3/3] Waiting for the Tigera Operator to reconcile the Installation CR (namespace $CALICO_NAMESPACE)..."
  # The Installation CR apply above only asks the Tigera Operator to act; the
  # operator creates the $CALICO_NAMESPACE namespace (and everything in it)
  # asynchronously as it reconciles. Running rollout-status before that
  # namespace exists fails with a hard NotFound instead of waiting, so poll
  # for the namespace first. Bounded wait, not a fixed sleep and not an
  # infinite wait.
  local waited=0
  local calico_ns_timeout=120
  until KUBECONFIG="$KUBECONFIG_OUT" kubectl get namespace "$CALICO_NAMESPACE" >/dev/null 2>&1; do
    if (( waited >= calico_ns_timeout )); then
      echo "ERROR: namespace $CALICO_NAMESPACE did not appear within ${calico_ns_timeout}s — Tigera Operator has not reconciled the Installation CR. Check 'kubectl -n $CALICO_OPERATOR_NAMESPACE logs deploy/tigera-operator'." >&2
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo "  -- namespace $CALICO_NAMESPACE present after ${waited}s"

  echo "==> Waiting for Calico to come up (rollout status on calico-node / calico-kube-controllers)..."
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
  ready=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CALICO_NAMESPACE" get ds calico-node -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)
  desired=$(KUBECONFIG="$KUBECONFIG_OUT" kubectl -n "$CALICO_NAMESPACE" get ds calico-node -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo -1)
  if [[ "$ready" -lt 1 || "$ready" != "$desired" ]]; then
    echo "ERROR: calico-node DaemonSet not fully Ready ($ready/$desired) — refusing to remove the previously-active CNI (cluster would be left with no CNI)." >&2
    exit 1
  fi
  echo "  -- calico-node DaemonSet Ready: $ready/$desired"

  echo "==> [2/4] Removing the previously-active CNI's remnants (Flannel and/or Cilium, whichever is present)..."
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
Usage: hack/kvm-cluster.sh <verify|reset-cluster|reset-cluster-k3s|reset-cluster-rke2|deploy-podmotion|provision-shared-storage|provision-longhorn|provision-cilium|cutover|provision-calico|cutover-calico|wipe|ssh <node-ip> [cmd]>

  verify            assert 3 nodes Ready via $KUBECONFIG_OUT
  reset-cluster     kubeadm reset+reinit+flannel+join ON the standing VMs (NEVER destroys VMs)
  reset-cluster-k3s k3s install (stock, embedded Flannel) ON the standing VMs (NEVER destroys VMs) — sprint50
  reset-cluster-rke2 RKE2 install (stock, default canal CNI) ON the standing VMs (NEVER destroys VMs) — sprint51
  deploy-podmotion  build+import images, mint mTLS, apply CRDs, helm install (TAG=<tag>; CONTAINERD_ADDRESS/AGENT_CONTAINERD_SOCKET_PATH/AGENT_CONTAINERD_STATE_DIR for k3s/RKE2)
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
    reset-cluster-k3s) cmd_reset_cluster_k3s ;;
    reset-cluster-rke2) cmd_reset_cluster_rke2 ;;
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
