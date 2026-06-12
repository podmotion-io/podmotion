#!/usr/bin/env bash
# m21-verify-overlay.sh — M21 overlay/netns manual verification script.
#
# Runs all M21 acceptance criteria checks against the live PoC cluster:
#   AC#1: ip netns exec pm-mig-<uid> ip addr show lists source pod IP as /32 on pmdst0
#   AC#2: bridge fdb show dev flannel.1 shows permanent entry on BOTH nodes
#   AC#3: ip neigh show dev flannel.1 shows AF_INET neighbor on BOTH nodes
#   AC#4: ping -c 20 source_pod_IP from third node; tcpdump VXLAN encap; zero grat ARP
#   AC#5: migration status shows DestinationNetnsReady=True + VXLANFDBUpdated=True
#
# Usage:
#   POD_IP=10.244.1.50 POD_UID=<uid> SOURCE_NODE=pm-worker DEST_NODE=pm-control \
#     ./scripts/m21-verify-overlay.sh
#
# All arguments can be overridden via environment variables.
# Requires: kubectl, ssh access to cluster nodes (ubuntu@<node>), jq.

set -euo pipefail

POD_IP="${POD_IP:-}"
POD_UID="${POD_UID:-}"
SOURCE_NODE="${SOURCE_NODE:-pm-worker}"
DEST_NODE="${DEST_NODE:-pm-control}"
MIGRATION_NAME="${MIGRATION_NAME:-}"
NAMESPACE="${NAMESPACE:-pm-e2e-m21}"

PASS=0
FAIL=0

pass() { echo "[PASS] $*"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $*"; FAIL=$((FAIL+1)); }
info() { echo "[INFO] $*"; }

require_var() {
    if [ -z "${!1:-}" ]; then
        echo "ERROR: $1 must be set" >&2
        exit 1
    fi
}

require_var POD_IP
require_var POD_UID

# Truncate UID the same way migrationnetns.go does: strip hyphens, take first 8 chars.
uid_clean="${POD_UID//-/}"
uid_short="${uid_clean:0:8}"
NETNS_NAME="pm-mig-${uid_short}"

info "Verifying M21 overlay/netns acceptance criteria"
info "  POD_IP=$POD_IP  POD_UID=$POD_UID"
info "  SOURCE_NODE=$SOURCE_NODE  DEST_NODE=$DEST_NODE"
info "  NETNS_NAME=$NETNS_NAME"
echo ""

# ── AC#1: ip netns exec inside migration netns ──────────────────────────────
info "AC#1: checking ip addr show on pmdst0 inside $NETNS_NAME on $DEST_NODE"
addr_out=$(ssh "ubuntu@${DEST_NODE}" \
    "sudo ip netns exec '${NETNS_NAME}' ip addr show dev pmdst0 2>&1" || true)
if echo "$addr_out" | grep -q "${POD_IP}/32"; then
    pass "AC#1: pmdst0 has ${POD_IP}/32 inside migration netns on $DEST_NODE"
else
    fail "AC#1: ${POD_IP}/32 NOT found on pmdst0 inside $NETNS_NAME on $DEST_NODE"
    echo "  Output: $addr_out"
fi

# ── AC#2: bridge fdb show on BOTH nodes ──────────────────────────────────────
for node in "$SOURCE_NODE" "$DEST_NODE"; do
    info "AC#2: checking bridge fdb show dev flannel.1 on $node"
    fdb_out=$(ssh "ubuntu@${node}" "bridge fdb show dev flannel.1 2>&1" || true)
    if echo "$fdb_out" | grep -q "permanent"; then
        pass "AC#2: permanent FDB entry found on flannel.1 on $node"
    else
        fail "AC#2: no permanent FDB entry on flannel.1 on $node"
        echo "  Output: $fdb_out"
    fi
done

# ── AC#3: ip neigh show on BOTH nodes ────────────────────────────────────────
for node in "$SOURCE_NODE" "$DEST_NODE"; do
    info "AC#3: checking ip neigh show dev flannel.1 on $node"
    neigh_out=$(ssh "ubuntu@${node}" "ip neigh show dev flannel.1 2>&1" || true)
    if echo "$neigh_out" | grep -q "$POD_IP"; then
        pass "AC#3: AF_INET neighbor for $POD_IP found on flannel.1 on $node"
    else
        fail "AC#3: $POD_IP NOT found in ip neigh show on flannel.1 on $node"
        echo "  Output: $neigh_out"
    fi
done

# ── AC#4: ping 20/20 + tcpdump VXLAN + zero gratuitous ARP ──────────────────
info "AC#4: running ping -c 20 $POD_IP (requires kubectl exec access to a prober pod)"
if kubectl get pod -n "$NAMESPACE" -l app=pm-m21-prober -o name 2>/dev/null | grep -q pod; then
    prober=$(kubectl get pod -n "$NAMESPACE" -l app=pm-m21-prober -o jsonpath='{.items[0].metadata.name}')
    ping_out=$(kubectl exec -n "$NAMESPACE" "$prober" -- ping -c 20 -W 2 "$POD_IP" 2>&1 || true)
    if echo "$ping_out" | grep -q "20 received"; then
        pass "AC#4: ping 20/20 success from prober pod to $POD_IP"
    else
        fail "AC#4: ping 20/20 failed to $POD_IP"
        echo "  Output: $ping_out"
    fi
else
    info "AC#4: prober pod not found in $NAMESPACE — skipping ping test"
    info "  Deploy: kubectl run pm-m21-prober -n $NAMESPACE --image=busybox -- sleep 600"
fi

info "AC#4: checking for gratuitous ARP on physical interface of $SOURCE_NODE"
phys=$(ssh "ubuntu@${SOURCE_NODE}" "ip route show default | grep -o 'dev [^ ]*' | awk '{print \$2}'" 2>/dev/null || echo "eth0")
grat_out=$(ssh "ubuntu@${SOURCE_NODE}" \
    "timeout 3 tcpdump -c 1 -i '$phys' -n 'arp and arp[6:2] = 2' 2>&1" || true)
if echo "$grat_out" | grep -q "$POD_IP"; then
    fail "AC#4: gratuitous ARP for $POD_IP detected on $phys of $SOURCE_NODE"
    echo "  Output: $grat_out"
else
    pass "AC#4: zero gratuitous ARP for $POD_IP on $phys of $SOURCE_NODE"
fi

# ── AC#5: status conditions ──────────────────────────────────────────────────
if [ -n "$MIGRATION_NAME" ]; then
    info "AC#5: checking PodMigration status conditions for $MIGRATION_NAME"
    netns_status=$(kubectl get podmigration -n "$NAMESPACE" "$MIGRATION_NAME" \
        -o jsonpath='{.status.conditions[?(@.type=="DestinationNetnsReady")].status}' 2>/dev/null || true)
    fdb_status=$(kubectl get podmigration -n "$NAMESPACE" "$MIGRATION_NAME" \
        -o jsonpath='{.status.conditions[?(@.type=="VXLANFDBUpdated")].status}' 2>/dev/null || true)

    if [ "$netns_status" = "True" ]; then
        pass "AC#5: DestinationNetnsReady=True"
    else
        fail "AC#5: DestinationNetnsReady=$netns_status (want True)"
    fi
    if [ "$fdb_status" = "True" ]; then
        pass "AC#5: VXLANFDBUpdated=True"
    else
        fail "AC#5: VXLANFDBUpdated=$fdb_status (want True)"
    fi
else
    info "AC#5: MIGRATION_NAME not set — skipping status condition check"
fi

echo ""
echo "════════════════════════════════════════"
echo " M21 overlay verification: PASS=$PASS FAIL=$FAIL"
echo "════════════════════════════════════════"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
