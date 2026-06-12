#!/usr/bin/env bash
# [PM-CONTROL] Start a TCP bidirectional echo server in a dedicated netns.
#
# The server IP 10.244.0.50 is assigned as a secondary address on the flannel
# bridge so it is reachable from the spike pod on pm-worker via the VXLAN overlay.
#
# The echo server uses socat in LOOP mode: every accepted connection spawns a thread
# that reads stdin and echoes it back with a sequence number prefix, producing
# SUSTAINED BIDIRECTIONAL TRAFFIC at all times — not idle.
set -euo pipefail

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Configuration ────────────────────────────────────────────────────────────
SERVER_IP="${SERVER_IP:-10.244.0.50}"
SERVER_PORT="${SERVER_PORT:-9000}"
FLANNEL_BRIDGE="${FLANNEL_BRIDGE:-cni0}"          # flannel bridge on pm-control
SERVER_NETNS="${SERVER_NETNS:-pm-spike-server}"
LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
# ─────────────────────────────────────────────────────────────────────────────

mkdir -p "$LOG_DIR"

# Idempotent cleanup of any prior run
if ip netns list 2>/dev/null | grep -q "^${SERVER_NETNS}"; then
    echo "[server] removing existing netns ${SERVER_NETNS}"
    ip netns del "${SERVER_NETNS}" || true
fi

echo "[server] creating server netns ${SERVER_NETNS}"
ip netns add "${SERVER_NETNS}"

# Create veth pair: veth-srv (host side) <-> veth-srv-pod (netns side)
ip link add veth-srv      type veth peer name veth-srv-pod
ip link set veth-srv-pod  netns "${SERVER_NETNS}"

# Host side: add to flannel bridge so it participates in overlay routing
ip link set veth-srv master "${FLANNEL_BRIDGE}"
ip link set veth-srv up

# Netns side: assign server IP in the same /24 as the flannel bridge (cni0 = 10.244.0.1/24)
# Using /24 ensures the netns answers ARP for this IP correctly.
BRIDGE_CIDR="${BRIDGE_CIDR:-24}"
ip netns exec "${SERVER_NETNS}" ip addr add "${SERVER_IP}/${BRIDGE_CIDR}" dev veth-srv-pod
ip netns exec "${SERVER_NETNS}" ip link set veth-srv-pod up
# Route via the bridge gateway (cni0 is the default gw for this subnet)
BRIDGE_GW="${BRIDGE_GW:-10.244.0.1}"
ip netns exec "${SERVER_NETNS}" ip route add default via "${BRIDGE_GW}" dev veth-srv-pod || true

# No extra host route needed — cni0 bridge already owns 10.244.0.0/24

echo "[server] server IP ${SERVER_IP} reachable via ${FLANNEL_BRIDGE}"

# Verify socat is available
if ! command -v socat &>/dev/null; then
    echo "[server] FATAL: socat not found — install with: apt-get install -y socat"
    exit 1
fi

# Start the echo server inside the netns.
# Protocol: client sends "SEQ:<n>:<payload>\n", server echoes back "ECHO:<n>:<payload>\n".
# The server script below is embedded to avoid file transfer.
cat > /tmp/pm-spike-server-echo.sh << 'SERVER_SCRIPT'
#!/usr/bin/env bash
# Per-connection handler: echo with prefix
while IFS= read -r line; do
    if [[ "$line" =~ ^SEQ:([0-9]+):(.*)$ ]]; then
        echo "ECHO:${BASH_REMATCH[1]}:${BASH_REMATCH[2]}"
    fi
done
SERVER_SCRIPT
chmod +x /tmp/pm-spike-server-echo.sh

echo "[server] starting socat TCP echo server on ${SERVER_IP}:${SERVER_PORT}"
ip netns exec "${SERVER_NETNS}" \
    socat \
        "TCP4-LISTEN:${SERVER_PORT},bind=${SERVER_IP},reuseaddr,fork" \
        "EXEC:/tmp/pm-spike-server-echo.sh" \
    > "${LOG_DIR}/server.log" 2>&1 &

echo $! > "${LOG_DIR}/server.pid"
echo "[server] PID $(cat ${LOG_DIR}/server.pid)"

# Wait for port to be reachable
echo -n "[server] waiting for port to open"
for i in $(seq 1 20); do
    if timeout 1 socat /dev/null "TCP:${SERVER_IP}:${SERVER_PORT},connect-timeout=1" 2>/dev/null; then
        echo " OK"
        break
    fi
    echo -n "."
    sleep 0.5
done

echo "[server] setup complete — echo server at ${SERVER_IP}:${SERVER_PORT}"
echo "[server] tail logs: tail -f ${LOG_DIR}/server.log"
