#!/usr/bin/env bash
# [PM-WORKER] Create the spike pod netns and start the bidirectional traffic generator.
#
# The traffic generator sends a sequenced message every 50ms and expects an echo reply.
# It tracks sent vs received sequence numbers and reports any gaps.
# This ensures SUSTAINED BIDIRECTIONAL IN-FLIGHT TRAFFIC at freeze time.
#
# The spike pod is a manual netns — not a Kubernetes pod — to avoid any CNI
# interference during the manual CRIU dump/restore.
set -euo pipefail

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Configuration ────────────────────────────────────────────────────────────
POD_IP="${POD_IP:-10.244.1.50}"
POD_NETNS="${POD_NETNS:-pm-spike-pod}"
SERVER_IP="${SERVER_IP:-10.244.0.50}"
SERVER_PORT="${SERVER_PORT:-9000}"
FLANNEL_BRIDGE="${FLANNEL_BRIDGE:-cni0}"
FLANNEL_DEV="${FLANNEL_DEV:-flannel.1}"
LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
BPF_DIR="${BPF_DIR:-${SPIKE_DIR}/bpf}"
# ─────────────────────────────────────────────────────────────────────────────

mkdir -p "$LOG_DIR"

# Idempotent cleanup
if ip netns list 2>/dev/null | grep -q "^${POD_NETNS}"; then
    echo "[pod] removing existing netns ${POD_NETNS}"
    # Kill any processes in the netns first
    if [[ -f "${LOG_DIR}/client.pid" ]]; then
        kill "$(cat ${LOG_DIR}/client.pid)" 2>/dev/null || true
    fi
    ip netns del "${POD_NETNS}" || true
fi

echo "[pod] creating pod netns ${POD_NETNS} with IP ${POD_IP}"
ip netns add "${POD_NETNS}"

# Create veth pair: veth-spike (host) <-> eth0 (netns)
ip link add veth-spike type veth peer name eth0
ip link set eth0 netns "${POD_NETNS}"

# Host side: add to flannel bridge
ip link set veth-spike master "${FLANNEL_BRIDGE}"
ip link set veth-spike up

# Netns side
ip netns exec "${POD_NETNS}" ip addr add "${POD_IP}/24" dev eth0
ip netns exec "${POD_NETNS}" ip link set eth0 up
ip netns exec "${POD_NETNS}" ip link set lo up

# Default route: through flannel bridge gateway
FLANNEL_GW=$(ip -4 addr show "${FLANNEL_BRIDGE}" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
if [[ -n "${FLANNEL_GW}" ]]; then
    ip netns exec "${POD_NETNS}" ip route add default via "${FLANNEL_GW}"
else
    # Flannel bridge may not have an IP directly; route through flannel.1
    ip netns exec "${POD_NETNS}" ip route add "${SERVER_IP}/32" dev eth0 via "${FLANNEL_GW:-$(ip route show dev ${FLANNEL_DEV} | awk '/default/{print $3; exit}')}"
fi

# Add proxy ARP / neighbor entry for the server IP so the spike pod's ARP resolves
SERVER_MAC=$(ip neigh show "${SERVER_IP}" 2>/dev/null | awk '{print $5}' | head -1)
if [[ -n "${SERVER_MAC}" ]]; then
    ip netns exec "${POD_NETNS}" ip neigh add "${SERVER_IP}" lladdr "${SERVER_MAC}" dev eth0 nud permanent
fi

# Record the veth host-side ifindex for BPF attachment
VETH_IFINDEX=$(ip link show veth-spike | head -1 | awk -F: '{print $1}')
echo "${VETH_IFINDEX}" > "${LOG_DIR}/veth_ifindex"
echo "veth-spike" > "${LOG_DIR}/veth_name"
POD_NETNS_PATH="/var/run/netns/${POD_NETNS}"
echo "${POD_NETNS_PATH}" > "${LOG_DIR}/pod_netns_path"

# Get the PID of a process inside the netns for CRIU to target
# We launch a long-lived process (the traffic generator) that CRIU will checkpoint

cat > "${LOG_DIR}/traffic_gen.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Bidirectional traffic generator for M18.5 spike.

Connects to the echo server, sends a sequenced message every SEND_INTERVAL_MS,
and verifies echo replies arrive in order. Logs errors prominently.

Also acts as a server on LOOPBACK_PORT — the monitor script reads stats from there.
"""
import socket, time, threading, sys, os, signal, json

# Close stdin (fd 0) so CRIU doesn't checkpoint it.
# stdout/stderr are fine — inherited from parent in the SAME mount namespace.
try:
    os.close(0)
except OSError:
    pass

SERVER_IP   = os.getenv("SERVER_IP",   "10.244.0.50")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9000"))
SEND_INTERVAL_MS = float(os.getenv("SEND_INTERVAL_MS", "50"))
LOG_DIR     = os.getenv("LOG_DIR", "/tmp/pm-spike")

stats = {
    "sent": 0, "received": 0, "errors": 0,
    "last_sent_seq": 0, "last_recv_seq": 0,
    "gaps": [], "running": True, "paused": False,
}
stats_lock = threading.Lock()

def sender(sock):
    seq = 0
    while True:
        with stats_lock:
            if not stats["running"]:
                break
            if stats["paused"]:
                time.sleep(0.05)
                continue
        msg = f"SEQ:{seq}:{'x' * 128}\n"
        try:
            sock.sendall(msg.encode())
            with stats_lock:
                stats["sent"]  += 1
                stats["last_sent_seq"] = seq
            seq += 1
        except Exception as e:
            with stats_lock:
                stats["errors"] += 1
                stats["gaps"].append(f"send_error@seq{seq}: {e}")
            print(f"[traffic] SEND ERROR seq={seq}: {e}", flush=True)
            break
        time.sleep(SEND_INTERVAL_MS / 1000.0)

def receiver(sock):
    buf = b""
    expected = 0
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                with stats_lock:
                    stats["running"] = False
                print("[traffic] connection closed by peer", flush=True)
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.decode(errors="replace").strip()
                if not line:
                    continue
                if line.startswith("ECHO:"):
                    parts = line.split(":", 2)
                    recv_seq = int(parts[1])
                    with stats_lock:
                        stats["received"] += 1
                        stats["last_recv_seq"] = recv_seq
                        if recv_seq != expected:
                            gap = f"seq_gap: got={recv_seq} expected={expected}"
                            stats["gaps"].append(gap)
                            stats["errors"] += 1
                            print(f"[traffic] *** {gap} ***", flush=True)
                        expected = recv_seq + 1
        except Exception as e:
            # ECONNRESET, EOF, or any recv error: mark running=False and exit.
            # No silent reconnect — any reconnect would hide migration failures.
            with stats_lock:
                stats["errors"] += 1
                stats["running"] = False
            print(f"[traffic] RECV ERROR: {e}", flush=True)
            break

def stats_reporter():
    while True:
        time.sleep(1.0)
        with stats_lock:
            if not stats["running"]:
                break
            print(f"[traffic] sent={stats['sent']} recv={stats['received']} "
                  f"errors={stats['errors']} gaps={len(stats['gaps'])}", flush=True)

print(f"[traffic] connecting to {SERVER_IP}:{SERVER_PORT}", flush=True)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_IP, SERVER_PORT))
sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
print(f"[traffic] connected", flush=True)

# Write PID for CRIU targeting
with open(f"{LOG_DIR}/client.pid", "w") as f:
    f.write(str(os.getpid()))

# Save fd number for inspection
for fd_num, fd_path in [(f, f"/proc/{os.getpid()}/fd/{f}") for f in range(3, 64)]:
    try:
        target = os.readlink(fd_path)
        if "socket" in target:
            with open(f"{LOG_DIR}/client_sock_fd", "w") as f:
                f.write(str(fd_num))
            break
    except:
        pass

t_send  = threading.Thread(target=sender,   args=(sock,), daemon=True)
t_recv  = threading.Thread(target=receiver, args=(sock,), daemon=True)
t_stats = threading.Thread(target=stats_reporter, daemon=True)
t_send.start(); t_recv.start(); t_stats.start()

def on_signal(sig, frame):
    with stats_lock:
        stats["running"] = False
    with open(f"{LOG_DIR}/final_stats.json", "w") as f:
        json.dump(stats, f, indent=2)
    print(f"[traffic] FINAL: {json.dumps(stats)}", flush=True)
    sys.exit(0)

def on_pause(sig, frame):
    with stats_lock:
        stats["paused"] = True
    print("[traffic] PAUSED (SIGUSR1) — holding connection open, stopping sends", flush=True)

def on_resume(sig, frame):
    with stats_lock:
        stats["paused"] = False
    print("[traffic] RESUMED (SIGUSR2) — sender restarting", flush=True)

signal.signal(signal.SIGTERM, on_signal)
signal.signal(signal.SIGINT,  on_signal)
signal.signal(signal.SIGUSR1, on_pause)
signal.signal(signal.SIGUSR2, on_resume)

t_send.join()
t_recv.join()
with open(f"{LOG_DIR}/final_stats.json", "w") as f:
    json.dump(stats, f, indent=2)
print(f"[traffic] FINAL: {json.dumps(stats)}", flush=True)
PYEOF
chmod +x "${LOG_DIR}/traffic_gen.py"

echo "[pod] starting traffic generator inside ${POD_NETNS}"
# unshare -m: give the process its own mount namespace so CRIU doesn't see
# host kubelet projected volume mounts (which have unreachable sharing).
# The network namespace is still the pod netns (set by ip netns exec).
# Run in the pod's network namespace only (no mount namespace isolation).
# CRIU will use --ext-mount-map auto + --enable-external-masters to handle
# host-specific mounts (boot/efi, kubelet projected volumes).
# stdin from /dev/null is fine — CRIU will map it as an external mount.
# Use nsenter --net (not ip netns exec) so the process enters ONLY the network
# namespace, staying in the host mount namespace. ip netns exec creates an extra
# unshare(CLONE_NEWNS) which gives the process a different mount namespace from
# the host, causing CRIU mount ID mismatches and sysfs unmount failures.
# With nsenter --net, CRIU sees the host mount namespace for both itself and the
# target process — all mount IDs are consistent and CRIU needs no special flags.
# stdout/stderr: opened as regular files here (in host mount namespace).
# They will have correct mnt_ids since both parent and child are in host mnt ns.
SERVER_IP="${SERVER_IP}" SERVER_PORT="${SERVER_PORT}" \
LOG_DIR="${LOG_DIR}" \
nsenter --net="/var/run/netns/${POD_NETNS}" -- python3 "${LOG_DIR}/traffic_gen.py" \
    < /dev/null > "${LOG_DIR}/client.log" 2>&1 &

TGEN_PID=$!
echo "${TGEN_PID}" > "${LOG_DIR}/tgen_host_pid"

sleep 1
if ! kill -0 "${TGEN_PID}" 2>/dev/null; then
    echo "[pod] FATAL: traffic generator died immediately"
    tail -20 "${LOG_DIR}/client.log"
    exit 1
fi

CLIENT_PID=$(cat "${LOG_DIR}/client.pid" 2>/dev/null || echo "")
echo "[pod] traffic generator running: host_pid=${TGEN_PID} client_pid=${CLIENT_PID}"
echo "[pod] CRIU will target: ip netns exec ${POD_NETNS} criu dump -t ${CLIENT_PID}"

echo ""
echo "[pod] setup complete"
echo "[pod] monitoring: tail -f ${LOG_DIR}/client.log"
echo "[pod] live stats: grep '\[traffic\]' ${LOG_DIR}/client.log | tail -5"
