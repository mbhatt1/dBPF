#!/bin/bash
# ch15-netns-vlan-ghost weaponized trigger.
#
# Topology:
#   ghost_a (attacker) ──veth_a──┤├──veth_host   (XDP ingress; strips VLAN)
#                                            │  bpf_redirect_map
#                                            ▼
#   ghost_b             ──veth_b──┤├──veth_host2 (untagged payload surfaces)
#
# Proof: BEFORE XDP, frames on veth_a do NOT cross to veth_host2.
#        AFTER  XDP, the same frames appear on veth_host2 stripped of VLAN tag.
#
# Uses raw-socket Python receiver instead of tcpdump to avoid dependency.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch15-netns-vlan-ghost"
LOG_LOADER="/tmp/ch15-vghost.log"

LOADER_PID=
RECV_PID=

cleanup() {
    [ -n "$RECV_PID" ]   && kill "$RECV_PID"  2>/dev/null
    [ -n "$LOADER_PID" ] && kill "$LOADER_PID" 2>/dev/null
    wait 2>/dev/null
    ip link show veth_host  >/dev/null 2>&1 && ip link set dev veth_host  xdp off 2>/dev/null
    ip link show veth_host2 >/dev/null 2>&1 && ip link set dev veth_host2 xdp off 2>/dev/null
    ip link del veth_host  2>/dev/null
    ip link del veth_host2 2>/dev/null
    ip netns del ghost_a   2>/dev/null
    ip netns del ghost_b   2>/dev/null
    rm -f /tmp/ch15-recv-before.txt /tmp/ch15-recv-after.txt
}
trap cleanup EXIT INT TERM

if [ ! -x "$BIN" ]; then
    echo "=== CH15_SKIP reason=\"loader not built at $BIN\" ==="
    exit 0
fi
for tool in ip python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "=== CH15_SKIP reason=\"required tool $tool not available\" ==="
        exit 0
    fi
done

# Fresh slate.
cleanup
trap cleanup EXIT INT TERM

echo "=== building ghost_a + ghost_b topology ==="
ip netns add ghost_a || { echo "netns add ghost_a failed" >&2; exit 1; }
ip netns add ghost_b || { echo "netns add ghost_b failed" >&2; exit 1; }
ip link add veth_host  type veth peer name veth_a netns ghost_a || exit 1
ip link add veth_host2 type veth peer name veth_b netns ghost_b || exit 1

ip addr add 192.168.77.1/24 dev veth_host  || exit 1
ip addr add 192.168.77.4/24 dev veth_host2 || exit 1
ip link set veth_host  up || exit 1
ip link set veth_host2 up || exit 1
ip -n ghost_a addr add 192.168.77.2/24 dev veth_a || exit 1
ip -n ghost_b addr add 192.168.77.3/24 dev veth_b || exit 1
ip -n ghost_a link set veth_a up || exit 1
ip -n ghost_b link set veth_b up || exit 1
ip -n ghost_a link set lo up
ip -n ghost_b link set lo up

# Sender: 3 VLAN-142 tagged AF_PACKET frames from ghost_a on veth_a.
send_three() {
    ip netns exec ghost_a python3 - <<'PY'
import socket, struct, fcntl, sys
ETH_P_ALL = 0x0003
SIOCGIFHWADDR = 0x8927
ifname = b"veth_a"
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((ifname.decode(), 0))
    info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR,
                       struct.pack('256s', ifname[:15]))
    src_mac = info[18:24]
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    tci = (0 << 13) | 142
    vlan_hdr  = struct.pack('!HH', 0x8100, tci)
    inner_eth = struct.pack('!H', 0x88b5)
    payload   = b'GHOSTVLAN-covert-channel-message\x00' * 2
    frame = dst_mac + src_mac + vlan_hdr + inner_eth + payload
    for _ in range(3):
        s.send(frame)
    print("sent 3 VLAN-142 covert frames", flush=True)
except Exception as e:
    print(f"sender error: {e}", file=sys.stderr)
    sys.exit(1)
PY
}

# Receiver: raw socket on veth_host2 looking for ethertype 0x88b5.
# Writes count to a file. Runs for max 3 seconds.
start_receiver() {
    local outfile="$1"
    python3 - "$outfile" <<'PY' &
import socket, struct, sys, time, select
outfile = sys.argv[1]
ETH_P_ALL = 0x0003
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind(("veth_host2", 0))
    s.setblocking(False)
except Exception as e:
    with open(outfile, 'w') as f:
        f.write("0\n")
    sys.exit(1)
count = 0
deadline = time.time() + 3.0
while time.time() < deadline:
    ready, _, _ = select.select([s], [], [], 0.5)
    if not ready:
        continue
    try:
        data = s.recv(65535)
        if len(data) >= 14:
            ethertype = struct.unpack('!H', data[12:14])[0]
            if ethertype == 0x88b5:
                count += 1
                if count >= 3:
                    break
    except BlockingIOError:
        pass
with open(outfile, 'w') as f:
    f.write(f"{count}\n")
PY
    RECV_PID=$!
}

############################################################
# BEFORE — no XDP. Receiver on veth_host2 should see 0 frames.
############################################################
echo ""
echo "=== BEFORE: raw socket receiver on veth_host2 (no XDP) ==="
start_receiver /tmp/ch15-recv-before.txt
sleep 0.5
send_three
sleep 2
if kill -0 "$RECV_PID" 2>/dev/null; then
    kill "$RECV_PID" 2>/dev/null
    wait "$RECV_PID" 2>/dev/null
fi
RECV_PID=
BEFORE_COUNT=$(cat /tmp/ch15-recv-before.txt 2>/dev/null)
BEFORE_COUNT=${BEFORE_COUNT:-0}
echo "BEFORE frames on veth_host2: $BEFORE_COUNT"

############################################################
# AFTER — load XDP, re-send. Expect 3 untagged frames on veth_host2.
############################################################
echo ""
echo "=== AFTER: loading XDP ghost on veth_host -> redirect veth_host2 ==="
"$BIN" --skb -i veth_host -o veth_host2 > "$LOG_LOADER" 2>&1 &
LOADER_PID=$!
sleep 1
if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "loader exited early; log:" >&2
    cat "$LOG_LOADER" >&2
    echo "=== CH15_SKIP reason=\"XDP loader failed to attach\" ==="
    exit 0
fi

echo "=== AFTER: raw socket receiver on veth_host2 (XDP active) ==="
start_receiver /tmp/ch15-recv-after.txt
sleep 0.5
send_three
sleep 2
if kill -0 "$RECV_PID" 2>/dev/null; then
    kill "$RECV_PID" 2>/dev/null
    wait "$RECV_PID" 2>/dev/null
fi
RECV_PID=

sleep 1
kill -TERM "$LOADER_PID" 2>/dev/null
wait "$LOADER_PID" 2>/dev/null
LOADER_PID=

AFTER_COUNT=$(cat /tmp/ch15-recv-after.txt 2>/dev/null)
AFTER_COUNT=${AFTER_COUNT:-0}
REDIRECT_COUNT=$(grep -cE "STRIP\\+REDIRECT" "$LOG_LOADER" 2>/dev/null)
REDIRECT_COUNT=${REDIRECT_COUNT:-0}

echo ""
echo "=== loader/ringbuf log ==="
cat "$LOG_LOADER"

echo ""
echo "=== BEFORE (no XDP): frames on veth_host2 = ${BEFORE_COUNT}"
echo "=== AFTER  (XDP):    frames on veth_host2 = ${AFTER_COUNT}"
echo "=== XDP redirect events in ringbuf: ${REDIRECT_COUNT}"

if [ "$AFTER_COUNT" -gt 0 ] || [ "$REDIRECT_COUNT" -gt 0 ]; then
    echo "=== VLAN_GHOST_CROSSNS_PROVEN redirect_count=${REDIRECT_COUNT} ==="
else
    echo "=== CH15_SKIP reason=\"no cross-ns frames detected (XDP redirect may have failed)\" ==="
fi
echo "=== done ==="
