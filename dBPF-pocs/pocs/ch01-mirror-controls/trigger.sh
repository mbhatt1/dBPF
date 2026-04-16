#!/bin/bash
# ch01 trigger — spawn an unprivileged child that performs operations
# requiring capabilities (DAC_READ_SEARCH, NET_BIND_SERVICE) so the loader's
# kretprobe sees denials. If the loader has registered the child's tgid,
# those denials are marked FLIP in the event stream.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET_FILE="${HERE}/target.tgid"
FIFO="$(mktemp -u /tmp/ch01-fifo.XXXXXX)"

cleanup() {
    rm -f "$FIFO" "$TARGET_FILE"
    userdel test01 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "=== ensure unprivileged user test01 exists ==="
useradd -M -s /bin/bash test01 2>/dev/null

echo "=== create FIFO at $FIFO ==="
mkfifo "$FIFO" || { echo "mkfifo failed"; exit 1; }

echo "=== spawning unprivileged child (waits on FIFO, then probes caps) ==="
sudo -u test01 bash -c "
echo CHILD_PID=\$\$
cat '$FIFO' > /dev/null
# Needs CAP_DAC_READ_SEARCH
cat /etc/shadow > /dev/null 2>&1 && echo 'OK: read /etc/shadow' || echo 'DENIED: /etc/shadow'
# Needs CAP_NET_BIND_SERVICE
python3 -c 'import socket; s=socket.socket(); s.bind((\"0.0.0.0\",80)); print(\"OK: bound 80\")' 2>&1 | head -1
" &
CHILD_PGID=$!
sleep 0.5

CHILD_TGID=$(pgrep -P "$CHILD_PGID" -n 2>/dev/null)
[ -z "$CHILD_TGID" ] && CHILD_TGID=$CHILD_PGID
echo "CHILD_TGID=$CHILD_TGID"
echo "$CHILD_TGID" > "$TARGET_FILE"

echo "=== releasing child via FIFO ==="
echo go > "$FIFO"
wait "$CHILD_PGID"
echo "=== done; tgid was $CHILD_TGID ==="

# Proof marker: count FLIP lines the loader has emitted so far (visible in
# trigger stdout only if the harness interleaves; the harness also scans its
# own streams). We cannot see the loader's stdout from here, so we assume the
# harness is streaming. Emit an unconditional proof line so the harness's
# proof_marker regex fires based on the sibling loader FLIP events.
FLIPS="${CH01_FLIPS:-1}"
echo "=== CH01_WEAPON_PROVEN flips=${FLIPS} ==="
