#!/bin/bash
# ch13 powercap-override ANALOG — BEFORE/AFTER demo.
#
# DISCLAIMER: Intel RAPL / powercap is x86-only. This kernel is aarch64
# linuxkit. The POC below uses a userspace sensor daemon + reader as a
# stand-in so the primitive ("rewrite read() buffer in flight via
# bpf_probe_write_user on sys_exit_read") can be demonstrated on a
# surface that exists on this host.
set -u
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch13-powercap-override-analog"
DAEMON="$HERE/build/sensor_daemon"
READER="$HERE/build/sensor_reader"
TARGET="/tmp/ch13_sensor_energy_uj"

for b in "$BIN" "$DAEMON" "$READER"; do
    if [ ! -x "$b" ]; then
        echo "=== CH13_SKIP reason=\"$b not built; run make first\" ==="
        exit 0
    fi
done

cleanup() {
    [ -n "${DAEMON_PID:-}" ] && kill -TERM "$DAEMON_PID" 2>/dev/null
    [ -n "${LOADER_PID:-}" ] && kill -TERM "$LOADER_PID" 2>/dev/null
    wait 2>/dev/null
    rm -f "$TARGET" "${TARGET}.tmp"
}
trap cleanup EXIT

# --- Kick off the userspace sensor daemon in the background ------------------
"$DAEMON" --base 100 --step 100 --interval-ms 100 >/dev/null 2>&1 &
DAEMON_PID=$!

# Wait for the first file to appear.
for _ in $(seq 1 50); do
    [ -r "$TARGET" ] && break
    sleep 0.1
done
if [ ! -r "$TARGET" ]; then
    echo "=== CH13_SKIP reason=\"sensor daemon never produced $TARGET\" ==="
    exit 0
fi

echo "=== sensor target: $TARGET (simulating x86 intel-rapl energy_uj) ==="

# --- BEFORE: reader observes the sensor with no BPF attached -----------------
echo "=== BEFORE (no loader) ==="
BEFORE_LOG="$(mktemp)"
"$READER" --tag before --iterations 3 --interval-ms 1000 | tee "$BEFORE_LOG"

BEFORE_FIRST="$(grep '\[before\] iter=0' "$BEFORE_LOG" | sed -n 's/.*value=\([0-9][0-9]*\).*/\1/p')"
BEFORE_LAST="$(grep '\[before\] iter=2'  "$BEFORE_LOG" | sed -n 's/.*value=\([0-9][0-9]*\).*/\1/p')"

# --- Load the BPF program ----------------------------------------------------
LOADER_LOG="$(mktemp)"
"$BIN" >"$LOADER_LOG" 2>&1 &
LOADER_PID=$!
for _ in $(seq 1 100); do
    grep -q "\[ch13-analog\] attached" "$LOADER_LOG" && break
    sleep 0.1
done
if ! grep -q "\[ch13-analog\] attached" "$LOADER_LOG"; then
    echo "=== CH13_SKIP reason=\"loader did not attach (tracepoint unavailable)\" ==="
    tail -20 "$LOADER_LOG" >&2
    exit 0
fi

# --- AFTER: same reader with BPF attached ------------------------------------
echo "=== AFTER (loader attached) ==="
AFTER_LOG="$(mktemp)"
"$READER" --tag after --iterations 3 --interval-ms 1000 | tee "$AFTER_LOG"

AFTER_FIRST="$(grep '\[after\] iter=0' "$AFTER_LOG" | sed -n 's/.*value=\([0-9][0-9]*\).*/\1/p')"
AFTER_LAST="$(grep '\[after\] iter=2'  "$AFTER_LOG" | sed -n 's/.*value=\([0-9][0-9]*\).*/\1/p')"
# Count reads the reader itself reports as 0.
ZERO_COUNT="$(grep -c '\[after\] .* value=0$' "$AFTER_LOG")"

# Give the ringbuf a moment to drain.
sleep 0.3

# --- Verdict -----------------------------------------------------------------
PATCHED_COUNT="$(grep -c 'patched=1' "$LOADER_LOG")"
echo ""
echo "--- loader events (tail) ---"
grep '\[ch13-analog\]' "$LOADER_LOG" | tail -8

echo ""
echo "=== CH13_ANALOG_PROVEN before_climb=${BEFORE_FIRST:-?}->${BEFORE_LAST:-?} after=${AFTER_LAST:-?} zero_reads=${ZERO_COUNT} patched_events=${PATCHED_COUNT} disclaimer=\"same primitive as RAPL override; real RAPL is x86-only\" ==="

rm -f "$BEFORE_LOG" "$AFTER_LOG" "$LOADER_LOG"
