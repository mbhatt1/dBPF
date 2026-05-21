#!/bin/bash
# ch05-cgroup-leash trigger — pedagogical BEFORE/AFTER demo.
#
# Measurable delta: `cat /sys/fs/cgroup/cpu.stat` reports real values without
# the BPF program, and zeros once the program is attached (bpf_probe_write_user
# clobbers the userspace buffer post-read).
set -u
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch05-cgroup-leash"
TARGET="/sys/fs/cgroup/cpu.stat"

extract_usage() {
    awk '/^usage_usec/ {print $2; exit}' "$1" 2>/dev/null
}

if [ ! -r "$TARGET" ]; then
    echo "!! $TARGET not readable; cgroup v2 required" >&2
    exit 1
fi

# --- BEFORE: read cpu.stat without the loader --------------------------------
BEFORE_FILE="$(mktemp)"
cat "$TARGET" > "$BEFORE_FILE"
BEFORE_USAGE="$(extract_usage "$BEFORE_FILE")"
echo "=== BEFORE ==="
echo "usage_usec=${BEFORE_USAGE:-<unknown>}"

# --- Load the BPF program and wait for attach --------------------------------
if [ ! -x "$BIN" ]; then
    echo "!! loader $BIN not built; run 'make' first" >&2
    rm -f "$BEFORE_FILE"
    exit 1
fi
LOADER_LOG="$(mktemp)"
"$BIN" >"$LOADER_LOG" 2>&1 &
LOADER_PID=$!
for _ in $(seq 1 100); do
    grep -q "\[ch05\] attached" "$LOADER_LOG" && break
    sleep 0.1
done
if ! grep -q "\[ch05\] attached" "$LOADER_LOG"; then
    echo "!! loader did not report [ch05] attached" >&2
    kill -TERM "$LOADER_PID" 2>/dev/null || true
    wait "$LOADER_PID" 2>/dev/null || true
    tail -20 "$LOADER_LOG" >&2
    rm -f "$BEFORE_FILE" "$LOADER_LOG"
    exit 1
fi

# --- AFTER: re-read cpu.stat with the loader attached ------------------------
AFTER_FILE="$(mktemp)"
cat "$TARGET" > "$AFTER_FILE"
AFTER_USAGE="$(extract_usage "$AFTER_FILE")"

# Give the ring buffer a moment to surface patched=1 events.
sleep 0.5
kill -TERM "$LOADER_PID" 2>/dev/null || true
wait "$LOADER_PID" 2>/dev/null || true

echo "=== AFTER ==="
echo "usage_usec=${AFTER_USAGE:-<unknown>}"

# --- Verdict -----------------------------------------------------------------
PATCHED_COUNT="$(grep -c 'patched=1' "$LOADER_LOG")"
if [ "${AFTER_USAGE:-x}" = "0" ]; then
    ZEROED="yes"
else
    ZEROED="no"
fi

echo "=== CH05_PROVEN before_usage=${BEFORE_USAGE:-<unknown>} after_usage=${AFTER_USAGE:-<unknown>} zeroed=${ZEROED} patched_events=${PATCHED_COUNT} ==="

echo "--- loader log tail ---" >&2
tail -20 "$LOADER_LOG" >&2
rm -f "$BEFORE_FILE" "$AFTER_FILE" "$LOADER_LOG"
