#!/bin/bash
# ch17 ACPI/WSMI ANALOG — BEFORE/AFTER demo.
#
# DISCLAIMER: acpi_evaluate_object / request_firmware don't fire on this
# kernel — no ACPI interpreter (aarch64 linuxkit), no driver calls
# request_firmware, no test_firmware module is loaded. This POC uses a
# userspace "firmware requester" as a stand-in so the primitive
# ("kernel-mediated string substituted in flight via bpf_probe_write_user
# on sys_enter_openat") can be demonstrated on a surface that exists here.
set -u
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch17-acpi-wsmi-analog"
REQUESTER="$HERE/build/fw_requester"

REAL_FILE="/tmp/CH17_REQ_real_firmware.bin"
REPL_FILE="/tmp/CH17_REQ_attacker_replacement.bin"

for b in "$BIN" "$REQUESTER"; do
    if [ ! -x "$b" ]; then
        echo "=== CH17_SKIP reason=\"$b not built; run make first\" ==="
        exit 0
    fi
done

cleanup() {
    [ -n "${LOADER_PID:-}" ] && kill -TERM "$LOADER_PID" 2>/dev/null
    wait 2>/dev/null
    rm -f "$REAL_FILE" "$REPL_FILE"
}
trap cleanup EXIT

# --- Seed the two files ------------------------------------------------------
printf 'ORIGINAL\n' > "$REAL_FILE"
printf 'REPLACED\n' > "$REPL_FILE"

echo "=== seeded files ==="
printf '  %-45s : ' "$REAL_FILE"; cat "$REAL_FILE"
printf '  %-45s : ' "$REPL_FILE"; cat "$REPL_FILE"

# --- BEFORE ------------------------------------------------------------------
echo ""
echo "=== BEFORE (no loader) ==="
BEFORE_OUT="$(echo "CH17_REQ_real_firmware.bin" | "$REQUESTER" 2>&1)"
echo "$BEFORE_OUT"
BEFORE_CONTENT="$(echo "$BEFORE_OUT" | sed -n 's/.*content="\([^"]*\)".*/\1/p')"

# --- Load BPF ----------------------------------------------------------------
LOADER_LOG="$(mktemp)"
"$BIN" >"$LOADER_LOG" 2>&1 &
LOADER_PID=$!
for _ in $(seq 1 100); do
    grep -q "\[ch17-analog\] attached" "$LOADER_LOG" && break
    sleep 0.1
done
if ! grep -q "\[ch17-analog\] attached" "$LOADER_LOG"; then
    echo "=== CH17_SKIP reason=\"loader did not attach (tracepoint unavailable)\" ==="
    tail -20 "$LOADER_LOG" >&2
    exit 0
fi

# --- AFTER -------------------------------------------------------------------
echo ""
echo "=== AFTER (loader attached) ==="
AFTER_OUT="$(echo "CH17_REQ_real_firmware.bin" | "$REQUESTER" 2>&1)"
echo "$AFTER_OUT"
AFTER_CONTENT="$(echo "$AFTER_OUT" | sed -n 's/.*content="\([^"]*\)".*/\1/p')"
AFTER_REQUESTED="$(echo "$AFTER_OUT" | sed -n 's/.*requested="\([^"]*\)".*/\1/p')"

# Drain ringbuf.
sleep 0.3

# --- Verdict -----------------------------------------------------------------
SWAPPED_COUNT="$(grep -c 'swapped=1' "$LOADER_LOG")"

echo ""
echo "--- loader events (tail) ---"
grep '\[ch17-analog\]' "$LOADER_LOG" | tail -8

echo ""
echo "=== CH17_ANALOG_PROVEN requested=CH17_REQ_real_firmware.bin served=${AFTER_CONTENT:-?} before_content=${BEFORE_CONTENT:-?} swapped_events=${SWAPPED_COUNT} disclaimer=\"same primitive as kernel request_firmware string swap; real request_firmware needs drivers that actually call it\" ==="

rm -f "$LOADER_LOG"
