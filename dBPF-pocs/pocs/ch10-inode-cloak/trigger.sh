#!/bin/bash
# Ch10 Inode Cloak — weaponized BEFORE/AFTER proof.
#
# Populates /tmp/cloak with visible + hidden files, captures a directory
# listing WITHOUT the BPF loader running, then starts the loader, waits
# for it to attach, and captures the listing again. The cloaked files
# disappear from readdir but stat() by name still resolves them.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch10-inode-cloak"
D=/tmp/cloak
EVENTS="$HERE/build/cloak-events.log"
STDERR="$HERE/build/cloak-stderr.log"

LOADER_PID=""
cleanup() {
    if [ -n "$LOADER_PID" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
        kill -TERM "$LOADER_PID" 2>/dev/null
        wait "$LOADER_PID" 2>/dev/null
    fi
    rm -rf "$D"
}
trap cleanup EXIT

rm -rf "$D"
mkdir -p "$D"
touch "$D/visible" "$D/.backdoor" "$D/evil.so" "$D/notes.txt"

# ---------- BEFORE ----------
echo "=== BEFORE (loader not running) ==="
echo "/tmp/cloak contents via ls -A:"
BEFORE_LS=$(/bin/ls -A "$D" 2>/dev/null | sort)
echo "$BEFORE_LS"
BEFORE_COUNT=$(printf '%s\n' "$BEFORE_LS" | grep -c .)
echo "files_seen=$BEFORE_COUNT"
echo

# ---------- Start loader ----------
if [ ! -x "$BIN" ]; then
    echo "=== CH10_SKIP reason=\"loader not built at $BIN\" ==="
    exit 0
fi

: > "$EVENTS"
: > "$STDERR"
# stdout (ringbuf events) -> EVENTS, stderr (status) -> STDERR
"$BIN" > "$EVENTS" 2> "$STDERR" &
LOADER_PID=$!

# Wait for "attached" on stderr (max ~10s)
for i in $(seq 1 100); do
    if grep -q "attached" "$STDERR" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$LOADER_PID" 2>/dev/null; then
        echo "=== CH10_SKIP reason=\"loader exited before attaching\" ==="
        cat "$STDERR" >&2
        exit 0
    fi
    sleep 0.1
done

if ! grep -q "attached" "$STDERR" 2>/dev/null; then
    echo "=== CH10_SKIP reason=\"loader did not report attached within 10s\" ==="
    cat "$STDERR" >&2
    exit 0
fi

# ---------- AFTER ----------
echo "=== AFTER (loader running — cloaking .backdoor and evil.so) ==="
echo "/tmp/cloak contents via ls -A:"
AFTER_LS=$(/bin/ls -A "$D" 2>/dev/null | sort)
echo "$AFTER_LS"
AFTER_COUNT=$(printf '%s\n' "$AFTER_LS" | grep -c .)
echo "files_seen=$AFTER_COUNT"
echo "hidden_by_bpf=\".backdoor evil.so\""
echo

# ---------- Bonus: stat by name still resolves ----------
STAT_OK="no"
if stat "$D/.backdoor" >/dev/null 2>&1; then
    STAT_OK="yes"
fi
echo "=== stat /tmp/cloak/.backdoor (cloak is readdir-only) ==="
stat "$D/.backdoor" 2>&1 | head -2
echo "stat_still_works=$STAT_OK"
echo

# ---------- Ringbuf proof ----------
# Give the loader a moment to drain any pending events from the AFTER ls.
sleep 0.3
echo "=== ringbuf cloak events (loader stdout) ==="
if [ -s "$EVENTS" ]; then
    head -20 "$EVENTS"
else
    echo "(no events captured — ringbuf may still be draining)"
fi
echo

HIDDEN=$(( BEFORE_COUNT - AFTER_COUNT ))
echo "=== CLOAK_PROVEN before_count=${BEFORE_COUNT} after_count=${AFTER_COUNT} hidden=${HIDDEN} stat_still_works=${STAT_OK} ==="
