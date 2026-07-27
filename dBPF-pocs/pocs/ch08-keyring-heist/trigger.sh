#!/bin/bash
# ch08 trigger: start the keyring observer, exercise the keyring so that
# lookup_user_key()/key_task_permission() run, and confirm the loader read
# `struct key` metadata out of band via its ringbuf. Read-only: the kernel's
# access decision is never changed (this is an observer, per the taxonomy).
#
# The loader takes no orchestration flags (-v/-h only); it attaches, prints
# "[ch08] status=ready", streams "[ch08] hook=... desc='...'" events, and on
# exit prints "[ch08] CH08_PROVEN events=N". So the trigger must launch it,
# generate keyring activity, then stop it and surface its log.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1
LOADER="$HERE/build/ch08-keyring-heist"
LOG=/tmp/ch08.log
LPID=""
KEY_ID=""
DESC="ch08-secret-$$"

cleanup() {
    [ -n "$LPID" ] && { kill "$LPID" 2>/dev/null; wait 2>/dev/null; }
    [ -n "$KEY_ID" ] && keyctl revoke "$KEY_ID" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

if ! command -v keyctl >/dev/null 2>&1; then
    echo '=== CH08_SKIP reason="keyctl not installed (install keyutils)" ==='
    exit 0
fi
if [ ! -x "$LOADER" ]; then
    echo "=== CH08_SKIP reason=\"loader not built at $LOADER (run make)\" ==="
    exit 0
fi

# --- start the observer and wait for it to attach ---
: > "$LOG"
"$LOADER" >"$LOG" 2>>"$LOG" &
LPID=$!
for _ in $(seq 1 50); do
    grep -q 'status=ready' "$LOG" 2>/dev/null && break
    kill -0 "$LPID" 2>/dev/null || break
    sleep 0.1
done
if ! kill -0 "$LPID" 2>/dev/null; then
    echo "=== loader exited during startup ==="; cat "$LOG"
    grep -q 'CH08_SKIP' "$LOG" 2>/dev/null && { grep CH08_SKIP "$LOG"; exit 0; }
    echo '=== CH08_SKIP reason="loader failed to start" ==='
    exit 0
fi
echo "=== loader attached pid=$LPID ==="

# --- exercise the keyring: each call runs lookup_user_key/key_task_permission ---
KEY_ID=$(keyctl add user "$DESC" "super-sekrit-payload" @u 2>/dev/null)
echo "added key id=$KEY_ID desc=$DESC"
keyctl describe "$KEY_ID"      >/dev/null 2>&1
keyctl print "$KEY_ID"         >/dev/null 2>&1
keyctl search @u user "$DESC"  >/dev/null 2>&1
keyctl list @u                 >/dev/null 2>&1

# --- let the ringbuf drain, then stop the loader so it prints its verdict ---
sleep 1
kill "$LPID" 2>/dev/null; wait 2>/dev/null; LPID=""

echo "=== loader log ==="
cat "$LOG"

EVENTS=$(grep -c '^\[ch08\] hook=' "$LOG" 2>/dev/null); EVENTS=${EVENTS:-0}
if grep -q "desc='$DESC'" "$LOG" 2>/dev/null; then SEEN=yes; else SEEN=no; fi
echo "=== summary events=$EVENTS description_in_ringbuf=$SEEN ==="
