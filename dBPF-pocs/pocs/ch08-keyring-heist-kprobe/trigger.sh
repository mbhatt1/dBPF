#!/bin/bash
# ch08-keyring-heist-kprobe trigger.
#
# Demonstrates CO-RE field extraction of kernel `struct key` from inside
# the access-denied syscall path.
#
# Flow:
#   - root adds a kernel keyring entry with a known description under @u
#   - unprivileged user 't08k' runs `keyctl search @u user <desc>`, which
#     returns non-zero (EACCES) because the key has restrictive perms
#   - BEFORE the loader is attached, that is the only observable effect:
#     stdout carries the error and no kernel-struct metadata is visible
#   - AFTER the loader is attached, the same unprivileged keyctl call
#     STILL returns non-zero (the kernel's access decision is untouched),
#     but the loader's ringbuf stream carries structure-level metadata
#     (serial, key type, description) that was CO-RE-read from the
#     `struct key` the kernel passed to key_task_permission().
#
# Pedagogical point: in the kernel, the same pointer that drives the
# access decision is visible to instrumentation at the decision site.
# Read-only structural observation does not require, and does not
# perform, any mutation.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
LOADER="$HERE/build/ch08-keyring-heist-kprobe"
LOG=/tmp/ch08k.log
LPID=""
KEY_ID=""
DUSER="t08k"
KEY_DESC="ch08-research-entry"
KEY_PAYLOAD="research-payload-value"

cleanup() {
    if [ -n "$LPID" ]; then
        kill "$LPID" 2>/dev/null
        wait 2>/dev/null
    fi
    if [ -n "$KEY_ID" ]; then
        keyctl unlink "$KEY_ID" @u >/dev/null 2>&1
    fi
    userdel "$DUSER" 2>/dev/null
}
trap cleanup EXIT INT TERM

# --- preflight ---
if ! command -v keyctl >/dev/null 2>&1; then
    echo '=== CH08K_SKIP reason="keyctl(1) not available (install keyutils)" ==='
    exit 0
fi
if [ ! -x "$LOADER" ]; then
    echo "=== CH08K_SKIP reason=\"loader not built at $LOADER (run make first)\" ==="
    exit 0
fi

# --- user setup ---
if ! id "$DUSER" >/dev/null 2>&1; then
    useradd -M "$DUSER" 2>/dev/null
fi
if ! id "$DUSER" >/dev/null 2>&1; then
    echo "=== CH08K_SKIP reason=\"cannot create user $DUSER\" ==="
    exit 0
fi

# --- root adds the keyring entry under the @u user session keyring ---
KEY_ID="$(keyctl add user "$KEY_DESC" "$KEY_PAYLOAD" @u 2>/dev/null)"
if [ -z "$KEY_ID" ]; then
    echo '=== CH08K_SKIP reason="keyctl add user @u failed" ==='
    exit 0
fi
# Restrictive perms: owner=all(0x3f), user-class=view-only(0x01), g/o=none.
# This is what causes the unprivileged search/print to return EACCES.
keyctl setperm "$KEY_ID" 0x3f010000 >/dev/null 2>&1
echo "=== root added keyring entry id=$KEY_ID desc=$KEY_DESC ==="

run_user_keyctl() {
    # Unprivileged `keyctl print <ID>` — expected to fail at key_task_permission
    # because the key has owner-only read perms. Going by numeric id avoids
    # the parent-keyring search-permission short-circuit that `keyctl search`
    # hits first, so this path actually reaches key_task_permission() on the
    # target key itself.
    su "$DUSER" -s /bin/sh -c "keyctl print $KEY_ID" 2>&1
}

# --- BEFORE: loader not attached ---
echo "=== BEFORE (loader not attached) ==="
BEFORE_OUT="$(run_user_keyctl)"
BEFORE_RC=$?
echo "before_rc=$BEFORE_RC"
echo "before_out=$BEFORE_OUT"

# --- start loader ---
: > "$LOG"
"$LOADER" >"$LOG" 2>>"$LOG" &
LPID=$!

# Wait up to ~5s for loader to print 'attached'
for _ in $(seq 1 50); do
    if grep -q 'attached' "$LOG" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$LPID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if ! kill -0 "$LPID" 2>/dev/null; then
    echo '=== loader failed to start ==='
    cat "$LOG"
    if grep -q '^\[ch08k\] CH08K_SKIP' "$LOG" 2>/dev/null; then
        grep 'CH08K_SKIP' "$LOG"
        exit 0
    fi
    echo '=== CH08K_SKIP reason="loader exited during startup" ==='
    exit 0
fi

if ! grep -q 'attached' "$LOG" 2>/dev/null; then
    echo '=== loader did not reach attached state ==='
    cat "$LOG"
    echo '=== CH08K_SKIP reason="loader did not attach in time" ==='
    exit 0
fi
echo "=== loader attached pid=$LPID ==="

# --- AFTER: loader attached; syscall still returns the same EACCES ---
echo "=== AFTER (loader attached) ==="
AFTER_OUT="$(run_user_keyctl)"
AFTER_RC=$?
echo "after_rc=$AFTER_RC"
echo "after_out=$AFTER_OUT"

# Let ringbuf drain.
sleep 1
kill "$LPID" 2>/dev/null
wait 2>/dev/null
LPID=""

echo "=== loader log ==="
cat "$LOG"

EVENT_COUNT=$(grep -c '^\[ch08k\] hook=' "$LOG" 2>/dev/null)
EVENT_COUNT=${EVENT_COUNT:-0}

if grep -q "desc='$KEY_DESC'" "$LOG" 2>/dev/null; then
    SIDESTREAM_READ=yes
else
    SIDESTREAM_READ=no
fi

# The kernel's access decision must be unchanged: before and after return
# values should both be non-zero (EACCES) for the unprivileged caller.
if [ "$BEFORE_RC" != "0" ] && [ "$AFTER_RC" != "0" ]; then
    SYSCALL_UNCHANGED=yes
else
    SYSCALL_UNCHANGED=no
fi

echo "=== summary ==="
echo "before_rc=$BEFORE_RC after_rc=$AFTER_RC"
echo "event_lines=$EVENT_COUNT"
echo "description_in_ringbuf=$SIDESTREAM_READ"
echo "syscall_rc_unchanged=$SYSCALL_UNCHANGED"
echo "=== CH08_CONCEPT_PROVEN syscall_rc_unchanged=$SYSCALL_UNCHANGED description_in_ringbuf=$SIDESTREAM_READ ==="
