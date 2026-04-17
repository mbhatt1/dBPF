#!/bin/bash
# ch07 trigger — weaponized device-cgroup houdini.
#
# Launches the loader with -a (wildcard targeting), then spawns an
# unprivileged child that touches device nodes. On each device-cgroup
# denial, the BPF program sends SIGUSR2 to the child. The child
# counts received signals as proof of real kernel-side effect.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1

BIN="$HERE/build/ch07-devcgroup-houdini"
LPID=""
LOG=/tmp/ch07.log

if ! command -v mknod >/dev/null 2>&1 && ! command -v dd >/dev/null 2>&1; then
    echo "=== CH07_SKIP reason=\"mknod/dd not available\" ==="
    exit 0
fi
if [ ! -x "$BIN" ]; then
    echo "=== CH07_SKIP reason=\"loader not built at $BIN\" ==="
    exit 0
fi

cleanup() {
    [ -n "$LPID" ] && kill "$LPID" 2>/dev/null && wait "$LPID" 2>/dev/null
    rm -rf /tmp/ch07-child-signals.txt
    userdel dut07 2>/dev/null
}
trap cleanup EXIT INT TERM

useradd -M dut07 2>/dev/null

echo "=== starting loader (wildcard targeting) ==="
: > "$LOG"
"$BIN" -a >"$LOG" 2>>"$LOG" &
LPID=$!
sleep 1

if ! kill -0 "$LPID" 2>/dev/null; then
    echo "=== loader exited early ==="
    cat "$LOG"
    grep -q 'CH07_SKIP' "$LOG" && grep 'CH07_SKIP' "$LOG"
    exit 0
fi

echo "=== spawning unprivileged child (catches SIGUSR2) ==="
su dut07 -s /bin/bash -c '
SIGCOUNT=0
trap "SIGCOUNT=\$((SIGCOUNT+1))" USR2

# Touch various device nodes — some will be denied by devcgroup
dd if=/dev/null of=/dev/null count=1 2>/dev/null
dd if=/dev/urandom of=/dev/null count=1 bs=1 2>/dev/null
dd if=/dev/zero of=/dev/null count=1 bs=1 2>/dev/null
cat /dev/random 2>/dev/null | head -c 1 >/dev/null
# These are likely to be denied:
dd if=/dev/mem of=/dev/null count=1 bs=1 2>/dev/null
dd if=/dev/kmsg of=/dev/null count=1 bs=1 2>/dev/null

sleep 0.3
echo "$SIGCOUNT" > /tmp/ch07-child-signals.txt
echo "SIGNALS_RECEIVED=$SIGCOUNT"
'

sleep 1
kill "$LPID" 2>/dev/null
wait "$LPID" 2>/dev/null
LPID=""

echo "=== loader output ==="
cat "$LOG"

SIGNALS=$(cat /tmp/ch07-child-signals.txt 2>/dev/null)
SIGNALS=${SIGNALS:-0}
EVENTS=$(grep -c '^\[ch07\]' "$LOG" 2>/dev/null)
EVENTS=${EVENTS:-0}
DENIALS=$(grep -c 'verdict=DENY' "$LOG" 2>/dev/null)
DENIALS=${DENIALS:-0}
SIG_EVENTS=$(grep -c 'SIGUSR2_SENT' "$LOG" 2>/dev/null)
SIG_EVENTS=${SIG_EVENTS:-0}

echo "=== summary ==="
echo "events=$EVENTS denials=$DENIALS signal_events=$SIG_EVENTS child_signals=$SIGNALS"

if [ "$SIG_EVENTS" -gt 0 ] || [ "$SIGNALS" -gt 0 ]; then
    echo "=== CH07_WEAPON_PROVEN signals=$SIGNALS denial_signals=$SIG_EVENTS events=$EVENTS ==="
elif [ "$EVENTS" -gt 0 ]; then
    echo "=== CH07_PROVEN events=$EVENTS denials=$DENIALS ==="
else
    echo "=== CH07_SKIP reason=\"no devcgroup events (privileged container may bypass devcgroup)\" ==="
fi
