#!/bin/bash
# ch07 trigger: start the device-cgroup observer, then perform device
# operations (privileged and unprivileged) so devcgroup_check_permission()
# runs and the loader records each verdict out of band. Observer: it reads the
# decision inputs at the hook site; it does not change the kernel's verdict.
#
# The loader takes no orchestration flags (-v/-h only); it prints
# "[ch07] attached — devcgroup observer active", streams "[ch07] pid=..."
# events, and on exit prints "[ch07] CH07_PROVEN events=N denies=M". So the
# trigger must launch it, generate device activity, then stop it.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1
LOADER="$HERE/build/ch07-devcgroup-houdini"
LOG=/tmp/ch07.log
LPID=""
TMP=$(mktemp -d)

cleanup() {
    [ -n "$LPID" ] && { kill "$LPID" 2>/dev/null; wait 2>/dev/null; }
    rm -rf "$TMP"; userdel dut07 2>/dev/null
}
trap cleanup EXIT INT TERM

if [ ! -x "$LOADER" ]; then
    echo "=== CH07_SKIP reason=\"loader not built at $LOADER (run make)\" ==="
    exit 0
fi
id dut07 >/dev/null 2>&1 || useradd -M dut07 2>/dev/null

# --- start the observer and wait for it to attach ---
: > "$LOG"
"$LOADER" >"$LOG" 2>>"$LOG" &
LPID=$!
for _ in $(seq 1 50); do
    grep -q 'attached' "$LOG" 2>/dev/null && break
    kill -0 "$LPID" 2>/dev/null || break
    sleep 0.1
done
if ! kill -0 "$LPID" 2>/dev/null; then
    echo "=== loader exited during startup ==="; cat "$LOG"
    grep -q 'CH07_SKIP' "$LOG" 2>/dev/null && { grep CH07_SKIP "$LOG"; exit 0; }
    echo '=== CH07_SKIP reason="loader failed to start" ==='
    exit 0
fi
echo "=== loader attached pid=$LPID ==="

# --- device operations: each runs devcgroup_check_permission() ---
echo "=== priv root device ops ==="
mknod "$TMP/null" c 1 3 2>&1 | head -1
dd if=/dev/null of=/dev/null count=1 2>/dev/null
echo "=== unpriv dut07 device ops ==="
runuser -u dut07 -- dd if=/dev/null of=/dev/null count=1 2>&1 | head -1
runuser -u dut07 -- dd if=/dev/urandom of=/dev/null count=1 bs=1 2>&1 | head -1
runuser -u dut07 -- dd if=/dev/mem of=/dev/null count=1 bs=1 2>&1 | head -1

# --- drain, then stop the observer so it prints its verdict ---
sleep 1
kill "$LPID" 2>/dev/null; wait 2>/dev/null; LPID=""

echo "=== loader log ==="
cat "$LOG"
EVENTS=$(grep -c '^\[ch07\] pid=' "$LOG" 2>/dev/null); EVENTS=${EVENTS:-0}
echo "=== summary events=$EVENTS ==="
