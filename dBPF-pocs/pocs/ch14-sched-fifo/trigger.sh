#!/bin/bash
# ch14 trigger: demonstrate that an unprivileged caller's
# sched_setscheduler(SCHED_FIFO) returns 0 once the BPF override is in
# place. We emit a baseline failure first, then the post-override claim
# of success in the loader's ringbuf output.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch14-sched-fifo"
LOG="${LOG:-/tmp/ch14-imp.log}"
USER_NAME="${USER_NAME:-t14}"

cleanup() {
    [[ -n "$LOADER_PID" ]] && kill "$LOADER_PID" 2>/dev/null
    wait 2>/dev/null
    userdel "$USER_NAME" 2>/dev/null
}
trap cleanup EXIT INT TERM

if [[ ! -x "$BIN" ]]; then
    echo "missing binary: $BIN — run 'make' first" >&2
    exit 1
fi

useradd -M "$USER_NAME" 2>/dev/null

echo "=== baseline: $USER_NAME runs chrt -f 50 \$\$ (no BPF) ==="
su "$USER_NAME" -c 'chrt -f 50 $$; echo baseline_ret=$?'

echo ""
echo "=== loading ch14 SCHED_FIFO impersonator (wildcard mode) ==="
"$BIN" --all > "$LOG" 2>&1 &
LOADER_PID=$!
sleep 1

if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "loader exited early; log:" >&2
    cat "$LOG" >&2
    exit 1
fi

echo ""
echo "=== with BPF: same chrt call ==="
su "$USER_NAME" -c 'chrt -f 50 $$; echo override_ret=$?'

# Let the ringbuf drain.
sleep 1
kill "$LOADER_PID" 2>/dev/null
wait 2>/dev/null
LOADER_PID=

echo ""
echo "=== loader output (ringbuf events on stdout, status on stderr) ==="
cat "$LOG"

FLIPS=$(grep -cE 'flipped=1|\bflip\b|override' "$LOG" 2>/dev/null || echo 0)
echo "=== SCHED_WEAPON_PROVEN flips=${FLIPS} ==="
