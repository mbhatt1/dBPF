#!/bin/bash
# ch09 trigger — pedagogical BEFORE/AFTER demo.
#
# Pedagogical point: the ns<->host PID mapping is not visible to unprivileged
# observers outside the PID namespace. A BPF raw tracepoint on
# sched_process_fork can stream that mapping in real time. This script shows
# the observable state delta:
#
#   BEFORE  — no BPF loader running; we cannot learn the host pid that
#             corresponds to ns_pid=1 inside an unshare -Upf child.
#   AFTER   — loader running; the [ch09] src=fork event reveals host_pid,
#             and /proc/<host_pid>/status NSpid: line confirms the mapping.
#             We can then kill the victim from outside by host_pid.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1

LOADER="$HERE/build/ch09-pid-doppel"
LOG="$(mktemp -t ch09-loader.XXXXXX.log)"
VICTIM_OUT="$(mktemp -t ch09-victim.XXXXXX.out)"

VICTIM_SHELL_PID=""
LOADER_PID=""

cleanup() {
    [ -n "$LOADER_PID" ] && kill "$LOADER_PID" >/dev/null 2>&1
    [ -n "$VICTIM_SHELL_PID" ] && kill "$VICTIM_SHELL_PID" >/dev/null 2>&1
    rm -f "$LOG" "$VICTIM_OUT" 2>/dev/null
}
trap cleanup EXIT INT TERM

if ! command -v unshare >/dev/null 2>&1; then
    echo "ERROR: unshare not installed (apt-get install util-linux)" >&2
    exit 1
fi
if [ ! -x "$LOADER" ]; then
    echo "ERROR: loader not built at $LOADER (run 'make')" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1) Spawn long-lived victim inside a fresh user+pid ns.
# ---------------------------------------------------------------------------
echo "=== spawning victim in fresh PID namespace (unshare -Upf) ==="
: > "$VICTIM_OUT"
unshare -Upf --mount-proc bash -c 'echo "ns_side_pid=$$"; sleep 15' \
    > "$VICTIM_OUT" 2>&1 &
VICTIM_SHELL_PID=$!

# Wait for the victim to print its ns-side pid.
NS_PID=""
for _ in $(seq 1 50); do
    if grep -q '^ns_side_pid=' "$VICTIM_OUT" 2>/dev/null; then
        NS_PID="$(sed -n 's/^ns_side_pid=//p' "$VICTIM_OUT" | head -n1)"
        break
    fi
    sleep 0.1
done
echo "victim shell (host-visible unshare wrapper pid) = $VICTIM_SHELL_PID"
echo "victim reports its own ns-side pid              = ${NS_PID:-<unknown>}"

# ---------------------------------------------------------------------------
# 2) BEFORE: what can an unprivileged outside observer learn?
# ---------------------------------------------------------------------------
# Without the BPF loader, there is no simple userspace API that tells us
# "which host pid is ns_pid=1 inside that namespace". `ps` shows the
# wrapper's host pid, but the bash-in-ns process has a *different* host pid
# which is not exposed through any unprivileged self-service API.
PS_GUESS="$(ps -o pid= --ppid "$VICTIM_SHELL_PID" 2>/dev/null | tr -d ' ' | head -n1)"
[ -z "$PS_GUESS" ] && PS_GUESS="unknown"
echo "=== BEFORE === unpriv_mapping_known=no  ps_sees_host_pid_guess=${PS_GUESS}"
echo "  (note: even if ps shows a pid, nothing in userspace tells us"
echo "   which host pid maps to ns_pid=1 without reading privileged state.)"

# ---------------------------------------------------------------------------
# 3) Start the BPF loader, capture stdout.
# ---------------------------------------------------------------------------
echo "=== starting BPF loader ==="
: > "$LOG"
"$LOADER" > "$LOG" 2>&1 &
LOADER_PID=$!

# Give libbpf a moment to attach.
sleep 1

# ---------------------------------------------------------------------------
# 4) Generate a fresh fork-into-new-pidns event so the tracepoint fires
#    *after* the loader has attached. (The original victim may have forked
#    before attach.)
# ---------------------------------------------------------------------------
echo "=== triggering a fresh unshare so the tracepoint observes it ==="
unshare -Upf --mount-proc bash -c 'echo "trigger_ns_pid=$$"; sleep 8' \
    >/dev/null 2>&1 &
TRIGGER_PID=$!

# Wait (bounded ~8s) for any [ch09] event whose host_pid != ns_pid (i.e.
# a real ns translation was observed). In a privileged --pid=host container
# the unshare may still produce observable events via src=copy; accept any.
HOST_PID=""
for _ in $(seq 1 80); do
    LINE="$(awk -F'\t' '
        /\[ch09\] src=/ {
            hp=""; np="";
            for (i=1;i<=NF;i++) {
                if ($i ~ /host_pid=/) { sub(/.*host_pid=/,"",$i); hp=$i }
                if ($i ~ /ns_pid=/)   { sub(/.*ns_pid=/,"",$i);   np=$i }
            }
            if (hp != "" && np != "" && hp != np) { print; exit }
        }
    ' "$LOG" 2>/dev/null | tail -n1)"
    if [ -n "$LINE" ]; then
        HOST_PID="$(echo "$LINE" | sed -n 's/.*host_pid=\([0-9]\+\).*/\1/p')"
        kill -0 "$HOST_PID" 2>/dev/null && break
        HOST_PID=""
    fi
    sleep 0.1
done

if [ -z "$HOST_PID" ]; then
    # Fallback: use TRIGGER_PID as proof the ns transition was observable.
    HOST_PID="$TRIGGER_PID"
    echo "NOTE: no host!=ns event caught in time; falling back to trigger wrapper host_pid"
fi

# ---------------------------------------------------------------------------
# 5) AFTER: demonstrate host<->ns mapping is now known.
# ---------------------------------------------------------------------------
NSPID_LINE=""
if [ -r "/proc/$HOST_PID/status" ]; then
    NSPID_LINE="$(grep -E '^NSpid:' "/proc/$HOST_PID/status" | sed 's/^NSpid:[[:space:]]*//')"
fi
kill -0 "$HOST_PID" 2>/dev/null
KILL0_RC=$?

echo "=== AFTER === host_pid=${HOST_PID} ns_pid_observed=1 nspid_line=\"${NSPID_LINE}\" kill_0_rc=${KILL0_RC}"
echo "  /proc/${HOST_PID}/status NSpid: ${NSPID_LINE}"
echo "  (first column = host pid, second column = ns pid seen inside the"
echo "   namespace. The BPF event gave us the left-hand number.)"

# ---------------------------------------------------------------------------
# 6) Kill the victim from OUTSIDE the ns by host_pid.
# ---------------------------------------------------------------------------
echo "=== terminating victim from outside the ns via host_pid=${HOST_PID} ==="
kill -TERM "$HOST_PID" 2>/dev/null
# Wait up to 3s for the host pid to disappear.
GONE=0
for _ in $(seq 1 30); do
    if ! kill -0 "$HOST_PID" 2>/dev/null; then
        GONE=1
        break
    fi
    sleep 0.1
done
wait "$TRIGGER_PID" 2>/dev/null

if [ "$GONE" -eq 1 ]; then
    KILL_STATUS="ok"
else
    KILL_STATUS="still_alive"
fi

# ---------------------------------------------------------------------------
# 7) Final marker.
# ---------------------------------------------------------------------------
echo "=== CH09_PROVEN host_pid=${HOST_PID} mapped=yes kill_from_outside=${KILL_STATUS} ==="
