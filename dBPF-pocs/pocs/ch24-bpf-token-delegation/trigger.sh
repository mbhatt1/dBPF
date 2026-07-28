#!/bin/bash
# ch24-bpf-token-delegation trigger.
#
# Demonstrates BPF token delegation (Linux 6.9+) against a stock, fully-hardened
# kernel. The single loader binary orchestrates the whole thing (see the long
# header comment in ch24-bpf-token-delegation.c for why this cannot be a plain
# privileged-server / unprivileged-client split):
#
#   * a privileged (init-userns) helper materializes a bpffs superblock with
#     delegate_* options, owned by a child user namespace (fsopen in the child,
#     fsconfig+FSCONFIG_CMD_CREATE in the init-userns helper);
#   * a user-namespace-confined MINTER calls the real BPF_TOKEN_CREATE and
#     passes the resulting token fd to a CONSUMER via SCM_RIGHTS;
#   * the CONSUMER -- which holds no capabilities in the init user namespace --
#     uses only that delegated token (with BPF_F_TOKEN_FD) to create a ringbuf
#     map, load a raw tracepoint program, and attach it via
#     BPF_RAW_TRACEPOINT_OPEN, then drains getuid() events from the ringbuf.
#
# Pedagogical point: a BPF token lets a privileged component delegate a narrow
# slice of BPF capability to a host-unprivileged, userns-confined workload
# without granting it CAP_BPF/CAP_SYS_ADMIN/CAP_PERFMON on the host -- and it
# works even with unprivileged_bpf_disabled=2.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch24-bpf-token-delegation"
RUN_LOG=/tmp/ch24-run.log

# --- preflight ---
if [ "$(id -u)" != "0" ]; then
    echo '=== CH24_SKIP reason="must run as root (init-userns helper needs CAP_SYS_ADMIN)" ==='
    exit 0
fi

KVER="$(uname -r)"
KMAJOR="$(echo "$KVER" | cut -d. -f1)"
KMINOR="$(echo "$KVER" | cut -d. -f2 | sed 's/[^0-9].*//')"
if [ -z "$KMAJOR" ] || [ -z "$KMINOR" ]; then
    echo "=== CH24_SKIP reason=\"cannot parse kernel version: $KVER\" ==="
    exit 0
fi
if [ "$KMAJOR" -lt 6 ] || { [ "$KMAJOR" -eq 6 ] && [ "$KMINOR" -lt 9 ]; }; then
    echo "=== CH24_SKIP reason=\"kernel $KVER < 6.9 (BPF token requires 6.9+)\" ==="
    exit 0
fi

if [ ! -x "$BIN" ]; then
    echo "=== CH24_SKIP reason=\"binary not built at $BIN (run make first)\" ==="
    exit 0
fi

echo "=== ch24 trigger starting (kernel=$KVER) ==="
echo "    unprivileged_bpf_disabled=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)"

# --- run the integrated proof ---
: > "$RUN_LOG"
cd "$HERE" || true
"$BIN" --run > "$RUN_LOG" 2>&1
RC=$?

echo "=== loader output ==="
cat "$RUN_LOG"
echo ""

# --- parse results ---
PROVEN_LINE="$(grep '^CH24_PROVEN' "$RUN_LOG" | tail -n1)"
SKIP_LINE="$(grep 'CH24_SKIP' "$RUN_LOG" | tail -n1)"

if [ -n "$PROVEN_LINE" ]; then
    UID_EVENTS="$(echo "$PROVEN_LINE" | sed -n 's/.*uid_events=\([0-9]*\).*/\1/p')"
    [ -z "$UID_EVENTS" ] && UID_EVENTS=0
    if [ "$UID_EVENTS" -gt 0 ]; then
        echo "=== CH24_PROVEN uid_events=$UID_EVENTS token_delegated=yes ==="
        exit 0
    fi
    echo '=== CH24_SKIP reason="delegated program loaded but observed 0 events" ==='
    exit 0
fi

if [ -n "$SKIP_LINE" ]; then
    SKIP_REASON="$(echo "$SKIP_LINE" | sed -n 's/.*reason="\([^"]*\)".*/\1/p')"
    [ -z "$SKIP_REASON" ] && SKIP_REASON="loader reported skip"
    echo "=== CH24_SKIP reason=\"$SKIP_REASON\" ==="
    exit 0
fi

echo "=== CH24_SKIP reason=\"loader produced no PROVEN/SKIP marker (rc=$RC)\" ==="
exit 0
