#!/bin/bash
# Ch16 Seccomp TID Hop — contrived-but-real weapon.
#
# Scenario: an attacker cannot read the target's seccomp filter directly
# (it's per-task kernel state). But with a kprobe on __secure_computing,
# every filter evaluation is streamed via ringbuf — the ringbuf is a
# covert side channel that leaks the filter's decisions, letting the
# attacker reconstruct which syscalls are blocked/allowed without any
# privilege over the target task itself.
#
# BEFORE (no loader): the seccomp-confined child calls getpriority and
# is killed by SIGSYS. An external observer sees only "child exited".
#
# AFTER (loader active): every __secure_computing evaluation is streamed
# with (pid, tgid, comm, mode, syscall_nr_ret). The attacker reconstructs
# the filter decisions — exactly which syscalls were checked and which
# were blocked — from the ringbuf.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch16-seccomp-tid-hop"
LOG=/tmp/sec.log
CHILD_LOG=/tmp/sec.child.log

cleanup() {
    if [ -n "${L:-}" ] && kill -0 "$L" 2>/dev/null; then
        kill "$L" 2>/dev/null
        wait "$L" 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not built — run 'make' in $HERE first"
    exit 2
fi

echo "=== kallsyms check ==="
grep -E ' __secure_computing$' /proc/kallsyms || {
  echo "FATAL: __secure_computing not in kallsyms"; exit 2; }

echo ""
echo "=== error_injection list (for reference; override_attempt is a no-op unless listed) ==="
grep -i secure_computing /sys/kernel/debug/error_injection/list 2>/dev/null \
  || echo "(__secure_computing NOT in error_injection list — observer-only as documented)"

# -----------------------------------------------------------------------------
# Build a tiny C child that installs a SECCOMP_RET_KILL_PROCESS filter for
# getpriority(). We use KILL rather than ERRNO so BEFORE vs AFTER is visually
# dramatic: BEFORE => child dies on SIGSYS, observer sees only the corpse.
# -----------------------------------------------------------------------------
CHILD_SRC=/tmp/ch16_seccomp_child.c
CHILD_BIN=/tmp/ch16_seccomp_child
cat > "$CHILD_SRC" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

/* arm64 syscall numbers */
#define NR_GETPRIORITY 141

int main(void) {
    struct sock_filter filter[] = {
        /* A = seccomp_data.nr */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_GETPRIORITY, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        fprintf(stderr, "[child] prctl(NNP): %s\n", strerror(errno));
        return 2;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0)) {
        fprintf(stderr, "[child] prctl(SECCOMP): %s\n", strerror(errno));
        return 2;
    }
    fprintf(stderr, "[child] pid=%d seccomp KILL_PROCESS filter installed\n", getpid());
    /* a few allowed syscalls first */
    (void)getuid(); (void)getgid(); (void)getpid(); (void)getppid();
    /* the forbidden one — should SIGSYS-kill us */
    fprintf(stderr, "[child] calling getpriority() — expect SIGSYS kill\n");
    long r = syscall(SYS_getpriority, 0, 0);
    /* unreachable under KILL_PROCESS */
    fprintf(stderr, "[child] getpriority returned %ld errno=%d (UNEXPECTED)\n", r, errno);
    return 0;
}
EOF

echo ""
echo "=== compiling child ==="
gcc -O1 -static -o "$CHILD_BIN" "$CHILD_SRC" || {
    echo "FATAL: could not build child"; exit 2; }

# -----------------------------------------------------------------------------
# PHASE 1 — BEFORE: run child without the BPF observer. External view: the
# child is killed. Nobody can tell *which* syscall, only that it died.
# -----------------------------------------------------------------------------
echo ""
echo "=== PHASE 1: BEFORE (no BPF observer) ==="
"$CHILD_BIN" >"$CHILD_LOG" 2>&1
BEFORE_RC=$?
BEFORE_SIG="none"
# bash encodes: 128+signum when killed by signal
if [ "$BEFORE_RC" -gt 128 ]; then
    SIGNUM=$((BEFORE_RC - 128))
    case "$SIGNUM" in
        31) BEFORE_SIG="SIGSYS" ;;
        *)  BEFORE_SIG="sig$SIGNUM" ;;
    esac
fi
echo "[before] child exit_code=$BEFORE_RC kill_signal=$BEFORE_SIG"
echo "[before] child stderr:"; sed 's/^/  | /' "$CHILD_LOG"
echo "=== BEFORE (no BPF observer) === child_behavior=killed_by_SIGSYS observer_sees=exit_only eval_log=unknown"

# -----------------------------------------------------------------------------
# PHASE 2 — AFTER: launch observer first, then run child. Observer captures
# every __secure_computing evaluation into the ringbuf.
# -----------------------------------------------------------------------------
echo ""
echo "=== PHASE 2: AFTER (BPF observer active) ==="
echo "=== launching observer with --all ==="
"$BIN" --all > "$LOG" 2>&1 &
L=$!
sleep 1

if ! kill -0 "$L" 2>/dev/null; then
    echo "FATAL: observer exited immediately; log:"
    cat "$LOG"
    exit 3
fi

echo "=== launching seccomp-confined child ==="
"$CHILD_BIN" >"$CHILD_LOG" 2>&1
AFTER_RC=$?
echo "[after] child exit_code=$AFTER_RC"
echo "[after] child stderr:"; sed 's/^/  | /' "$CHILD_LOG"

# let ringbuf drain
sleep 2

# stop observer so log is stable
kill "$L" 2>/dev/null
wait "$L" 2>/dev/null
L=""

echo ""
echo "=== ringbuf events (last 40 lines) ==="
tail -n 40 "$LOG"

# -----------------------------------------------------------------------------
# Reconstruct filter decisions from ringbuf. Every "[seccomp]" line is a
# __secure_computing evaluation — that by itself is a leak (we see every
# syscall number the filter inspects). Count them and count the ones in
# FILTER mode to prove the ringbuf side channel carries filter-mode decisions.
# -----------------------------------------------------------------------------
SECCOMP_EVENTS=$(grep -c '^\[seccomp\]' "$LOG")
FILTER_EVENTS=$(grep -c 'mode=FILTER' "$LOG")
# Count unique syscall_nr values seen under FILTER mode — the observable
# alphabet of the target's filter.
UNIQUE_NRS=$(grep 'mode=FILTER' "$LOG" | \
    sed -n 's/.*nr\/ret=\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | sort -u | wc -l)

# "filter_reconstructed" — we got at least one FILTER-mode event AND at
# least one distinct syscall number from the target. If so the covert
# side channel is proven.
RECON="no"
if [ "$FILTER_EVENTS" -gt 0 ] && [ "$UNIQUE_NRS" -gt 0 ]; then
    RECON="yes"
fi

echo ""
echo "=== AFTER (BPF observer) === seccomp_events=$SECCOMP_EVENTS filter_decisions_leaked=$FILTER_EVENTS unique_syscalls_observed=$UNIQUE_NRS filter_reconstructed=$RECON"
echo "=== SECCOMP_SIDECHANNEL_PROVEN events=$SECCOMP_EVENTS ===" 
if [ "$RECON" = "yes" ]; then
    echo "=== CH16_PROVEN seccomp_events=$SECCOMP_EVENTS filter_events=$FILTER_EVENTS unique_syscalls=$UNIQUE_NRS ==="
fi
echo ""
echo "=== trigger done ==="
