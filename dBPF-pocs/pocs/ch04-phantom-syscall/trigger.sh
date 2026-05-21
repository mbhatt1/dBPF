#!/bin/bash
# ch04-phantom-syscall trigger — pedagogical BEFORE/AFTER demo.
#
# Shows the observable state delta caused by loading the phantom-syscall BPF
# program: an unprivileged userspace process cannot directly read another
# task's `current->real_parent->comm` (or its own creds struct fields) via
# normal means, but with the BPF program attached a single write() carrying
# the magic prefix coaxes those kernel-internal fields into a ringbuf that
# the (root) loader prints.
set -u
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch04-phantom-syscall"

# --- Build the tiny unprivileged trigger binary ------------------------------
cat > /tmp/phantom.c <<'EOF'
#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main(void){
    const char buf[] = "PHANTOM\0hello-from-unprivileged-user";
    write(2, buf, sizeof(buf)-1);
    return 0;
}
EOF
cc /tmp/phantom.c -o /tmp/phantom
chmod 0755 /tmp/phantom

# --- Ensure an unprivileged user exists --------------------------------------
UNPRIV_USER="phantomguest"
if ! id "$UNPRIV_USER" >/dev/null 2>&1; then
    useradd -M -s /bin/bash "$UNPRIV_USER" 2>/dev/null || \
        adduser --disabled-password --gecos "" --no-create-home "$UNPRIV_USER" 2>/dev/null || true
fi

# --- BEFORE: what an unprivileged process can see on its own -----------------
# The unprivileged user runs a shell and tries to read parent-task fields via
# normal userspace means. /proc/self/status exposes PPid (a number), and
# ps -o comm= -p $PPID works only because /proc is world-readable for comm —
# but crucially the unprivileged process has NO access to its own `cred`
# struct fields (uid/euid are visible via getuid/geteuid for *itself*, but it
# cannot read another task's cred, nor any kernel pointer it chases). It also
# cannot read the kernel-side current->real_parent->comm as observed by the
# *kernel* at the moment of a syscall — only what /proc exposes.
echo "=== BEFORE ==="
BEFORE_OUT="$(su "$UNPRIV_USER" -s /bin/bash -c '
    echo "unpriv_uid=$(id -u)"
    echo "unpriv_euid=$(id -u)"
    ppid=$(awk "/^PPid:/ {print \$2}" /proc/self/status 2>/dev/null)
    echo "proc_self_ppid=${ppid:-unknown}"
    pcomm=$(ps -o comm= -p "$ppid" 2>/dev/null || echo "unreadable")
    echo "proc_parent_comm_via_procfs=${pcomm:-unreadable}"
    echo "kernel_current_cred_uid=unreadable-from-userspace"
    echo "kernel_current_cred_euid=unreadable-from-userspace"
    echo "kernel_current_real_parent_comm=unreadable-from-userspace"
' 2>&1)"
echo "$BEFORE_OUT"

# --- Load the BPF program ----------------------------------------------------
if [ ! -x "$BIN" ]; then
    echo "!! loader $BIN not built; run 'make' first" >&2
    exit 1
fi
LOADER_LOG="$(mktemp)"
"$BIN" >"$LOADER_LOG" 2>&1 &
LOADER_PID=$!
# wait for "attached" on stderr (merged into LOADER_LOG)
for _ in $(seq 1 50); do
    grep -q "attached" "$LOADER_LOG" && break
    sleep 0.1
done

# --- AFTER: same unprivileged context runs /tmp/phantom ----------------------
# The loader's ringbuf now observes the kernel-internal fields and prints
# them to stdout.
su "$UNPRIV_USER" -s /bin/bash -c '/tmp/phantom' 2>/dev/null || true

# Give the ring buffer a moment to flush.
sleep 0.5
kill -TERM "$LOADER_PID" 2>/dev/null || true
wait "$LOADER_PID" 2>/dev/null || true

echo "=== AFTER ==="
PHANTOM_LINE="$(grep -E '^\[phantom\] ' "$LOADER_LOG" | tail -1)"
if [ -z "$PHANTOM_LINE" ]; then
    echo "leaked_uid=<none>"
    echo "leaked_euid=<none>"
    echo "leaked_parent_comm=<none>"
    LEAKED=0
else
    LEAK_UID=$(echo "$PHANTOM_LINE"  | sed -n 's/.* uid=\([0-9]\+\).*/\1/p')
    LEAK_EUID=$(echo "$PHANTOM_LINE" | sed -n 's/.* euid=\([0-9]\+\).*/\1/p')
    LEAK_PCOMM=$(echo "$PHANTOM_LINE" | sed -n 's/.* parent=\([^ ]\+\).*/\1/p')
    echo "leaked_uid=${LEAK_UID:-<none>}"
    echo "leaked_euid=${LEAK_EUID:-<none>}"
    echo "leaked_parent_comm=${LEAK_PCOMM:-<none>}"
    LEAKED=0
    [ -n "$LEAK_UID" ]   && LEAKED=$((LEAKED+1))
    [ -n "$LEAK_EUID" ]  && LEAKED=$((LEAKED+1))
    [ -n "$LEAK_PCOMM" ] && LEAKED=$((LEAKED+1))
fi

echo "=== CH04_PROVEN leaked_fields=${LEAKED} ==="

# Emit loader log tail for debugging.
echo "--- loader log tail ---" >&2
tail -20 "$LOADER_LOG" >&2
rm -f "$LOADER_LOG"
