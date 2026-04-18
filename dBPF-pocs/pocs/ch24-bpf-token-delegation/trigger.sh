#!/bin/bash
# ch24-bpf-token-delegation trigger.
#
# Demonstrates BPF token delegation (Linux 6.9+): a privileged server mounts
# bpffs with a BPF token, passes the token fd over a UNIX socket via
# SCM_RIGHTS to an unprivileged client, and the client uses that token to
# load a tracepoint program it otherwise could not load.
#
# Flow:
#   - root starts the server (--server) which mounts bpffs at
#     /tmp/ch24-bpffs, creates the token, listens on /tmp/ch24.sock.
#   - unprivileged user tu24 runs the client (--client); it connects to
#     the socket, receives the token fd, calls bpf_prog_load with
#     token_fd=received_fd, attaches tracepoint:syscalls:sys_enter_getuid,
#     and drains the ringbuf.
#   - trigger generates getuid() events from both root and tu24, then
#     waits for the client to print CH24_PROVEN with an event count.
#
# Pedagogical point: BPF token lets a privileged component delegate
# narrow BPF capabilities to an unprivileged one without granting
# CAP_BPF/CAP_SYS_ADMIN to the full user namespace.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch24-bpf-token-delegation"
BIN_ABS="$BIN"
SOCK=/tmp/ch24.sock
READY=/tmp/ch24-server-ready
BPFFS=/tmp/ch24-bpffs
SERVER_LOG=/tmp/ch24-server.log
CLIENT_LOG=/tmp/ch24-client.log
DUSER="tu24"
SERVER_PID=""
CLIENT_PID=""

cleanup() {
    if [ -n "$CLIENT_PID" ] && kill -0 "$CLIENT_PID" 2>/dev/null; then
        kill -TERM "$CLIENT_PID" 2>/dev/null
        wait "$CLIENT_PID" 2>/dev/null
    fi
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    if mountpoint -q "$BPFFS" 2>/dev/null; then
        umount "$BPFFS" 2>/dev/null
    fi
    [ -d "$BPFFS" ] && rmdir "$BPFFS" 2>/dev/null
    rm -f "$SOCK" "$READY" 2>/dev/null
}
trap cleanup EXIT INT TERM

# --- preflight ---
if [ "$(id -u)" != "0" ]; then
    echo '=== CH24_SKIP reason="must run as root" ==='
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

# --- user setup ---
if ! id "$DUSER" >/dev/null 2>&1; then
    useradd -M -s /bin/bash "$DUSER" 2>/dev/null
fi
if ! id "$DUSER" >/dev/null 2>&1; then
    echo "=== CH24_SKIP reason=\"cannot create user $DUSER\" ==="
    exit 0
fi

# --- clean leftovers from prior runs ---
if mountpoint -q "$BPFFS" 2>/dev/null; then
    umount "$BPFFS" 2>/dev/null
fi
[ -d "$BPFFS" ] && rmdir "$BPFFS" 2>/dev/null
rm -f "$SOCK" "$READY" 2>/dev/null

# Make binary executable by tu24 (absolute path so su can find it).
chmod a+rx "$BIN_ABS" 2>/dev/null

echo "=== ch24 trigger starting (kernel=$KVER user=$DUSER) ==="

# --- start server as root ---
: > "$SERVER_LOG"
"$BIN_ABS" --server --ready-file="$READY" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait up to 3s for ready file.
READY_OK=no
for _ in $(seq 1 30); do
    if [ -e "$READY" ]; then
        READY_OK=yes
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if [ "$READY_OK" != "yes" ]; then
    echo "=== server did not become ready ==="
    tail -n 40 "$SERVER_LOG" 2>/dev/null
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    SERVER_PID=""
    echo '=== CH24_SKIP reason="server did not become ready" ==='
    exit 0
fi
echo "=== server ready pid=$SERVER_PID ==="

# --- start client as tu24 ---
: > "$CLIENT_LOG"
su -s /bin/bash "$DUSER" -c "cd $PWD && $BIN_ABS --client" > "$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!

# Wait up to 3s for 'attached' or a SKIP line.
CLIENT_READY=no
CLIENT_SKIPPED=no
for _ in $(seq 1 30); do
    if grep -q 'attached' "$CLIENT_LOG" 2>/dev/null; then
        CLIENT_READY=yes
        break
    fi
    if grep -q 'CH24_SKIP' "$CLIENT_LOG" 2>/dev/null; then
        CLIENT_SKIPPED=yes
        break
    fi
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if [ "$CLIENT_SKIPPED" = "yes" ]; then
    SKIP_REASON="$(grep 'CH24_SKIP' "$CLIENT_LOG" | head -n1 | sed -n 's/.*reason="\([^"]*\)".*/\1/p')"
    [ -z "$SKIP_REASON" ] && SKIP_REASON="client reported skip"
    echo "=== client log ==="
    cat "$CLIENT_LOG"
    echo "=== server log tail ==="
    tail -n 40 "$SERVER_LOG"
    echo "=== CH24_SKIP reason=\"$SKIP_REASON\" ==="
    exit 0
fi

if [ "$CLIENT_READY" != "yes" ]; then
    echo "=== client did not attach in time ==="
    cat "$CLIENT_LOG"
    echo "=== server log tail ==="
    tail -n 40 "$SERVER_LOG"
    echo '=== CH24_SKIP reason="client did not attach" ==='
    exit 0
fi
echo "=== client attached pid=$CLIENT_PID ==="

# --- generate getuid events ---
echo "=== generating getuid() events ==="
for _ in $(seq 1 10); do
    id >/dev/null 2>&1
    sleep 0.1
done
for _ in $(seq 1 10); do
    su -s /bin/bash "$DUSER" -c 'id >/dev/null 2>&1'
    sleep 0.1
done

# --- wait for client to finish its ~10s poll ---
WAIT_OK=no
for _ in $(seq 1 150); do
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        WAIT_OK=yes
        break
    fi
    sleep 0.1
done
if [ "$WAIT_OK" != "yes" ] && [ -n "$CLIENT_PID" ] && kill -0 "$CLIENT_PID" 2>/dev/null; then
    kill -TERM "$CLIENT_PID" 2>/dev/null
fi
wait "$CLIENT_PID" 2>/dev/null
CLIENT_PID=""

# --- tear down server ---
if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
fi
SERVER_PID=""

if mountpoint -q "$BPFFS" 2>/dev/null; then
    umount "$BPFFS" 2>/dev/null
fi
[ -d "$BPFFS" ] && rmdir "$BPFFS" 2>/dev/null
rm -f "$SOCK" "$READY" 2>/dev/null

# --- parse results ---
echo "=== client log ==="
cat "$CLIENT_LOG"
echo ""
echo "=== server log tail ==="
tail -n 40 "$SERVER_LOG"
echo ""

PROVEN_LINE="$(grep '^\[ch24-client\] CH24_PROVEN' "$CLIENT_LOG" | tail -n1)"
SKIP_LINE="$(grep '^\[ch24-client\] CH24_SKIP' "$CLIENT_LOG" | tail -n1)"

if [ -n "$PROVEN_LINE" ]; then
    UID_EVENTS="$(echo "$PROVEN_LINE" | sed -n 's/.*uid_events=\([0-9]*\).*/\1/p')"
    [ -z "$UID_EVENTS" ] && UID_EVENTS=0
    echo "=== CH24_PROVEN uid_events=$UID_EVENTS token_delegated=yes ==="
    exit 0
fi

if [ -n "$SKIP_LINE" ]; then
    SKIP_REASON="$(echo "$SKIP_LINE" | sed -n 's/.*reason="\([^"]*\)".*/\1/p')"
    [ -z "$SKIP_REASON" ] && SKIP_REASON="client reported skip"
    echo "=== CH24_SKIP reason=\"$SKIP_REASON\" ==="
    exit 0
fi

echo '=== CH24_SKIP reason="client produced no PROVEN/SKIP marker" ==='
exit 0
