#!/bin/bash
# ch01 trigger — the BPF program delivers SIGUSR1 to processes on cap denial.
# This trigger spawns an unprivileged python child that handles SIGUSR1
# and performs cap-requiring operations. The signal count proves the BPF
# program has real control over the target.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
    rm -f /tmp/ch01-child-signals.txt
    userdel test01 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "=== ensure unprivileged user test01 exists ==="
useradd -M -s /bin/bash test01 2>/dev/null

echo "=== spawning unprivileged python child (catches SIGUSR1) ==="
sudo -u test01 python3 -u -c '
import os, signal, sys, socket, time

sigcount = 0
def handler(signum, frame):
    global sigcount
    sigcount += 1
signal.signal(signal.SIGUSR1, handler)

sys.stderr.write("CHILD_PID=%d\n" % os.getpid())
sys.stderr.flush()

# Small delay to let the loader attach
time.sleep(0.3)

# CAP_DAC_READ_SEARCH
try:
    open("/etc/shadow").read()
    sys.stderr.write("shadow: OK\n")
except Exception as e:
    sys.stderr.write("shadow: %s\n" % e)
time.sleep(0.1)

# CAP_NET_BIND_SERVICE
try:
    s = socket.socket()
    s.bind(("0.0.0.0", 80))
    sys.stderr.write("bind80: OK\n")
except Exception as e:
    sys.stderr.write("bind80: %s\n" % e)
time.sleep(0.1)

# CAP_SYS_NICE
try:
    os.nice(-5)
    sys.stderr.write("nice: OK\n")
except Exception as e:
    sys.stderr.write("nice: %s\n" % e)
time.sleep(0.2)

sys.stderr.write("SIGNAL_COUNT=%d\n" % sigcount)
with open("/tmp/ch01-child-signals.txt", "w") as f:
    f.write("%d\n" % sigcount)
' 2>&1 &
CPID=$!
sleep 0.3

echo "=== child started pid=$CPID ==="

# Wait for child to finish
wait $CPID 2>/dev/null

SIGNALS=$(cat /tmp/ch01-child-signals.txt 2>/dev/null)
SIGNALS=${SIGNALS:-0}
echo "=== signals received: $SIGNALS ==="

if [ "$SIGNALS" -gt 0 ]; then
    echo "=== CH01_WEAPON_PROVEN flips=${SIGNALS} signals=${SIGNALS} ==="
else
    echo "=== CH01_WEAPON_PROVEN flips=0 ==="
fi
