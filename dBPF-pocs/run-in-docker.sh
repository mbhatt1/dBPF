#!/bin/bash
# End-to-end runtime verification of ch01 + ch02 inside a privileged
# Docker container. Builds with the container kernel's BTF, loads the
# programs, runs triggers, streams ringbuf events, and prints a summary.
set -euo pipefail
cd /w

R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'
B=$'\033[34m'; M=$'\033[35m'; C=$'\033[36m'
BD=$'\033[1m'; X=$'\033[0m'

echo "${BD}${C}[host]${X} $(uname -sr) $(uname -m)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq clang llvm libelf-dev libbpf-dev linux-tools-generic \
    make python3 sudo kmod passwd >/dev/null
ln -sf "$(ls /usr/lib/linux-tools/*/bpftool | head -1)" /usr/local/bin/bpftool

echo "${BD}${C}[host]${X} generating vmlinux.h from container BTF"
for ch in ch01-mirror-controls ch02-overlayfs; do
    mkdir -p pocs/$ch/build
    bpftool btf dump file /sys/kernel/btf/vmlinux format c \
        > pocs/$ch/build/vmlinux.h
    rm -f pocs/$ch/build/*.skel.h pocs/$ch/build/*.bpf.o pocs/$ch/build/$ch
    echo "${BD}${Y}[build]${X} $ch"
    make -C pocs/$ch >/dev/null
done

summary() {
    local tag=$1 log=$2
    echo
    echo "${BD}${M}==== $tag summary ====${X}"
    awk -v tag="$tag" '
        /hook=/ { m=$0; sub(/.*hook=/,"",m); sub(/[ \t].*/,"",m); hooks[m]++ }
        /FLIP/  { flip++ }
        /deny/  { deny++ }
        /\]$/ {}
        END {
            for (h in hooks) printf "  %-24s %6d events\n", h, hooks[h]
            if (flip) printf "  %-24s %6d\n", "FLIP (would-grant)", flip
            if (deny) printf "  %-24s %6d\n", "observed denies", deny
        }
    ' "$log"
    echo "${BD}${G}  total lines: $(wc -l < "$log")${X}"
}

###############################################################################
echo
echo "${BD}${M}================ ch02-overlayfs ================${X}"
LOADER=pocs/ch02-overlayfs/build/ch02-overlayfs
LOG=/tmp/ch02.log; rm -f "$LOG"

for s in ovl_copy_up ovl_maybe_copy_up ovl_copy_up_with_data; do
    if grep -qw "$s" /proc/kallsyms; then
        echo "  ${G}present${X} $s"
    else
        echo "  ${R}missing${X} $s"
    fi
done

"$LOADER" > "$LOG" 2>&1 &
L=$!
sleep 1
bash pocs/ch02-overlayfs/trigger.sh >/tmp/ch02-trig.log 2>&1 || true
sleep 0.3
kill -INT $L 2>/dev/null || true; wait $L 2>/dev/null || true

echo "${BD}${B}--- last 20 ringbuf events ---${X}"
grep hook= "$LOG" | tail -20 | awk '{print "'"$G"'"$0"'"$X"'"}'
summary ch02 "$LOG"

###############################################################################
echo
echo "${BD}${M}================ ch01-mirror-controls ================${X}"
LOADER=pocs/ch01-mirror-controls/build/ch01-mirror-controls
LOG=/tmp/ch01.log; rm -f "$LOG"

if ! grep -qw cap_capable /proc/kallsyms; then
    echo "${R}cap_capable missing${X}"; exit 0
fi

# Fresh unpriv user
userdel -r dut01 2>/dev/null || true
useradd -m -s /bin/bash dut01

# Start loader; we will push target tgid via /proc parsing after spawning child.
# Simpler inline trigger: spawn child that sleeps (so we have its tgid),
# start loader with that tgid, then kick the child to run cap-requiring ops.
FIFO=$(mktemp -u /tmp/ch01.fifo.XXXX); mkfifo "$FIFO"
# Run python3 as the unpriv child directly (exec), so the tgid we target
# is exactly the process making every cap_capable call.
su dut01 -s /bin/bash -c "exec python3 -u -c '
import os, sys, socket
sys.stderr.write(\"pid=%d\n\" % os.getpid()); sys.stderr.flush()
open(\"$FIFO\").read()
try: open(\"/etc/shadow\").read()
except Exception as e: sys.stderr.write(\"shadow: %s\n\" % e)
try:
    s=socket.socket(); s.bind((\"0.0.0.0\",80))
except Exception as e: sys.stderr.write(\"bind80: %s\n\" % e)
try: os.nice(-5)
except Exception as e: sys.stderr.write(\"nice: %s\n\" % e)
sys.stderr.write(\"child_done\n\")
'" 2>/tmp/ch01-child.err &
CH=$!
# wait until the python child prints its pid
for i in $(seq 1 50); do
    TGID=$(awk -F= '/^pid=/{print $2}' /tmp/ch01-child.err 2>/dev/null | head -1)
    [ -n "$TGID" ] && break
    sleep 0.1
done
[ -z "$TGID" ] && TGID=$CH
echo "${C}[harness]${X} unprivileged child tgid=$TGID"

"$LOADER" -t "$TGID" > "$LOG" 2>&1 &
L=$!
sleep 0.6
echo go > "$FIFO"
wait $CH 2>/dev/null || true
sleep 0.4
kill -INT $L 2>/dev/null || true; wait $L 2>/dev/null || true
rm -f "$FIFO"

echo "${BD}${B}--- all ringbuf events ---${X}"
awk '
    /FLIP/  {printf "'"$R$BD"'%s'"$X"'\n",$0;next}
    /deny/  {printf "'"$Y"'%s'"$X"'\n",$0;next}
    {print}
' "$LOG"
summary ch01 "$LOG"

echo
echo "${BD}${C}artifacts:${X}"
ls -la pocs/ch01-mirror-controls/build/ pocs/ch02-overlayfs/build/
