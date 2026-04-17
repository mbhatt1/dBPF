#!/bin/bash
# ch01-mirror-controls-lsm trigger: spawn unprivileged child that tries
# CAP_DAC_READ_SEARCH; register its tgid, run loader, verify the child's
# subsequent attempts succeed on a BPF-LSM-enabled kernel.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
LPID=""

if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo "=== CH01_SKIP reason=\"BPF LSM not active in /sys/kernel/security/lsm\" ==="
  exit 0
fi
if [ ! -x "$HERE/build/ch01-mirror-controls-lsm" ]; then
  echo "=== CH01_SKIP reason=\"loader not built at $HERE/build/ch01-mirror-controls-lsm\" ==="
  exit 0
fi

cleanup() {
  [ -n "$LPID" ] && kill "$LPID" 2>/dev/null && wait "$LPID" 2>/dev/null
  userdel t01lsm 2>/dev/null
  rm -f /tmp/ch01-lsm.log
}
trap cleanup EXIT INT TERM

useradd -M t01lsm 2>/dev/null
echo "=== baseline (no BPF) ==="
su t01lsm -c 'cat /etc/shadow 2>&1 | head -1; echo ret=$?'

echo "=== starting LSM loader (--all) ==="
"$HERE/build/ch01-mirror-controls-lsm" -a >/tmp/ch01-lsm.log 2>&1 &
LPID=$!
sleep 1

echo "=== with BPF LSM fmod_ret override: read should succeed ==="
su t01lsm -c 'cat /etc/shadow 2>&1 | head -1; echo ret=$?'

sleep 1
kill $LPID 2>/dev/null
wait $LPID 2>/dev/null
LPID=""
echo "=== loader log ==="
cat /tmp/ch01-lsm.log
