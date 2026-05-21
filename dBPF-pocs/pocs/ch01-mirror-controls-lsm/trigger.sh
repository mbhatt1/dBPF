#!/bin/bash
# ch01-mirror-controls-lsm trigger: spawn unprivileged child that tries
# CAP_DAC_READ_SEARCH; register its tgid, run loader, verify the child's
# subsequent attempts succeed on a BPF-LSM-enabled kernel.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo "[trigger] ERROR: host kernel does not have BPF LSM active (cat /sys/kernel/security/lsm)"
  exit 2
fi
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
wait 2>/dev/null
echo "=== loader log ==="
cat /tmp/ch01-lsm.log
userdel t01lsm 2>/dev/null
