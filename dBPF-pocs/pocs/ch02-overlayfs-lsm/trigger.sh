#!/bin/bash
# ch02-overlayfs-lsm trigger: construct a tmpfs-backed overlay with a
# secret file in the lower layer, prove baseline copy-up works, then
# load the BPF LSM program and show copy-up is denied for the targeted
# basename.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo "[trigger] ERROR: host kernel does not have BPF LSM active"
  exit 2
fi

ROOT="$(mktemp -d /tmp/ch02-ovl.XXXXXX)"
mkdir -p "$ROOT/lower" "$ROOT/upper" "$ROOT/work" "$ROOT/merged"
# tmpfs mounts so overlay has a real memory-backed upper layer
mount -t tmpfs tmpfs "$ROOT/upper"
mount -t tmpfs tmpfs "$ROOT/work"
# overlay requires upper and work on the same fs
mkdir -p "$ROOT/upper/u" "$ROOT/work/w"

SECRET="secret.txt"
echo "original-lower-content" > "$ROOT/lower/$SECRET"

mount -t overlay overlay \
  -o "lowerdir=$ROOT/lower,upperdir=$ROOT/upper/u,workdir=$ROOT/work/w" \
  "$ROOT/merged"

cleanup() {
  kill $LPID 2>/dev/null
  wait 2>/dev/null
  umount "$ROOT/merged" 2>/dev/null
  umount "$ROOT/upper" 2>/dev/null
  umount "$ROOT/work" 2>/dev/null
  rm -rf "$ROOT"
}
trap cleanup EXIT

echo "=== baseline (no BPF): copy-up via write should succeed ==="
echo "tampered-baseline" >> "$ROOT/merged/$SECRET"
ls -la "$ROOT/upper/u/"
# reset: remove upper copy so we can re-test
rm -f "$ROOT/upper/u/$SECRET"

echo "=== starting BPF LSM loader (protect $SECRET) ==="
"$HERE/build/ch02-overlayfs-lsm" -p "$SECRET" >/tmp/ch02-lsm.log 2>&1 &
LPID=$!
sleep 1

echo "=== with BPF LSM: write attempt should fail (EPERM) ==="
( echo "tampered-after-bpf" >> "$ROOT/merged/$SECRET" ) 2>&1
RET=$?
echo "write ret=$RET"
echo "upper layer contents (should be empty — copy-up denied):"
ls -la "$ROOT/upper/u/"

sleep 1
echo "=== loader log ==="
cat /tmp/ch02-lsm.log
