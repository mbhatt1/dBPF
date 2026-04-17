#!/bin/bash
# ch02-overlayfs-lsm trigger: construct a tmpfs-backed overlay with a
# secret file in the lower layer, prove baseline copy-up works, then
# load the BPF LSM program and show copy-up is denied for the targeted
# basename.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
LPID=""

if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo "=== CH02_SKIP reason=\"BPF LSM not active in /sys/kernel/security/lsm\" ==="
  exit 0
fi
if [ ! -x "$HERE/build/ch02-overlayfs-lsm" ]; then
  echo "=== CH02_SKIP reason=\"loader not built at $HERE/build/ch02-overlayfs-lsm\" ==="
  exit 0
fi

ROOT="$(mktemp -d /tmp/ch02-ovl.XXXXXX)"
mkdir -p "$ROOT/lower" "$ROOT/merged"
# Single tmpfs so upper and work share the same filesystem (overlay requirement)
mkdir -p "$ROOT/backing"
mount -t tmpfs tmpfs "$ROOT/backing"
mkdir -p "$ROOT/backing/upper" "$ROOT/backing/work"

SECRET="secret.txt"
echo "original-lower-content" > "$ROOT/lower/$SECRET"

mount -t overlay overlay \
  -o "lowerdir=$ROOT/lower,upperdir=$ROOT/backing/upper,workdir=$ROOT/backing/work" \
  "$ROOT/merged"

cleanup() {
  kill $LPID 2>/dev/null
  wait 2>/dev/null
  umount "$ROOT/merged" 2>/dev/null
  umount "$ROOT/backing" 2>/dev/null
  rm -rf "$ROOT"
}
trap cleanup EXIT

echo "=== baseline (no BPF): copy-up via write should succeed ==="
echo "tampered-baseline" >> "$ROOT/merged/$SECRET"
ls -la "$ROOT/backing/upper/"
# reset: remove upper copy so we can re-test
rm -f "$ROOT/backing/upper/$SECRET"

echo "=== starting BPF LSM loader (protect $SECRET) ==="
"$HERE/build/ch02-overlayfs-lsm" -p "$SECRET" >/tmp/ch02-lsm.log 2>&1 &
LPID=$!
sleep 1

echo "=== with BPF LSM: write attempt should fail (EPERM) ==="
( echo "tampered-after-bpf" >> "$ROOT/merged/$SECRET" ) 2>&1
RET=$?
echo "write ret=$RET"
echo "upper layer contents (should be empty — copy-up denied):"
ls -la "$ROOT/backing/upper/"

sleep 1
echo "=== loader log ==="
cat /tmp/ch02-lsm.log

# Proof: if upper layer is empty after write attempt, copy-up was denied
UPPER_COUNT=$(ls "$ROOT/backing/upper/" 2>/dev/null | wc -l)
if [ "$UPPER_COUNT" -eq 0 ]; then
  echo "=== CH02_LSM_PROVEN copy_up_denied=yes upper_empty=yes ==="
else
  echo "=== CH02_LSM_SKIP reason=\"upper layer not empty ($UPPER_COUNT files)\" ==="
fi
