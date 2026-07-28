#!/bin/bash
# ch02-overlayfs-lsm trigger: construct tmpfs-backed overlays with a
# secret file in the lower layer, prove baseline copy-up works, then
# load the BPF LSM program and show copy-up is DENIED (-EPERM) for the
# targeted basename.
#
# Two independent overlay mounts are used on purpose:
#   - a "baseline" mount to show copy-up normally succeeds, and
#   - a fresh "test" mount for the BPF-denied case.
# Reusing one mount (writing, then rm'ing the copied-up file from the
# upperdir underneath a live overlay) leaves stale overlay dentry state,
# so copy_up would not fire again — hence two clean mounts.
#
# NOTE on layout: overlayfs requires upperdir and workdir to reside under
# the SAME mount. /tmp is tmpfs here, so plain subdirectories under one
# mktemp root already satisfy that (do NOT mount a separate tmpfs per dir,
# or the mount fails: "workdir and upperdir must reside under the same
# mount").
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo "[trigger] ERROR: host kernel does not have BPF LSM active"
  exit 2
fi

SECRET="secret.txt"
LPID=""
BASE=""
TEST=""

cleanup() {
  [ -n "$LPID" ] && kill "$LPID" 2>/dev/null
  wait 2>/dev/null
  [ -n "$BASE" ] && { umount "$BASE/merged" 2>/dev/null; rm -rf "$BASE"; }
  [ -n "$TEST" ] && { umount "$TEST/merged" 2>/dev/null; rm -rf "$TEST"; }
}
trap cleanup EXIT

mk_overlay() { # $1 = root dir; creates lower/upper/work/merged + secret in lower
  local R="$1"
  mkdir -p "$R/lower" "$R/upper" "$R/work" "$R/merged"
  echo "original-lower-content" > "$R/lower/$SECRET"
  mount -t overlay overlay \
    -o "lowerdir=$R/lower,upperdir=$R/upper,workdir=$R/work" \
    "$R/merged"
}

echo "=== baseline (no BPF): copy-up via write should succeed ==="
BASE="$(mktemp -d /tmp/ch02-base.XXXXXX)"
mk_overlay "$BASE" || { echo "[trigger] baseline overlay mount failed"; exit 3; }
echo "tampered-baseline" >> "$BASE/merged/$SECRET"
echo "baseline upper contents (should contain $SECRET — copy-up happened):"
ls -la "$BASE/upper/"
umount "$BASE/merged" 2>/dev/null; rm -rf "$BASE"; BASE=""

echo "=== starting BPF LSM loader (protect $SECRET) ==="
"$HERE/build/ch02-overlayfs-lsm" -p "$SECRET" >/tmp/ch02-lsm.log 2>&1 &
LPID=$!
sleep 2

echo "=== with BPF LSM: write attempt should fail (EPERM) ==="
TEST="$(mktemp -d /tmp/ch02-test.XXXXXX)"
mk_overlay "$TEST" || { echo "[trigger] test overlay mount failed"; exit 3; }
( echo "tampered-after-bpf" >> "$TEST/merged/$SECRET" ) 2>&1
RET=$?
echo "write ret=$RET (nonzero = denied)"
echo "test upper contents (should be empty — copy-up denied):"
ls -la "$TEST/upper/"
echo "merged content (still attacker-controlled lower layer):"
cat "$TEST/merged/$SECRET"

sleep 1
echo "=== loader log ==="
cat /tmp/ch02-lsm.log
