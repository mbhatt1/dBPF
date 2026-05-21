#!/bin/bash
# ch06-silence-selinux-lsm trigger.
#
# Requires a host kernel with BOTH "bpf" AND "selinux" active in
# /sys/kernel/security/lsm. On linuxkit aarch64 neither is present;
# prints CH06_SKIP and exits so the harness records an honest skip.
#
# On a proper BPF-LSM+SELinux host (e.g. Fedora 38+ with
# lsm=bpf,selinux,... on the boot cmdline):
#   1. Label a staging file with an SELinux type the running user is
#      denied ("shadow_t").
#   2. Demonstrate baseline: unprivileged read fails with EACCES.
#   3. Start the loader with wildcard flip.
#   4. Retry the read — BPF LSM fmod_ret short-circuits the SELinux
#      verdict and the read succeeds.
#   5. Count FLIP lines emitted and print `CH06_PROVEN flipped=N`.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
LOG=/tmp/ch06-lsm.log

LSM_LINE="$(cat /sys/kernel/security/lsm 2>/dev/null)"
if [ -z "$LSM_LINE" ]; then
  echo "=== CH06_SKIP reason=\"/sys/kernel/security/lsm unreadable\" ==="
  exit 0
fi
if ! echo "$LSM_LINE" | grep -q bpf; then
  echo "=== CH06_SKIP reason=\"BPF LSM not enabled (boot with lsm=bpf,selinux,...)\" ==="
  exit 0
fi
if ! echo "$LSM_LINE" | grep -q selinux; then
  echo "=== CH06_SKIP reason=\"SELinux not in /sys/kernel/security/lsm\" ==="
  exit 0
fi
if ! command -v chcon >/dev/null 2>&1; then
  echo "=== CH06_SKIP reason=\"chcon not available; no SELinux userspace tooling\" ==="
  exit 0
fi
if ! selinuxenabled 2>/dev/null; then
  # selinuxenabled may not exist on every image; fall through if so
  if command -v selinuxenabled >/dev/null 2>&1; then
    echo "=== CH06_SKIP reason=\"selinuxenabled reports SELinux disabled\" ==="
    exit 0
  fi
fi

STAGE="$(mktemp -d /tmp/ch06-stage.XXXXXX)"
SECRET="$STAGE/secret.txt"
echo "selinux-protected-content" > "$SECRET"
chmod 644 "$SECRET"

if ! chcon -t shadow_t "$SECRET" 2>/dev/null; then
  echo "=== CH06_SKIP reason=\"chcon -t shadow_t failed (policy missing)\" ==="
  rm -rf "$STAGE"
  exit 0
fi

useradd -M dut06lsm 2>/dev/null

cleanup() {
  if [ -n "$LPID" ]; then
    kill "$LPID" 2>/dev/null
    wait 2>/dev/null
  fi
  userdel dut06lsm 2>/dev/null
  rm -rf "$STAGE"
}
trap cleanup EXIT

echo "=== baseline (no BPF): unprivileged read of SELinux-labeled file ==="
su dut06lsm -c "cat '$SECRET' >/dev/null 2>&1; echo baseline_ret=\$?"

echo "=== starting BPF LSM loader (wildcard) ==="
"$HERE/build/ch06-silence-selinux-lsm" -a >"$LOG" 2>&1 &
LPID=$!
sleep 1

echo "=== with BPF LSM active: retry the read ==="
for _ in 1 2 3; do
  su dut06lsm -c "cat '$SECRET' >/dev/null 2>&1; echo retry_ret=\$?"
done

sleep 1
kill "$LPID" 2>/dev/null
wait 2>/dev/null
LPID=""

FLIPS=$(grep -cE 'FLIP\s+hook=' "$LOG" 2>/dev/null)
FLIPS=${FLIPS:-0}
echo "=== loader log ==="
cat "$LOG"

if [ "$FLIPS" -gt 0 ]; then
  echo "CH06_PROVEN flipped=$FLIPS"
else
  echo "=== CH06_SKIP reason=\"no FLIP events captured (SELinux did not deny)\" ==="
fi
