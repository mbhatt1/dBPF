#!/bin/bash
# ch07 trigger: provoke device-cgroup decisions. Privileged container root
# bypasses devcgroup entirely, so we also run as an unprivileged user.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1

if ! command -v mknod >/dev/null 2>&1 && ! command -v dd >/dev/null 2>&1; then
    echo "=== CH07_SKIP reason=\"mknod/dd not available\" ==="
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; userdel dut07 2>/dev/null' EXIT

useradd -M dut07 2>/dev/null

echo "=== priv root ==="
mknod "$TMP/null" c 1 3 2>&1 | head -1
dd if=/dev/null of=/dev/null count=1 2>/dev/null

echo "=== unpriv dut07 ==="
su dut07 -c "dd if=/dev/null of=/dev/null count=1 2>&1 | head -1"
su dut07 -c "dd if=/dev/urandom of=/dev/null count=1 bs=1 2>&1 | head -1"
su dut07 -c "dd if=/dev/mem of=/dev/null count=1 bs=1 2>&1 | head -1"

echo "=== done ==="
