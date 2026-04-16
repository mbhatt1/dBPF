#!/bin/bash
# ch08 trigger: exercise keyring via keyctl. Works as root inside container.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1

if ! command -v keyctl >/dev/null 2>&1; then
    echo "=== CH08_SKIP reason=\"keyctl not installed\" ==="
    exit 0
fi

DESC="ch08-test-$$"
ID=""
cleanup() { [ -n "$ID" ] && keyctl revoke "$ID" >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

echo "=== keyctl add ==="
ID=$(keyctl add user "$DESC" "super-sekrit-$(date +%s)" @u 2>&1)
echo "id=$ID"
echo "=== describe ==="
keyctl describe "%user:$DESC" 2>&1 | head -2
echo "=== list @s ==="
keyctl list @s 2>&1 | head -5
echo "=== print ==="
keyctl print "$ID" 2>&1 | head -1
echo "=== search ==="
keyctl search @u user "$DESC" 2>&1 | head -1
echo "=== done ==="
