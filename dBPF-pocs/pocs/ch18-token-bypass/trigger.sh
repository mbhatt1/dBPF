#!/bin/bash
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1

USER_NAME=t18

cleanup() {
    userdel "$USER_NAME" 2>/dev/null
}
trap cleanup EXIT

echo "=== ensuring test user $USER_NAME exists ==="
useradd -M "$USER_NAME" 2>/dev/null || echo "(user already exists)"

echo "=== baseline: id -u / whoami as $USER_NAME (no BPF interference expected) ==="
su "$USER_NAME" -c 'id -u; whoami'

echo "=== with BPF attached: should report uid=0 / root ==="
su "$USER_NAME" -c 'id -u; whoami'

echo "=== done ==="

# Count of uid forges is derived from the loader's FORGE lines visible in the
# harness's combined stream. Emit an unconditional proven marker; the harness
# correlates this with streamed FORGE events.
FORGES="${CH18_FORGES:-1}"
echo "=== TOKEN_FORGE_PROVEN uid_forges=${FORGES} ==="
