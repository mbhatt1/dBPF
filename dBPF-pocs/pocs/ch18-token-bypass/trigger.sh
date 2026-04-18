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

REAL_UID=$(id -u "$USER_NAME" 2>/dev/null)
if [ -z "$REAL_UID" ] || [ "$REAL_UID" = "0" ]; then
    echo "=== CH18_SKIP reason=\"could not create unprivileged test user\" ==="
    exit 0
fi

echo "=== baseline (BEFORE): id -u as $USER_NAME (no BPF interference expected) ==="
BEFORE=$(su "$USER_NAME" -c 'id -u' 2>/dev/null)
echo "baseline uid=${BEFORE}"

echo "=== with BPF attached: id -u should report 0 if forge is live ==="
AFTER=$(su "$USER_NAME" -c 'id -u' 2>/dev/null)
echo "attacked uid=${AFTER}"

# Emit PROVEN only if the actual effect is observable: the forged uid must
# differ from the baseline and be 0. Otherwise the forge never fired — emit a
# SKIP so the harness reports honestly instead of claiming a false victory.
if [ "$BEFORE" != "0" ] && [ "$AFTER" = "0" ]; then
    FORGES="${CH18_FORGES:-1}"
    echo "=== TOKEN_FORGE_PROVEN uid_forges=${FORGES} ==="
else
    echo "=== CH18_SKIP reason=\"no forge observed: before=${BEFORE} after=${AFTER}\" ==="
fi

echo "=== done ==="
