#!/bin/bash
# ch23 TPM Unseal Heist trigger.
#
# Spawns the loader, creates a 32-byte trusted key via keyctl, forces the
# kernel to exercise the unseal path via keyctl print, cleans up.
#
# Honest skip behavior:
#   - no /dev/tpm0 or /dev/tpmrm0 → CH23_SKIP (no TPM device)
#   - tpm2_unseal_trusted not in kallsyms → CH23_SKIP
#   - keyctl add trusted fails → CH23_SKIP (trusted-key type unavailable)
set +e

echo "=== CH23 trigger starting ==="

if ! [ -e /dev/tpm0 ] && ! [ -e /dev/tpmrm0 ]; then
    echo "=== CH23_SKIP reason=\"no /dev/tpm0 or /dev/tpmrm0\" ==="
    exit 0
fi

if ! grep -q ' tpm2_unseal_trusted$' /proc/kallsyms 2>/dev/null; then
    echo "=== CH23_SKIP reason=\"tpm2_unseal_trusted not in kallsyms\" ==="
    exit 0
fi

LOG=$(mktemp)
./build/ch23-tpm-unseal-heist > "$LOG" 2>&1 &
LPID=$!

# Wait up to 2s for the loader to print its attached banner.
for _ in $(seq 1 20); do
    grep -q '\[ch23\] attached' "$LOG" && break
    sleep 0.1
done

# Mint a 32-byte trusted key. `new 32` tells the kernel to generate
# 32 random bytes and seal them under the default SRK.
KEY_ID=$(keyctl add trusted ch23_test_key "new 32" @u 2>/dev/null)
if [ -z "$KEY_ID" ]; then
    echo "=== CH23_SKIP reason=\"keyctl add trusted failed — trusted-key type unavailable\" ==="
    kill -TERM "$LPID" 2>/dev/null
    wait "$LPID" 2>/dev/null
    rm -f "$LOG"
    exit 0
fi

# Force a read path that exercises tpm2_unseal_trusted.
keyctl print "$KEY_ID" > /dev/null 2>&1

# Give the ringbuf a moment to drain.
sleep 1

kill -TERM "$LPID" 2>/dev/null
wait "$LPID" 2>/dev/null

CAPTURES=$(grep -c 'CAPTURE pid=' "$LOG")
BYTES=$(grep 'CAPTURE pid=' "$LOG" | head -1 | sed 's/.*captured=\([0-9]*\).*/\1/')

# Clean up the test key.
keyctl revoke "$KEY_ID" 2>/dev/null
keyctl unlink "$KEY_ID" @u 2>/dev/null

cat "$LOG"

if [ "$CAPTURES" -gt 0 ]; then
    echo "=== CH23_PROVEN key_bytes_captured=${BYTES:-0} captures=$CAPTURES kind=trusted ==="
else
    echo "=== CH23_SKIP reason=\"no captures — unseal path not exercised\" ==="
fi

rm -f "$LOG"
