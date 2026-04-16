#!/bin/bash
# ch17 trigger — force the kernel to evaluate ACPI objects (x86) or to
# request firmware (aarch64 fallback).
#
# Steps (all best-effort; set +e keeps going on error):
#   1. Try `modprobe test_firmware` — provides /sys/devices/virtual/misc/
#      test_firmware/trigger_request. Often absent on linuxkit.
#   2. If the trigger node exists, echo a bogus filename into it. The kernel
#      will request_firmware("bogus"), fail to find it, and return -ENOENT,
#      having traversed the request_firmware → _request_firmware →
#      firmware_request_nowarn chain.
#   3. Fallback: walk /sys/firmware/* entries. On some systems a read
#      probes ACPI namespace or causes a firmware lookup.
set +e

echo "=== step 1: modprobe test_firmware ==="
modprobe test_firmware 2>&1 | head -5
MOD_RC=$?
echo "  (modprobe exit: $MOD_RC)"

TRIG=/sys/devices/virtual/misc/test_firmware/trigger_request
if [ -w "$TRIG" ]; then
    echo "=== step 2: trigger a firmware request ==="
    echo "bogus-ch17-$(date +%s).bin" > "$TRIG" 2>&1
    echo "  (trigger_request written)"
else
    echo "=== step 2: test_firmware absent (no $TRIG); falling back ==="
fi

echo
echo "=== step 3: walk /sys/firmware entries (may probe ACPI/firmware) ==="
if [ -d /sys/firmware ]; then
    find /sys/firmware -maxdepth 3 -type f 2>/dev/null | head -5 | while read f; do
        head -c 1 "$f" >/dev/null 2>&1
        echo "  read: $f"
    done
else
    echo "  /sys/firmware absent — no fallback path available"
fi

echo
echo "=== ch17 trigger finished; check loader stdout for ACPI_PROBE_PROVEN or CH17_SKIP ==="
