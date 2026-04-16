#!/bin/bash
# ch13 trigger — drive powercap activity so the observer emits events.
#
# Pre-checks the four expected kallsyms; if none are present we emit
# CH13_SKIP and exit 0. Otherwise we stat /sys/class/powercap/* to force
# powercap_get_max_power_uw to fire, which the observer catches.
set +e

SYMS=(
    powercap_register_control_type
    powercap_set_max_power_uw
    powercap_get_max_power_uw
    thermal_zone_device_update
)

present=0
if [ -r /proc/kallsyms ]; then
    for s in "${SYMS[@]}"; do
        if grep -qE "[ \t]${s}\$" /proc/kallsyms 2>/dev/null; then
            present=1
            break
        fi
    done
else
    echo "(warn: /proc/kallsyms unreadable; cannot confirm symbol presence)"
fi

if [ "$present" -eq 0 ]; then
    echo "=== CH13_SKIP reason=\"RAPL/powercap not present\" ==="
    echo "(linuxkit aarch64 has no powercap/RAPL subsystem)"
    exit 0
fi

if [ ! -d /sys/class/powercap ]; then
    echo "=== CH13_SKIP reason=\"RAPL/powercap not present\" ==="
    echo "(/sys/class/powercap missing despite kallsyms entries)"
    exit 0
fi

echo "=== /sys/class/powercap domains ==="
ls -1 /sys/class/powercap/ 2>&1 | head -20

echo "=== stat max_power_uw (exercises powercap_get_max_power_uw) ==="
for f in /sys/class/powercap/*/max_power_uw; do
    [ -r "$f" ] || continue
    printf '  %s: ' "$f"
    cat "$f" 2>/dev/null || echo "(read failed)"
done

echo "=== stat constraint_0_max_power_uw ==="
for f in /sys/class/powercap/*/constraint_0_max_power_uw; do
    [ -r "$f" ] || continue
    printf '  %s: ' "$f"
    cat "$f" 2>/dev/null || echo "(read failed)"
done

echo "=== energy_uj samples (RAPL counters; indirect activity) ==="
for f in /sys/class/powercap/*/energy_uj; do
    [ -r "$f" ] || continue
    printf '  %s: ' "$f"
    cat "$f" 2>/dev/null || echo "(read failed)"
done

# Repeat to give the observer more chances to catch the kprobe.
for _ in 1 2 3 4 5; do
    for f in /sys/class/powercap/*/max_power_uw; do
        [ -r "$f" ] && cat "$f" >/dev/null 2>&1
    done
    sleep 0.1
done

echo "=== done — powercap reads issued ==="
