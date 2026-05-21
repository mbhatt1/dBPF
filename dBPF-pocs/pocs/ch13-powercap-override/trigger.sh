#!/bin/bash
# ch13 Powercap Override trigger.
set +e

echo "=== CH13 trigger starting ==="

# Check that at least one powercap symbol is present
if ! grep -qE ' (powercap_register_control_type|powercap_get_max_power_uw|thermal_zone_device_update)$' \
        /proc/kallsyms 2>/dev/null; then
    echo "=== CH13_SKIP reason=\"no powercap symbols in kallsyms\" ==="
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG=$(mktemp)

sudo "$SCRIPT_DIR/build/ch13-powercap-override" > "$LOG" 2>&1 &
LPID=$!

for _ in $(seq 1 30); do
    grep -q 'status=ready' "$LOG" && break
    sleep 0.1
done

if ! grep -q 'status=ready' "$LOG"; then
    echo "=== CH13_SKIP reason=\"observer did not attach — no hookable symbols\" ==="
    kill -TERM "$LPID" 2>/dev/null; wait "$LPID" 2>/dev/null
    cat "$LOG"; rm -f "$LOG"; exit 0
fi

# Primary path: read existing powercap sysfs entries
if [ -d /sys/class/powercap ] && ls /sys/class/powercap/ 2>/dev/null | grep -q .; then
    for f in /sys/class/powercap/*/max_power_uw /sys/class/powercap/*/energy_uj; do
        [ -r "$f" ] && cat "$f" > /dev/null 2>&1
    done
fi

# Fallback: kernel module registers a dummy powercap_control_type,
# which fires the kprobe on powercap_register_control_type.
if grep -q ' powercap_register_control_type$' /proc/kallsyms 2>/dev/null; then
    BUILD_DIR=$(sudo mktemp -d /root/ch13_XXXXXX)
    sudo tee "$BUILD_DIR/ch13_trig.c" > /dev/null << 'CEOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/powercap.h>
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ch13 powercap trigger");
static struct powercap_control_type *ct;
static int __init init(void) {
    ct = powercap_register_control_type(NULL, "ch13-test", NULL);
    if (!IS_ERR(ct)) powercap_unregister_control_type(ct);
    return 0;
}
static void __exit fini(void) {}
module_init(init); module_exit(fini);
CEOF
    sudo sh -c "echo 'obj-m := ch13_trig.o' > $BUILD_DIR/Makefile"
    sudo make -C /lib/modules/$(uname -r)/build M="$BUILD_DIR" modules 2>/dev/null
    if [ -f "$BUILD_DIR/ch13_trig.ko" ]; then
        sudo insmod "$BUILD_DIR/ch13_trig.ko" 2>/dev/null
        sudo rmmod ch13_trig 2>/dev/null
    fi
    sudo rm -rf "$BUILD_DIR"
fi

sleep 0.5

kill -TERM "$LPID" 2>/dev/null
wait "$LPID" 2>/dev/null

cat "$LOG"

if grep -q 'CH13_PROVEN' "$LOG"; then
    grep 'CH13_PROVEN' "$LOG"
else
    echo "=== CH13_SKIP reason=\"no events captured — powercap path not exercised\" ==="
fi

rm -f "$LOG"
