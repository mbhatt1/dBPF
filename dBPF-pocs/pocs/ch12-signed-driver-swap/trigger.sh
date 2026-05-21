#!/bin/bash
# ch12 trigger — force the kernel down the module-loading / signature-check
# path so the loader's kprobes fire.
#
# Two attempts, both harmless:
#   1. modprobe a non-existent module name (expected: "Module not found",
#      ENOENT) — still calls into finit_module/load_module entry points on
#      some kernel/userspace combos.
#   2. insmod a tiny fake .ko (just an ELF magic + minimal header) from
#      /tmp/fake.ko (expected: EBADMSG / EKEYREJECTED / ENOEXEC). This
#      guarantees load_module / module_sig_check / mod_verify_sig are hit
#      on any signed-module kernel.
set +e

FAKE_KO="$(mktemp -u /tmp/ch12-fake.XXXXXX.ko)"
cleanup() {
    rm -f "$FAKE_KO"
}
trap cleanup EXIT INT TERM

echo "=== attempt 1: modprobe a non-existent module ==="
modprobe does-not-exist-module 2>&1 | head -5
echo "  (modprobe exit: $?)"

echo
echo "=== build a fake .ko (ELF magic + minimal header) ==="
# 64-byte ELF64 header with e_type=ET_REL (1), e_machine=any, version=1.
# Just enough bytes that finit_module/load_module will reach the signature
# gate and reject with EBADMSG / EKEYREJECTED.
printf '\x7fELF\x02\x01\x01\x00' > "$FAKE_KO"
printf '\x00\x00\x00\x00\x00\x00\x00\x00' >> "$FAKE_KO"
# Pad to 1 KiB so the kernel's early parse doesn't short-circuit before the
# signature-check path.
dd if=/dev/zero bs=1 count=1016 >> "$FAKE_KO" 2>/dev/null
ls -l "$FAKE_KO"

echo
echo "=== attempt 2: insmod the fake .ko ==="
insmod "$FAKE_KO" 2>&1 | head -5
echo "  (insmod exit: $?)"

echo
echo "=== modprobe/insmod output above ==="
# Proof marker is emitted by the loader on its first ringbuf event; this
# trigger only needs to drive the kernel path. We still print a hint line
# so the harness correlates timestamps.
echo "[ch12] trigger finished; check loader stdout for CH12_PROVEN"
