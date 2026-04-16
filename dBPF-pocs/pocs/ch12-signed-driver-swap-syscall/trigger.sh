#!/bin/bash
# ch12 signed-driver-swap-syscall — trigger.
#
# 1. BEFORE: insmod of a non-ELF blob returns nonzero (ENOEXEC / EINVAL).
# 2. Start the loader with --all (wildcard) so every tgid's module-load
#    syscall return is forged to 0.
# 3. AFTER: insmod of the same non-ELF blob returns 0 — but lsmod still
#    does not show any fake module (kernel state unchanged). The syscall
#    return was forged; the loader never saw the bytes.
# 4. Emit CH12_CONCEPT_PROVEN marker.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1

FAKE_KO=/tmp/ch12s-fake.ko
LOADER="$HERE/build/ch12-signed-driver-swap-syscall"
MODNAME=ch12sfake   # what lsmod would display if the kernel actually loaded it

cleanup() {
    if [[ -n "$LOADER_PID" ]]; then
        kill "$LOADER_PID" 2>/dev/null
        wait "$LOADER_PID" 2>/dev/null
    fi
    rm -f "$FAKE_KO"
}
trap cleanup EXIT INT TERM

# Build a 1 KiB non-ELF blob. insmod will fail with ENOEXEC ("Invalid module
# format") on any kernel — this is pre-signature-check rejection, so the LSM
# variant couldn't observe it, but the syscall return is still what userspace
# sees.
printf '\x7fELF\x02\x01\x01\x00' > "$FAKE_KO"
printf '\x00\x00\x00\x00\x00\x00\x00\x00' >> "$FAKE_KO"
dd if=/dev/zero bs=1 count=1016 >> "$FAKE_KO" 2>/dev/null
echo "=== fake .ko ready ==="
ls -l "$FAKE_KO"

echo
echo "=== error_injection list check ==="
grep -E "finit_module|init_module" /sys/kernel/debug/error_injection/list \
    2>/dev/null || echo "(no match — override would not be permitted)"

echo
echo "=== BEFORE (no loader attached) ==="
BEFORE_OUT="$(insmod "$FAKE_KO" 2>&1)"
BEFORE_RC=$?
ERR_TEXT="$(echo "$BEFORE_OUT" | head -1)"
# Translate the common error string to the errno name the kernel returned.
if echo "$ERR_TEXT" | grep -qi "Invalid module format"; then
    ERRNAME="ENOEXEC"
elif echo "$ERR_TEXT" | grep -qi "Exec format error"; then
    ERRNAME="ENOEXEC"
elif echo "$ERR_TEXT" | grep -qi "Key was rejected"; then
    ERRNAME="EKEYREJECTED"
elif echo "$ERR_TEXT" | grep -qi "Invalid argument"; then
    ERRNAME="EINVAL"
elif echo "$ERR_TEXT" | grep -qi "Required key not available"; then
    ERRNAME="ENOKEY"
else
    ERRNAME="UNKNOWN"
fi
echo "insmod stderr: $BEFORE_OUT"
echo "BEFORE: insmod_rc=${BEFORE_RC} error_text=\"${ERRNAME}\""
lsmod | grep -q "^${MODNAME}\b" && BEFORE_LSMOD=yes || BEFORE_LSMOD=no
echo "BEFORE: lsmod_shows_module=${BEFORE_LSMOD}"

if [[ ! -x "$LOADER" ]]; then
    echo "[trigger] loader binary missing: $LOADER" >&2
    exit 1
fi

echo
echo "=== starting loader (wildcard, forges all callers) ==="
"$LOADER" --all >/tmp/ch12s.out 2>/tmp/ch12s.err &
LOADER_PID=$!

# Wait for "status=ready" before proceeding so the kretprobe is attached.
for i in $(seq 1 50); do
    if grep -q "status=ready" /tmp/ch12s.err 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if ! grep -q "status=ready" /tmp/ch12s.err 2>/dev/null; then
    echo "[trigger] loader did not become ready — stderr follows:" >&2
    cat /tmp/ch12s.err >&2
    exit 1
fi
echo "[trigger] loader ready (pid=$LOADER_PID)"

echo
echo "=== AFTER (loader attached, override active) ==="
AFTER_OUT="$(insmod "$FAKE_KO" 2>&1)"
AFTER_RC=$?
echo "insmod stderr: ${AFTER_OUT:-(empty)}"

# Verify the kernel did NOT actually load the module: lsmod must not show it,
# and /proc/modules must not list it. The user-visible syscall return is
# forged to 0, but no module state exists.
lsmod | grep -q "^${MODNAME}\b" && AFTER_LSMOD=yes || AFTER_LSMOD=no

if [[ "$AFTER_RC" -eq 0 ]]; then
    FORGED=yes
else
    FORGED=no
fi
echo "AFTER: insmod_rc=${AFTER_RC} lsmod_shows_module=${AFTER_LSMOD} syscall_return_forged=${FORGED}"

echo
echo "=== loader ringbuf (last 20 lines) ==="
tail -20 /tmp/ch12s.out 2>/dev/null || echo "(no stdout)"

echo
# Final proof marker. The primitive is "proven" iff:
#   - BEFORE rc was nonzero (baseline: kernel rejects bad .ko)
#   - AFTER rc is 0 (syscall return forged)
#   - lsmod still does not show the module (kernel state unchanged)
if [[ "$BEFORE_RC" -ne 0 && "$AFTER_RC" -eq 0 && "$AFTER_LSMOD" == "no" ]]; then
    echo "=== CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no ==="
else
    echo "=== CH12_CONCEPT_UNPROVEN before_rc=${BEFORE_RC} after_rc=${AFTER_RC} lsmod=${AFTER_LSMOD} ==="
fi
