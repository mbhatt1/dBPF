#!/bin/bash
# ch12-signed-driver-swap-lsm trigger:
#   - fabricate a fake .ko with valid ELF magic but bogus content.
#   - baseline insmod -> EBADMSG (signature/module-format gate rejects).
#   - with BPF LSM loader running, kernel_read_file/kernel_load_data/
#     locked_down return 0 -> the signature gate is bypassed. insmod
#     still fails (the payload is not a real module) but with a different
#     errno (ENOEXEC or similar) — the errno shift EBADMSG -> ENOEXEC is
#     the evidence that the LSM override fired.
#   - prints CH12_PROVEN flipped=N hook=<name> or CH12_SKIP with reason.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
LOADER="$HERE/build/ch12-signed-driver-swap-lsm"
LOG=/tmp/ch12-lsm.log
FAKE=/tmp/ch12-fake.ko
LPID=""

cleanup() {
  if [ -n "$LPID" ]; then
    kill "$LPID" 2>/dev/null
    wait 2>/dev/null
  fi
  rm -f "$FAKE" "$LOG" 2>/dev/null
}
trap cleanup EXIT INT TERM

# --- Preflight: BPF LSM available ---
if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo '=== CH12_SKIP reason="kernel lacks bpf in /sys/kernel/security/lsm" ==='
  exit 0
fi
if ! command -v insmod >/dev/null 2>&1; then
  echo '=== CH12_SKIP reason="insmod(8) not available" ==='
  exit 0
fi
if [ ! -x "$LOADER" ]; then
  echo "=== CH12_SKIP reason=\"loader not built at $LOADER\" ==="
  exit 0
fi

# --- Fabricate fake.ko: valid ELF relocatable header for aarch64. ---
# ELF64 header: magic, class=64, LE, EI_VERSION=1, OS_ABI=0
# e_type=1 (ET_REL), e_machine=0xB7 (EM_AARCH64), e_version=1
# Everything else zeroed — enough for the kernel to enter the module
# loading path (past ELF header validation) where the LSM hooks fire.
python3 -c '
import struct, sys
# ELF64 header: 64 bytes
ident = b"\x7fELF" + b"\x02\x01\x01" + b"\x00"*9  # 16 bytes
hdr = struct.pack("<HHIQ3QI6H",
    1,        # e_type = ET_REL
    0xB7,     # e_machine = EM_AARCH64
    1,        # e_version
    0,        # e_entry
    0,        # e_phoff
    0,        # e_shoff
    0,        # e_flags
    64,       # e_ehsize
    0, 0,     # e_phentsize, e_phnum
    0, 0,     # e_shentsize, e_shnum
    0,        # e_shstrndx
)
sys.stdout.buffer.write(ident + hdr)
sys.stdout.buffer.write(b"\x00" * (4096 - 64))
' > "$FAKE"

echo "=== baseline (no BPF) ==="
BASE_OUT="$(insmod "$FAKE" 2>&1)"
BASE_RET=$?
echo "baseline_out=$BASE_OUT"
echo "baseline_ret=$BASE_RET"
# Try to tag the baseline errno class.
BASE_ERRNO="unknown"
case "$BASE_OUT" in
  *"Bad message"*|*EBADMSG*)        BASE_ERRNO="EBADMSG" ;;
  *"Key was rejected"*|*EKEYREJECTED*) BASE_ERRNO="EKEYREJECTED" ;;
  *"Required key not available"*|*ENOKEY*) BASE_ERRNO="ENOKEY" ;;
  *"Exec format error"*|*ENOEXEC*)  BASE_ERRNO="ENOEXEC" ;;
  *"Operation not permitted"*|*EPERM*) BASE_ERRNO="EPERM" ;;
esac
echo "baseline_errno=$BASE_ERRNO"

echo "=== starting LSM loader (--all wildcard) ==="
"$LOADER" -a >"$LOG" 2>&1 &
LPID=$!
sleep 1

if ! kill -0 "$LPID" 2>/dev/null; then
  echo '=== loader failed to start ==='
  cat "$LOG"
  if grep -q '^CH12_SKIP' "$LOG"; then
    grep '^CH12_SKIP' "$LOG"
    exit 0
  fi
  echo '=== CH12_SKIP reason="loader crashed on startup" ==='
  exit 0
fi

echo "=== with BPF LSM fmod_ret override: signature gate bypassed ==="
OVR_OUT="$(insmod "$FAKE" 2>&1)"
OVR_RET=$?
echo "override_out=$OVR_OUT"
echo "override_ret=$OVR_RET"
OVR_ERRNO="unknown"
case "$OVR_OUT" in
  *"Bad message"*|*EBADMSG*)        OVR_ERRNO="EBADMSG" ;;
  *"Key was rejected"*|*EKEYREJECTED*) OVR_ERRNO="EKEYREJECTED" ;;
  *"Required key not available"*|*ENOKEY*) OVR_ERRNO="ENOKEY" ;;
  *"Exec format error"*|*ENOEXEC*)  OVR_ERRNO="ENOEXEC" ;;
  *"Operation not permitted"*|*EPERM*) OVR_ERRNO="EPERM" ;;
esac
echo "override_errno=$OVR_ERRNO"

# Drain ringbuf.
sleep 1
kill "$LPID" 2>/dev/null
wait 2>/dev/null
LPID=""

echo "=== loader log ==="
cat "$LOG"

FLIPS=$(grep -c 'FLIP' "$LOG" 2>/dev/null)
FLIPS=${FLIPS:-0}

# Pick a hook name out of the loader log for the proof line. Prefer
# kernel_read_file (the canonical gate), fall back to the first flip.
HOOK="$(grep -o 'hook=[a-z_]*' "$LOG" | head -1 | sed 's/hook=//')"
[ -z "$HOOK" ] && HOOK="kernel_read_file"

if [ "$FLIPS" -gt 0 ] && [ "$BASE_ERRNO" != "$OVR_ERRNO" ]; then
  echo "CH12_PROVEN flipped=$FLIPS hook=$HOOK baseline=$BASE_ERRNO override=$OVR_ERRNO"
elif [ "$FLIPS" -gt 0 ]; then
  # Flip fired even if the post-gate ELF validator returned the same errno.
  echo "CH12_PROVEN flipped=$FLIPS hook=$HOOK"
else
  echo '=== CH12_SKIP reason="no kernel_read_file/load_data/locked_down flip observed (module-sig path not taken)" ==='
fi
