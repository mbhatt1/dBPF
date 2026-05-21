#!/bin/bash
# ch06-silence-selinux-lsm-synthetic trigger.
#
# Proves the primitive "a BPF LSM program can synthesize a denial AND
# flip that denial to an allow", without requiring SELinux on the host.
#
# Procedure:
#   1. Sanity-check that 'bpf' is active in /sys/kernel/security/lsm.
#   2. Create an unprivileged user + sentinel file readable by it.
#   3. Baseline-A: cat with no BPF attached → succeeds.
#   4. Start loader (stage=OFF) → behavior unchanged.
#   5. Send SIGUSR1 (stage=DENY) → cat fails with EACCES (synthetic deny).
#   6. Send SIGUSR2 (stage=FLIP) → cat succeeds (flip primitive).
#   7. Emit the concept-proven marker line.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch06-silence-selinux-lsm-synthetic"
LOG=/tmp/ch06-synth.log
PIDFILE=/tmp/ch06-synth.pid

LSM_LINE="$(cat /sys/kernel/security/lsm 2>/dev/null)"
echo "=== kernel LSM line: ${LSM_LINE:-<unreadable>} ==="
if ! echo "$LSM_LINE" | grep -q bpf; then
  echo "=== CH06_SYNTH_SKIP reason=\"BPF LSM not in /sys/kernel/security/lsm\" ==="
  exit 0
fi

if [ ! -x "$BIN" ]; then
  echo "=== CH06_SYNTH_SKIP reason=\"loader not built: $BIN\" ==="
  exit 0
fi

# --- build stage: unprivileged user + sentinel file -------------------
STAGE="$(mktemp -d /tmp/ch06-synth-stage.XXXXXX)"
SENTINEL="$STAGE/sentinel.txt"
echo "ch06-synth-secret" > "$SENTINEL"
chmod 644 "$SENTINEL"
# Make the dir world-traversable so the unprivileged user can reach the file.
chmod 755 "$STAGE"

DUT=dut06synth
id "$DUT" >/dev/null 2>&1 || useradd -M "$DUT" 2>/dev/null || adduser -D "$DUT" 2>/dev/null
DUT_UID="$(id -u "$DUT" 2>/dev/null)"
if [ -z "$DUT_UID" ]; then
  echo "=== CH06_SYNTH_SKIP reason=\"could not create unprivileged user\" ==="
  rm -rf "$STAGE"
  exit 0
fi
echo "=== target uid=$DUT_UID sentinel=$SENTINEL ==="

cleanup() {
  if [ -n "$LPID" ] && kill -0 "$LPID" 2>/dev/null; then
    kill -TERM "$LPID" 2>/dev/null
    wait "$LPID" 2>/dev/null
  fi
  rm -f "$PIDFILE"
  userdel "$DUT" 2>/dev/null || deluser "$DUT" 2>/dev/null
  rm -rf "$STAGE"
}
trap cleanup EXIT

read_as_dut() {
  # Use `su` if available; fall back to `runuser`.
  if command -v su >/dev/null 2>&1; then
    su "$DUT" -s /bin/sh -c "cat '$SENTINEL' >/dev/null 2>&1; echo \$?"
  else
    runuser -u "$DUT" -- sh -c "cat '$SENTINEL' >/dev/null 2>&1; echo \$?"
  fi
}

# --- baseline A: no BPF attached --------------------------------------
echo "=== baseline (no BPF): unprivileged cat ==="
BASELINE_RC=$(read_as_dut)
echo "baseline_rc=$BASELINE_RC"

# --- start the loader in stage=OFF ------------------------------------
echo "=== starting loader (stage=off) ==="
rm -f "$PIDFILE"
: > "$LOG"
"$BIN" -u "$DUT_UID" -s "$SENTINEL" -p "$PIDFILE" >"$LOG" 2>&1 &
LPID=$!
# Wait for the loader to write its pidfile (attach completed).
for _ in $(seq 1 50); do
  [ -s "$PIDFILE" ] && break
  sleep 0.1
done
if [ ! -s "$PIDFILE" ]; then
  echo "=== loader failed to start — log follows ==="
  cat "$LOG"
  echo "=== CH06_SYNTH_SKIP reason=\"loader attach failed\" ==="
  exit 0
fi
LPID="$(cat "$PIDFILE")"
echo "loader_pid=$LPID"

# --- BEFORE: denier only (stage=DENY) ---------------------------------
echo "=== BEFORE: stage=DENY — expect EACCES ==="
kill -USR1 "$LPID"
sleep 0.3
BEFORE_RC=$(read_as_dut)
echo "before_rc=$BEFORE_RC (expected=1, EACCES)"

# --- AFTER: flipper on (stage=FLIP) -----------------------------------
echo "=== AFTER: stage=FLIP — expect success ==="
kill -USR2 "$LPID"
sleep 0.3
AFTER_RC=$(read_as_dut)
echo "after_rc=$AFTER_RC (expected=0, success)"

# --- collect events ----------------------------------------------------
kill -HUP "$LPID" 2>/dev/null
sleep 0.2
kill -TERM "$LPID" 2>/dev/null
wait "$LPID" 2>/dev/null
LPID=""

echo "=== loader log ==="
cat "$LOG"

DENY_HITS=$(grep -cE 'stage=deny .* verdict=-13' "$LOG" 2>/dev/null)
FLIP_HITS=$(grep -cE 'stage=flip .* verdict=0 ' "$LOG" 2>/dev/null)
DENY_HITS=${DENY_HITS:-0}
FLIP_HITS=${FLIP_HITS:-0}

DENIAL_OK=no
FLIP_OK=no
if [ "$BEFORE_RC" = "1" ] && [ "$DENY_HITS" -gt 0 ]; then
  DENIAL_OK=yes
fi
if [ "$AFTER_RC" = "0" ] && [ "$FLIP_HITS" -gt 0 ]; then
  FLIP_OK=yes
fi

echo "=== summary ==="
echo "baseline_rc=$BASELINE_RC before_rc=$BEFORE_RC after_rc=$AFTER_RC"
echo "deny_events=$DENY_HITS flip_events=$FLIP_HITS"

if [ "$DENIAL_OK" = "yes" ] && [ "$FLIP_OK" = "yes" ]; then
  echo "=== CH06_CONCEPT_PROVEN denial_injected=yes flip_applied=yes ==="
  exit 0
fi

echo "=== CH06_SYNTH_FAIL denial_injected=$DENIAL_OK flip_applied=$FLIP_OK ==="
exit 1
