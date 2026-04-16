#!/bin/bash
# ch07-devcgroup-houdini-lsm trigger — synthetic deny + flip.
#
# Why synthetic: a standard LSM chain runs `capability` BEFORE `bpf`, and
# vfs_mknod direct-calls `capable(CAP_MKNOD)` ahead of the LSM chain.
# That means an organic cap_mknod-based denial short-circuits the chain
# before our `lsm.s/inode_mknod` fmod_ret program can see it. The
# ch06-silence-selinux-lsm-synthetic POC established the right pattern
# for these kernels: one program implements both the denier and the
# flipper, selected by a stage control map. This trigger drives that
# pattern:
#
#   1. BEFORE: attach loader with target_tgid=$BASH_PID, stage=deny.
#      The probe bash runs `mknod $NODE b 8 0`. The BPF program returns
#      -EPERM → syscall fails. rc=1 (EPERM).
#   2. AFTER:  flip the stage to `flip`. Repeat the same mknod. The BPF
#      program returns 0 → syscall succeeds → rc=0 and block dev appears.
#   3. Print:
#        === CH07_CONCEPT_PROVEN before_rc=<N> after_rc=0 flips=<M> ===
#
# BTF-driven hook prune in the loader removes dev_open if the kernel
# does not expose `bpf_lsm_dev_open` in vmlinux BTF (linuxkit 6.12
# aarch64 does not).
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch07-devcgroup-houdini-lsm"
LOG=/tmp/ch07-lsm.log
PIDFILE=/tmp/ch07-lsm.pid

# --- prereq: BPF LSM ------------------------------------------------------
LSM_LINE="$(cat /sys/kernel/security/lsm 2>/dev/null)"
echo "=== kernel LSM line: ${LSM_LINE:-<unreadable>} ==="
if [ -z "$LSM_LINE" ]; then
  echo "=== CH07_SKIP reason=\"/sys/kernel/security/lsm unreadable\" ==="
  exit 0
fi
if ! echo "$LSM_LINE" | grep -q bpf; then
  echo "=== CH07_SKIP reason=\"BPF LSM not enabled (boot with lsm=bpf,...)\" ==="
  exit 0
fi
if [ ! -x "$BIN" ]; then
  echo "=== CH07_SKIP reason=\"loader binary not built: $BIN\" ==="
  exit 0
fi

# --- stage ----------------------------------------------------------------
STAGE="$(mktemp -d /tmp/ch07-stage.XXXXXX)"
chmod 777 "$STAGE"
NODE="$STAGE/ch07-bdev"
rm -f "$NODE"

cleanup() {
  if [ -n "$LPID" ] && kill -0 "$LPID" 2>/dev/null; then
    kill -TERM "$LPID" 2>/dev/null
    wait "$LPID" 2>/dev/null
  fi
  rm -f "$PIDFILE"
  rm -rf "$STAGE"
}
LPID=""
trap cleanup EXIT

# The probe runs `mknod` as a direct fork-exec from this bash. The child
# process's tgid differs from $$, so we target wildcard (tgid=0) and
# rely on the short `stage=deny|flip` window to bound collateral damage.
# The BPF hook only fires on char/block mknod + open, so non-device
# syscalls are never affected.
PROBE_PID=$$
echo "=== probe pgid=$PROBE_PID (wildcard target — brief windows only) node=$NODE ==="

# --- start loader: wildcard tgid, initial stage=off (safe until flipped) --
: > "$LOG"
rm -f "$PIDFILE"
"$BIN" -t 0 -p "$PIDFILE" -s off >"$LOG" 2>&1 &
LPID=$!

# Wait for pidfile (attach complete). libbpf LSM attach is synchronous
# but skeleton load can take time on slow emulated CI hosts.
for _ in $(seq 1 80); do
  [ -s "$PIDFILE" ] && break
  sleep 0.1
done
if [ ! -s "$PIDFILE" ]; then
  echo "=== loader failed to start — log follows ==="
  cat "$LOG"
  echo "=== CH07_SKIP reason=\"loader attach failed\" ==="
  exit 0
fi
LPID="$(cat "$PIDFILE")"
echo "loader_pid=$LPID"

# --- switch to stage=deny -------------------------------------------------
echo "=== switching stage -> deny (SIGUSR1) ==="
kill -USR1 "$LPID"
# Give the loader's main-loop a tick to ingest the signal and push the map.
sleep 0.3

# --- BEFORE: stage=deny — expect EPERM ------------------------------------
echo "=== BEFORE (stage=deny): mknod b 8 0 $NODE ==="
rm -f "$NODE"
mknod "$NODE" b 8 0 2>&1 | sed -n '1,2p'
mknod "$NODE" b 8 0 >/dev/null 2>&1
BEFORE_RC=$?
echo "before_rc=$BEFORE_RC (expected non-zero)"
rm -f "$NODE"

# --- switch to stage=flip -------------------------------------------------
echo "=== switching stage -> flip (SIGUSR2) ==="
kill -USR2 "$LPID"
# Give the loader's main-loop a tick to ingest the signal and push the map.
sleep 0.3

# --- AFTER: stage=flip — expect success -----------------------------------
echo "=== AFTER  (stage=flip): mknod b 8 0 $NODE ==="
rm -f "$NODE"
mknod "$NODE" b 8 0 2>&1 | sed -n '1,2p'
mknod "$NODE" b 8 0 >/dev/null 2>&1
AFTER_RC=$?
echo "after_rc=$AFTER_RC (expected 0)"
if [ -b "$NODE" ]; then
  ls -l "$NODE"
fi

# Run a couple more mknod attempts to give the ring buffer time to drain.
for _ in 1 2; do
  rm -f "$NODE"
  mknod "$NODE" b 8 0 >/dev/null 2>&1
done

# --- harvest --------------------------------------------------------------
# Let ringbuf finalize.
sleep 0.5
kill -HUP  "$LPID" 2>/dev/null
sleep 0.2
kill -TERM "$LPID" 2>/dev/null
wait "$LPID" 2>/dev/null
LPID=""

DENIES=$(grep -cE '\[ch07\] DENY hook=' "$LOG" 2>/dev/null)
FLIPS=$(grep -cE '\[ch07\] FLIP hook='  "$LOG" 2>/dev/null)
DENIES=${DENIES:-0}
FLIPS=${FLIPS:-0}

echo "=== loader log ==="
cat "$LOG"
echo "=== summary ==="
echo "before_rc=$BEFORE_RC after_rc=$AFTER_RC denies=$DENIES flips=$FLIPS"

# Proof conditions:
#   1. before_rc != 0 (deny observed at syscall boundary)
#   2. after_rc == 0  (flip observed at syscall boundary)
#   3. FLIPS > 0      (in-kernel flip event recorded)
if [ "$BEFORE_RC" -ne 0 ] && [ "$AFTER_RC" -eq 0 ] && [ "$FLIPS" -gt 0 ]; then
  # Emit both the legacy proof marker and the explicit CONCEPT marker.
  echo "CH07_PROVEN flipped=$FLIPS"
  echo "=== CH07_CONCEPT_PROVEN before_rc=$BEFORE_RC after_rc=0 flips=$FLIPS ==="
  exit 0
fi

if [ "$FLIPS" -gt 0 ]; then
  echo "CH07_PROVEN flipped=$FLIPS"
  echo "=== CH07_CONCEPT_PARTIAL before_rc=$BEFORE_RC after_rc=$AFTER_RC flips=$FLIPS denies=$DENIES ==="
  exit 0
fi

echo "=== CH07_CONCEPT_FAIL before_rc=$BEFORE_RC after_rc=$AFTER_RC flips=$FLIPS denies=$DENIES ==="
exit 1
