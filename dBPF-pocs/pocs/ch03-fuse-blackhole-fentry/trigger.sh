#!/bin/bash
# ch03-fuse-blackhole-fentry trigger: install an audit rule on openat,
# generate some events, show audit.log grows (baseline), load the BPF
# suppression, repeat, show either zero new audit records
# (audit_log_start path) or blocked syslog reads (fallback path).
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"

if ! command -v auditctl >/dev/null 2>&1; then
  echo "[trigger] ERROR: auditctl not installed (install audit userspace)"
  exit 2
fi

AUDIT_LOG="/var/log/audit/audit.log"
[ -r "$AUDIT_LOG" ] || AUDIT_LOG="$(ls -1 /var/log/audit/audit.log* 2>/dev/null | head -1)"
[ -n "$AUDIT_LOG" ] || AUDIT_LOG="/var/log/audit/audit.log"

echo "=== installing audit rule on openat ==="
auditctl -D >/dev/null 2>&1
auditctl -a always,exit -F arch=b64 -S openat -k ch03 || {
  echo "[trigger] ERROR: failed to install audit rule"; exit 3; }
auditctl -l | grep ch03

TARGET="$(mktemp /tmp/ch03-target.XXXXXX)"

count_records() {
  if [ -r "$AUDIT_LOG" ]; then
    grep -c 'key="ch03"' "$AUDIT_LOG" 2>/dev/null || echo 0
  else
    ausearch -k ch03 2>/dev/null | grep -c '^type=SYSCALL' || echo 0
  fi
}

echo "=== baseline: generating 5 openat events (no BPF) ==="
B0=$(count_records)
for i in 1 2 3 4 5; do dd if="$TARGET" of=/dev/null bs=1 count=1 2>/dev/null; done
sleep 1
B1=$(count_records)
echo "audit records: before=$B0 after=$B1 delta=$((B1-B0))"

echo "=== starting BPF audit suppressor ==="
"$HERE/build/ch03-fuse-blackhole-fentry" >/tmp/ch03-fe.log 2>&1 &
LPID=$!
sleep 1

echo "=== with BPF loaded: 5 more openat events ==="
A0=$(count_records)
for i in 1 2 3 4 5; do dd if="$TARGET" of=/dev/null bs=1 count=1 2>/dev/null; done
sleep 1
A1=$(count_records)
echo "audit records: before=$A0 after=$A1 delta=$((A1-A0))"

echo "=== dmesg/syslog read probe (fallback path indicator) ==="
dmesg | tail -1 >/dev/null 2>&1
echo "dmesg ret=$?"

sleep 1
kill $LPID 2>/dev/null
wait 2>/dev/null
echo "=== loader log ==="
cat /tmp/ch03-fe.log
auditctl -D >/dev/null 2>&1
rm -f "$TARGET"
echo ""
echo "Interpretation:"
echo "  - If 'attached fmod_ret/audit_log_start' appeared in the loader"
echo "    log, the delta after BPF load should be 0 (full suppression)."
echo "  - If 'attached lsm.s/syslog (fallback)' appeared, audit.log will"
echo "    still grow, but SYSLOG_ACTION_* reads (dmesg) should return EPERM."
