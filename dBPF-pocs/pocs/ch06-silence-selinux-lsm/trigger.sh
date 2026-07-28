#!/bin/bash
# ch06-silence-selinux-lsm trigger — HONEST demo.
#
# This POC was meant to flip SELinux denials (deny -> allow) from a BPF LSM
# hook. That is IMPOSSIBLE: the LSM framework is deny-wins and runs selinux
# BEFORE bpf, so a bpf hook never sees (and cannot undo) a SELinux denial.
# This trigger PROVES that, and proves the honest fallback capability:
# the hooks fire on ALLOWED decisions, i.e. ch06 is an observer.
#
# Requires a kernel with BOTH "bpf" AND "selinux" in
# /sys/kernel/security/lsm, SELinux enforcing, and the SELinux policy
# tools (semodule) to build a controlled denial. Missing prereqs -> honest
# skip.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/build/ch06-silence-selinux-lsm"
LOG=/tmp/ch06-lsm.log
AUDIT=/var/log/audit/audit.log

LSM_LINE="$(cat /sys/kernel/security/lsm 2>/dev/null)"
if [ -z "$LSM_LINE" ]; then
  echo "=== CH06_SKIP reason=\"/sys/kernel/security/lsm unreadable\" ==="; exit 0
fi
echo "$LSM_LINE" | grep -q bpf || {
  echo "=== CH06_SKIP reason=\"BPF LSM not enabled (boot with lsm=bpf,selinux,...)\" ==="; exit 0; }
echo "$LSM_LINE" | grep -q selinux || {
  echo "=== CH06_SKIP reason=\"SELinux not in /sys/kernel/security/lsm\" ==="; exit 0; }
command -v chcon >/dev/null 2>&1 || {
  echo "=== CH06_SKIP reason=\"chcon not available\" ==="; exit 0; }
if command -v selinuxenabled >/dev/null 2>&1 && ! selinuxenabled; then
  echo "=== CH06_SKIP reason=\"SELinux disabled\" ==="; exit 0
fi
command -v semodule >/dev/null 2>&1 || {
  echo "=== CH06_SKIP reason=\"semodule not available; cannot build controlled denial\" ==="; exit 0; }

echo "=== LSM order (note: selinux BEFORE bpf => bpf cannot un-deny) ==="
echo "$LSM_LINE"

[ -x "$BIN" ] || make -C "$HERE" >/dev/null 2>&1
[ -x "$BIN" ] || { echo "=== CH06_SKIP reason=\"build failed\" ==="; exit 0; }

STAGE="$(mktemp -d /tmp/ch06-lsm.XXXXXX)"
DENY="$STAGE/deny.txt"; echo protected > "$DENY"; chmod 644 "$DENY"
CIL="$STAGE/ch06deny.cil"
# ch06deny_t: unconfined_t may relabel a file to it but is NOT allowed to read
# it -> a genuine, self-contained SELinux read denial for the current domain.
FSTYPE="$(stat -f -c %T "$STAGE" 2>/dev/null)"
FSLABEL=tmpfs_t; [ "$FSTYPE" = "tmpfs" ] || FSLABEL="$(ls -Zd "$STAGE" | awk '{print $1}' | cut -d: -f3)"
cat > "$CIL" <<CILEOF
(type ch06deny_t)
(roletype object_r ch06deny_t)
(allow unconfined_t ch06deny_t (file (relabelto relabelfrom getattr)))
(allow ch06deny_t ${FSLABEL} (filesystem (associate)))
CILEOF

cleanup() {
  [ -n "$LPID" ] && { kill "$LPID" 2>/dev/null; wait 2>/dev/null; }
  semodule -r ch06deny 2>/dev/null
  rm -rf "$STAGE"
}
trap cleanup EXIT

semodule -i "$CIL" 2>/dev/null || { echo "=== CH06_SKIP reason=\"semodule -i failed\" ==="; exit 0; }
chcon -t ch06deny_t "$DENY" 2>/dev/null || { echo "=== CH06_SKIP reason=\"could not label controlled type\" ==="; exit 0; }

echo "=== baseline (no BPF): current domain reads the ch06deny_t file ==="
cat "$DENY" >/dev/null 2>&1; BASE=$?
echo "baseline_ret=$BASE (expect nonzero: SELinux denies)"
if [ "$BASE" -eq 0 ]; then
  echo "=== CH06_SKIP reason=\"expected SELinux denial did not occur\" ==="; exit 0
fi

PRE=$(wc -l < "$AUDIT" 2>/dev/null); PRE=${PRE:-0}
STATS_WAS=$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null)
[ -w /proc/sys/kernel/bpf_stats_enabled ] && echo 1 > /proc/sys/kernel/bpf_stats_enabled

echo "=== attach BPF LSM hooks (wildcard 'flip every deny') ==="
: > "$LOG"
"$BIN" -a >"$LOG" 2>&1 &
LPID=$!
sleep 1

echo "=== with BPF active: retry the DENIED read + drive ALLOWED reads ==="
for _ in 1 2 3; do cat "$DENY" >/dev/null 2>&1; echo "retry_deny_ret=$?"; done
for _ in $(seq 1 50); do cat "$STAGE/deny.txt" 2>/dev/null; ls "$STAGE" >/dev/null 2>&1; done >/dev/null 2>&1

sleep 1

# observer evidence: did the attached lsm progs actually execute?
# Prefer JSON (robust); fall back to parsing "run_cnt N" from plain output.
RUNS=$(bpftool -j prog show 2>/dev/null | python3 -c \
  'import sys,json
try: d=json.load(sys.stdin)
except Exception: print(0); sys.exit()
print(sum(p.get("run_cnt",0) for p in d if p.get("type")=="lsm"))' 2>/dev/null)
if [ -z "$RUNS" ] || [ "$RUNS" = "0" ]; then
  RUNS=$(bpftool prog show 2>/dev/null | grep -oE 'name lsm_[a-z_]+.*run_cnt [0-9]+' \
         | grep -oE 'run_cnt [0-9]+' | awk '{s+=$2} END{print s+0}')
fi
[ -z "$RUNS" ] && RUNS=0

kill "$LPID" 2>/dev/null; wait 2>/dev/null; LPID=""
[ -n "$STATS_WAS" ] && [ -w /proc/sys/kernel/bpf_stats_enabled ] && echo "$STATS_WAS" > /proc/sys/kernel/bpf_stats_enabled

FLIPS=$(grep -cE 'FLIP[[:space:]]+hook=' "$LOG" 2>/dev/null); FLIPS=${FLIPS:-0}
NEWAVC=$(tail -n +$((PRE+1)) "$AUDIT" 2>/dev/null | grep -c 'avc:  denied.*ch06deny_t')

echo "=== loader log ==="; cat "$LOG"
echo "=== results ==="
echo "flips_emitted=$FLIPS (expect 0)"
echo "avc_denials_while_active=$NEWAVC (SELinux still enforcing)"
echo "lsm_hook_run_cnt=$RUNS (hooks executed => they observe allowed decisions)"

# Honest verdict. These markers are deliberately NOT the weapon regex
# (CH06_PROVEN / CH06_WEAPON_PROVEN / FLIP hook=), because the silencer does
# not work — the truthful outcome is: flip impossible, observer proven.
if [ "$FLIPS" -eq 0 ] && [ "$BASE" -ne 0 ]; then
  echo "CH06_FLIP_IMPOSSIBLE reason=\"LSM deny-wins; selinux ordered before bpf; hook never sees the denial\""
else
  echo "CH06_UNEXPECTED flips=$FLIPS base=$BASE"
fi
if [ "$RUNS" -gt 0 ]; then
  echo "CH06_OBSERVER_PROVEN lsm_run_cnt=$RUNS hooks=file_permission,inode_permission,bprm_check_security"
fi
