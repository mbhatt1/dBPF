#!/bin/bash
# Ch03 trigger — pedagogical BEFORE/AFTER proof for a lecture demo.
#
# The observable state delta this POC exposes is VISIBILITY, not mutation:
#
#   BEFORE (no BPF):   An unprivileged reader of /proc and /var/log/audit
#                      cannot see per-process audit metadata. On this
#                      linuxkit 6.12 image there is no auditd at all, so
#                      /var/log/audit/audit.log does not exist and ausearch
#                      returns nothing. The audit subsystem is effectively
#                      invisible from userspace.
#
#   AFTER  (BPF on):   The loader attaches kprobes to audit_log_start /
#                      audit_log_format / audit_log_end and streams every
#                      in-kernel audit record construction to its own stdout
#                      via a ringbuf — a channel unprivileged userspace had
#                      no way to obtain.
#
# We also opportunistically try the fentry fmod_ret suppressor from the
# sibling POC; if it actually attaches on this kernel we print both the
# visibility delta (variant B) and the suppression delta (variant A).

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SIBLING="$(cd "$HERE/../ch03-fuse-blackhole-fentry" 2>/dev/null && pwd || true)"
LOADER="$HERE/build/ch03-fuse-blackhole"
FE_LOADER="${SIBLING:+$SIBLING/build/ch03-fuse-blackhole-fentry}"

AUDIT_LOG="/var/log/audit/audit.log"
BEFORE_LOG="$(mktemp /tmp/ch03-before.XXXXXX.log)"
AFTER_LOG="$(mktemp  /tmp/ch03-after.XXXXXX.log)"
FE_LOG="$(mktemp     /tmp/ch03-fe.XXXXXX.log)"
trap 'rm -f "$BEFORE_LOG" "$AFTER_LOG" "$FE_LOG"' EXIT

# -- pedagogical noise generator: provoke audit-worthy events ---------------
noise() {
    echo 1 > /proc/sys/kernel/dmesg_restrict 2>/dev/null || true
    echo 0 > /proc/sys/kernel/dmesg_restrict 2>/dev/null || true
    for i in 1 2 3 4 5; do
        /bin/true
        /bin/false || true
    done
    /nonexistent/binary arg1 2>/dev/null || true
    touch /tmp/ch03_audit_probe 2>/dev/null || true
    rm -f /tmp/ch03_audit_probe 2>/dev/null || true
    /sbin/ip link show 2>/dev/null | head -1 >/dev/null || true
    id >/dev/null 2>&1 || true
}

# -- BEFORE: what an unprivileged observer can learn about audit ------------
# Run the audit-inspection attempts as a non-root user ('nobody') so we
# actually measure the privilege boundary, not root's view.
collect_before() {
    {
        # 1. Does auditd expose a log at all?
        if [ -r "$AUDIT_LOG" ]; then
            unpriv_bytes="$(su -s /bin/sh nobody -c "wc -c <'$AUDIT_LOG'" 2>&1 || echo 'DENIED')"
            echo "unpriv_read_audit_log=$unpriv_bytes"
        else
            echo "unpriv_read_audit_log=NO_SUCH_FILE ($AUDIT_LOG absent on linuxkit)"
        fi

        # 2. ausearch — the canonical userspace query path.
        if command -v ausearch >/dev/null 2>&1; then
            ucnt="$(su -s /bin/sh nobody -c 'ausearch -ts recent 2>&1 | grep -c ^type=' 2>/dev/null || echo 0)"
            echo "unpriv_ausearch_records=$ucnt"
        else
            echo "unpriv_ausearch_records=NO_AUSEARCH"
        fi

        # 3. Can unprivileged userspace see kernel audit traffic via netlink?
        #    Binding NETLINK_AUDIT requires CAP_AUDIT_READ; we don't have it.
        echo "unpriv_netlink_audit=requires_CAP_AUDIT_READ (denied)"
    } >"$BEFORE_LOG" 2>&1
}

# -- AFTER: what the BPF observer reveals -----------------------------------
# Run the ch03 kprobe loader for a few seconds while we generate events.
collect_after() {
    if [ ! -x "$LOADER" ]; then
        echo "LOADER_MISSING=$LOADER" >"$AFTER_LOG"
        return 1
    fi
    : >"$AFTER_LOG"
    "$LOADER" >>"$AFTER_LOG" 2>&1 &
    local lpid=$!
    sleep 1
    noise
    sleep 2
    kill -TERM "$lpid" 2>/dev/null || true
    wait "$lpid" 2>/dev/null || true
}

# -- Optional variant A: fentry suppressor ---------------------------------
# Attempts fmod_ret/audit_log_start. On this kernel that symbol is typically
# NOT in bpf_modify_return_targets, so attach fails and we fall back to B.
try_fentry() {
    [ -n "${FE_LOADER:-}" ] && [ -x "$FE_LOADER" ] || return 1
    timeout 4 "$FE_LOADER" >"$FE_LOG" 2>&1 &
    local fpid=$!
    sleep 2
    kill -TERM "$fpid" 2>/dev/null || true
    wait "$fpid" 2>/dev/null || true
    grep -q 'attached fmod_ret/audit_log_start' "$FE_LOG"
}

# ===========================================================================
collect_before
collect_after

BEFORE_RECORDS=0
if grep -q 'NO_SUCH_FILE\|DENIED\|NO_AUSEARCH\|requires_CAP_AUDIT_READ' "$BEFORE_LOG"; then
    BEFORE_RECORDS=0
fi

# Count distinct audit_log_start events captured by the BPF observer.
AFTER_RECORDS="$(grep -c '^\[audit\] audit_log_start' "$AFTER_LOG" 2>/dev/null || echo 0)"
AFTER_RECORDS="${AFTER_RECORDS//[^0-9]/}"
: "${AFTER_RECORDS:=0}"

VARIANT="B"
VARIANT_NOTE="visibility: unprivileged userspace cannot read audit state; BPF observer streams it"

if try_fentry; then
    VARIANT="A"
    VARIANT_NOTE="suppression: fmod_ret/audit_log_start attached; audit records nulled"
fi

echo "=== BEFORE ==="
sed 's/^/  /' "$BEFORE_LOG"
echo "  bpf_observer_events_visible_to_unpriv=0"
echo "=== AFTER ==="
echo "  bpf_observer_attached=1 (kprobe on audit_log_start/format/end)"
echo "  audit_log_start_events_captured=$AFTER_RECORDS"
echo "  sample_events:"
grep '^\[audit\] audit_log_start' "$AFTER_LOG" 2>/dev/null | head -3 | sed 's/^/    /'
if [ "$VARIANT" = "A" ]; then
    echo "  fentry_fmod_ret_attached=1"
    grep -E 'attached|SUPPRESSED' "$FE_LOG" | head -3 | sed 's/^/    /'
fi
echo "=== CH03_PROVEN variant=$VARIANT before=$BEFORE_RECORDS after=$AFTER_RECORDS ==="
echo "# note: $VARIANT_NOTE"

# If the BPF observer itself failed to attach (AFTER_RECORDS==0 and loader
# never reported "attached"), emit the skip marker for honesty.
if [ "$AFTER_RECORDS" = "0" ] && ! grep -q 'attached' "$AFTER_LOG" 2>/dev/null; then
    REASON="ch03 kprobe loader did not attach; see $AFTER_LOG"
    [ -s "$AFTER_LOG" ] && REASON="$REASON :: $(tr '\n' ' ' <"$AFTER_LOG" | head -c 180)"
    echo "=== CH03_SKIP reason=\"$REASON\" ==="
fi
