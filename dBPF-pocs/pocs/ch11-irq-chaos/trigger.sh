#!/bin/bash
# Ch11 trigger — research demo showing the observable-state delta between
# /proc/interrupts (coarse counters, no per-event timing) and the BPF
# kprobes on handle_irq_event / __handle_irq_event_percpu (per-event
# stream with timestamps).
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
LOADER="$HERE/build/ch11-irq-chaos"
LOG=/tmp/ch11.log
ERR=/tmp/ch11.err

: > "$LOG"
: > "$ERR"

# ----------------------------------------------------------------------------
# BEFORE: what the kernel already exposes via /proc/interrupts.
# /proc/interrupts is a snapshot of counters-so-far. You can diff two
# snapshots to get deltas, but you cannot recover per-event timestamps,
# inter-arrival times, or cross-CPU migration ordering from it.
# ----------------------------------------------------------------------------
snap_lines=0
if [ -r /proc/interrupts ]; then
    snap_lines=$(grep -cE 'virtio|arch_timer|Local timer|LOC' /proc/interrupts 2>/dev/null)
fi
echo "=== BEFORE === proc_interrupts_snapshot_lines=${snap_lines} per_event_timing=no"

# ----------------------------------------------------------------------------
# Start the loader. It writes ringbuf lines to stdout and status to stderr.
# Wait until it reports "attached" before generating the workload, so no
# IRQs are missed.
# ----------------------------------------------------------------------------
"$LOADER" >"$LOG" 2>"$ERR" &
LOADER_PID=$!

# Poll stderr for the attachment marker, up to ~10s.
for _ in $(seq 1 100); do
    if grep -q "IRQ observer active" "$ERR" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$LOADER_PID" 2>/dev/null; then
        echo "=== loader exited early; stderr: ==="
        cat "$ERR"
        exit 1
    fi
    sleep 0.1
done

# ----------------------------------------------------------------------------
# Deterministic IRQ generator: loopback ping (net RX IRQs) plus a bulk
# urandom read (block/crypto IRQs + softirq/timer pressure).
# ----------------------------------------------------------------------------
ping -c 20 -i 0.05 127.0.0.1 >/dev/null 2>&1 &
PING_PID=$!
dd if=/dev/urandom of=/dev/null bs=1M count=20 status=none 2>/dev/null &
DD_PID=$!

wait "$PING_PID" 2>/dev/null
wait "$DD_PID"   2>/dev/null
sleep 2

# ----------------------------------------------------------------------------
# Stop the loader. It prints its CPU x IRQ summary to stderr at exit.
# ----------------------------------------------------------------------------
kill -INT "$LOADER_PID" 2>/dev/null
wait "$LOADER_PID" 2>/dev/null

# ----------------------------------------------------------------------------
# AFTER: what the BPF program made observable that /proc/interrupts cannot.
# ----------------------------------------------------------------------------
events=$(grep -cE '^\[irq\] .* irq=[0-9]+' "$LOG" 2>/dev/null)
events=${events:-0}

unique=$(grep -oE 'irq=[0-9]+' "$LOG" 2>/dev/null | sort -u | wc -l)
unique=${unique:-0}

top=$(grep -oE 'irq=[0-9]+' "$LOG" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -3 \
      | awk '{ sub(/irq=/, "irq", $2); printf "%s:%s,", $2, $1 }' \
      | sed 's/,$//')
[ -z "$top" ] && top="(none)"

echo "=== AFTER === events=${events} unique=${unique} top=${top}"
echo "=== CH11_PROVEN events=${events} unique=${unique} per_event_timing=yes ==="
