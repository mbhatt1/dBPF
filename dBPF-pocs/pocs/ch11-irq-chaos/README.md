# Ch11 -- IRQ Affinity Chaos

**Category**: OBSERVER
**Primitive**: kprobe on IRQ dispatch path functions
**Hook(s)**: `SEC("kprobe/handle_irq_event")`, `SEC("kprobe/__handle_irq_event_percpu")`, `SEC("kprobe/handle_irq_event_percpu")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Hooks the kernel's IRQ dispatch path and streams every hardware interrupt through a ring buffer with `{cpu, irq_num, driver_name, pid-in-context}`. A per-CPU BPF hash map accumulates per-IRQ counts that the loader dumps at exit as a `CPU | IRQ# | count` table -- a `/proc/interrupts`-style snapshot assembled purely from BPF observations. Defenders can diff the per-CPU column to spot IRQ affinity-pinning attacks.

## What this does NOT do

Cannot mutate -- `handle_irq_event` and friends are not in the error-injection allowlist; these paths run with local IRQs disabled (sleep-in-atomic); and on aarch64, HW routing lives in the GIC distributor below the kernel. Real affinity manipulation requires writing `/proc/irq/<n>/smp_affinity` from userspace or flipping `GICD_ITARGETSR` via `/dev/mem`.

## Prerequisites

- `CONFIG_KPROBES=y`
- At least one of `handle_irq_event`, `__handle_irq_event_percpu`, `handle_irq_event_percpu` in `/proc/kallsyms`
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch11-irq-chaos.bpf.c` | Kernel-side BPF program (kprobes on IRQ dispatch ladder, per-CPU hash counters) |
| `ch11-irq-chaos.c` | Userspace loader, ringbuf consumer, summary table printer |
| `trigger.sh` | Activity generator (disk/net I/O to provoke IRQs) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
./build/ch11-irq-chaos        # streams events; SIGINT prints summary
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show type kprobe | grep -iE 'irq_event|handle_irq'` lists the attached probes.
- Audit `/sys/kernel/tracing/kprobe_events` for IRQ-related probes.
- Monitor `/proc/irq/*/smp_affinity` for last-writer identity; pair with this POC's per-CPU asymmetry check to catch affinity-pinning attacks at their effect.
