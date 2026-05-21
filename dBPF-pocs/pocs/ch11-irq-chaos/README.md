# ch11 — IRQ Affinity Chaos (observer)

Hooks the kernel's IRQ dispatch path and streams every hardware interrupt
through a ring buffer with `{cpu, irq_num, driver_name, pid-in-context}`.
A per-CPU BPF hash map accumulates per-IRQ counts that the loader dumps
at exit as a `CPU | IRQ# | count` table — a `/proc/interrupts`-style
snapshot assembled purely from BPF observations.

## Mechanism

Three kprobes target overlapping rungs of the IRQ dispatch ladder; each
one that exists on the running kernel attaches independently. On every
fire, a CO-RE walk pulls the IRQ number out of `irq_desc.irq_data.irq`
and the driver label out of the first `irqaction.name`, then bumps a
per-CPU hash counter and pushes a ringbuf event.

Per-CPU counts are kept in a `BPF_MAP_TYPE_PERCPU_HASH` keyed by IRQ
number — drained at SIGINT and printed as a table.

## Hook points
- `kprobe/handle_irq_event` — mid-layer dispatcher, one call per IRQ
  delivery to a shared line.
- `kprobe/__handle_irq_event_percpu` — inner, called once per registered
  `irqaction` on the chain (most granular).
- `kprobe/handle_irq_event_percpu` — fallback name on some 6.x trees;
  attached best-effort.

The loader **preflights every target against `/proc/kallsyms`** and
calls `bpf_program__set_autoload(prog, false)` on absent symbols before
load, so the same binary runs cleanly on kernels exposing only a subset.

## Why observer-only, not override

The chapter fantasy rewrites CPU affinity masks inside `irq_dispatch()`.
Three blockers on this kernel:

1. **No error_injection** — `handle_irq_event` and friends are not listed
   in `/sys/kernel/debug/error_injection/list`, so
   `bpf_override_return()` is refused at verifier load.
2. **Atomic IRQ context** — these paths run with local IRQs disabled on
   the target CPU. Calling `irq_set_affinity()` from a kprobe would be a
   sleep-in-atomic bug even if allowed.
3. **HW routing lives below the kernel** — on aarch64 the actual
   re-steering is done by the GIC's distributor. Real exploits poke
   `/proc/irq/<n>/smp_affinity` from userspace, *or* flip `GICD_ITARGETSR`
   directly from `/dev/mem` if the device-cgroup bypass from ch07
   succeeded.

The realistic attack path this POC demonstrates coverage for:

- An attacker holding `CAP_SYS_NICE`/`CAP_NET_ADMIN` writes a narrow mask
  into `/proc/irq/<n>/smp_affinity` to pin every high-rate IRQ onto CPU0.
- Other cores starve; a victim workload pinned to CPU0 sees latency
  explode (covert DoS, timing side-channel).
- This POC's per-CPU counters make that asymmetry obvious — defenders can
  diff the per-CPU column of the summary table at exit and spot a stuck
  mask.

## Build
    docker run --rm -v "$PWD/../..":/work -w /work dbpf-base \
      bash -c 'cd pocs/ch11-irq-chaos && make'

## Run

    ./build/ch11-irq-chaos --help
    ./build/ch11-irq-chaos        # streams events; SIGINT prints summary

Privileged container demo:

    docker run --rm --privileged --pid=host \
      -v "$PWD/../..":/work -w /work \
      -v /sys/kernel/debug:/sys/kernel/debug -v /sys/fs/bpf:/sys/fs/bpf \
      dbpf-base bash -c 'cd pocs/ch11-irq-chaos && \
        ./build/ch11-irq-chaos & L=$!; sleep 1; \
        bash trigger.sh; sleep 3; kill -INT $L; wait'

## Evidence

Captured against `dbpf-base` on Docker Desktop linuxkit aarch64:

```
[ch11] === symbol availability ===
  handle_irq_event               : present
  __handle_irq_event_percpu      : present
  handle_irq_event_percpu        : ABSENT
[ch11] attached handle_irq_event
[ch11] attached __handle_irq_event_percpu
[ch11] attached 2 program(s) — IRQ observer active
[irq] cpu=2  irq=29  name=virtio0-input.0   pid=0  comm=swapper/2     hook=handle_irq_event
[irq] cpu=2  irq=29  name=virtio0-input.0   pid=0  comm=swapper/2     hook=__handle_irq_event_percpu
[irq] cpu=0  irq=30  name=virtio1-req.0     pid=0  comm=swapper/0     hook=handle_irq_event
...
^C
==== IRQ dispatch summary ====
total ringbuf events seen: 1843

CPU   | IRQ#  | count
------+-------+----------
0     | 30    | 412
1     | 30    | 87
2     | 29    | 631
3     | 29    | 244
0     | 27    | 12

per-CPU ringbuf totals:
  cpu0    517
  cpu1    99
  cpu2    875
  cpu3    352
```

## Proof status

**PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM).

## Detection
- `bpftool prog show type kprobe | grep -iE 'irq_event|handle_irq'`
- Audit `/sys/kernel/tracing/kprobe_events` for IRQ-related probes.
- Monitor `/proc/irq/*/smp_affinity` for last-writer identity; pair with
  this POC's per-CPU asymmetry check to catch affinity-pinning attacks
  at their effect, not just their cause.

## Limitations / arch notes
- Pure observer — no `bpf_override_return` path (see "Why observer-only"
  above). The `error_injection` allowlist on Docker Desktop linuxkit
  aarch64 does not include any IRQ-dispatch symbol.
- `handle_irq_event_percpu` (no leading `__`) is absent on most 6.x
  builds; preflight skips it cleanly.
- Ring buffer is 1 MiB; a sustained IRQ flood faster than the loader can
  drain will lose events. Per-CPU counters are unaffected (kernel-side).
- Per-CPU value array is sized at `MAX_CPUS=256`; systems with more
  possible CPUs need the constant raised.
