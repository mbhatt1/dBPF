---
layout: book
title: "Chapter 11: IRQ Affinity Chaos"
date: 2025-02-11
---

# Chapter 11: What the IRQ Dispatch Path Will and Won't Let You Do

> **See also**: [Blog post]({{ site.baseurl }}/irq-affinity-chaos.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch11-irq-chaos) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Proof status**: Proved on Ubuntu 6.17.0-29-generic aarch64 (Lima VM).

I started this one wanting to rewrite CPU affinity masks inside `irq_dispatch()` from BPF. That's the fantasy. What the POC actually ships is an IRQ observer, because the override path is refused at the verifier by the kernel's error-injection allowlist, and the real re-steering lives below the Linux IRQ layer on aarch64 anyway. The previous version of this chapter described the override as if it worked. It didn't. Below is what the POC does and why.

Per-IRQ timing and per-CPU-delivery side channels are academic-grade primitives at this point. Brumley and Boneh on cache timing, the long literature on keystroke-timing inference over SSH, and the line of work on cross-VM covert channels via shared CPU resources are decades old. A BPF-based IRQ observer is a fresh implementation of a well-understood building block. No new attack is claimed; the goal is to document what the dispatch path actually exposes when you look at it with CO-RE on 6.12.

## Mechanism

Three kprobe targets sit on overlapping rungs of the dispatch ladder. The loader preflights each against `/proc/kallsyms` and disables `autoload` on any that don't resolve:

| Target | Role | Present on linuxkit aarch64 6.12 |
| --- | --- | --- |
| `handle_irq_event` | mid-layer dispatcher, one call per IRQ delivery | present, attached |
| `__handle_irq_event_percpu` | inner, once per registered `irqaction` | present, attached |
| `handle_irq_event_percpu` | fallback name on some 6.x trees | absent, skipped |

Two out of three fire on this kernel. CO-RE walks pull the IRQ number out of `irq_desc.irq_data.irq` and the driver label out of the first `irqaction.name`, bump a per-CPU BPF hash counter, and push a ringbuf event.

## Why not override

Three independent blockers, any one of which kills the approach:

1. Neither `handle_irq_event` nor `__handle_irq_event_percpu` appears in `/sys/kernel/debug/error_injection/list` on this kernel, so `bpf_override_return()` is refused at verifier load. No allowlist entry, no injection.
2. These paths run with local IRQs disabled on the target CPU ; atomic context. Calling `irq_set_affinity()` from a kprobe in that context would be a sleep-in-atomic bug even if the verifier let it through.
3. On aarch64 the routing decision is done by the GIC distributor, not by a Linux function. Re-pointing an IRQ at a different CPU means writing `GICD_ITARGETSR`/`GICD_IROUTER`, and those MMIO registers live behind the device-cgroup wall that ch07 spent a chapter not quite breaking.

The realistic userspace attack the observer actually catches is narrower and more boring: a process with `CAP_SYS_NICE`/`CAP_NET_ADMIN` writes a narrow mask into `/proc/irq/<n>/smp_affinity`, pinning every high-rate IRQ onto CPU0. Other cores starve; a victim pinned to CPU0 sees latency explode. The per-CPU counters make the asymmetry obvious in the exit summary, and a defender diffing the per-CPU column over time can spot a stuck mask.

## Hook points

```c
SEC("kprobe/handle_irq_event")
int BPF_KPROBE(kp_hie, struct irq_desc *desc)
{
    emit(desc, 1);
    return 0;
}

SEC("kprobe/__handle_irq_event_percpu")
int BPF_KPROBE(kp_hiep, struct irq_desc *desc)
{
    emit(desc, 2);
    return 0;
}

SEC("kprobe/handle_irq_event_percpu")
int BPF_KPROBE(kp_hiep2, struct irq_desc *desc)  // fallback; may be absent
{
    emit(desc, 2);
    return 0;
}
```

`emit()` reads `desc->irq_data.irq` and `desc->action->name` with `BPF_CORE_READ`, bumps the per-CPU HASH counter keyed by irq number, and submits a ringbuf event containing `{ts_ns, cpu, irq, pid, comm, name, hook}`. The POC also maintains a `last_ts` per-CPU array and a `timing_hist` bucketing inter-arrival deltas, which turns the observer into a covert timing channel source. The loader emits `IRQ_COVERT_CHANNEL_PROVEN timed_events=N` alongside `CH11_PROVEN` when timing data is present.

## Verification

`trigger.sh` runs a BEFORE/AFTER against a `ping -c 20 127.0.0.1` plus `dd if=/dev/urandom of=/dev/null bs=1M count=20` workload. `/proc/interrupts` provides the BEFORE baseline ; coarse counters, no per-event timing. The BPF observer provides the AFTER delta.

```
[ch11] === symbol availability ===
  handle_irq_event               : present
  __handle_irq_event_percpu      : present
  handle_irq_event_percpu        : ABSENT
[ch11] attached handle_irq_event
[ch11] attached __handle_irq_event_percpu
[ch11] attached 2 program(s) ; IRQ observer active

==== IRQ dispatch summary ====
total ringbuf events seen: 1843

CPU   | IRQ#  | count
------+-------+----------
0     | 30    | 412
2     | 29    | 631
3     | 29    | 244

per-CPU ringbuf totals:
  cpu0  517
  cpu1  99
  cpu2  875
  cpu3  352

=== CH11_PROVEN events=1843 unique=4 per_event_timing=yes ===
```

The data `/proc/interrupts` can't give you and the observer can: per-event wall-clock timestamps, inter-arrival distributions per IRQ, the task-in-context at the moment of delivery, and the cross-CPU migration ordering as a time-indexed stream. That's the raw material for keystroke-timing inference on a shared host, for network-packet timing correlation, and for cache-state leaks via interrupt-induced context switches. None of it requires override. Observation is enough.

## Detection

`bpftool prog show type kprobe | grep -iE 'irq_event|handle_irq'` lists the attached probes. `/sys/kernel/tracing/kprobe_events` is the persistent registration interface and shows the same thing. On the effect side, monitoring `/proc/irq/*/smp_affinity` for last-writer identity and diffing the per-CPU column of `/proc/interrupts` against a historical baseline catches the affinity-pinning attack at its symptom even if the BPF load is invisible.

Factual note: the original chapter draft claimed hooks on `irq_dispatch()` with inline affinity-mask rewrites. That wasn't the POC's behaviour and, per the three blockers above, isn't achievable on this kernel from BPF. The observer is honest; the override was wishful thinking.

> **See also**: [POC source ; ch11-irq-chaos](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch11-irq-chaos) · Harness entry: `Poc("ch11", ...)` in `dBPF-pocs/harness/proof.py`
