---
layout: book
title: "IRQ Affinity Chaos"
date: 2025-02-11
---

Act II: Kernel Intrusion

**Chapter 12: What the IRQ Dispatch Path Will and Won't Let You Do**

I started this one wanting to rewrite CPU affinity masks inside `irq_dispatch()` from BPF. That's the fantasy. What I got was an IRQ observer, because the override path is blocked at the verifier by the kernel's error-injection allowlist, and the real re-steering lives below the Linux IRQ layer on aarch64 anyway.

The useful thing to be clear about up front: per-IRQ timing and per-CPU-delivery side channels are academic-grade primitives at this point. Brumley and Boneh on cache-timing attacks, the long literature on keystroke-timing inference over SSH, the line of work on cross-VM covert channels via shared CPU resources — all of that is decades old and thoroughly published. A BPF-based IRQ observer is a fresh implementation of a well-understood building block. I'm not claiming a new attack; I'm documenting what the dispatch path actually exposes when you look at it with CO-RE on 6.12.

I picked three kprobe targets along overlapping rungs of the dispatch ladder and let the loader preflight each against `/proc/kallsyms`, disabling any that didn't resolve before attaching:

| Target | Role | Present on linuxkit aarch64 6.12 |
| --- | --- | --- |
| `handle_irq_event` | mid-layer dispatcher, one call per IRQ delivery | present, attached |
| `__handle_irq_event_percpu` | inner, once per registered `irqaction` | present, attached |
| `handle_irq_event_percpu` | fallback name on some 6.x trees | absent, skipped |

Two out of three fired on this kernel. The third is a naming variant that never resolved; the preflight kept the load clean. CO-RE walk pulls the IRQ number out of `irq_desc.irq_data.irq` and the driver label out of the first `irqaction.name`, bumps a per-CPU hash counter, and pushes a ringbuf event.

Why I gave up on override. Three independent blockers, any one of which kills the approach:

1. Neither `handle_irq_event` nor `__handle_irq_event_percpu` appears in `/sys/kernel/debug/error_injection/list` on this kernel, so `bpf_override_return()` is refused at verifier load. No allowlist entry, no injection.
2. These paths run with local IRQs disabled on the target CPU — atomic context. Calling `irq_set_affinity()` from a kprobe in that context would be a sleep-in-atomic bug even if the verifier let it through.
3. On aarch64 the routing decision is done by the GIC distributor, not by a Linux function. Re-pointing an IRQ at a different CPU means writing `GICD_ITARGETSR`/`GICD_IROUTER`, and those registers live behind the device-cgroup wall that ch07 spent a chapter not quite breaking.

The realistic userspace attack that the POC's observer actually catches: a process with `CAP_SYS_NICE`/`CAP_NET_ADMIN` writes a narrow mask into `/proc/irq/<n>/smp_affinity`, pinning every high-rate IRQ onto CPU0. Other cores starve; a victim pinned to CPU0 sees latency explode. My per-CPU counters make the asymmetry obvious in the exit summary, and a defender diffing the per-CPU column over time can spot a stuck mask.

```c
SEC("kprobe/handle_irq_event")
int kp_handle_irq_event(struct pt_regs *ctx) {
    // CO-RE read desc->irq_data.irq; bump per-CPU counter; push ringbuf event
    return 0;
}

SEC("kprobe/__handle_irq_event_percpu")
int kp_handle_irq_event_percpu(struct pt_regs *ctx) {
    // same, inner handler
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

Evidence from a short run on linuxkit aarch64:

```
[ch11] === symbol availability ===
  handle_irq_event               : present
  __handle_irq_event_percpu      : present
  handle_irq_event_percpu        : ABSENT
[ch11] attached 2 program(s) — IRQ observer active

==== IRQ dispatch summary ====
total ringbuf events seen: 1843
CPU   | IRQ#  | count
0     | 30    | 412
2     | 29    | 631
3     | 29    | 244
per-CPU ringbuf totals:
  cpu0 517  cpu1 99  cpu2 875  cpu3 352
```

The timing side-channel angle: once you have per-IRQ nanosecond deltas streaming from the inner handler, you have the raw material for keystroke inference on a shared host, for network-packet timing correlation, and for cache-state leaks via interrupt-induced context switches. None of this requires override. Observation is enough.

Detection. `bpftool prog show type kprobe | grep -iE 'irq_event|handle_irq'` lists the attached probes. `/sys/kernel/tracing/kprobe_events` is the persistent registration interface. On the effect side, monitoring `/proc/irq/*/smp_affinity` for last-writer identity and diffing the per-CPU column of `/proc/interrupts` against a historical baseline catches the affinity-pinning attack at its symptom even if the BPF load is invisible.

Factual note: the original chapter claimed I hooked `irq_dispatch()` and rewrote the CPU affinity mask inline. That's not what the POC does and, as above, it isn't achievable on this kernel. The observer is honest; the override was wishful thinking.
