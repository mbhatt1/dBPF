---
layout: book
title: "Chapter 11: IRQ Affinity Chaos"
date: 2025-02-11
---

# Chapter 11: What the IRQ Dispatch Path Will and Won't Let You Do

> **See also**: [Blog post]({{ site.baseurl }}/irq-affinity-chaos.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch11-irq-chaos) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

## The Fantasy I Started With

I started this one wanting to rewrite CPU affinity masks inside `irq_dispatch()` from BPF. That was the fantasy. I had a specific shape in mind: attach a kprobe somewhere on the inbound IRQ path, detect that the IRQ in question was routed at CPU0, and before the handler ran, rewrite the target mask to shove that IRQ onto some other core. The implementation in my head looked the same as half the other chapters in this book — a kprobe, a CO-RE read to pull the `irq_desc`, a `bpf_override_return` or a targeted write, and then walk away with a real re-steering primitive. The dream was enforcement, not observation.

None of it is achievable on the kernel I am actually running. I need to be honest about that before I describe anything else, because "BPF program that repoints hardware interrupts from userspace" is exactly the kind of claim people cite without checking, and it is exactly the kind of claim that dissolves the moment you read the source tree. What I built is an observer. The observer is real, the observer works, and the observer is genuinely useful — but it is not the thing I sat down wanting to build.

There are three independent reasons the override plan died. Any one of them by itself is enough to kill the approach. Taken together, they are why this chapter is titled what it is and why the POC at `dBPF-pocs/pocs/ch11-irq-chaos/` contains zero calls to `bpf_override_return` anywhere in the BPF bytecode.

The first reason is the error-injection allowlist. On a stock 6.12 kernel, `bpf_override_return` is gated at verifier load time by `check_attach_btf_id` against a list of functions that have been explicitly annotated with `ALLOW_ERROR_INJECTION` in their defining source file. The IRQ dispatch functions are not on that list. You can check for yourself:

```
# cat /sys/kernel/debug/error_injection/list | grep -iE 'irq_event|handle_irq|irq_dispatch'
(empty)
```

I read `/sys/kernel/debug/error_injection/list` on the linuxkit aarch64 kernel in my Docker Desktop VM and confirmed the file was empty for anything in the IRQ dispatch path. The loader at `ch11-irq-chaos.c` deliberately does not attempt `bpf_override_return` because there is no outcome where that succeeds. The verifier would reject the program at load. The kernel is not going to let you change the return value of `handle_irq_event` no matter how cleverly you attach to it, because the developers never put the annotation there. This is the same wall `cap_capable` is behind in chapter 1 — the gate is explicit consent from the function's author, and the IRQ path has never given it.

The second reason is atomic context. Even if the verifier allowed you to load an override program on `__handle_irq_event_percpu`, what you would be loading it into is a code path that runs with local IRQs disabled on the target CPU. Look at `kernel/irq/handle.c` on the running kernel: the dispatch routines take per-descriptor locks and run with preemption off and interrupts masked. Any function you might call from the kprobe — anything that sleeps, anything that takes a blocking lock, anything that schedules — is a sleep-in-atomic bug. `irq_set_affinity()` itself can sleep in the path that pushes the new mask down to the GIC. You cannot call it from here. You could try to bang on the distributor registers directly from BPF, but BPF programs in kprobe context cannot do MMIO, cannot take `raw_spinlock_t`, and cannot loop over the low-level chip data to cleanly reprogram a target. The environment is wrong for the work.

The third reason is architectural, and this is the one that really takes the dream away on aarch64 specifically. Linux on ARM sits on top of the GIC — the Generic Interrupt Controller. The routing decision for any given IRQ is ultimately a bit pattern in the GIC distributor: on GICv2, `GICD_ITARGETSR`; on GICv3, `GICD_IROUTER`. Those registers live in memory-mapped IO behind a device node. The Linux IRQ layer's view of affinity is an abstraction on top of these; writing to `/proc/irq/<n>/smp_affinity` eventually lands in a chip driver callback that programs the real bits. If you want to re-steer an IRQ on aarch64, the primitive is a register write in MMIO space, not a function call anywhere in the kernel. BPF does not have that reach. The ch07 device-cgroup POC spent most of a chapter trying to get to `/dev/mem` from a container and not quite making it. Even if ch07 had worked, the place it got you to was userspace with a mapping of the distributor — not BPF-in-kernel with the ability to poke MMIO from a kprobe.

So the chapter-as-I-imagined-it does not fire. Three independent blockers, any one of them fatal, all three of them real. What I built instead is a high-resolution observer of the same code path. And before I describe the observer, I want to say why an observer is worth building at all, because the obvious retort is that `/proc/interrupts` already exists and has for thirty years.

## What /proc/interrupts Does Not Give You

The supported kernel interface for "who is getting IRQs" is `/proc/interrupts`. Open it and you see a table: rows are IRQ numbers, columns are CPUs, cells are counters-since-boot. That is useful in aggregate. It is almost useless per-event.

`/proc/interrupts` is a snapshot of totals. You can diff two snapshots a second apart and recover a rate. You cannot recover:

- Per-event timestamps, which you need for anything that cares about the timing distribution of interrupt arrivals — keystroke inference, packet-arrival-correlation, covert channel timing.
- Inter-arrival deltas, which are the raw material for any cadence-based attack or defense.
- The task context the IRQ landed in — whose quantum got interrupted, what `current` was.
- The name of the `irqaction` that ran, when more than one handler is chained.
- Ordering across CPUs at sub-jiffy resolution.

Every single one of those is in the live `irq_desc` at the moment dispatch happens. `/proc/interrupts` throws them away and only keeps the totals. A kprobe at the dispatch point can pull them out at wire speed. That is the gap the observer POC fills.

## Source Walk: The BPF Program

The BPF object is small. It is at `dBPF-pocs/pocs/ch11-irq-chaos/ch11-irq-chaos.bpf.c`, about a hundred lines of code total, and every line is there for a specific reason. I will walk it top to bottom.

The license and the event struct:

```c
char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned long long ts_ns;
    unsigned int cpu;
    unsigned int irq;
    unsigned int pid;       // task in whose context the IRQ landed
    char comm[16];
    char name[32];          // irqaction->name (driver label)
    int hook;               // 1=handle_irq_event 2=__handle_irq_event_percpu
};
```

The license is GPL because `bpf_probe_read_kernel_str` and `bpf_get_current_comm` are both GPL-only helpers on modern kernels. Not declaring GPL here loads a verifier error that specifically names the helper you touched. I spent an hour on this once in an earlier chapter before remembering.

The event fields encode the five things `/proc/interrupts` throws away: a nanosecond timestamp, the CPU, the IRQ number, the task context (PID plus comm), and the driver label. The `hook` field tags which of the three probes fired — the reason for that becomes clear below.

The maps:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);   // 1 MiB — interrupts are chatty
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, unsigned int);
    __type(value, unsigned long long);
    __uint(max_entries, 4096);
} per_cpu_counts SEC(".maps");
```

Two maps. The first is a standard 1 MiB ringbuf. The sizing matters: on a host with active network traffic and storage IO, you can see multiple IRQs per millisecond. 1 MiB of ringbuf holds roughly 16K events at 64 bytes each; at 1000 events per second, that is a fifteen-second buffer before userspace has to have drained. I picked that bound deliberately — I wanted enough headroom that a slow `printf` in the loader does not start losing events, and small enough that I am not cosplaying as a production-grade pipeline.

The second map is the more interesting one. `BPF_MAP_TYPE_PERCPU_HASH` keyed by IRQ number, value is a count. Per-CPU means every logical CPU has its own private copy of the map, and updates from that CPU do not have to synchronize with any other CPU's updates. At IRQ-delivery rate that matters. A normal `BPF_MAP_TYPE_HASH` would turn every bump into an atomic operation; under even modest IRQ load that becomes a source of cross-CPU cache line bouncing, and you end up measuring your observer more than the thing you wanted to observe. Per-CPU pushes all that contention into the quiet corner of userspace-draining-at-SIGINT, which is fine, because at that point the workload is already done.

The `bump` helper:

```c
static __always_inline void bump(unsigned int irq)
{
    unsigned long long *v = bpf_map_lookup_elem(&per_cpu_counts, &irq);
    if (v) {
        (*v)++;
    } else {
        unsigned long long one = 1;
        bpf_map_update_elem(&per_cpu_counts, &irq, &one, BPF_ANY);
    }
}
```

Two-path increment: if the slot exists, bump in place; if it does not, insert with value 1. This is the standard lookup-then-update idiom, and because it runs on a per-CPU map, there is no race. The only CPU that can race me on `per_cpu_counts[irq]` is me. The `__always_inline` keeps the helper body inside the caller so the verifier sees one function to analyze and not two.

The emission function is where the CO-RE walk happens:

```c
static __always_inline void emit(struct irq_desc *desc, int hook)
{
    if (!desc) return;
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;

    e->ts_ns = bpf_ktime_get_ns();
    e->cpu = bpf_get_smp_processor_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;

    // irq_desc.irq_data.irq is the Linux IRQ number.
    unsigned int irq = BPF_CORE_READ(desc, irq_data.irq);
    e->irq = irq;
    bump(irq);

    // irq_desc.action is a singly linked list of irqaction; first one's
    // name is the driver-registered label ("eth0", "nvme0q1", ...).
    struct irqaction *act = BPF_CORE_READ(desc, action);
    if (act) {
        const char *nm = BPF_CORE_READ(act, name);
        bpf_probe_read_kernel_str(&e->name, sizeof(e->name), nm);
    } else {
        e->name[0] = 0;
    }

    bpf_ringbuf_submit(e, 0);
}
```

Let me unpack what this is doing. `bpf_ringbuf_reserve` allocates a slot in the ringbuf atomically; the event is written in place, then either submitted or discarded. If the ringbuf is full, `reserve` returns NULL and we drop the event cleanly rather than blocking. In an IRQ handler that is the right choice — we cannot block on anything ever, and dropping is strictly better than stalling the dispatch path.

The four scalars come from BPF helpers: `bpf_ktime_get_ns` for the timestamp, `bpf_get_smp_processor_id` for the CPU on which the probe is running, `bpf_get_current_pid_tgid` for the task context, `bpf_get_current_comm` for that task's command name. The task context is interesting in IRQ probes — hardware IRQs interrupt whatever was running, so `current` is whoever was using the CPU when the IRQ landed. On an idle CPU, that is `swapper/N`. On a busy CPU, it could be any running process. The PID field is a clue about which workload is eating the CPU at the moment the IRQ arrives, which is useful for causality analysis when you are trying to figure out why a specific process is latency-sensitive.

Then the CO-RE reads. `BPF_CORE_READ(desc, irq_data.irq)` is the relocatable-read macro that traverses `desc->irq_data.irq` using BTF-encoded field offsets at load time. The kernel could change the layout of `struct irq_desc` between versions and this code still works because the compiled BPF object ships with a relocation table that tells the loader what the actual offsets are on the live kernel. The Linux IRQ number we recover here is the virtual IRQ — the one `/proc/interrupts` shows in its first column, the one you'd put in `/proc/irq/<N>/smp_affinity`.

The `irqaction` walk is the most informative field. `irq_desc` contains a pointer to a linked list of `irqaction` structs, one per registered handler for that IRQ. Shared IRQs have multiple; dedicated ones have exactly one. The `.name` field is the string the driver passed to `request_irq` — things like `"virtio0-input.0"`, `"eth0"`, `"nvme0q1"`, `"arch_timer"`. That string is what turns the probe output from "IRQ 29 fired on CPU 2" into "the virtio network card delivered a packet IRQ on CPU 2." The difference is exactly the difference between a number and a diagnostic.

`bpf_probe_read_kernel_str` is the right helper for reading a kernel-space NUL-terminated string; it stops at the NUL or at the size limit, whichever is first, and fills in the buffer. I cap the copy at 32 bytes because I never have seen an `irqaction` name longer than that and the verifier wants a bounded size.

Finally, `bpf_ringbuf_submit` makes the event visible to userspace. Between `reserve` and `submit`, the event exists in ringbuf memory but is not delivered; this is the commit point.

The three probes themselves:

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
int BPF_KPROBE(kp_hiep2, struct irq_desc *desc)
{
    emit(desc, 2);
    return 0;
}
```

Three probes on three different rungs of the dispatch ladder. `handle_irq_event` is the mid-layer dispatcher: it runs once per IRQ delivery to a given CPU and kicks off the percpu handler. `__handle_irq_event_percpu` is the inner loop that walks the `irqaction` chain and calls each registered handler. `handle_irq_event_percpu` without the leading underscores is a naming variant that showed up on some 6.x trees — specifically, kernels where the inner function was renamed during a refactor. I did not bother figuring out exactly which kernels it covers; I just added it to the probe set and let the preflight sort it out.

Why all three? Because the code paths through the dispatch ladder are not identical across hardware configurations. Some kernels route everything through the non-percpu variant first; some go straight to the percpu path. Attaching to all the probable names and letting the preflight disable the missing ones is the cheapest way to get correct behavior on every 6.x build without branching on kernel version at load time. This is how ch01 handled `cap_capable` and how every subsequent CO-RE chapter has handled its target — if the symbol exists you attach, if it doesn't you skip. The cost of an attempted attach that gracefully skips is far lower than the cost of shipping a binary that only works on your test kernel.

A note on what these probes do *not* see. Timer IRQs on aarch64 can bypass the dispatch path entirely and land in the arch timer chip driver's per-CPU hook, which is outside `handle_irq_event`. IPI (inter-processor interrupts) have their own path through `handle_IPI`. Soft IRQs (`do_softirq`) are serviced from the IRQ-exit hook and are not hardware interrupts in the sense this POC cares about. What the probes catch is the hardware-IRQ dispatch path for device-delivered interrupts — the virtio ring queues, any physical NIC or storage controller, any PCIe device with a real MSI/MSI-X vector. On a typical workload that covers everything you want.

## The Kallsyms Preflight

The loader at `dBPF-pocs/pocs/ch11-irq-chaos/ch11-irq-chaos.c` has the preflight logic I have used in every CO-RE chapter since ch05. The relevant code block:

```c
struct prog_entry table[] = {
    { "handle_irq_event",          get_kp_hie   },
    { "__handle_irq_event_percpu", get_kp_hiep  },
    { "handle_irq_event_percpu",   get_kp_hiep2 },
};
int n = (int)(sizeof(table) / sizeof(table[0]));

struct ch11_irq_chaos_bpf *s = ch11_irq_chaos_bpf__open();

fprintf(stderr, "[ch11] === symbol availability ===\n");
int present_mask = 0;
for (int i = 0; i < n; i++) {
    int ok = sym_exists(table[i].sym);
    fprintf(stderr, "  %-30s : %s\n", table[i].sym,
            ok == 1 ? "present" : (ok == 0 ? "ABSENT" : "kallsyms-err"));
    if (ok != 1) {
        bpf_program__set_autoload(table[i].getter(s), false);
    } else {
        present_mask |= (1 << i);
    }
}
```

The `sym_exists` function reads `/proc/kallsyms` line by line, parses the type character, and looks for the symbol. The filter `type != 'T' && type != 't' && type != 'W' && type != 'w'` restricts matches to text-segment symbols, ignoring data, BSS, and read-only constants. `T`/`t` is "regular text function" (exported and non-exported); `W`/`w` is "weak" (the linker-resolvable variant). A kprobe target has to be a text function; anything else is a load-time error we would rather avoid by skipping.

If the symbol is absent, `bpf_program__set_autoload(prog, false)` marks that program so that the subsequent `ch11_irq_chaos_bpf__load` skips it. The skeleton infrastructure handles this cleanly — no awkward conditional compilation, no preprocessor games. This is the pattern libbpf recommends for exactly the "three-probe fallback with graceful degradation" shape this POC has.

On the running linuxkit aarch64 6.12 kernel, the preflight prints:

```
[ch11] === symbol availability ===
  handle_irq_event               : present
  __handle_irq_event_percpu      : present
  handle_irq_event_percpu        : ABSENT
```

Two of three present. The third is the no-underscore variant that never resolved on any 6.12 linuxkit I have tested. The preflight kept the load clean — none of the probes were attempted with missing targets, no verifier error, no confusing libbpf backtrace. The loader then continues to the attachment phase with only the two present programs.

The preflight is cheap to run. `/proc/kallsyms` is a text file; reading it end-to-end takes a few milliseconds on any host. The alternative — attempt all three attaches and catch the per-program failures — works, but produces ugly error spew and slower startup. The preflight is the clean path.

## What the Per-CPU Hash Gives You at Exit

The per-CPU hash map accumulates counts continuously; the ringbuf emits per-event. At SIGINT, the loader walks the per-CPU map and prints a summary. Here is the relevant code:

```c
static void summary(struct ch11_irq_chaos_bpf *s)
{
    fprintf(stderr, "\n==== IRQ dispatch summary ====\n");
    fprintf(stderr, "total ringbuf events seen: %llu\n", total_events);

    int ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0) ncpu = 1;
    if (ncpu > MAX_CPUS) ncpu = MAX_CPUS;

    int fd = bpf_map__fd(s->maps.per_cpu_counts);
    ...
    unsigned int key = 0, next;
    int has_prev = 0;
    unsigned long long vals[MAX_CPUS];
    int rows = 0;

    while (bpf_map_get_next_key(fd, has_prev ? &key : NULL, &next) == 0) {
        key = next;
        has_prev = 1;
        memset(vals, 0, sizeof(vals));
        if (bpf_map_lookup_elem(fd, &key, vals) != 0) continue;
        for (int c = 0; c < ncpu; c++) {
            if (vals[c]) {
                fprintf(stderr, "%-5d | %-5u | %llu\n", c, key, vals[c]);
                rows++;
            }
        }
    }
    ...
}
```

For each IRQ number in the map, lookup returns a per-CPU array — one `unsigned long long` per possible CPU. The loop prints a row per (CPU, IRQ, count) tuple wherever the count is nonzero. This produces a table shaped exactly like `/proc/interrupts` but assembled from the BPF observations over the run window rather than from kernel-side counters since boot.

The loader uses `bpf_map_lookup_elem` rather than `bpf_map_lookup_and_delete_batch` in this snippet for simplicity, but the batch variant exists and would be the production choice. The difference is one atomic drain of the whole map versus many individual lookups. At the rates this observer sees (tens of thousands of events per minute under load), either is fine.

The per-CPU array size is `MAX_CPUS = 256`. That is a userspace-side ceiling; the BPF-side map stores as many slots as `libbpf_num_possible_cpus()` returns, which on any system I care about is well below 256. If you wanted to run this on a 512-CPU box you would raise the constant.

## The Sampled Stdout

One detail in the loader that matters for usability: the event handler throttles how much goes to stdout.

```c
static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)sz;
    struct evt *e = data;
    total_events++;
    if (e->cpu < MAX_CPUS) per_cpu_events[e->cpu]++;

    if (total_events <= 20 || (total_events & 63) == 0) {
        printf("[irq] cpu=%u\tirq=%-3u\tname=%-16s\tpid=%u\tcomm=%-16s\thook=%s\n",
               e->cpu, e->irq, e->name[0] ? e->name : "(none)",
               e->pid, e->comm, hook_str(e->hook));
        fflush(stdout);
    }
    return 0;
}
```

Every event bumps the counters. Only the first 20 events, and thereafter every 64th event, actually print. The full total lands in the exit summary, and the per-CPU map retains every count in the kernel. The reason for this is practical: during a ping flood or a disk burst, the IRQ rate is high enough that an unthrottled `printf` per event will either fall behind and lose ringbuf slots, or will drown anything else sharing the terminal.

The first-twenty-unconditional part exists because if you run the POC for only a few seconds of quiet, you still want to see something. Otherwise a defender running this would see nothing for the first idle second and assume the probe was broken. Twenty events is enough to confirm the attach worked without spamming. After that, one-in-sixty-four is a decent sample for visual inspection while still leaving the machinery available for machine processing of the full stream.

This is a small choice but it has saved me from "why isn't anything happening" questions more than once. The full stream is always available in the ringbuf if you want it; the stdout is a sampled window.

## What the Harness Entry Expects

The entry in `dBPF-pocs/harness/proof.py` is at lines 104-107:

```python
Poc("ch11", "IRQ Chaos", "ch11-irq-chaos",
    hooks=["handle_irq_event", "__handle_irq_event_percpu",
           "handle_irq_event_percpu"], prefix="[irq]",
    proof_marker=r"CH11_PROVEN|IRQ_COVERT_CHANNEL_PROVEN"),
```

Three hooks declared — the same three the BPF program attempts. The `prefix="[irq]"` lines up with the stdout format in the loader. The `proof_marker` is a regex that the harness looks for in trigger output to call the run a success; it accepts either of two patterns to allow for renaming over time.

The actual marker the `trigger.sh` emits is:

```
=== CH11_PROVEN events=${events} unique=${unique} per_event_timing=yes ===
```

The event count and unique-IRQ count come from grepping the loader stdout; the `per_event_timing=yes` annotation is the declarative answer to the question `/proc/interrupts` cannot answer — yes, we have per-event timing data in the ringbuf stream. That marker is the proof that the observer fired, that events were captured, and that at least one unique IRQ appeared in the window.

The harness runs `trigger.sh` which itself starts the loader, waits for "IRQ observer active", generates deterministic IRQ load (20 loopback pings plus 20 MiB of `/dev/urandom` reads), sleeps two seconds for the ringbuf to drain, then sends SIGINT to the loader and prints the summary. The whole run takes under ten seconds.

A representative capture from the trigger:

```
[ch11] === symbol availability ===
  handle_irq_event               : present
  __handle_irq_event_percpu      : present
  handle_irq_event_percpu        : ABSENT
[ch11] attached handle_irq_event
[ch11] attached __handle_irq_event_percpu
[ch11] attached 2 program(s) — IRQ observer active
[irq] cpu=2  irq=29  name=virtio0-input.0   pid=0  comm=swapper/2     hook=handle_irq_event
[irq] cpu=0  irq=30  name=virtio1-req.0     pid=0  comm=swapper/0     hook=handle_irq_event
...
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

=== CH11_PROVEN events=1843 unique=3 per_event_timing=yes ===
```

Three unique IRQs, 1843 total events, clearly asymmetric per-CPU totals. IRQ 29 is the virtio network input, IRQ 30 is a virtio block request queue, IRQ 27 is a timer. CPU 2 got the bulk of the network IRQs; CPU 0 got the bulk of the block IRQs. That asymmetry is the thing the observer sees that `/proc/interrupts` also shows — but the observer saw it in an eight-second window, and the per-event timing in the ringbuf would let you compute the arrival distribution, the inter-arrival histogram, the timing correlation with any other observable.

## Why Observer-Only is the Right Answer (And How I Know)

There is a version of this argument where I try to get clever and claim the observer is what I wanted all along, the override would have been unwise anyway, and really the observer is the better research tool. I am not going to make that argument. I wanted override. Override is more interesting. Override is the thing that, if it worked, would change what an attacker could do with a BPF program on this kernel. The observer is an instrument. The override would have been a weapon.

What I will say instead is that the honest posture — "I wanted this, these three blockers killed it, here is what I built instead" — is the one you learn to adopt as soon as you have written a few chapters like this and had reviewers and readers catch you overclaiming. The temptation is always there. You spent a week on the chapter, the thing you built is real, and if you tilt the framing slightly you can make the smaller thing sound like the bigger thing. The internet is full of BPF write-ups that did exactly that, and most of them fall apart on careful reading. This chapter is not going to be one of them.

The three blockers deserve to be spelled out one more time, because the interaction between them is the actual lesson:

**Allowlist gating is kernel-developer-consent.** `ALLOW_ERROR_INJECTION` is an explicit annotation that says, "this function's authors have agreed that a BPF program can rewrite its return." That consent has to happen at the source-tree level, not the exploitation level. You cannot argue your way past it from outside the kernel. For `cap_capable` (chapter 1), for `irq_dispatch` (this chapter), and for `powercap_get_energy_uj` (chapter 13), the answer is the same: the annotation is not there, and without it, `bpf_override_return` is verifier-rejected at load. There is no userspace technique that changes this. The allowlist is the developers' fence, and the fence is honored.

**Atomic context is a runtime constraint.** Even if the allowlist were permissive, the execution environment of a kprobe inside an IRQ handler is hostile to anything that sleeps, blocks, or schedules. BPF programs in that context have fewer helpers available; the verifier is stricter about which helpers can be called. Look at the BPF helper reference: `bpf_copy_from_user` is off-limits in non-sleepable contexts, `bpf_loop` has per-context bounds, any operation that could acquire a mutex is disallowed. The set of things you *can* do from a hard-IRQ kprobe is observation, ringbuf emission, and map updates on preempt-disabled per-CPU storage. That is enough for the observer. It is not enough for anything that wants to reconfigure the world.

**Architecture boundaries are below the Linux layer.** On aarch64, the GIC distributor is the hardware arbiter of IRQ routing. The Linux IRQ subsystem is a cross-architecture abstraction that calls into arch-specific chip drivers to program the distributor. A BPF program is below the architecture-neutral layer in the sense that it runs in kernel mode, but above it in the sense that it sees the abstractions, not the chip registers. If the routing decision lives in `GICD_IROUTER` and your program cannot do MMIO, you cannot change the routing. You can change the Linux-layer view of the routing, but that view is not what the hardware consults when an IRQ fires. The hardware wins. This is architecturally the same reason you cannot intercept a USB packet from BPF before the HCI driver has seen it — the packet has happened already, in silicon, before any kernel code runs on it.

All three of these are not BPF limitations specifically. They are consequences of what BPF is: an in-kernel verified programming environment for observation and policy, not a kernel debugger, not a hypervisor, and not a chip-level emulator. Anyone asking BPF to do things outside that envelope is going to discover one of the three walls, usually in that order.

## Timing Side-Channel Implications

Now the part of the chapter I keep going back and forth on. The observer is small. The consequence depends entirely on what you feed it and what you are trying to learn from the feed.

The baseline primitive is: per-event hardware-IRQ timestamps at kernel-firmware-clock resolution, tagged with device identity, across all CPUs, delivered in a streaming ringbuf. That is the raw material for a set of well-understood attacks.

Cryptographic cache-timing attacks. Brumley and Boneh 2003, "Remote Timing Attacks are Practical," was the one that shook the field — and everyone who built on it. The attack model there is "watch when the remote system is busy, infer what it was doing." You do not need IRQ-level timing to do that attack; the network RTT itself is enough. But IRQ-level timing on the server side is *better* data, because it localizes the wake-up ordering within a microsecond window rather than the millisecond window the network gives you. An observer that can see "virtio packet IRQ arrived, then crypto-disk IRQ arrived 1.3 ms later, then packet-out IRQ fired 0.4 ms after that" gives you a much cleaner signal for pattern analysis than the wire view does.

Keystroke inference. The USB HID interrupt cadence is deterministic at the hardware level — a keyboard emits an IRQ per keypress (and one per release). The inter-arrival distribution of those IRQs leaks typing rhythm. There is a long line of academic work on keystroke timing over SSH, SSH tunnels, even network round-trip patterns; an IRQ observer on a shared host gets that signal at first-class resolution. If you can correlate the IRQ stream with knowledge of which VM or container is connected to the USB bus you are watching, you have per-user typing cadence. That is enough, in combination with linguistic models, to do statistically significant password inference on known-format inputs.

Network pacing inference. NIC RX IRQs are the hardware-level equivalent of "a packet arrived." An observer on the IRQ stream can see arrival timing with microsecond resolution, independent of what the network stack does afterward with it. This is useful for traffic analysis in contexts where the application layer is encrypted but the arrival pattern is not — HTTP/2 frame sizes, WebSocket heartbeats, VoIP packetization. Most network monitoring tools see post-sk_buff timings; an IRQ observer sees pre-sk_buff, which is closer to the wire truth.

Cross-VM covert channels. Two VMs running on the same host, sharing a CPU or a physical NIC, can signal each other through the IRQ cadence of the shared hardware. The sender modulates IRQ-generating activity; the receiver watches the IRQ stream. This is a published attack pattern — Ristenpart et al. 2009, and a dozen follow-ups through the 2010s. The IRQ-observer POC I built is not a covert channel by itself; it is the instrument you would point at the receiving end.

I want to be clear about what I am and am not claiming. I am not claiming to have discovered any of these attacks. The literature on side channels through IRQ timing is decades old, and the mechanisms are well understood. What I am claiming is that BPF-based kprobes on the dispatch path are a notably clean way to implement the observer side of these attacks — you get CO-RE portability, you get kernel-speed data capture, you get the ability to run the observer as an unprivileged (or less-privileged) program in a container alongside whatever you are spying on. Compared to kernel modules, this is easier to build, less detectable, and more portable across kernels.

The flip side is that the primitive is small. You are reading timestamps and IRQ identities. You are not rewriting anything, not re-steering anything, not injecting anything. Everything downstream — the statistical inference, the correlation, the actual attack — is ordinary analysis on the captured stream, and that work is outside the scope of a BPF program.

The honest posture is: the observer is a building block, it lowers the cost of implementing the observer-half of classical side-channel attacks, it is well-suited for an attacker with a foothold in a colocated container, and it does not by itself constitute an exploit.

## What You Measure When You Measure an IRQ

A digression I want to include because it comes up every time I explain this primitive. The question is: what exactly is the timestamp on a ringbuf event?

`bpf_ktime_get_ns` returns the system monotonic clock in nanoseconds. The resolution depends on the hardware clock source; on x86, it is the TSC (time stamp counter) read through `rdtsc` and converted to nanoseconds, which is single-digit nanoseconds of resolution. On aarch64, it is the architectural counter `CNTVCT_EL0`, which is typically 10-50 MHz — so tens of nanoseconds per tick. Either way, the resolution is far finer than inter-IRQ arrival distance at realistic rates.

The meaning of the timestamp is "the moment BPF ran the helper inside the kprobe entry." That is a few nanoseconds into the dispatch path, after the hardware raised the interrupt, after the kernel's IRQ-entry code saved registers and established the stack context, after the dispatch function was called. It is not "the moment the hardware signaled." The gap between "hardware signaled" and "BPF timestamp taken" is small (a few hundred nanoseconds on modern hardware) and is roughly constant for a given (CPU, device) pair. For timing-correlation purposes, the constant offset is not a problem — you care about deltas and distributions, not absolute truth.

What can skew the timestamp: the kernel can coalesce IRQs (MSI coalescing, NAPI polling), which means one dispatch event corresponds to multiple hardware events. You see a single IRQ fire, but the `irqaction` handler processes a batch. The ringbuf event reports a single timestamp per dispatch, not per batched event. For network RX, this is real — NAPI batches RX completions behind a single IRQ. If you are trying to do fine-grained packet timing, the IRQ stream is a lower-bound estimate of event count, not an exact count. The `ethtool -c <iface>` settings control the coalescing parameters; on a host configured for minimum latency (interrupts per packet), the IRQ stream is a close proxy for packets. On a host configured for throughput (many packets per IRQ), it is not.

What does not skew the timestamp: the CO-RE reads themselves. The BPF_CORE_READ walk happens after the timestamp is taken, so the time spent chasing pointers into `irq_desc` does not contaminate the event. The ordering in the `emit` helper is deliberate: timestamp first, CPU ID second, then scalars, then the heavier reads. If a later read fails (say, the `action` pointer is NULL), the event still has a valid timestamp and a valid CPU ID.

For correlation work — matching IRQ events against tcpdump captures, against application-level log timestamps, against other BPF observers running on the same host — the monotonic clock is the right reference. `clock_gettime(CLOCK_MONOTONIC)` in userspace is the same clock source; no conversion needed. If you want wall-clock time, add `clock_gettime(CLOCK_REALTIME)` at the moment you record the monotonic value, and store the offset.

## A Note on What "Observer" Means Here

Not all BPF observers are created equal. There is a gradient from "extracts telemetry that the kernel already exposes" to "extracts kernel state that the supported interfaces hide." This POC is somewhere in the middle, and the location on that gradient matters for thinking about its legitimacy.

At the permissive end, BPF observers that read what `/proc` already shows are pure convenience tools. A kprobe that counts `openat` calls is in the same category as running `strace`; nothing hidden, nothing privileged, nothing that a defender's existing tooling could not already see. These are fine to write and fine to run, and they are what most of bcc's `tools/` directory looks like.

At the restrictive end, BPF observers that extract kernel state the supported interfaces deliberately do not expose are effectively covert instrumentation of the kernel. Reading the contents of internal data structures that have no userspace interface at all, recording information that the kernel authors chose not to make available — this is closer to reverse engineering the kernel's internals than to using its APIs. It is legal, it is not necessarily unethical, but it is a step further from "pure telemetry" and closer to "observational exploitation."

This POC sits in the middle. `/proc/interrupts` exposes some of what the probes see (counts per IRQ per CPU); the probes expose more (per-event timestamps, task contexts, driver labels, microsecond cadences). The additional information is not secret — every field we read has a stable meaning and a well-documented structure — but it is not packaged for general consumption either. The per-event stream is a richer view than the kernel maintainers decided to publish. Whether that is "observation" or "observational exploitation" depends on who you ask and what they want to do with it.

I call it an observer because the primitive is read-only. No rewrite, no block, no policy decision. The data is there in the kernel; we are reading it. That is observation in the narrow sense. In the broad sense of "is this a thing ops teams would approve of on a shared host," it depends on the ops team.

## Layering the Observer with Other Probes

The dispatch observer gets you half of a useful picture. The other half is instrumenting the *cause* of IRQ asymmetry — the writes to `/proc/irq/<n>/smp_affinity`, the boot-time irqbalance configuration, the runtime use of `sched_setaffinity` for IRQ threads, and the hardware-layer MSI-X vector assignments.

A fuller defense pipeline would include:

1. **This observer** on `handle_irq_event` and `__handle_irq_event_percpu` — per-event dispatch data.
2. **A write-side observer** on `proc_irq_set_affinity_hint` or on the `/proc/irq/<n>/smp_affinity` sysctl store path — captures who is changing affinity masks.
3. **An fsnotify or inotify watch** on `/proc/irq/` — catches the userspace writes at the VFS layer, independent of whether the BPF probe landed.
4. **Auditd rules** on the `ioctl` calls that some drivers use for per-device affinity configuration — catches the device-specific paths that don't go through sysctl.

Each of these is its own small POC; each is cheap to build on the same CO-RE patterns this POC uses. Stacked together they give you cause-effect correlation: "process X wrote mask Y to IRQ Z, and the dispatch asymmetry changed by delta ΔZ in the following minute." That is the shape of a deployable detector, not just a demo.

The POC in this chapter is the first of the four. The others live in their own chapters (not all of them written yet in this book). What I wanted to flag here is that the observer is a component, not a product. You plug it into a pipeline; the pipeline does the detection work.

## The Realistic User-Visible Attack This Observer Catches

The attack the observer is directly instrumenting, in the defender's frame, is the affinity-pinning DoS. A process with `CAP_SYS_NICE` or `CAP_NET_ADMIN` writes a narrow mask into `/proc/irq/<n>/smp_affinity` for every high-rate IRQ on the system, pinning them all onto CPU0. Other cores now see no IRQs at all; every network packet, every block completion, every timer expiration lands on CPU0.

From the victim's perspective, any workload pinned to CPU0 now runs with unpredictable latency because IRQs are continually preempting it, and any workload pinned to another CPU never gets a timely IRQ notification because its local interrupts have been pushed elsewhere. This is a covert DoS — the machine's CPU utilization graphs look normal in aggregate, but the asymmetry is severe.

`/proc/interrupts` catches this if a defender diffs it over time. The per-CPU column for IRQ `N` shows zero growth on CPUs 1-3 and all-the-growth on CPU0. My observer catches it the same way: the per-CPU column of the exit summary shows zero on CPUs 1-3 for pinned IRQs. The detection is the same signal.

What the observer adds over `/proc/interrupts` is a continuous, timestamped feed. You do not have to remember to diff snapshots; you have every event. You can build a running asymmetry-of-last-N-events metric and alert on it. You can correlate the asymmetry with the identity of the process that wrote to `/proc/irq/<n>/smp_affinity` (via a separate write-side probe — that is a later chapter, not this one). The point is, this observer is a component you plug into a defender's pipeline, not a finished detection product.

## Detection

Now from the other direction: what does a defender running this observer look like to an attacker, and what does an attacker running this observer look like to a defender?

On the detector side, if a defender attaches this program, there is nothing visible to a workload running on the host except a small constant overhead on every IRQ delivery — a few instructions of BPF executing inline on the dispatch path. Not detectable from userspace by any practical means; not detectable from an unprivileged observer. The program shows up in `bpftool prog show`, which requires `CAP_BPF` or `CAP_SYS_ADMIN` to read.

On the attacker side, if an attacker loads this program in a privileged container or on a rooted host, the program is directly visible:

```
# bpftool prog show type kprobe | grep -iE 'irq_event|handle_irq'
```

This one grep finds the attached probes by function name. `/sys/kernel/tracing/kprobe_events` is the persistent-registration interface and will show any probes registered by the BPF-autoload path. `perf list` includes the BPF-attached probes if you know to look. A defender auditing a production host where no legitimate observability tool probes the IRQ path by default — and on most hosts, none does — would treat any non-zero output from that grep as high-signal.

The supported interface for IRQ observation on Linux is `/proc/interrupts`, full stop. Nothing else. If an auditor sees a kprobe attached to `handle_irq_event`, `__handle_irq_event_percpu`, or any variant, the correct assumption is that someone is running a per-event observer, and that someone is not using the official interface. That is a small set of legitimate use cases (I can think of a few performance-tuning scenarios) and a much larger set of illegitimate ones.

On the effect side, a defender who has deployed the observer as a monitor can detect affinity-pinning attacks at the symptom layer — "one CPU is getting all the IRQs, the others are getting none" — regardless of whether the pinner used `/proc/irq/smp_affinity`, an ioctl on a raw device, a BPF program, or direct MMIO. The observer is neutral to the attack mechanism and sensitive to the outcome.

Auditd configuration is also a clean defense path: `auditctl -w /proc/irq -p wa` watches every write to `/proc/irq/*/smp_affinity` and records the writer's identity. Combined with the per-CPU asymmetry check from the observer, you catch both the cause and the effect.

## Cross-Architecture Portability Notes

A quick set of notes on what changes between architectures, because this matters for anyone trying to run the POC outside the linuxkit aarch64 VM it was developed in.

On x86_64, the dispatch symbol set is close to identical. `handle_irq_event` and `__handle_irq_event_percpu` are both present on any 6.x build. The absent `handle_irq_event_percpu` variant is a naming quirk that is also absent on x86. The preflight handles it the same way. Attach should succeed on the same two of three.

On older aarch64 kernels (5.4, 5.10 LTS), `__handle_irq_event_percpu` may not be present — the function was renamed during a refactor. I have not tracked down exactly when. If the preflight shows that symbol as ABSENT, falling back to `handle_irq_event` alone gets you the mid-layer view without the inner-chain detail. The data is coarser but the observer still works.

On RISC-V, I have not tested. The IRQ subsystem code is shared across architectures, so the function names should be the same; the arch-specific bits are in the chip drivers below the dispatch layer. If you test this on RISC-V and find differences, the preflight will catch them cleanly.

For VMs specifically, the IRQ delivery pattern depends on the hypervisor's virtual interrupt controller. On KVM with virtio devices, every device IRQ goes through a virtual GIC (on aarch64) or a virtual APIC (on x86), and the `irq_desc` you see from BPF is the guest's view. The `irqaction.name` strings are the driver labels the guest assigned. This is the setup the POC was developed against. For bare-metal hosts, the `irqaction.name` strings are the driver labels of the physical devices; most of what the POC sees on a typical bare-metal server is `eth0`, storage controllers, and timer IRQs.

For nested virtualization, timestamps get weird. The host clock source and the guest clock source are not the same; `bpf_ktime_get_ns` reads the guest's view of monotonic time, and the guest's monotonic time is paravirtualized in complicated ways. For any cross-guest or cross-host correlation you want to also capture `clock_gettime(CLOCK_REALTIME)` on the analysis side to have a common reference. I have seen enough weirdness in nested-virt timing analysis to strongly recommend doing the correlation in wall-clock, not monotonic, when guests are involved.

For container runtimes, nothing changes. The BPF program lives in the host kernel; the container boundary does not affect what `bpf_ktime_get_ns` returns. If you run the observer from a privileged container, you see IRQs delivered to the host — all of them. The ringbuf is attached to your own container's BPF program, but the events include all host IRQs, not just those destined for workloads in your container. For per-container IRQ observation (which is a weaker abstraction than you might want, because hardware IRQs are physical and containers are virtual), you would correlate the IRQ stream with per-container network or storage namespace identifiers — that correlation is outside the scope of this POC.

## Kernel Version Behavior and Breakage Risk

CO-RE gives you portability across kernel versions in terms of struct offsets. It does not give you portability across kernel versions in terms of function names or call graphs. If the 6.15 kernel renames `__handle_irq_event_percpu` again, the POC's preflight will report it ABSENT, the autoload will disable it, and the observer falls back to `handle_irq_event` alone. Graceful degradation.

If the 6.20 kernel rearranges `irq_desc` to move `irq_data.irq` elsewhere, CO-RE relocations handle it — the BTF encoded in the kernel describes the new layout, the BPF loader rewrites the offsets, the program works. The only way this breaks is if a field is *deleted* — if some future kernel stops tracking the Linux IRQ number in `irq_desc.irq_data.irq` and moves it to a completely different structure. That would be a more involved refactor and would show up as a CO-RE relocation error at load, not a silent correctness bug. The error message would name the field that could not be located.

If the 6.30 kernel adds a new IRQ delivery path that does not go through `handle_irq_event` at all — some new fast-path that bypasses the mid-layer — the POC would miss those IRQs. The attach succeeds, the probe fires when it fires, but the new fast-path's IRQs never touch the dispatch function. This is the failure mode you cannot catch with a preflight. You would notice it because your observed event rate would drop below a known baseline, or because `/proc/interrupts` would show counter growth that the observer did not see. The fix is to find the new fast-path and add a probe for it. This is how BPF observability drifts as kernel internals evolve: you chase the abstraction.

I am flagging this because it matters for anyone who plans to deploy the observer for long-term monitoring. BPF CO-RE is good at field-layout drift; it is not magical against function-set drift. Any BPF observer that attaches by function name is implicitly taking a dependency on the function existing and being on the relevant path. Kernel developers do not guarantee either. The mitigation is: run the preflight, log the results, monitor the observer's event rate against a sanity-check counter (like `/proc/interrupts` totals), and alert if the observer goes silent on a host that used to be chatty. That tells you the kernel changed out from under you.

## A Closing Thought on Scope

I keep circling back to scope in these chapters because it is the thing that most separates honest work from hype. This POC's scope is: observe the IRQ dispatch path with per-event fidelity on any kernel where the target symbols exist, degrade gracefully when they do not, and surface both streaming events and summary counters to userspace.

Within that scope, the POC works. The harness marker `CH11_PROVEN events=N unique=M per_event_timing=yes` fires every time I run it on a kernel that has any IRQ activity. Outside that scope, the POC does nothing. It does not block IRQs, does not rewrite affinity, does not re-steer dispatch, does not do anything that modifies the behavior of the system it runs on. An attacker who loaded this program and walked away would have changed nothing the defender cares about except the defender's visibility.

The defender-side use case is where I think this program earns its keep: paired with an auditd watch on `/proc/irq/*/smp_affinity` and an alerting rule on per-CPU IRQ asymmetry, it catches the affinity-pinning covert DoS at the symptom layer. That is a real attack with real published precedents, and the observer is a cheap detector for it.

The researcher-side use case — the side-channel work I spent several paragraphs discussing above — is where the primitive is most interesting. The attacker-side use case is the researcher-side one with adversarial intent; the observer is the same, the data is the same, the interpretation is different. All three audiences are going to find something useful here, and all three audiences will be operating within the same envelope of what BPF on the IRQ dispatch path can actually do.

## What This Chapter Actually Gives You

A high-resolution IRQ observer built on kprobes. Not an override. Not a re-steering primitive. The override path is walled off by the error-injection allowlist, by atomic context, and on aarch64 by the GIC distributor living outside Linux — three independent blockers I cannot get around with BPF on this kernel.

What the observer buys is per-event timing at the dispatch point, per-CPU counters for summary analysis, driver-label identification for workload attribution, and a clean stream in a 1 MiB ringbuf. The building-block utility is real: defenders get a symptom-level detector for affinity-pinning DoS, researchers get a telemetry source for side-channel work, and attackers get an implementation template for the observer side of classical IRQ-timing attacks. All three are legitimate audiences. The primitive is small, the consequences are specific, and the ceiling is the error-injection allowlist — as it has been for every chapter in this act.

Factual note: the original chapter draft claimed I hooked `irq_dispatch()` and rewrote the CPU affinity mask inline. That is not what the POC does, and for the three reasons above it is not achievable on this kernel. The observer is what actually exists. The override was wishful thinking. I am leaving the original fantasy language out of this version and keeping the note here so anyone who reads the earlier draft and the current one knows what changed and why.
