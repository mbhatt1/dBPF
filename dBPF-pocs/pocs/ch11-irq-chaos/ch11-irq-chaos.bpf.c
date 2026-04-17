// Ch11 IRQ Affinity Chaos — observer for hardware IRQ dispatch.
// Hooks `handle_irq_event` and `__handle_irq_event_percpu` to emit a
// ringbuf event per IRQ with {cpu, irq_num, action_name, pid-in-context}.
// Pure observation: hardware IRQ routing is not safely overridable from
// eBPF on this kernel (no error_injection entries, and writing the affinity
// mask lives in an atomic context we cannot safely re-enter).
//
// REAL EFFECT: computes inter-IRQ timing deltas and stores them in a
// per-CPU histogram map. The userspace loader exports these deltas as
// proof that the BPF program has measured a covert timing channel —
// information about system activity (network traffic, disk I/O, user
// input) leaks through IRQ arrival patterns.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TIMING_BUCKETS 8   // log2 buckets: <1us, <10us, <100us, <1ms, <10ms, <100ms, <1s, >=1s

struct evt {
    unsigned long long ts_ns;
    unsigned long long delta_ns;  // time since last IRQ on this CPU
    unsigned int cpu;
    unsigned int irq;
    unsigned int pid;       // task in whose context the IRQ landed
    char comm[16];
    char name[32];          // irqaction->name (driver label)
    int hook;               // 1=handle_irq_event 2=__handle_irq_event_percpu
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);   // 1 MiB — interrupts are chatty
} events SEC(".maps");

// Per-CPU IRQ counters — quickly visible post-mortem without draining
// the ring buffer. Key = irq number.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, unsigned int);
    __type(value, unsigned long long);
    __uint(max_entries, 4096);
} per_cpu_counts SEC(".maps");

// Per-CPU last-IRQ timestamp for delta computation.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned long long);
    __uint(max_entries, 1);
} last_ts SEC(".maps");

// Covert channel timing histogram: per-CPU bucket counts.
// Bucket 0: <1μs, 1: <10μs, 2: <100μs, 3: <1ms, 4: <10ms, 5: <100ms, 6: <1s, 7: >=1s
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned long long);
    __uint(max_entries, TIMING_BUCKETS);
} timing_hist SEC(".maps");

static __always_inline unsigned int delta_bucket(unsigned long long delta_ns)
{
    if (delta_ns < 1000ULL)           return 0;  // <1μs
    if (delta_ns < 10000ULL)          return 1;  // <10μs
    if (delta_ns < 100000ULL)         return 2;  // <100μs
    if (delta_ns < 1000000ULL)        return 3;  // <1ms
    if (delta_ns < 10000000ULL)       return 4;  // <10ms
    if (delta_ns < 100000000ULL)      return 5;  // <100ms
    if (delta_ns < 1000000000ULL)     return 6;  // <1s
    return 7;                                     // >=1s
}

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

static __always_inline void emit(struct irq_desc *desc, int hook)
{
    if (!desc) return;
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;

    unsigned long long now = bpf_ktime_get_ns();
    e->ts_ns = now;
    e->cpu = bpf_get_smp_processor_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;

    // Compute inter-IRQ delta for covert channel timing measurement.
    unsigned int zero = 0;
    unsigned long long *prev = bpf_map_lookup_elem(&last_ts, &zero);
    unsigned long long delta = 0;
    if (prev && *prev != 0) {
        delta = now - *prev;
        // Update timing histogram bucket.
        unsigned int bucket = delta_bucket(delta);
        unsigned long long *cnt = bpf_map_lookup_elem(&timing_hist, &bucket);
        if (cnt)
            (*cnt)++;
    }
    bpf_map_update_elem(&last_ts, &zero, &now, BPF_ANY);
    e->delta_ns = delta;

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

// Mid-layer: called once per IRQ dispatch, before percpu fan-out.
SEC("kprobe/handle_irq_event")
int BPF_KPROBE(kp_hie, struct irq_desc *desc)
{
    emit(desc, 1);
    return 0;
}

// Inner: called for each irqaction on the chain. Fires more often, gives
// the clearest picture of which driver is getting hit on which CPU.
SEC("kprobe/__handle_irq_event_percpu")
int BPF_KPROBE(kp_hiep, struct irq_desc *desc)
{
    emit(desc, 2);
    return 0;
}

// Some 6.x kernels route through handle_irq_event_percpu (no leading __).
// Best-effort attach; libbpf reports an error if the symbol is missing.
SEC("kprobe/handle_irq_event_percpu")
int BPF_KPROBE(kp_hiep2, struct irq_desc *desc)
{
    emit(desc, 2);
    return 0;
}
