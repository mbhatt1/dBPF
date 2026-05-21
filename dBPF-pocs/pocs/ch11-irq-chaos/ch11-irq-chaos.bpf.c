// Ch11 IRQ Affinity Chaos — observer for hardware IRQ dispatch.
// Hooks `handle_irq_event` and `__handle_irq_event_percpu` to emit a
// ringbuf event per IRQ with {cpu, irq_num, action_name, pid-in-context}.
// Pure observation: hardware IRQ routing is not safely overridable from
// eBPF on this kernel (no error_injection entries, and writing the affinity
// mask lives in an atomic context we cannot safely re-enter).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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
