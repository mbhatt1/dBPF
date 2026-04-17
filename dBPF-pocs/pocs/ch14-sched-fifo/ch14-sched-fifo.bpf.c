// Ch14 SCHED_FIFO Impersonator — override __arm64_sys_sched_setscheduler's
// return to 0 (success) for tgids in the target map, bypassing EPERM that
// normally blocks non-CAP_SYS_NICE callers.
// NOTE: overriding the syscall return makes userspace *believe* the call
// succeeded. The scheduler state isn't actually changed (that would require
// writable kernel memory). The observable effect: chrt/sched_setscheduler
// return 0 instead of -1/EPERM. This is the "impersonator" — userspace
// thinks it got FIFO, tooling reports the call succeeded.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int policy;
    int prio;
    int flipped;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);
    __type(value, struct evt);
    __uint(max_entries, 4096);
} inflight SEC(".maps");

// NOTE: arch-specific symbol. On x86_64 use __x64_sys_sched_setscheduler.
// The loader should select the correct symbol at runtime based on uname -m.
SEC("kprobe/__arm64_sys_sched_setscheduler")
int BPF_KPROBE(kp_sched, struct pt_regs *regs)
{
    // real args live in regs->regs[0..2]: pid, policy, param*
    struct evt e = {};
    unsigned long id = bpf_get_current_pid_tgid();
    e.pid = id & 0xffffffff;
    e.tgid = id >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    // We don't unpack param (kernel ptr dance); record policy via regs.
    bpf_map_update_elem(&inflight, &id, &e, BPF_ANY);
    return 0;
}

// NOTE: arch-specific symbol. On x86_64 use __x64_sys_sched_setscheduler.
SEC("kretprobe/__arm64_sys_sched_setscheduler")
int BPF_KRETPROBE(kr_sched, long ret)
{
    unsigned long id = bpf_get_current_pid_tgid();
    struct evt *p = bpf_map_lookup_elem(&inflight, &id);
    if (!p) return 0;
    unsigned int tgid = id >> 32;
    int match = bpf_map_lookup_elem(&target_tgids, &tgid) ? 1 : 0;
    unsigned int zero = 0;
    if (!match && bpf_map_lookup_elem(&target_tgids, &zero)) match = 1;
    int flipped = 0;
    if (match && ret != 0) {
        bpf_override_return(ctx, 0);
        flipped = 1;
    }
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memcpy(e, p, sizeof(*e));
        e->flipped = flipped;
        e->policy = (int)ret;   // reuse field: orig_ret
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
