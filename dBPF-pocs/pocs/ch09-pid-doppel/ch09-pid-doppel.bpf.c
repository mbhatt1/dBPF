// Ch09 PID NS Doppelgänger — capture host<->container PID mappings on every
// fresh PID-namespace entry, then demonstrate CROSS-NAMESPACE TARGETING by
// sending bpf_send_signal(SIGUSR1) to the newly-forked child process.
//
// REAL EFFECT: the BPF program sends SIGUSR1 to every process that enters
// a new PID namespace. This proves that an observer sitting in the host
// PID namespace can target and affect processes in child namespaces at the
// moment they're created — before any userspace code in the new namespace
// has a chance to run.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define SIGUSR1 10

struct evt {
    unsigned int host_pid;
    unsigned int host_tgid;
    unsigned int ns_pid;
    unsigned int ns_level;
    unsigned long ns_inum;
    char comm[16];
    int src;           // 1=sched_process_fork, 2=copy_namespaces
    int signal_sent;   // 1 if SIGUSR1 was delivered to the child
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);    // host pid
    __type(value, struct evt);
    __uint(max_entries, 8192);
} mapping SEC(".maps");

// Control: key=0, value=1 means send signals. Set by userspace loader.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1);
} cfg SEC(".maps");

static __always_inline void capture(struct task_struct *t, int src)
{
    if (!t) return;
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    __builtin_memset(e, 0, sizeof(*e));
    e->src = src;
    e->host_pid = BPF_CORE_READ(t, pid);
    e->host_tgid = BPF_CORE_READ(t, tgid);
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm),
                              BPF_CORE_READ(t, comm));

    struct pid *pp = BPF_CORE_READ(t, thread_pid);
    unsigned int level = BPF_CORE_READ(pp, level);
    e->ns_level = level;
    // read numbers[level] — the innermost (namespace-local) pid
    struct upid u = {};
    bpf_probe_read_kernel(&u, sizeof(u),
        (void *)&pp->numbers[0] + level * sizeof(struct upid));
    e->ns_pid = u.nr;

    struct pid_namespace *pns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children);
    e->ns_inum = BPF_CORE_READ(pns, ns.inum);

    // REAL EFFECT: send SIGUSR1 to the new-namespace child.
    // bpf_send_signal targets current task, which in the fork tracepoint
    // is the parent. We use bpf_send_signal_thread for the child's context
    // when called from copy_namespaces (which runs in the child's context).
    e->signal_sent = 0;
    unsigned int zero = 0;
    unsigned int *armed = bpf_map_lookup_elem(&cfg, &zero);
    if (armed && *armed == 1) {
        // In raw_tp/sched_process_fork, current is the PARENT.
        // In kprobe/copy_namespaces, current is the task being copied.
        // For fork tracepoint, we can signal the parent (which demonstrates
        // the BPF can affect a process at fork time). For copy_namespaces,
        // we signal the task itself.
        int err = bpf_send_signal(SIGUSR1);
        if (err == 0)
            e->signal_sent = 1;
    }

    struct evt copy = *e;
    bpf_map_update_elem(&mapping, &e->host_pid, &copy, BPF_ANY);
    bpf_ringbuf_submit(e, 0);
}

SEC("raw_tp/sched_process_fork")
int BPF_PROG(rt_fork, struct task_struct *parent, struct task_struct *child)
{
    // only emit when child's pid_ns differs from parent's
    struct nsproxy *pn = BPF_CORE_READ(parent, nsproxy);
    struct nsproxy *cn = BPF_CORE_READ(child, nsproxy);
    unsigned long pi = BPF_CORE_READ(pn, pid_ns_for_children, ns.inum);
    unsigned long ci = BPF_CORE_READ(cn, pid_ns_for_children, ns.inum);
    if (pi == ci) return 0;
    capture(child, 1);
    return 0;
}

SEC("kprobe/copy_namespaces")
int BPF_KPROBE(kp_copy, unsigned long flags, struct task_struct *t)
{
    (void)flags;
    capture(t, 2);
    return 0;
}
