// Ch09 PID NS Doppelgänger — capture host<->container PID mappings on every
// fresh PID-namespace entry. raw_tp/sched_process_fork covers the common
// `unshare --pid` / `clone(CLONE_NEWPID)` path; the kprobe on copy_namespaces
// catches non-fork ns transitions when present.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int host_pid;
    unsigned int host_tgid;
    unsigned int ns_pid;
    unsigned int ns_level;
    unsigned long ns_inum;
    char comm[16];
    int src;  // 1=sched_process_fork, 2=copy_namespaces
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

    struct evt copy = *e;
    bpf_map_update_elem(&mapping, &e->host_pid, &copy, BPF_ANY);
    bpf_ringbuf_submit(e, 0);
}

SEC("raw_tp/sched_process_fork")
int BPF_PROG(rt_fork, struct task_struct *parent, struct task_struct *child)
{
    // only emit when child's pid_ns differs from parent's (i.e. a new namespace was entered)
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
