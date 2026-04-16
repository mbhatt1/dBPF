// ch07 devcgroup-houdini observer: kprobe devcgroup_check_permission and
// (if present) the inlined __devcgroup_check_permission; stream every
// decision as a ringbuf event.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int hook;       // 1=devcgroup_check_permission 2=__devcgroup_check_permission
    short type;     // S_IFCHR==2 S_IFBLK==6 per devcgroup
    unsigned int major;
    unsigned int minor;
    int access;
    int verdict;    // populated by kretprobe
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);
    __type(value, struct evt);
    __uint(max_entries, 8192);
} inflight SEC(".maps");

SEC("kprobe/devcgroup_check_permission")
int BPF_KPROBE(kp_dcp, short type, unsigned int major, unsigned int minor, int access)
{
    struct evt e = {};
    unsigned long id = bpf_get_current_pid_tgid();
    e.pid = id & 0xffffffff;
    e.tgid = id >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.hook = 1;
    e.type = type;
    e.major = major;
    e.minor = minor;
    e.access = access;
    e.verdict = 0;
    bpf_map_update_elem(&inflight, &id, &e, BPF_ANY);
    return 0;
}

SEC("kretprobe/devcgroup_check_permission")
int BPF_KRETPROBE(kr_dcp, int ret)
{
    unsigned long id = bpf_get_current_pid_tgid();
    struct evt *p = bpf_map_lookup_elem(&inflight, &id);
    if (!p) return 0;
    p->verdict = ret;
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memcpy(e, p, sizeof(*e));
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
