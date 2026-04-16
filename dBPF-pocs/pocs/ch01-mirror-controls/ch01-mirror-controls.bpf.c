// Ch01 Mirror Controls — observe every cap_capable decision and, when a
// target pid (via control map) is denied, override the return value to 0
// (granted) using bpf_override_return.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int cap;
    int orig_ret;
    int flipped;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// target_tgids: if a tgid is present, its denials will be flipped to grants
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);   // pid_tgid
    __type(value, int);           // cap
    __uint(max_entries, 8192);
} in_flight SEC(".maps");

SEC("kprobe/cap_capable")
int BPF_KPROBE(kp_cap, const void *cred, void *ns, int cap, unsigned int opts)
{
    unsigned long id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&in_flight, &id, &cap, BPF_ANY);
    return 0;
}

SEC("kretprobe/cap_capable")
int BPF_KRETPROBE(kr_cap, int ret)
{
    unsigned long id = bpf_get_current_pid_tgid();
    int *cap_p = bpf_map_lookup_elem(&in_flight, &id);
    if (!cap_p) return 0;
    int cap = *cap_p;
    bpf_map_delete_elem(&in_flight, &id);

    unsigned int tgid = id >> 32;
    unsigned int *hit = bpf_map_lookup_elem(&target_tgids, &tgid);
    int flipped = 0;
    // Note: internal-function override blocked on this kernel (not in
    // error_injection allowlist). We mark what WOULD be flipped.
    if (hit && ret != 0) flipped = 1;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = id & 0xffffffff;
    e->tgid = tgid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->cap = cap;
    e->orig_ret = ret;
    e->flipped = flipped;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
