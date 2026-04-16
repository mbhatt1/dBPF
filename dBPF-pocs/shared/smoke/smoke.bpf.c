#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

SEC("kprobe/cap_capable")
int BPF_KPROBE(kp_cap_capable, const void *cred, void *ns, int cap, unsigned int opts) {
    u32 *e = bpf_ringbuf_reserve(&events, sizeof(u32), 0);
    if (!e) return 0;
    *e = (u32)cap;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
