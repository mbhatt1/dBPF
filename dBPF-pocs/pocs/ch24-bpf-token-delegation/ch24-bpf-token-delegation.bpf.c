// ch24 bpf-token-delegation BPF program.
//
// A minimal tracepoint on sys_enter_getuid that emits one ringbuf event
// per call. Its only job is to prove that a BPF program loaded via
// bpf_token delegation from an unprivileged caller actually runs.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    __u64 ts;
    __u32 pid;
    __u32 uid;
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_getuid")
int tp_sys_enter_getuid(void *ctx)
{
    (void)ctx;
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    e->ts  = bpf_ktime_get_ns();
    e->pid = pid_tgid & 0xffffffff;
    e->uid = uid_gid & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
