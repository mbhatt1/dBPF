// ch08 keyring-heist observer: kprobe key_task_permission + lookup_user_key,
// emit ringbuf {serial, type, desc, hook} via CO-RE reads.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid;
    char comm[16];
    int serial;
    unsigned int datalen;
    char type[16];
    char desc[64];
    int hook;         // 1=key_task_permission 2=lookup_user_key
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

static __always_inline void emit_key(struct key *k, int hook)
{
    if (!k) return;
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    __builtin_memset(e, 0, sizeof(*e));
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;
    e->serial = BPF_CORE_READ(k, serial);
    e->datalen = BPF_CORE_READ(k, datalen);
    struct key_type *kt = BPF_CORE_READ(k, type);
    const char *tname = BPF_CORE_READ(kt, name);
    if (tname) bpf_probe_read_kernel_str(&e->type, sizeof(e->type), tname);
    const char *desc = BPF_CORE_READ(k, description);
    if (desc) bpf_probe_read_kernel_str(&e->desc, sizeof(e->desc), desc);
    bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/key_task_permission")
int BPF_KPROBE(kp_ktp, void *key_ref)
{
    unsigned long kr = (unsigned long)key_ref;
    struct key *k = (struct key *)(kr & ~3UL);
    emit_key(k, 1);
    return 0;
}

SEC("kprobe/lookup_user_key")
int BPF_KPROBE(kp_luk, int id)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = 2;
    e->serial = id;
    __builtin_memcpy(e->type, "lookup", 7);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
