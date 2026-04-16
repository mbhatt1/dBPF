// Ch12 Signed-Driver Swap — observe the kernel module signature-check path.
// Hooks the three canonical gates that the kernel uses when loading a .ko:
//   - load_module         : top-level entry
//   - module_sig_check    : signature-presence / format gate
//   - mod_verify_sig      : signature verification body (+ kretprobe for ret)
// Pure observer: ringbuf events only. A mutating variant lives in
// ch12-signed-driver-swap-lsm (BPF LSM kernel_read_file fmod_ret).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Hook discriminator.
#define HOOK_LOAD_MODULE      1
#define HOOK_MODULE_SIG_CHECK 2
#define HOOK_MOD_VERIFY_SIG   3
#define HOOK_MOD_VERIFY_SIG_R 4

#define MODNAME_LEN 56

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    int          hook;
    int          ret;
    char         modname[MODNAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// Per-CPU scratch so we don't blow the 512B BPF stack budget with MODNAME_LEN.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct evt);
    __uint(max_entries, 1);
} scratch SEC(".maps");

static __always_inline void fill_common(struct evt *e, int hook, int ret)
{
    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid  = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    e->hook = hook;
    e->ret  = ret;
    e->modname[0] = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void submit(struct evt *src)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    __builtin_memcpy(e, src, sizeof(*e));
    bpf_ringbuf_submit(e, 0);
}

// load_module(struct load_info *info, const char __user *uargs, int flags).
// load_info->name holds the module's declared name once parsed; early in the
// call it may still be empty. Best-effort.
SEC("kprobe/load_module")
int BPF_KPROBE(kp_load_module, void *info)
{
    unsigned int zero = 0;
    struct evt *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;
    fill_common(e, HOOK_LOAD_MODULE, 0);

    // `struct load_info` is kernel-internal (defined in kernel/module/internal.h,
    // not exported to vmlinux.h). We can't CO-RE read it portably; leave the
    // modname empty and let downstream hooks (module_sig_check) populate it
    // if the symbol resolves — otherwise the pid/comm alone is enough to
    // correlate with the userspace insmod/modprobe.
    (void)info;
    submit(e);
    return 0;
}

// module_sig_check(struct load_info *info, int flags). Called from load_module
// to gate signature presence on signed-module kernels.
SEC("kprobe/module_sig_check")
int BPF_KPROBE(kp_module_sig_check, void *info)
{
    unsigned int zero = 0;
    struct evt *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;
    fill_common(e, HOOK_MODULE_SIG_CHECK, 0);
    (void)info;
    submit(e);
    return 0;
}

// mod_verify_sig(const void *mod, struct load_info *info). Entry probe.
SEC("kprobe/mod_verify_sig")
int BPF_KPROBE(kp_mod_verify_sig)
{
    unsigned int zero = 0;
    struct evt *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;
    fill_common(e, HOOK_MOD_VERIFY_SIG, 0);
    submit(e);
    return 0;
}

// mod_verify_sig return — this is the signature-rejection signal (non-zero
// ret means the sig check failed; -ENODATA/-EKEYREJECTED/-EBADMSG are the
// common codes).
SEC("kretprobe/mod_verify_sig")
int BPF_KRETPROBE(kr_mod_verify_sig, int ret)
{
    unsigned int zero = 0;
    struct evt *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;
    fill_common(e, HOOK_MOD_VERIFY_SIG_R, ret);
    submit(e);
    return 0;
}
