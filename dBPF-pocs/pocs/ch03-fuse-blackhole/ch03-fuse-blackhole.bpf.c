// Ch03 FUSE Audit Black-Hole — observer for kernel audit event construction.
//
// Hooks every call into the audit-message-building path and streams metadata
// (pid, comm, audit type, syscall nr for syscall-class records) through a
// ring buffer. The same hook site is where a malicious actor would call
// bpf_override_return() to drop-on-the-floor audit records — but internal
// kernel functions like audit_log_start() are not on this kernel's
// error_injection allowlist, so mutation is blocked by policy. The observer
// proves the hook fires on every audit-worthy event; the README explains how
// the "black-hole" would work on a kernel where override_return is permitted.
//
// CO-RE only. Targets the linuxkit 6.12 aarch64 kernel in this environment.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MSG_MAX 96

struct evt {
    unsigned int pid;
    unsigned int tgid;
    int          hook;        // 1=audit_log_start 2=audit_log_end 3=audit_log_format
    int          audit_type;  // AUDIT_* constant (from audit_log_start arg)
    int          has_ctx;     // 1 if audit_context present on task
    char         comm[16];
    char         fmt_preview[MSG_MAX]; // first bytes of format string for hook==3
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// Optional control map: ctrl[0] = 1 means "pretend to drop". We cannot call
// bpf_override_return() on audit_log_start/end on this kernel (it's not in
// the error_injection list), so this flag is advertised in the ringbuf event
// and the userspace loader prints the intent rather than actually muting the
// audit subsystem. This keeps the POC a faithful observer while documenting
// the mutation vector the chapter describes.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1);
} ctrl SEC(".maps");

static __always_inline void fill_common(struct evt *e, int hook)
{
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = (__u32)id;
    e->tgid = id >> 32;
    e->hook = hook;
    e->audit_type = 0;
    e->has_ctx = 0;
    e->fmt_preview[0] = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// audit_log_start(struct audit_context *ctx, gfp_t gfp_mask, int type)
SEC("kprobe/audit_log_start")
int BPF_KPROBE(kp_als, void *actx, unsigned int gfp, int type)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, 1);
    e->audit_type = type;
    e->has_ctx = actx != NULL;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// audit_log_end(struct audit_buffer *ab) — end of a record that is about to
// be queued to the audit daemon. Classic mutation site ("black-hole the
// record here"). We only observe.
SEC("kprobe/audit_log_end")
int BPF_KPROBE(kp_ale, void *ab)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, 2);
    // ab==NULL means audit_log_start() bailed; still interesting.
    e->has_ctx = ab != NULL;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// audit_log_format(struct audit_buffer *ab, const char *fmt, ...)
// We peek the first bytes of the format string to give operators a clue
// what record is being built.
SEC("kprobe/audit_log_format")
int BPF_KPROBE(kp_alf, void *ab, const char *fmt)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, 3);
    e->has_ctx = ab != NULL;
    if (fmt)
        bpf_probe_read_kernel_str(&e->fmt_preview, sizeof(e->fmt_preview), fmt);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
