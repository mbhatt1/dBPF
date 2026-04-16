// Ch06 Silence SELinux — observer variant.
//
// Kprobes SELinux's in-kernel access-vector cache (AVC) entry points and
// the file-permission hook. Every labeled access decision streams a
// ringbuf event with {pid, comm, hook, ssid, tsid, tclass}. No mutation
// is attempted here — the override path is BPF LSM (fmod_ret), which
// lives in ../ch06-silence-selinux-lsm/.
//
// On kernels without SELinux compiled in (linuxkit aarch64, for example)
// none of these symbols exist; the loader disables the programs via
// bpf_program__set_autoload(false) and exits cleanly with a CH06_SKIP.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int hook;           // 1=avc_has_perm 2=avc_has_perm_noaudit 3=selinux_file_permission
    unsigned int ssid;  // source sid (0 if unknown)
    unsigned int tsid;  // target sid
    unsigned int tclass;
    int requested;      // requested access bits (perm mask)
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

static __always_inline void fill_common(struct evt *e, int hook)
{
    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;
}

// int avc_has_perm(u32 ssid, u32 tsid, u16 tclass, u32 requested,
//                  struct common_audit_data *auditdata)
SEC("kprobe/avc_has_perm")
int BPF_KPROBE(kp_avc_has_perm,
               unsigned int ssid, unsigned int tsid,
               unsigned short tclass, unsigned int requested)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, 1);
    e->ssid = ssid;
    e->tsid = tsid;
    e->tclass = tclass;
    e->requested = (int)requested;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// int avc_has_perm_noaudit(struct selinux_state *state, u32 ssid, u32 tsid,
//                          u16 tclass, u32 requested, ...)
// Signature varies across kernels; we only pull the first four scalars,
// which is the intersection every variant exposes in the same register
// order (ssid, tsid, tclass, requested) *after* the optional state arg.
// Using BPF_KPROBE we only grab (arg0..argN); we read both shapes and
// pick the non-zero one at userspace triage time. For robustness we
// just record arg1..arg3 on kernels where arg0 is the state pointer.
SEC("kprobe/avc_has_perm_noaudit")
int BPF_KPROBE(kp_avc_has_perm_noaudit,
               unsigned long a0, unsigned long a1,
               unsigned long a2, unsigned long a3)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, 2);
    // Heuristic: if a0 looks like a pointer (high bit set on 64-bit kernels)
    // treat it as selinux_state and shift args. Otherwise assume
    // scalar-first (ssid, tsid, tclass, requested).
    if (a0 > 0xffff000000000000ULL) {
        e->ssid = (unsigned int)a1;
        e->tsid = (unsigned int)a2;
        e->tclass = (unsigned int)(a3 & 0xffff);
        e->requested = 0;
    } else {
        e->ssid = (unsigned int)a0;
        e->tsid = (unsigned int)a1;
        e->tclass = (unsigned int)(a2 & 0xffff);
        e->requested = (int)a3;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// int selinux_file_permission(struct file *file, int mask)
SEC("kprobe/selinux_file_permission")
int BPF_KPROBE(kp_selinux_file_permission, struct file *file, int mask)
{
    (void)file;
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, 3);
    e->ssid = 0;
    e->tsid = 0;
    e->tclass = 0;
    e->requested = mask;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
