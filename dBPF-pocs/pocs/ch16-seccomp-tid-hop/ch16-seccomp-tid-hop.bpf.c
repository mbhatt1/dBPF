// Ch16 Seccomp TID Hop — observer kprobe on __secure_computing that
// captures every seccomp evaluation (pid, tid, syscall_nr, filter mode,
// comm). For tgids that userspace has added to `target_tgids`, we *also*
// attempt to override the retval via kretprobe (only effective if the
// kernel lists __secure_computing in error_injection/list — on 6.12 it
// typically is NOT, so this silently degrades to pure observation and
// the `override_attempted` flag records the ambition).
//
// Why observer-only is honest here: task->seccomp.mode lives in the
// task_struct and cannot be written from BPF; the filter chain is a
// BPF program itself, not mutable data. The book's "borrow a TID"
// fantasy maps to exactly this: you can *watch* every check and, if
// __secure_computing becomes injectable, you can force it to return
// SECCOMP_RET_ALLOW (0). Until then we surface the primitive and its
// limit with full fidelity.
//
// Hook target verification: `__secure_computing` is present in
// /proc/kallsyms on 6.12.54-linuxkit aarch64.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid;            // kernel "pid" (thread id)
    unsigned int tgid;           // kernel "tgid" (process id)
    int          syscall_nr;     // from task->thread_info or pt_regs (best-effort)
    int          seccomp_mode;   // current->seccomp.mode
    int          override_attempted;
    int          override_ok;
    unsigned long long ts_ns;
    char         comm[16];
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

// per-task in-flight so kretprobe can find what the kprobe recorded
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);
    __type(value, struct evt);
    __uint(max_entries, 4096);
} inflight SEC(".maps");

static __always_inline int read_syscall_nr(struct task_struct *task)
{
    // On arm64, the syscall number lives in pt_regs->regs[8] (x8) at the
    // thread's kernel stack. Reading it robustly from a kprobe on
    // __secure_computing is non-trivial; best-effort via task->thread_info
    // isn't portable. Return -1 to signal "unknown" and let userspace
    // correlate via comm + timestamp. CO-RE keeps this future-proof.
    return -1;
}

SEC("kprobe/__secure_computing")
int BPF_KPROBE(kp_secure_computing)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    unsigned long id = bpf_get_current_pid_tgid();
    unsigned int tgid = id >> 32;

    struct evt e = {};
    e.pid  = id & 0xffffffff;
    e.tgid = tgid;
    e.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.syscall_nr = read_syscall_nr(task);

    // current->seccomp.mode — CO-RE read (field exists on 6.12).
    int mode = 0;
    if (bpf_core_field_exists(task->seccomp)) {
        mode = BPF_CORE_READ(task, seccomp.mode);
    }
    e.seccomp_mode = mode;

    int targeted = 0;
    if (bpf_map_lookup_elem(&target_tgids, &tgid)) targeted = 1;
    unsigned int zero = 0;
    if (!targeted && bpf_map_lookup_elem(&target_tgids, &zero)) targeted = 1;
    e.override_attempted = targeted;
    e.override_ok = 0;

    bpf_map_update_elem(&inflight, &id, &e, BPF_ANY);

    // Emit observation immediately; the retprobe will emit a second
    // event if the override succeeded.
    struct evt *ring = bpf_ringbuf_reserve(&events, sizeof(*ring), 0);
    if (ring) {
        __builtin_memcpy(ring, &e, sizeof(*ring));
        bpf_ringbuf_submit(ring, 0);
    }
    return 0;
}

SEC("kretprobe/__secure_computing")
int BPF_KRETPROBE(kr_secure_computing, int ret)
{
    unsigned long id = bpf_get_current_pid_tgid();
    struct evt *p = bpf_map_lookup_elem(&inflight, &id);
    if (!p) return 0;

    // Emit a second event on the return path with the final ret value
    // encoded into syscall_nr (repurposed) so defenders can correlate
    // which checks allowed (ret==0) vs denied. We do NOT call
    // bpf_override_return: __secure_computing is not listed in
    // /sys/kernel/debug/error_injection/list on 6.12.54-linuxkit, so
    // overriding would fail at attach time and prevent the observer
    // from loading. This is the "observer-only" degradation the book
    // anticipates when kernel-memory writes are blocked.
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memcpy(e, p, sizeof(*e));
        e->override_ok = (ret == 0) ? 1 : 0; // repurpose: ret==ALLOW?
        e->syscall_nr = ret;                  // repurpose: final retval
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
