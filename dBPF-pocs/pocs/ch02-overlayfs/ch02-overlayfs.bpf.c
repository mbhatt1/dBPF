// Ch02 OverlayFS Trojan Horse — observe every overlayfs copy-up (file being
// promoted from lower -> upper on first write) and exfil path + inode info
// via ringbuf. Use kprobe on ovl_copy_up (entry: dentry *d).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    char name[64];
    unsigned long ino;
    unsigned int mode;
    int hook;   // 1=ovl_copy_up 2=ovl_maybe_copy_up 3=ovl_copy_up_with_data
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

static __always_inline void emit(struct dentry *d, int hook)
{
    if (!d) return;
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    unsigned long id = bpf_get_current_pid_tgid();
    e->pid = id & 0xffffffff;
    e->tgid = id >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;
    const unsigned char *name = BPF_CORE_READ(d, d_name.name);
    bpf_probe_read_kernel_str(&e->name, sizeof(e->name), name);
    struct inode *ino = BPF_CORE_READ(d, d_inode);
    e->ino  = BPF_CORE_READ(ino, i_ino);
    e->mode = BPF_CORE_READ(ino, i_mode);
    bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/ovl_copy_up")
int BPF_KPROBE(kp_cup, struct dentry *dentry)
{
    emit(dentry, 1);
    return 0;
}

SEC("kprobe/ovl_maybe_copy_up")
int BPF_KPROBE(kp_mcup, struct dentry *dentry, int flags)
{
    emit(dentry, 2);
    return 0;
}

SEC("kprobe/ovl_copy_up_with_data")
int BPF_KPROBE(kp_cupd, struct dentry *dentry)
{
    emit(dentry, 3);
    return 0;
}
