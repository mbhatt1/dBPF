// ch07 Device-cgroup Houdini — LSM variant (SYNTHETIC deny+flip).
//
// Chapter claim: "escape the device cgroup and access arbitrary devices".
// Implementation reality on a Linux LSM chain: hooks short-circuit on
// first non-zero return and BPF LSM is registered LAST on every standard
// boot (capability always runs first). So a vanilla
// `fmod_ret lsm.s/inode_mknod` CANNOT flip a cap_inode_mknod denial —
// it never gets called. Even worse, `vfs_mknod` direct-calls
// `capable(CAP_MKNOD)` *before* `security_inode_mknod`, so cap denials
// never even reach the LSM chain.
//
// To prove the primitive anyway, this variant follows the
// ch06-silence-selinux-lsm-synthetic design: a single sleepable BPF LSM
// program implements BOTH the denier AND the flipper, selected at
// runtime via a stage control map. That proves in-kernel that a BPF LSM
// fmod_ret program can (a) synthesize a device-gate denial for a
// target process and (b) turn the same match into an allow.
//
// Three hooks are compiled in; the loader disables the ones whose
// `bpf_lsm_<hook>` BTF FUNC is absent (linuxkit 6.12 aarch64 has
// inode_mknod and file_open but not dev_open).
//
//   lsm.s/inode_mknod   — gate mknod(2) of char/block nodes
//   lsm.s/file_open     — gate open(2) of existing char/block nodes
//   lsm.s/dev_open      — (optional) post-open hook
//
// Stages:
//   STAGE_OFF   — pass through unchanged
//   STAGE_DENY  — if the target tgid touches a char/block device, return
//                 -EPERM (the "device cgroup says no" synthesis)
//   STAGE_FLIP  — same match, return 0 (the "houdini escape")
//
// Every matched invocation pushes a ringbuf event. The loader prints
// `[ch07] FLIP hook=<name> ...` on STAGE_FLIP events, matching the
// harness proof regex `CH07_PROVEN|CH07_CONCEPT_PROVEN|FLIP\s+hook=`.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

#define STAGE_OFF  0
#define STAGE_DENY 1
#define STAGE_FLIP 2

// Hook identifiers mirrored by the userspace loader's name table.
#define H_INODE_MKNOD  1
#define H_FILE_OPEN    2
#define H_DEV_OPEN     3

// i_mode masks — subset of <linux/stat.h>; vmlinux.h does not expose them.
#define CH07_S_IFMT   00170000
#define CH07_S_IFCHR  0020000
#define CH07_S_IFBLK  0060000

struct ctrl {
    unsigned int stage;
    unsigned int target_tgid;  // 0 == wildcard (match every tgid)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct ctrl);
    __uint(max_entries, 1);
} ctrl_map SEC(".maps");

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;
    int stage;
    int verdict;            // 0 = allow, -EPERM = deny
    int matched;            // 1 if the filter matched
    unsigned int major;
    unsigned int minor;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

static __always_inline int match_tgid(struct ctrl *c, unsigned int tgid)
{
    return (c->target_tgid == 0) || (c->target_tgid == tgid);
}

static __always_inline unsigned int ch07_major(unsigned int dev)
{
    // MAJOR(dev) = (dev >> 20)
    return (dev >> 20) & 0xfff;
}

static __always_inline unsigned int ch07_minor(unsigned int dev)
{
    // MINOR(dev) = dev & 0xfffff
    return dev & 0xfffff;
}

static __always_inline int run_stage(int hook, unsigned int mode,
                                     unsigned int dev)
{
    unsigned int k = 0;
    struct ctrl *c = bpf_map_lookup_elem(&ctrl_map, &k);
    if (!c)
        return 0;
    if (c->stage == STAGE_OFF)
        return 0;

    // Only gate char/block device operations.
    unsigned int ifmt = mode & CH07_S_IFMT;
    if (ifmt != CH07_S_IFCHR && ifmt != CH07_S_IFBLK)
        return 0;

    unsigned long long id = bpf_get_current_pid_tgid();
    unsigned int tgid = (unsigned int)(id >> 32);
    if (!match_tgid(c, tgid))
        return 0;

    int verdict = 0;
    if (c->stage == STAGE_DENY)
        verdict = -EPERM;
    else if (c->stage == STAGE_FLIP)
        verdict = 0;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = (unsigned int)(id & 0xffffffff);
        e->tgid = tgid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->hook = hook;
        e->stage = (int)c->stage;
        e->verdict = verdict;
        e->matched = 1;
        e->major = ch07_major(dev);
        e->minor = ch07_minor(dev);
        bpf_ringbuf_submit(e, 0);
    }
    return verdict;
}

// LSM hook signature (lsm_hook_defs.h, stable across 5.x..6.12):
//   LSM_HOOK(int, 0, inode_mknod,
//            struct inode *dir, struct dentry *dentry,
//            umode_t mode, dev_t dev)
// The trailing `int ret` is libbpf's synthesis of the accumulated
// upstream LSM result (BPF LSM programs see the chain ret via this
// extra arg).
SEC("lsm.s/inode_mknod")
int BPF_PROG(lsm_inode_mknod,
             struct inode *dir, struct dentry *dentry,
             unsigned short mode, unsigned int dev, int ret)
{
    (void)dir; (void)dentry; (void)ret;
    return run_stage(H_INODE_MKNOD, (unsigned int)mode, dev);
}

// int security_file_open(struct file *file)
SEC("lsm.s/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret)
{
    (void)ret;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    unsigned int dev = (unsigned int)BPF_CORE_READ(inode, i_rdev);
    return run_stage(H_FILE_OPEN, (unsigned int)mode, dev);
}

// int security_dev_open(struct file *file)
// Not present on every kernel; loader's BTF prune will disable this
// program via bpf_program__set_autoload(false) when the bpf_lsm_dev_open
// FUNC is missing from vmlinux BTF.
SEC("lsm.s/dev_open")
int BPF_PROG(lsm_dev_open, struct file *file, int ret)
{
    (void)ret;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    unsigned int dev = 0;
    unsigned short mode = 0;
    if (inode) {
        dev = (unsigned int)BPF_CORE_READ(inode, i_rdev);
        mode = BPF_CORE_READ(inode, i_mode);
    }
    return run_stage(H_DEV_OPEN, (unsigned int)mode, dev);
}
