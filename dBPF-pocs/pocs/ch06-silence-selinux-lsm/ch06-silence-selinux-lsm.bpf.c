// ch06 Silence SELinux — BPF LSM OBSERVER (the "silence" flip is impossible).
//
// HONEST STATUS (proven live on Fedora 43, kernel 6.17.1, SELinux enforcing):
// The chapter's original claim — "force SELinux denials to grants" — is
// IMPOSSIBLE via BPF LSM. The kernel LSM framework runs hooks as an ordered
// chain and is DENY-WINS: call_int_hook() iterates the registered modules
// and bails out on the FIRST hook that returns a non-default (nonzero) value.
// On every stock kernel the LSM order places selinux BEFORE bpf, e.g.
//   /sys/kernel/security/lsm = lockdown,capability,yama,selinux,bpf,...
// So when SELinux denies an access it returns -EACCES first and the chain
// short-circuits: the bpf hook is NEVER invoked for a denied access, and
// even if it were, returning 0 cannot undo the -EACCES already selected by
// the framework. A BPF LSM hook can only make policy MORE restrictive
// (turn an allow into a deny, because it runs after selinux's allow); it can
// never relax a SELinux denial.
//
// PROOF (see trigger.sh): with these hooks attached in wildcard "flip every
// deny" mode, 150+ genuine SELinux denials (unconfined_t reading a custom
// ch06deny_t-labeled file, permissive=0) were generated. Result: every read
// still failed with EACCES, ZERO flips occurred, and across ~34,000 hook
// invocations the trailing `ret` arg was 0 EVERY time (nonzero=0) — direct
// evidence the hook never even sees a pending denial.
//
// What ch06 CAN honestly do: OBSERVE. These hooks fire on every *allowed*
// access decision (ret==0) and can read/emit them. That makes ch06 a
// legitimate BPF LSM observer of SELinux-permitted operations, not a
// silencer. The flip code below is retained only to demonstrate that the
// flip path is dead (`ret != 0` is never true on a real SELinux host).
//
// Three hooks cover the common access paths:
//   lsm/file_permission       — vfs read/write/execute on an open file
//   lsm/inode_permission      — path walk / open-time permission check
//   lsm/bprm_check_security   — execve of a binary
//
// Each reads the upstream `ret` arg (return value accumulated by the LSM
// chain so far — always 0 by the time a bpf hook runs). Emits a ringbuf
// event with {pid, comm, hook, orig_ret, flipped}.
//
// Prereqs (verify on the host before running):
//   cat /sys/kernel/security/lsm     # must contain "bpf" AND "selinux"
//   bpftool feature probe | grep lsm # program_type lsm available
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
SEC("lsm/file_permission")
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
SEC("lsm/inode_permission")
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
SEC("lsm/bprm_check_security")
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
