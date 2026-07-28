// ch24 bpf-token-delegation BPF program.
//
// A raw tracepoint on sys_enter that emits one ringbuf event per getuid()
// syscall. Its only job is to prove that a BPF program loaded via bpf_token
// delegation from a user-namespace-confined (host-unprivileged) caller
// actually runs.
//
// Why a RAW tracepoint (raw_tp/sys_enter) and not a classic tracepoint
// (tp/syscalls/sys_enter_getuid)?  A classic tracepoint program can only be
// attached with perf_event_open() + PERF_EVENT_IOC_SET_BPF.  perf_event_open()
// for a tracepoint is NOT covered by a BPF token -- it needs CAP_PERFMON in the
// init user namespace, which the confined caller does not have (it fails with
// EACCES).  A raw tracepoint is attached with the BPF_RAW_TRACEPOINT_OPEN
// bpf() command, which the token *does* delegate (delegate_cmds).  So the whole
// load+attach path stays inside the delegated bpf() surface.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* getuid() syscall number. arm64 (the PoC target) uses the asm-generic table
 * where __NR_getuid == 174. Fall back to that if the build environment did not
 * define it. */
#ifndef TARGET_NR_GETUID
#define TARGET_NR_GETUID 174
#endif

struct evt {
    __u64 ts;
    __u32 pid;
    __u32 uid;
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

SEC("raw_tp/sys_enter")
int rtp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    /* sys_enter raw tracepoint args: args[0] = struct pt_regs *,
     *                                 args[1] = long syscall_nr. */
    unsigned long long nr = ctx->args[1];
    if (nr != TARGET_NR_GETUID)
        return 0;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    e->ts  = bpf_ktime_get_ns();
    e->pid = pid_tgid & 0xffffffff;
    e->uid = uid_gid & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
