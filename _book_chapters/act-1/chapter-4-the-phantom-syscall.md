---
layout: book
title: "Chapter 4: The Phantom Syscall"
date: 2025-02-03
---

# Act I: Foundations of Breach

# Chapter 4: The Phantom Syscall

> **See also**: [Blog post]({{ site.baseurl }}/2025/02/03/the-phantom-syscall.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch04-phantom-syscall) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

I was trying to see how far a tail-called BPF program could walk `task_struct` from a kprobe on `__x64_sys_write` before the verifier got unhappy. The idea is well-trodden: stage 1 is a small gatekeeper on syscall entry that checks some predicate on the current task, and stage 2, reached via `bpf_tail_call`, does the work that would blow the instruction budget in a single program. The interesting question is not whether this works — it does — but what exactly the verifier accepts when stage 2 reads `current->cred`, `current->nsproxy`, and friends. This chapter is notes from reading the reject messages.

## Stage 1: The Gate

```c
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __type(key, u32);
    __type(value, u32);
} prog_array SEC(".maps");

SEC("kprobe/__x64_sys_write")
int stage1(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!target_pid(pid))
        return 0;
    bpf_tail_call(ctx, &prog_array, 0);
    return 0;
}
```

Nothing remarkable. The verifier has supported `bpf_tail_call` from a kprobe context for a long time. The program type of the tail-callee must match the caller — a kprobe program can only tail-call into another kprobe program. The max tail-call depth is 33 on current kernels (up from 32 in older versions).

## Stage 2: Reading current->cred

This is where it got interesting. I wrote:

```c
SEC("kprobe/stage2")
int stage2(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred *cred;
    kuid_t uid;

    bpf_probe_read_kernel(&cred, sizeof(cred), &task->cred);
    bpf_probe_read_kernel(&uid, sizeof(uid), &cred->uid);

    // ...
    return 0;
}
```

That loads. The verifier is happy because every dereference of a kernel pointer goes through `bpf_probe_read_kernel`, which returns an error rather than oopsing on a bad address.

What the verifier rejects is the direct-dereference shortcut:

```c
const struct cred *cred = task->cred;           // BTF read, fine on modern kernels
kuid_t uid = cred->uid;                         // REJECTED: "invalid access to map value"
```

On 5.15 and later with BTF and `CONFIG_DEBUG_INFO_BTF=y`, the first line is accepted as a BTF-typed pointer read. The second is not, because `cred` is now tracked as a `PTR_TO_BTF_ID_OR_NULL` and the verifier requires the NULL check before the dereference. The fix is:

```c
const struct cred *cred = task->cred;
if (!cred) return 0;
kuid_t uid = BPF_CORE_READ(cred, uid);
```

`BPF_CORE_READ` expands to a chain of `bpf_probe_read_kernel` calls with CO-RE relocations. The verifier accepts this. `bpftool prog dump xlated` shows the calls getting inlined on kernels that support inlining.

## What the Verifier Accepts, Concretely

Tested on 6.12:

- `task->pid`, `task->tgid`: direct BTF read, accepted.
- `task->cred` into a local pointer: accepted. Dereferencing that pointer requires a NULL check.
- `task->real_cred`: same as `cred`.
- `task->nsproxy->pid_ns_for_children->level`: rejected without NULL checks at each level. With checks, accepted.
- `task->mm->pgd`: rejected. `mm` can be NULL for kernel threads; verifier requires the check, and even with the check the `pgd` field is gated further.
- `task->fs->root.dentry`: accepted after NULL check on `fs`.

The pattern is consistent: anything reachable from `current` that can legitimately be NULL requires the check, and the verifier knows which fields can be NULL from BTF.

## What the Verifier Rejects

- Loops without bounded iteration. `for (int i = 0; i < n; i++)` where `n` comes from a map value is rejected unless you use `bpf_loop` (5.17+) or `#pragma unroll` with a compile-time constant.
- Pointer arithmetic on `PTR_TO_BTF_ID`. `&task->cred + 1` does not work.
- Writes to task fields. `task->cred = new_cred;` is rejected. The verifier tracks BTF pointers as read-only.
- Calls to most kernel functions. `kfuncs` are a narrow allowlist; `commit_creds` is not on it.

That last one is the thing. The phantom-syscall framing in earlier drafts implied you could swap credentials from BPF. You cannot. `commit_creds` is not a kfunc. `override_creds` is not a kfunc. The cred structure is readable from BPF and not writable from BPF, and the set of kfuncs that might change that is governed by `kernel/bpf/helpers.c` and the per-subsystem kfunc sets registered via `register_btf_kfunc_id_set`.

## So What Is the Phantom Syscall, Really

A two-stage kprobe that reads task state on syscall entry and emits events based on that state. It is an observer with a cheap predicate in stage 1 and expensive walking in stage 2. The tail call keeps each program under the 1M-instruction verifier limit and lets you conditionally skip the expensive work.

It is not a credential-swap primitive. It is not a syscall-bypass primitive. The syscall still runs; seccomp still sees it; auditd still sees it. What you get is visibility into syscalls conditioned on task state that a single-program kprobe couldn't compute without blowing the complexity budget.

If a prior write-up described this as "syscalls that leave no trace," that write-up was wrong about what BPF can do to `current->cred`. Read the verifier. The rules are strict and they are documented in `Documentation/bpf/verifier.rst`.

## Detection

- `bpftool prog show` lists both stage 1 and stage 2, plus the prog array map.
- `bpftool map dump id <prog_array_id>` reveals the tail-call targets.
- `/sys/kernel/debug/kprobes/list` shows the `__x64_sys_write` probe.
- `perf stat -e bpf_trace_printk` or equivalent catches any debug output.
- Tail calls are visible in `bpftool prog profile` as a distinct program enter/exit pattern.

## Summary

Two programs, one prog-array map, one kprobe. Stage 1 gates, stage 2 walks. The verifier enforces NULL checks on nullable BTF fields and rejects writes to task state. The technique is a visibility primitive, not a bypass primitive. Prior art: `bpf_tail_call` has been in the kernel since 4.2; chained kprobes into stage-2 programs are a staple of bcc and bpftrace internals. What this chapter documents is the specific accept/reject boundary the verifier draws on modern kernels, because that boundary is where a lot of write-ups have drifted into fiction.
