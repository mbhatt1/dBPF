# ch04 — Phantom Syscall

Userspace issues exactly one syscall: `write(fd, "PHANTOM\0..payload..", N)`.
A tracepoint on `sys_enter_write` sniffs the magic, then tail-calls stage 2,
which reads kernel-only data (current->cred uid/euid, real_parent->comm) and
exfils via ringbuf. Seccomp would only see `write` — yet kernel-space data
reached the attacker.

## Hook points
- `tp/syscalls/sys_enter_write` (stage1) — magic detection + payload copy.
- `bpf_tail_call(ctx, &jumps, 0)` → stage2 (manual-attach only).
- Stage2 reads creds/task info and submits ringbuf event.

## Evidence
```
[phantom] pid=20786 tgid=20786 uid=0 euid=0 comm=phantom parent=bash
          payload='hello-from-unprivileged-user'
```

## Detection
Rings loud on syscall tracepoint audit; ringbuf map visible in
`bpftool map list`; PROG_ARRAY usage and tail_call are flags.

## Blog post

See the chapter write-up: [`2025-02-03-the-phantom-syscall`](../../../_posts/2025-02-03-the-phantom-syscall.md) in the Diabolical eBPF Field Manual.
