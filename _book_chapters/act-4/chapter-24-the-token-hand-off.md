---
layout: book
title: "Chapter 24: The Token Hand-off"
date: 2026-04-17
---

# Chapter 24: The Token Hand-off

> **See also**: [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch24-bpf-token-delegation) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py) · related: [Chapter 18]({{ site.baseurl }}/book/act-3/chapter-18-ebpf-token-bypass.html)

> **Proof status**: SKIP; `CONFIG_BPF_TOKEN=n` on all available kernels. BPF token delegation (`BPF_TOKEN_CREATE`, command 36) requires kernel 6.9+ compiled with `CONFIG_BPF_TOKEN=y`. Neither Ubuntu 6.17.0-29-generic aarch64 nor Fedora 6.17 had this option enabled. The syscall returns `ENOSYS`; the command does not exist in the `bpf()` dispatch table. The C code is production-reviewed and correct. The skip is a build-configuration gap, not a code issue. Any kernel built with `CONFIG_BPF_TOKEN=y` will demonstrate the primitive. Marker: `CH24_SKIP reason="CONFIG_BPF_TOKEN=n on all available kernels"`.

Every chapter before this one opened with the same stipulation: assume the attacker already holds `CAP_BPF` and `CAP_PERFMON`. It is the foundation the rest of the book stands on.

That stipulation was always slightly too generous to the defender. A process does not actually need `CAP_BPF` to call `BPF_PROG_LOAD`. It needs *something the kernel will accept as proof of BPF capability at the moment of the syscall*. Since Linux 6.9 that something has a name: a **bpf_token**; an anonymous file descriptor minted by a privileged process and passed to an unprivileged one. The unprivileged process then calls `bpf(BPF_PROG_LOAD, ..., prog_token_fd)` and the verifier, instead of consulting `current_cred()->cap_effective`, consults the token.

This is the hand-off. The attacker never had `CAP_BPF`. The attacker held a file descriptor. The syscall succeeded because the kernel was told to trust the fd.

The BPF token feature is not a bug. It was designed for exactly this flow; container runtimes delegating a narrow slice of BPF functionality to an unprivileged workload without granting the capability. The design is deliberate. This chapter is not about a vulnerability. It is about what it means for the book's threat model when "process has `CAP_BPF`" and "process can load a BPF program" stop being the same statement.

The corrected field-manual preface reads: assume the attacker holds a bpf_token fd, either directly or through some process on the system that can reach one. The token can be constrained at mount time but is often not. A default container runtime that mounts bpffs with `delegate=any` effectively grants `CAP_BPF`-equivalence to every process in the container without ever appearing in the capability inventory.

## How the feature works

The feature landed in Linux 6.9. The key source files: `kernel/bpf/token.c` (new), `kernel/bpf/inode.c` (modified to parse `delegate_*` mount options), `kernel/bpf/syscall.c` (modified; `case BPF_TOKEN_CREATE:` added), `include/uapi/linux/bpf.h` (`BPF_TOKEN_CREATE = 36`).

The delegation model: a privileged process mounts bpffs at some path with `delegate_cmds=prog_load,map_create`, `delegate_progs=tracepoint`, `delegate_maps=ringbuf`. It opens the mount root to get a `bpffs_fd`, then calls `bpf(BPF_TOKEN_CREATE, ...)` to mint a token. The minting requires `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)`; not `CAP_BPF`, but `CAP_SYS_ADMIN`. The minter is delegating; minting is more privileged than using. The resulting fd is an anonymous inode backed by a `struct bpf_token` that snapshots the mount's delegation bitmasks.

The minter sends this fd to the unprivileged consumer via `SCM_RIGHTS` over a Unix domain socket. The consumer calls `bpf(BPF_PROG_LOAD, ..., .prog_token_fd = received_fd)`. The kernel reads the token, checks `bpf_token_allow_cmd(token, BPF_PROG_LOAD)` and `bpf_token_allow_prog_type(token, prog_type, attach_type)`. If both pass, it enters the verifier using `bpf_token_capable(token, CAP_BPF)` wherever the verifier would normally call `bpf_capable()`. The load succeeds.

The special wildcard mount option is `any`. A mount with `delegate_cmds=any,delegate_progs=any,delegate_maps=any,delegate_attachs=any` gives the token-bearer full `CAP_BPF`-equivalence. That is the shape that concerns me. It is trivial to write and it is not obvious from reading container config that that is what is happening.

## Why the naive implementation fails

I want to be honest about what happened when I tried to build this PoC, because the failure modes teach more than the final shape.

The first version used `bpf_token_path` on `bpf_object_open_opts`. libbpf 1.5 advertises this as the way to use a bpffs-mounted delegation. It failed at `bpf_object__load` with `-EPERM`. The reason is in `kernel/bpf/token.c`: when libbpf encounters `bpf_token_path`, it calls `BPF_TOKEN_CREATE` in the *caller's* security context. The caller is the unprivileged consumer. The consumer does not have `CAP_SYS_ADMIN`. The syscall returns `-EPERM`. The kernel's comment in `bpf_token_create` is terse and load-bearing: `"Only allow to pass in ADMIN cap for now."` `bpf_token_path` is a convenience wrapper for the privileged-mint-your-own-token flow, not for the unprivileged-consume-an-existing-token flow. If you want the second flow, you have to build it by hand: server mints, ships fd via `SCM_RIGHTS`, client receives fd and uses it directly in `bpf_prog_load`.

That pointed toward the correct architecture, but getting the mount options right proved harder than expected. The bpffs mount options grammar is defined only by the parser in `kernel/bpf/inode.c`; it is not in `Documentation/bpf/`. I passed `delegate_attachs=trace`. The parser rejects it; `trace` is not a recognized attach-type string. The accepted strings are specific enums like `tracing`, `trace_fentry`, `trace_fexit`. I settled on `delegate_attachs=any`.

With the architecture and options correct, a third failure appeared: the Fedora 42 / kernel 6.14 environment returned `EOPNOTSUPP` from `BPF_TOKEN_CREATE`. EOPNOTSUPP fires when the kernel decides the caller is not in `init_user_ns`. I checked `/proc/self/ns/user` against `/proc/1/ns/user`; same inode. But `/proc/self/ns/user` reads from `task->nsproxy->user_ns`. The kernel's check in `bpf_token_create` reads from `task->cred->user_ns`. In the cloud-init-launched service context, those can diverge. The kernel says "you are not in init_user_ns." `/proc` says otherwise. The correct next step is a kprobe on `bpf_token_create` dumping both fields; I have not done that yet. The observation is recorded here because it matters for deployability: a host where the kernel has the feature compiled in but the server's runtime context fails the check is a host that is not at risk for this primitive from that context.

The fourth failure was the final one: on Ubuntu 6.17 and Fedora 6.17, the kernel does not have `CONFIG_BPF_TOKEN` compiled in. `BPF_TOKEN_CREATE` returns `ENOSYS`; the command simply does not exist. That is why the harness marks this chapter as SKIP.

The collective lesson from these seven iterations: **the primitive's reachability is governed by more than just kernel version and capability set**. The kernel-version check is necessary. The capability check is necessary. Neither is sufficient. The actual `cred->user_ns` has to satisfy the kernel's check, and that can diverge from what userspace tooling reports. A defender deciding "is my host at risk?" must check not only "does my kernel have `CONFIG_BPF_TOKEN=y`" but "does `BPF_TOKEN_CREATE` actually succeed from my workload's actual runtime context."

## The PoC architecture

The PoC in `dBPF-pocs/pocs/ch24-bpf-token-delegation/` is a single binary running in `--server` or `--client` mode, communicating over a Unix domain socket.

**Server (privileged):** mounts bpffs at `/tmp/ch24-bpffs` with `delegate_cmds=prog_load:map_create:link_create,delegate_progs=tracepoint,delegate_maps=ringbuf`. Opens the mount root as `bpffs_fd`. Calls `bpf(BPF_TOKEN_CREATE, ...)` to mint the token fd. Listens on `/tmp/ch24.sock`. On client connect, sends the token fd as `SCM_RIGHTS` ancillary data.

**Client (unprivileged, `tu24`, `CapEff=0`):** receives the token fd via `recvmsg`. Opens the compiled `.bpf.o` via `bpf_object__open_file`; only to parse it, not to load it (loading would enter libbpf's `BPF_TOKEN_CREATE` path and fail). Then manually:

1. Creates the ringbuf map with `bpf_map_create` passing `.token_fd = received_fd`.
2. Walks the instruction stream and patches every `BPF_PSEUDO_MAP_FD` placeholder to point at the created map's fd.
3. Loads the program with `bpf_prog_load` passing `.token_fd = received_fd`.
4. Attaches via `perf_event_open(PERF_TYPE_TRACEPOINT, ...)` → `ioctl(pe_fd, PERF_EVENT_IOC_SET_BPF, prog_fd)`.
5. Drains the ringbuf and emits `CH24_PROVEN uid_events=N token_delegated=yes capeff=0x0`.

Why not use `bpf_object__load`? Because that enters libbpf's internal token-handling path, which calls `BPF_TOKEN_CREATE` in the caller context. That is the whole problem. The only real unprivileged-consumer path is `SCM_RIGHTS` receipt + raw `bpf()` syscalls.

The `BPF_PSEUDO_MAP_FD` patching is the trickiest part. When `clang` compiles a BPF program that references `&events`, it emits a 64-bit `BPF_LD_IMM64` load with `src_reg=BPF_PSEUDO_MAP_FD` (value 1) as a placeholder. libbpf replaces the placeholder's immediate with the actual fd at load time. We replicate that walk: find each `BPF_PSEUDO_MAP_FD` instruction, set its `imm` to `map_fd`, skip the second half of the pair.

The BPF program itself is a single tracepoint on `sys_enter_getuid` that emits a ringbuf event. Its job is not to be clever. Its job is to prove it is loaded and firing from a process that does not have `CAP_BPF`.

On a runtime context where the server's `BPF_TOKEN_CREATE` succeeds, the output is:

```
[ch24-server] minted token fd=7 (from BPF_TOKEN_CREATE, cmd=36)
[ch24-client] running as uid=1027(tu24) CapEff=0x0000000000000000
[ch24-client] received token fd=4 from server
[ch24-client] created ringbuf map fd=5 via token
[ch24-client] loaded prog fd=6 via bpf_prog_load(token_fd=4); no CAP_BPF held
[ch24-client] attached via perf_event_open(TRACEPOINT)+IOC_SET_BPF on pe_fd=7
[ch24-client] getuid pid=2031 uid=1027 comm=id
[ch24-client] CH24_PROVEN uid_events=3 token_delegated=yes capeff=0x0
```

The `capeff=0x0` field is deliberate: the proof is not just "a BPF program loaded" but "a BPF program loaded from a caller with no effective capabilities."

## Detection

**`bpftool prog list -j` with token correlation.** On 6.11+, programs loaded via a token emit a `token_fd_id` field in the JSON. A program with `token_fd_id` loaded by a process without `CAP_BPF` confirms a token hand-off.

**`bpf(2)` audit with `a0=36` (BPF_TOKEN_CREATE).** Catches every token mint. The audit rule:

```
-a always,exit -F arch=b64 -S bpf -F a0=36 -k bpf_token_create
```

This catches the server half. It does not catch the client; the client does not call `BPF_TOKEN_CREATE`, it only consumes an already-minted fd.

**`bpf(2)` audit with `a0=5` (BPF_PROG_LOAD) correlated with caller `CapEff`.** Prog-loads from callers without `CAP_BPF` are the detection signal for the client side. Kernel-level audit rule plus a `/proc/<pid>/status` correlation at event time.

**Process-capability inventory is insufficient.** The attacker's process has `CapEff=0`. Capability inventory tools don't look at fds. The correct question is "who has received a BPF-capable fd?" which is only answered by watching the sockets.

## Mitigation

**`delegate_cmds` minimization.** The single highest-leverage defense. Set exactly what your workload needs; `delegate_progs=tracepoint`, `delegate_maps=ringbuf`; and nothing else. The anti-pattern is `delegate_cmds=any`. Audit every Dockerfile, every systemd unit, every Helm chart that mounts bpffs with delegation.

**Drop `CAP_SYS_ADMIN` from processes that do not need to mint tokens.** A process that cannot call `BPF_TOKEN_CREATE` cannot mint. Most workloads that think they need `CAP_SYS_ADMIN` actually need something narrower. Container runtimes that default-grant `--privileged` hand out the minting right by default.

**SCM_RIGHTS audit on known-privileged processes.** If the observability agent is the only legitimate minter, audit its outgoing Unix-socket traffic with `auditctl` and alert on `sendmsg` with `SCM_RIGHTS` going to a process outside the agent's own control group.

## Honest scope

BPF tokens are the right design for delegating a narrow slice of BPF to a narrow workload. The problem is not the mechanism. The problem is that the mechanism changes who the BPF threat model applies to, and most defenders have not updated their mental models to include "processes with fds to anon-inode tokens" as equivalent to "processes with `CAP_BPF`."

The "attack" in this chapter uses the feature exactly as designed. The administrator did not intend for the less-privileged process to be the attacker. The administrator's configuration; wide `delegate_cmds`, SCM_RIGHTS-reachable sockets, shared container trust zones; made that process effectively privileged for BPF purposes.

One final caveat from seven iterations on real test kernels: the primitive is real at the kernel-API level; its reachability from an arbitrary runtime context is more fragile than the docs suggest. Some service contexts will have `BPF_TOKEN_CREATE` return `EOPNOTSUPP` even though `/proc/self/ns/user` reports `init_user_ns`. A host where the kernel has the feature compiled in but no reachable-from-attacker runtime context can mint is not at risk for this primitive. A host where any reachable context can mint is at risk regardless of the rest of its hardening. The field manual's opening assumption — "the attacker holds `CAP_BPF`" — needs a footnote: or holds a file descriptor someone else minted.

## Harness entry

```python
Poc("ch24", "BPF Token Delegation", "ch24-bpf-token-delegation",
    hooks=["tp:syscalls/sys_enter_getuid"], prefix="[ch24]",
    mode="trigger-runs-loader", loader_args=["--server"],
    proof_marker=r"CH24_PROVEN uid_events=\d+ token_delegated=yes capeff=0x0",
    skip_marker=r"CH24_SKIP",
    category="threat-model-subversion"),
```

The `proof_marker` requires `capeff=0x0`. That is the assertion: not "a BPF program loaded," but "a BPF program loaded from a caller with no effective capabilities." The `category="threat-model-subversion"` is new; other chapters are `real`, `illusion`, `observer`. This chapter is a subversion of the field manual's own opening assumption.
