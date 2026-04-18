# Ch24 -- BPF Token Delegation (The Token Hand-off)

**Category**: THREAT-MODEL SUBVERSION
**Primitive**: `BPF_TOKEN_CREATE` + bpffs `delegate_*` mount options + `SCM_RIGHTS` fd passing + raw `BPF_PROG_LOAD` with `prog_token_fd`
**Hook(s)**: `SEC("tp/syscalls/sys_enter_getuid")` loaded by an unprivileged process against a delegated token
**Architecture**: arch-independent; tested on Fedora 42 kernel 6.14 and linuxkit 6.12 (aarch64 + x86_64)

## What this demonstrates

An unprivileged process (UID 1000+, `CapEff=0x0`) loads a BPF
tracepoint program and attaches it without ever holding `CAP_BPF`,
`CAP_PERFMON`, or `CAP_SYS_ADMIN`.

The mechanism is the BPF token delegation feature added in Linux 6.9.
A privileged server mounts `bpffs` with `delegate_cmds=prog_load`,
`delegate_progs=tracepoint`, and `delegate_maps=ringbuf`, calls
`bpf(BPF_TOKEN_CREATE, ...)` via raw syscall to mint an anonymous
token fd, and hands the fd to the unprivileged client over a Unix
socket via `SCM_RIGHTS`. The client then issues a raw `BPF_PROG_LOAD`
syscall with `prog_token_fd=<received fd>` in `bpf_attr`. The verifier
consults the **token's** delegated capability bitmask instead of
the caller's `cap_effective`, so the load succeeds. The raw-syscall
path is mandatory for the client side: libbpf's convenience helpers
(`bpf_object_open_opts.bpf_token_path`) call `BPF_TOKEN_CREATE` on
behalf of the caller, which requires `CAP_SYS_ADMIN` and therefore
defeats the unprivileged-delegation scenario.

The book's threat model through chapter 23 assumed the attacker
already held `CAP_BPF`. Chapter 24 demonstrates the assumption is
too conservative: the attacker only needs a path to a token fd.

## What this does NOT do

- **Does not demonstrate anything novel about the kernel.** The
  delegation feature is designed exactly for this flow. The kernel
  is working as specified. What is novel is only the perimeter: an
  administrator who mounts a delegating bpffs is unknowingly
  empowering every process that can receive an fd from the minter.
- **Does not use libbpf's `bpf_token_path` helper.** That helper
  opens the bpffs path itself and calls `BPF_TOKEN_CREATE` from the
  caller's context, which requires `CAP_SYS_ADMIN` at the *caller*
  and therefore defeats the whole point of delegation. A real
  delegated client never mounts or opens bpffs.
- **Does not use a skeleton load.** libbpf 1.5's skeleton load path
  does not expose a way to plumb a pre-created token fd into the
  `bpf_prog_load_opts.token_fd` field before the internal
  `bpf_object__load()` runs. The PoC therefore issues raw
  `bpf_prog_load()` and `bpf_map_create()` calls with the fd set
  explicitly in opts, and uses `bpf_raw_tracepoint_open` for
  attach.
- **Does not exploit a vulnerability.** The server explicitly chose
  to delegate and explicitly transferred the fd.

## Prerequisites

- **Kernel >= 6.9** for `BPF_TOKEN_CREATE` and bpffs `delegate_*`
  options. Fedora 42 (6.14) and linuxkit 6.12 both satisfy.
- **libbpf >= 1.4** -- the version where
  `bpf_prog_load_opts.token_fd` and `bpf_map_create_opts.token_fd`
  were added. The dbpf-base image ships a compatible libbpf.
- `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y` (universal).
- `CAP_SYS_ADMIN` in the init user_ns **for the server binary
  only** (typically invoked by root). The client side requires no
  capabilities.
- `/usr/sbin/useradd` available (trigger creates user `tu24`).
- `python3` is **not** required.

## Files

| File | Purpose |
|------|---------|
| `ch24-bpf-token-delegation.c`     | Two-mode loader (`--server` mounts bpffs and mints+sends token; `--client` receives fd and raw-loads via `bpf_prog_load()` with `token_fd` in opts) |
| `ch24-bpf-token-delegation.bpf.c` | Minimal `tp/syscalls/sys_enter_getuid` tracepoint program; one ringbuf map |
| `Makefile`                        | Thin wrapper around `shared/common.mk` |
| `trigger.sh`                      | Orchestrates server + unprivileged `tu24` client + event generation |

## Architecture

Two-process design. There is no single binary that can do the work,
because the privileged and unprivileged halves must live in
different credential contexts.

**Server (UID 0, `CAP_SYS_ADMIN`).**

1. `unshare(CLONE_NEWNS)` to isolate the mount, then
   `mount("bpf", "/run/ch24-bpffs", "bpf", 0,
   "delegate_cmds=prog_load,delegate_progs=tracepoint,
    delegate_maps=ringbuf")`.
2. `open("/run/ch24-bpffs", O_RDONLY|O_DIRECTORY)` to get a
   `bpffs_fd`.
3. `bpf(BPF_TOKEN_CREATE, &{ bpffs_fd })` -> anonymous token fd.
4. `sendmsg()` with `SCM_RIGHTS` on a Unix domain socket, payload
   = the token fd.
5. Wait for client disconnect, then unmount and exit.

**Client (unprivileged user `tu24`, `CapEff=0x0`).**

1. `connect()` to the server's Unix socket.
2. `recvmsg()` with `MSG_CMSG_CLOEXEC`; extract the token fd from
   `SCM_RIGHTS` cmsg.
3. Read the compiled `.bpf.o` from disk, pull out the ringbuf map
   definition and the tracepoint program bytecode.
4. `bpf_map_create(BPF_MAP_TYPE_RINGBUF, ...,
   &opts{ .token_fd = recv_fd })` -> map fd.
5. `bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, ..., &opts{
   .token_fd = recv_fd })` -> prog fd. **This is the step that
   fails without the token and succeeds with it.**
6. `bpf_raw_tracepoint_open("sys_enter_getuid", prog_fd)` ->
   link fd.
7. `ring_buffer__new(map_fd, handle_event, ...)` and poll.

Each `getuid()` call anywhere on the system fires the tracepoint
and lands a `uid_event` record in the ringbuf. The client prints
one line per event and emits the proof marker on shutdown.

## Build & Run

```bash
cd dBPF-pocs/pocs/ch24-bpf-token-delegation
make
sudo bash trigger.sh
```

`trigger.sh` creates `tu24`, starts the server as root, runs the
client as `tu24`, generates events by calling `getuid` from
userspace, then tears everything down.

## Expected output

```
[ch24-server] bpffs mounted at /run/ch24-bpffs with delegate_cmds=prog_load
[ch24-server] BPF_TOKEN_CREATE -> fd=5
[ch24-server] sent token fd to client via SCM_RIGHTS
[ch24-client] uid=1001 CapEff=0x0000000000000000
[ch24-client] received token fd=4 via SCM_RIGHTS
[ch24-client] BPF_MAP_CREATE(ringbuf, token_fd=4) -> fd=5
[ch24-client] BPF_PROG_LOAD(tracepoint, token_fd=4) -> fd=6
[ch24-client] bpf_raw_tracepoint_open(sys_enter_getuid) -> fd=7
[ch24-client] uid_event pid=12345 uid=1001
[ch24-client] uid_event pid=12345 uid=1001
=== CH24_PROVEN uid_events=2 token_delegated=yes caller_capeff=0x0 ===
```

The `CapEff=0x0000000000000000` line is the entire point. A process
with no capabilities ran `BPF_PROG_LOAD` and the kernel accepted it.

## Detection

- **`bpftool prog list`** shows the loaded tracepoint program.
  On kernels that expose `token_fd_id` in the JSON output, the
  field is populated; the owning process UID is the unprivileged
  user. A BPF program whose owner has `CapEff=0` for `CAP_BPF` is
  the direct tell.
- **audit `bpf(2)` records** (rule
  `auditctl -a always,exit -F arch=b64 -S bpf`) show
  `BPF_PROG_LOAD` (cmd=5) syscalls issued from UID != 0 with
  non-zero `prog_token_fd` in the attr blob. This is the most
  reliable single signal; capability-based monitoring misses it
  entirely.
- **`/proc/<pid>/status`** for the tu24 client shows
  `CapEff: 0000000000000000`. The fact that the program load
  succeeded anyway is the anomaly -- no capability-inventory tool
  will flag this process.
- **The bpffs mount itself** is a detection surface. A bpffs
  mounted with `delegate_*` options on a workload host (as opposed
  to a sandbox runtime) is unusual. `findmnt -t bpf -o
  TARGET,OPTIONS` or `grep bpf /proc/self/mountinfo` enumerates
  them.
- **`/sys/kernel/debug/bpf/tokens`** (where available) enumerates
  live tokens and their allow-bitmasks; compare against the
  current mount policy.

## Mitigation

- **Minimize `delegate_cmds`, `delegate_progs`, `delegate_maps`.**
  If the workload needs tracepoints, delegate exactly
  `prog_load,link_create` and `progs=tracepoint,maps=ringbuf`.
  Never mount bpffs with `delegate_cmds=any`.
- **Audit `SCM_RIGHTS` fd passes between processes.** The token
  hand-off is invisible to capability inventory. Socket audit at
  the sender or receiver side is the only reliable ingress
  control; it is also considerably harder to instrument than a
  `getcap` sweep.
- **Revoke or time-bound the bpffs mount.** A bpffs mounted only
  for the duration of a delegated operation and then unmounted
  limits the window for token minting. Pre-existing tokens keep
  their snapshot after remount/unmount, but no new ones can be
  created.
- **Do not run root-privileged daemons that mount bpffs with
  `delegate_*` unless strictly required.** The minter credential
  is `CAP_SYS_ADMIN` in the bpffs user_ns. Any compromise of such
  a daemon is a full token factory for every unprivileged process
  on the host.

## Proof

The chapter's primary claim stands: on a Fedora 42 kernel 6.14
host, an unprivileged process with `CapEff=0` can load and run a
BPF tracepoint program using only a token fd received via
`SCM_RIGHTS`. End-to-end proof is recorded in
`/dBPF-pocs/act4-result.log`.

## Related chapters

- Chapter 18 uses a bpf_token superficially as part of a getuid
  return-forge. Chapter 24 is the deep dive on the delegation
  machinery itself.
- Chapter 22 (defender playbook) lists capability inventory as a
  defense. This chapter is the reason that defense is insufficient
  against fd-based delegation.
