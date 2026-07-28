# Ch24 -- BPF Token Delegation (The Token Hand-off)

**Category**: THREAT-MODEL SUBVERSION
**Primitive**: `BPF_TOKEN_CREATE` + bpffs `delegate_*` mount options (built with the new mount API) + `SCM_RIGHTS` fd passing + raw `BPF_MAP_CREATE`/`BPF_PROG_LOAD`/`BPF_RAW_TRACEPOINT_OPEN` with `token_fd` and `BPF_F_TOKEN_FD`
**Hook**: `SEC("raw_tp/sys_enter")` loaded by a host-unprivileged, user-namespace-confined process against a delegated token
**Architecture**: arch-independent. **Proven on Ubuntu 25.10, kernel `6.17.0-35-generic`, aarch64, with `kernel.unprivileged_bpf_disabled=2` (the stock hardened default).**

## What this demonstrates

A process that holds **no capabilities in the host (init) user namespace** loads
a BPF program and attaches it, using nothing but a BPF token fd handed to it over
a Unix socket. Without the token, the identical `BPF_MAP_CREATE` and
`BPF_PROG_LOAD` calls fail with `EPERM`.

The mechanism is the BPF token delegation feature added in Linux 6.9. It lets a
privileged component delegate a narrow slice of BPF capability to a confined
workload without giving that workload `CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN` on
the host -- and it keeps working even when unprivileged BPF is globally disabled
(`unprivileged_bpf_disabled=2`).

## Important corrections to the "obvious" mental model

Getting this to actually run forces several corrections to the naive
"privileged root server mints a token, unprivileged UID-1000 client uses it"
picture. All of the following were verified against the kernel source
(`kernel/bpf/{token,inode,syscall}.c`, v6.17) and by direct experiment:

1. **There is no `CONFIG_BPF_TOKEN`.** Token support is part of
   `CONFIG_BPF_SYSCALL` and is compiled into every modern kernel. The gate is a
   *runtime* one, not a build-time one. (A prior investigation that looked for
   `CONFIG_BPF_TOKEN=y` was chasing a config symbol that does not exist.)

2. **A token cannot be minted in the init user namespace.**
   `bpf_token_create()` contains `if (current_user_ns() == &init_user_ns) return
   -EOPNOTSUPP;`. Plain root therefore can *never* create a token. Tokens only
   make sense inside a non-init user namespace (i.e. a container).

3. **The bpffs must be owned by that same non-init userns**
   (`if (current_user_ns() != sb->s_user_ns) return -EPERM;`), yet the
   `delegate_*` mount options may only be *set* by a process with
   `CAP_SYS_ADMIN` in the **init** userns (the parser uses `capable()`, not
   `ns_capable()`). A single `mount(2)` can satisfy at most one of those two
   constraints, so the naive `mount -t bpf -o delegate_cmds=any` from inside a
   userns fails with `EPERM`. The filesystem must be built with the new mount
   API, split across the userns boundary:

   ```
   child  (userns X):  fs_fd = fsopen("bpf")                 # binds sb to X
   parent (init ns):   fsconfig(fs_fd, delegate_*, "any")    # needs init CAP_SYS_ADMIN
                       fsconfig(fs_fd, FSCONFIG_CMD_CREATE)   # instantiates sb (owned by X)
   child  (userns X):  mnt = fsmount(fs_fd)
                       bpffs_fd = openat(mnt, ".")            # fsmount fd itself -> EBADF
                       token = bpf_token_create(bpffs_fd)     # non-init + owns sb -> OK
   ```

4. **Using the token requires two things the naive code omits:**
   - The caller must be `ns_capable(token->userns, CAP_BPF)` -- i.e. it must live
     *inside* the delegating userns (it is "container root": full caps in X,
     zero caps on the host). It is **not** a UID-1000 `CapEff=0x0` process; such a
     process fails `bpf_token_capable()` and the token is rejected.
   - `map_flags`/`prog_flags` **must** include `BPF_F_TOKEN_FD`. libbpf's
     `.token_fd` opt does not set this automatically; without the flag the kernel
     ignores the token fd entirely and falls back to init-userns capability
     checks (which fail).

5. **Classic tracepoints cannot be used.** A `tp/syscalls/...` program can only be
   attached with `perf_event_open()` + `PERF_EVENT_IOC_SET_BPF`.
   `perf_event_open()` for a tracepoint is **not** covered by a BPF token; it
   needs `CAP_PERFMON` in the init userns and fails with `EACCES` for the confined
   caller. This PoC therefore uses a **raw** tracepoint, attached with the
   `BPF_RAW_TRACEPOINT_OPEN` bpf() command, which the token *does* delegate.

The chapter's threat-model point survives all of this intact -- and is arguably
sharper: an administrator who mounts a delegating bpffs is empowering every
process that can (a) enter the owning user namespace and (b) receive a token fd,
regardless of that process's host capabilities.

## What this does NOT do

- **Does not demonstrate a kernel bug.** The delegation feature is working
  exactly as specified. The novelty is the perimeter, not a flaw.
- **Does not use libbpf's `bpf_token_path` helper.** That helper opens a bpffs
  path and calls `BPF_TOKEN_CREATE` from the caller's own context. This PoC
  instead mints the token explicitly and passes the *fd* via `SCM_RIGHTS`, which
  is the delegation story the chapter is about.
- **Does not weaken the host.** It runs with `unprivileged_bpf_disabled=2` and
  AppArmor's `apparmor_restrict_unprivileged_userns=1` -- the Ubuntu defaults.
  No sysctl is changed.

## Prerequisites

- **Kernel >= 6.9** for `BPF_TOKEN_CREATE` and bpffs `delegate_*` options.
- **libbpf >= 1.4** for `bpf_map_create_opts.token_fd` /
  `bpf_prog_load_opts.token_fd`. (Proven with libbpf 1.6.2.)
- **glibc >= 2.36** for `fsopen`/`fsconfig`/`fsmount` wrappers (raw-syscall
  fallback is provided for older libc).
- `CONFIG_BPF_SYSCALL=y` (universal). No special kconfig is needed.
- The loader must start as **root** so its init-userns helper holds
  `CAP_SYS_ADMIN` to set the `delegate_*` options. Everything that touches BPF
  runs in a child user namespace with **no host capabilities**.
- Unprivileged user namespaces must be creatable (they are, by default, even
  with `apparmor_restrict_unprivileged_userns=1`, because the loader is started
  by root).

## Files

| File | Purpose |
|------|---------|
| `ch24-bpf-token-delegation.c`     | Integrated loader (`--run`). Forks an init-userns helper (materializes the delegate bpffs superblock), a userns-confined **minter** (`BPF_TOKEN_CREATE`), and a **consumer** that receives the token via `SCM_RIGHTS` and raw-loads map+prog with `token_fd` + `BPF_F_TOKEN_FD`. `--server`/`--client` are accepted as aliases. |
| `ch24-bpf-token-delegation.bpf.c` | Minimal `raw_tp/sys_enter` program filtering `getuid()`; one ringbuf map. |
| `Makefile`                        | Cross-compiles the BPF object (arm64 target) and links the loader against libbpf. |
| `trigger.sh`                      | Root preflight, runs the loader, parses the proof marker. |
| `smoke-test.sh`                   | Static verification (safe on macOS; does not build or run). |

## Architecture

Single invocation (`--run`, as root). Three cooperating processes:

```
top  (init userns, CAP_SYS_ADMIN)     HELPER
  |    recv fs_fd; fsconfig(delegate_*); FSCONFIG_CMD_CREATE; send ack
  |
  +-fork-> minter (userns X; container-root, host-unprivileged)   MINTER
  |          unshare(NEWUSER)+uid/gid maps+unshare(NEWNS)+private /
  |          fs_fd = fsopen("bpf"); send fs_fd to helper; recv ack
  |          mnt = fsmount(fs_fd); bpffs_fd = openat(mnt,".")
  |          token_fd = BPF_TOKEN_CREATE(bpffs_fd)     <-- real token
  |          getuid() x200 (generates events)
  |
  +--fork-> consumer (userns X; host-unprivileged)                CONSUMER
             recv token_fd via SCM_RIGHTS
             bpf_map_create(RINGBUF, .token_fd, map_flags|=BPF_F_TOKEN_FD)
             bpf_prog_load(RAW_TRACEPOINT, .token_fd, prog_flags|=BPF_F_TOKEN_FD)
             bpf_raw_tracepoint_open("sys_enter", prog_fd)
             ring_buffer__poll(); print CH24_PROVEN
```

Each `getuid()` anywhere on the system fires the raw tracepoint; the in-kernel
program filters on the syscall number and lands one ringbuf record per call. The
consumer counts them and emits the proof marker.

## Build & Run

```bash
cd dBPF-pocs/pocs/ch24-bpf-token-delegation
make
sudo bash trigger.sh
```

## Expected / actual output

Verified on Ubuntu 25.10, `6.17.0-35-generic`, aarch64:

```
[ch24-minter] userns self=user:[4026532465] init(pid1)= non_init=yes
[ch24-helper] delegate bpffs superblock created (owning userns = minter's)
[ch24-minter] minted real bpf token_fd=6
[ch24-minter] handing token to consumer via SCM_RIGHTS
[ch24-consumer] uid=0 euid=0 CapEff=0x1ffffffffff (host-unprivileged: no caps in init userns)
[ch24-consumer] received delegated token_fd=3 via SCM_RIGHTS
[ch24-consumer] created ringbuf map fd=6 via delegated token
[ch24-consumer] relocated 1 map-fd placeholder(s)
[ch24-consumer] loaded raw_tp program fd=8 via delegated token
[ch24-consumer] attached raw tracepoint 'sys_enter' link_fd=9
CH24_PROVEN uid_events=40 token_delegated=yes capeff=0x1ffffffffff
=== CH24_PROVEN uid_events=40 token_delegated=yes ===
```

`CapEff=0x1ffffffffff` is the full capability set **within user namespace X only**
-- the process has **zero** capabilities in the host/init user namespace. The
same map/prog load calls issued without the token (or without `BPF_F_TOKEN_FD`)
return `EPERM`, which is what makes the token load-bearing.

## Detection

- **audit `bpf(2)` records** (`auditctl -a always,exit -F arch=b64 -S bpf`) show
  `BPF_MAP_CREATE`/`BPF_PROG_LOAD` with the `BPF_F_TOKEN_FD` flag set and a
  non-zero `*_token_fd`, issued from a task whose init-userns capabilities are
  empty. Capability-inventory tooling misses this entirely.
- **The bpffs mount itself.** A bpffs mounted with `delegate_*` options is the
  root enabler. Enumerate via `findmnt -t bpf -o TARGET,OPTIONS` or
  `grep bpf /proc/self/mountinfo` (note: a *detached* `fsmount` mount, as used
  here, may not appear in a host mount table -- inspect the owning userns).
- **`bpftool token list`** / `BPF_TOKEN_GET_INFO` exposes a live token's
  `allowed_cmds`/`allowed_maps`/`allowed_progs`/`allowed_attachs` bitmasks;
  compare against the mount's declared delegation policy. A token with
  `allowed_* = 0xffffffffffffffff` corresponds to `delegate_*=any`.
- **`SCM_RIGHTS` fd passes** between processes are the covert channel for the
  hand-off; socket-level audit at sender or receiver is the only reliable
  ingress control.

## Mitigation

- **Never mount bpffs with `delegate_*=any`.** Delegate exactly the cmds/maps/
  progs/attachs the workload needs (e.g.
  `delegate_cmds=prog_load:map_create:raw_tracepoint_open`,
  `delegate_progs=raw_tracepoint`, `delegate_maps=ringbuf`).
- **Scope the delegating bpffs to the runtime that needs it**, and unmount it
  when idle. Pre-existing tokens keep their snapshot, but no new ones can be
  minted once the mount is gone.
- **Treat any process that can enter the delegating user namespace as
  BPF-capable**, regardless of its host capability set.
- **Audit `SCM_RIGHTS`** on sockets exposed by token-minting daemons.

## Proof

On Ubuntu 25.10 kernel `6.17.0-35-generic` (aarch64), with the stock
`unprivileged_bpf_disabled=2`, a user-namespace-confined process holding no host
capabilities minted a real BPF token (`BPF_TOKEN_CREATE`), delegated it via
`SCM_RIGHTS`, and used it to load and attach a raw tracepoint that observed 40
`getuid()` events:

```
=== CH24_PROVEN uid_events=40 token_delegated=yes ===
```

## Related chapters

- Chapter 18 uses a bpf_token superficially. Chapter 24 is the deep dive on the
  delegation machinery.
- Chapter 22 (defender playbook) lists capability inventory as a defense. This
  chapter is precisely why that defense is insufficient against fd-based token
  delegation.
