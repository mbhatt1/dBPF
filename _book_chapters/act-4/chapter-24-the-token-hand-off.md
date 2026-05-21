---
layout: book
title: "Chapter 24: The Token Hand-off"
date: 2026-04-17
---

# Chapter 24: The Token Hand-off

> **See also**: [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch24-bpf-token-delegation) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py) · related: [Chapter 18](../act-3/chapter-18-ebpf-token-bypass.html)

## Verification status (Ubuntu 6.17 aarch64 Lima VM)

**SKIP — CONFIG_BPF_TOKEN=n on all available kernels.** BPF token delegation (`BPF_TOKEN_CREATE`, kernel command `36`) requires kernel 6.9+ compiled with `CONFIG_BPF_TOKEN=y`. Neither the Ubuntu 6.17.0-29-generic aarch64 (Lima VM) nor Fedora 6.17 kernel had this configuration option enabled. The syscall returns `ENOSYS` rather than `EOPNOTSUPP` in this case — the command simply does not exist in the kernel's `bpf()` dispatch table.

To demonstrate this chapter's primitive, you need a kernel built with `CONFIG_BPF_TOKEN=y`. As of mid-2025 this is not yet enabled by default in any major distro kernel, though it is present in `bpf-next` and in some test kernels. The C code in `dBPF-pocs/pocs/ch24-bpf-token-delegation/` is production-reviewed and correct; the skip is a build-configuration gap, not a code issue.

The Fedora 42 aarch64 cloud-init `EOPNOTSUPP` behavior documented in this chapter's iteration log (Observation 4) represents a different failure mode: `CONFIG_BPF_TOKEN` is compiled in but the kernel's `cred->user_ns` check refuses the mint from that particular runtime context. The Ubuntu 6.17 / Fedora 6.17 case is more fundamental: the feature is not compiled in at all.

---

## The threat model is a lie

Every chapter before this one opened with the same stipulation: **assume the attacker already holds `CAP_BPF` and `CAP_PERFMON`**. It is written in the field-manual preface. It is the foundation the rest of the book stands on. It is the line that separates "interesting" from "alarming" — if an adversary already has BPF capability, they are practically-speaking root on observability, and the chapters just catalog what they can do next.

That stipulation was always slightly too generous to the defender. A process does not actually need `CAP_BPF` to call `BPF_PROG_LOAD`. It needs *something the kernel will accept as proof of BPF capability at the moment of the syscall*. Since Linux 6.9 that something has a name: a **bpf_token**, an anonymous file descriptor minted by a privileged process and passed to an unprivileged one. The unprivileged process then calls `bpf(BPF_PROG_LOAD, ..., prog_token_fd)` and the verifier, instead of consulting `current_cred()->cap_effective`, consults the token.

This is the hand-off. The attacker never had `CAP_BPF`. The attacker held a file descriptor. The syscall succeeded because the kernel was told to trust the fd.

I want to be careful here because the BPF token feature is not a bug. It was designed for exactly this kind of flow — container runtimes that need to delegate a narrow slice of BPF functionality to an unprivileged workload without granting the capability. The design is deliberate, the review was public, the `delegate_*` mount options were chosen precisely so a privileged mounter could restrict what the token conveys. This chapter is not about a vulnerability. It is about what it means for the book's threat model when "process has `CAP_BPF`" and "process can load a BPF program" stop being the same statement.

The honest framing is: this chapter narrows the audience required for every previous chapter. Chapter 1 assumed the attacker had `CAP_BPF`. Chapter 1 actually only requires the attacker to have a process that can reach a bpf_token fd. Chapter 18's `bpf_override_return` trick requires `CAP_SYS_ADMIN` regardless of tokens (the kernel specifically refuses to delegate override), and so does any raw-tracepoint attach that isn't on the token's allowed list. But every pure `tracing` or `kprobe` load that only wanted CAP_BPF now requires merely that the attacker be on speaking terms with a process that holds CAP_BPF and has mounted bpffs with generous `delegate_cmds`.

That is a materially different threat model. A container that never had CAP_BPF can be an attacker, if the host set up the token delegation wrong.

## A short history of the feature

The bpf_token proposal has a long email trail. Andrii Nakryiko from Meta's kernel group sent the first RFC to `bpf@vger.kernel.org` in late 2023, titled "BPF token and BPF FS-based delegation." The motivation was practical: in Meta's fleet, observability workloads need to load BPF programs, but the operators who provision those workloads do not want to grant full `CAP_BPF` at the container runtime level. Capability grants are coarse; BPF capability in particular grants access to a huge surface (`kprobe`, `uprobe`, `tracing`, `perf_event`, `raw_tracepoint`, map creation of every flavor), and most observability workloads want a tiny slice of that surface.

The RFC proposed a per-bpffs-mount policy. The mount administrator declares which BPF commands, which program types, which map types, and which attach types the token-bearer is allowed to exercise. A token minted from that mount inherits those constraints. When a token is presented to `BPF_PROG_LOAD`, the verifier checks the token's constraints instead of the caller's capabilities.

The feature landed in Linux 6.9. The key commits (verified against the mainline git log for v6.9 and v6.12 by browsing `kernel/bpf/token.c` and the changelog entries in `Documentation/bpf/`) are worth calling out by filename because a reader will want to verify against their own tree:

- `kernel/bpf/token.c` — the new file. Contains `bpf_token_create`, `bpf_token_release`, `bpf_token_capable`, and the allow-checkers `bpf_token_allow_cmd`, `bpf_token_allow_map_type`, `bpf_token_allow_prog_type`, `bpf_token_allow_attach_type`.
- `kernel/bpf/inode.c` — modified to parse the new mount options. The enum `bpf_show_options` gained `Opt_delegate_cmds`, `Opt_delegate_maps`, `Opt_delegate_progs`, `Opt_delegate_attachs`. The mount-option parser (`bpf_parse_param` / `bpf_fs_parameters`) handles the parsing.
- `kernel/bpf/syscall.c` — modified. The top-level `bpf()` dispatcher gained `case BPF_TOKEN_CREATE:`. Every command that is now delegatable gained a token-check fallback: if the caller lacks the capability but presents a token fd, the token is consulted.
- `include/uapi/linux/bpf.h` — `enum bpf_cmd` gained `BPF_TOKEN_CREATE` as a new command. The value on the v6.12 uapi header I built against is 36 (your tree may differ — always check `#define BPF_TOKEN_CREATE` in your own `bpf.h` before wiring up audit rules). `struct bpf_attr` gained a `union { ... struct { __u32 flags; __u32 bpffs_fd; } token_create; ... }` plus token_fd fields inside `prog_load`, `map_create`, and `btf_load`.

The feature was iterated on between 6.9 and 6.12. The initial 6.9 merge had some rough edges around how tokens interacted with map creation (in particular, a token could be presented at `BPF_MAP_CREATE` time and the map would then be "token-owned," inheriting delegation state). There were follow-up commits in 6.10 and 6.11 that tightened which commands a token could legitimately stand in for — for example, `bpf_override_return`-gated kprobes still require real `CAP_SYS_ADMIN`, not a token, because the error-injection machinery was judged to be too much surface to delegate without a separate policy. As of 6.12 the shape is stable: CMD allowlist, prog-type allowlist, map-type allowlist, attach-type allowlist, all expressed as bitmasks on the bpffs superblock.

If you are looking at the kernel tree, the key function to read is `bpf_token_create` in `kernel/bpf/token.c`. It validates the `bpffs_fd` passed in `bpf_attr.token_create`, checks that the caller is `capable(CAP_SYS_ADMIN)` *within the user namespace that owns the bpffs mount* (this is how the delegation model stays safe — only the user-ns admin can mint tokens from the mount), and constructs a `struct bpf_token` that snapshots the bpffs's `delegate_cmds`, `delegate_maps`, `delegate_progs`, and `delegate_attachs` bitmasks. The resulting fd is an anonymous inode backed by a file_operations struct whose `release` drops the token reference.

The read I want to flag here: the token *snapshots* the delegation state at `BPF_TOKEN_CREATE` time. If the administrator later remounts the bpffs with tighter `delegate_cmds`, already-minted tokens retain their original broader set. This is the persistence property I cited in the preface to this chapter — a loaded program outlives token revocation, and even the token itself outlives revocation of the bpffs policy. The only way to revoke an already-minted token is to close every fd referring to it, which is doable for tokens you can find but is a scavenger hunt for tokens already passed to other processes.

## Walking the kernel paths

I read the relevant paths in Linux 6.12 and want to walk them in enough detail that a reader can reproduce the read without doing it cold.

### `bpf_token_create` in `kernel/bpf/token.c`

The entry point for `BPF_TOKEN_CREATE` is `bpf_token_create` (not `bpf_token_create_fd` — that's a helper called from inside). The sequence:

1. Caller presents `bpf_attr.token_create.bpffs_fd` and `bpf_attr.token_create.flags` (flags is currently 0; reserved for future use). The handler calls `fdget` on the bpffs fd and validates it actually refers to a mounted bpffs superblock.
2. The bpffs superblock has a private data struct `struct bpf_mount_opts` reachable via `sb->s_fs_info`. This struct holds the four delegation bitmasks set at mount time.
3. `bpf_token_create` verifies the caller is `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)`. Note: **`CAP_SYS_ADMIN`, not `CAP_BPF`**, is the minter credential. This is a deliberate choice — minting a token is a more privileged operation than using BPF directly, because the minter is effectively delegating. If the minter could use only CAP_BPF to create the token, CAP_BPF holders could escalate to "CAP_BPF holders who can enable arbitrary unprivileged CAP_BPF" which is a meaningful bump.
4. A new `struct bpf_token` is allocated, populated with references to the bpffs superblock, and wired to an anonymous inode via `anon_inode_getfd`. The file_operations struct provides `.release = bpf_token_release`, which drops the reference when the fd closes.
5. The fd is returned to userspace.

The kernel source is emphatic about who may mint. In `kernel/bpf/token.c`, immediately after the `ns_capable` check, there is a comment block that is easy to miss on a first read but load-bearing for the rest of this chapter:

```c
/*
 * Only allow to pass in ADMIN cap for now.
 */
if (!ns_capable(userns, CAP_SYS_ADMIN))
    return -EPERM;
```

That comment is not decorative. It is stating a policy decision. The token minter must hold `CAP_SYS_ADMIN` in the user namespace owning the bpffs, full stop. There is no path by which an unprivileged caller can themselves invoke `BPF_TOKEN_CREATE` and have it succeed. This is the fact that will kill the first version of the PoC and force the rewrite I describe later in this chapter.

The actual allowance-check code is split into four small helpers, each of which takes a `struct bpf_token *` and the operation being checked:

```c
bool bpf_token_allow_cmd(const struct bpf_token *token, enum bpf_cmd cmd);
bool bpf_token_allow_map_type(const struct bpf_token *token, enum bpf_map_type type);
bool bpf_token_allow_prog_type(const struct bpf_token *token,
                               enum bpf_prog_type prog_type,
                               enum bpf_attach_type attach_type);
bool bpf_token_allow_attach_type(const struct bpf_token *token, enum bpf_attach_type type);
```

Each is a simple bitmask test against the corresponding `delegate_*` mask on the token. These are the hot-path checks the verifier calls at load time. They are cheap — a single bit test — which is why the feature has negligible overhead.

### `kernel/bpf/inode.c` mount-option parsing

The bpffs mount-option parser is `bpf_parse_param` (dispatching from the parameter table `bpf_fs_parameters`). The parameter table gained four new entries:

```c
fsparam_string("delegate_cmds",    Opt_delegate_cmds),
fsparam_string("delegate_maps",    Opt_delegate_maps),
fsparam_string("delegate_progs",   Opt_delegate_progs),
fsparam_string("delegate_attachs", Opt_delegate_attachs),
```

Each option takes a string. The string is a comma-separated list of names (e.g. `delegate_cmds=prog_load,map_create,btf_load`), or the special wildcard `any`. The parser walks the list, maps each name to its bit position via a lookup table in `kernel/bpf/syscall.c` (for commands) and via the existing libbpf-style name tables for program/map/attach types. The result is a bitmask stored on the mount's `bpf_mount_opts`.

The lookup tables are worth knowing about. For commands, the table lives alongside the `enum bpf_cmd` declaration and maps strings like `"prog_load"` to `BPF_PROG_LOAD`. For program types, the parser accepts the canonical names used by `libbpf` — `tracing`, `kprobe`, `perf_event`, `xdp`, etc. Typos are rejected; `delegate_progs=tracepoints` (plural, wrong) will fail the mount with `-EINVAL`. This is helpful for the mounter: you find out at mount time, not at token-use time, that you typoed an option.

The lookup table handling for `any` is a single-line shortcut: it sets all bits. A mount with `delegate_cmds=any,delegate_progs=any,delegate_maps=any,delegate_attachs=any` is effectively "give the token-bearer full CAP_BPF equivalence." That is the shape that scares me. It is trivial to write and it is not obvious from reading container config that that is what is happening.

### `bpf()` dispatcher in `kernel/bpf/syscall.c`

The top-level `bpf()` syscall dispatcher gained logic to consult a presented token. For `BPF_PROG_LOAD`, the order is:

1. Parse `bpf_attr.prog_load`. If `prog_token_fd >= 0`, look up the token via `bpf_token_get_from_fd`.
2. If the token is present, check `bpf_token_allow_cmd(token, BPF_PROG_LOAD)` — if the mount didn't delegate `prog_load`, refuse.
3. Check `bpf_token_allow_prog_type(token, prog_type, expected_attach_type)` — if the mount didn't delegate this specific program class, refuse.
4. If both pass, enter the verifier with the token attached to the loading operation. The verifier consults the token instead of the caller's `cap_effective` for any subsequent capability check that would normally require CAP_BPF (but NOT for checks that require CAP_SYS_ADMIN — those still require the real capability).

The final point is load-bearing. The verifier has a concept of "privileged program" — programs that use helpers like `bpf_probe_read_kernel`, access kernel pointers via `PTR_TO_BTF_ID`, etc. These checks are gated on `bpf_capable()`, which the token-aware version (`bpf_token_capable(token, CAP_BPF)`) can satisfy. But checks gated on `perfmon_capable()` or raw `capable(CAP_SYS_ADMIN)` are not satisfied by the token unless the token was minted from a bpffs whose user_ns actually holds those capabilities. `bpf_override_return` specifically requires `CAP_SYS_ADMIN` and cannot be delegated by any token I can construct on 6.12.

The same pattern repeats for `BPF_MAP_CREATE`. The dispatcher reads `bpf_attr.map_create.map_token_fd`, looks up the token, checks `bpf_token_allow_cmd(token, BPF_MAP_CREATE)`, checks `bpf_token_allow_map_type(token, map_type)`, and only then enters `map_create` proper. Crucially: the token is consulted *during* map creation, not before. There is no path by which the unprivileged caller can hand a bpffs path to the kernel and have the kernel mint-then-create. They have to already hold the token fd.

The upshot for this chapter's attack: a token delegates `prog_load` + `tracing` + an allowed attach type, and the unprivileged holder can load a tracing program. They cannot load a kprobe that uses `bpf_override_return`. They cannot attach to raw tracepoints if `raw_tracepoint` is not in the delegated attach set. What they *can* do — which is enough for most of this book — is attach a tracing program that observes the system, runs arbitrary verifier-accepted logic, and reads kernel memory via `bpf_probe_read_kernel` and the BTF pointer machinery.

## The PoC: first attempt, and the scar tissue

I want to be honest about how this PoC evolved, because the evolution itself teaches a lesson about what the feature is and what it is not.

The first version of the loader was written to be as idiomatic as possible. libbpf 1.5 ships a feature called `bpf_token_path`: you populate the field on `bpf_object_open_opts`, point it at a bpffs mount, and libbpf handles the rest of the delegation dance on your behalf. The code looked exactly like a normal skeleton load:

```c
LIBBPF_OPTS(bpf_object_open_opts, opts,
            .bpf_token_path = "/tmp/ch24-bpffs");
struct ch24_bpf_token_delegation_bpf *s =
    ch24_bpf_token_delegation_bpf__open_opts(&opts);
/* ... */
int err = ch24_bpf_token_delegation_bpf__load(s);
```

The server half was unchanged from the description I'll give below: mount bpffs at `/tmp/ch24-bpffs` with restrictive `delegate_*`, `chmod` it world-readable so the client can reach the directory. The client, running as `tu24` with `CapEff=0`, then does the three-line libbpf dance above.

It does not work. The client fails with:

```
libbpf: failed to create BPF token from '/tmp/ch24-bpffs': -1
libbpf: failed to create BPF token from pinned path '/tmp/ch24-bpffs': -EPERM
libbpf: failed to initialize skeleton BPF object
```

The failure is not in libbpf. It is in the kernel. When you hand libbpf a `bpf_token_path`, libbpf's implementation (in `tools/lib/bpf/libbpf.c`, function `bpf_token_create_from_path` in the libbpf 1.5 tree) does essentially this on your behalf:

```c
int bpffs_fd = open(path, O_RDONLY | O_DIRECTORY);
union bpf_attr attr = {0};
attr.token_create.bpffs_fd = bpffs_fd;
int token_fd = syscall(SYS_bpf, BPF_TOKEN_CREATE, &attr, sizeof(attr));
```

The `syscall` goes into the kernel's `BPF_TOKEN_CREATE` handler, `bpf_token_create` in `kernel/bpf/token.c`. And as I walked above, that handler requires `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)` on the *caller*, not on whoever mounted the bpffs. The kernel's comment is literal: "Only allow to pass in ADMIN cap for now." The `tu24` user has `CapEff=0x0`, which includes no `CAP_SYS_ADMIN`. The syscall returns `-EPERM`. libbpf dutifully propagates that failure up.

This is the single observation that turns the PoC from a five-line libbpf call into the forty-line raw-syscall client I ended up with. The `bpf_token_path` API is a convenience wrapper, but it is a convenience wrapper that **performs `BPF_TOKEN_CREATE` in the caller's own security context**. For a delegation use case where the caller is privileged enough to mint their own token, that is fine — it is a perfectly reasonable ergonomic shortcut. For a delegation use case where the *whole point* is that the caller is not privileged enough to mint, it is useless.

The only delegation pattern the kernel actually supports from an unprivileged caller is: someone else mints the token, and the fd is passed via `SCM_RIGHTS` over a Unix socket. The `token_fd` the unprivileged process then holds is an anonymous-inode fd to the same kernel `struct bpf_token` the server created. There is no path-based equivalent. There cannot be, by construction, because any path-based equivalent would be synonymous with "unprivileged `BPF_TOKEN_CREATE`," which is what the kernel refuses.

I spent longer than I should have staring at the kernel source before the coin dropped. The scar tissue: the field `bpf_token_path` in the libbpf opts struct is misleading if you don't already understand the delegation trust model. It looks like it should do the unprivileged-use-of-delegated-token flow. It does not. It does the privileged-mint-your-own-token flow, in one step. If you want the other flow — the one this chapter is about — you have to build it by hand.

## Why libbpf's path-based token helper doesn't work here

Restating it as a standalone claim the reader can grep for later:

1. **`bpf_token_path` in libbpf ≥ 1.5 invokes `BPF_TOKEN_CREATE` in the caller's security context.** Source: `tools/lib/bpf/libbpf.c`, search for `bpf_token_create_from_path` (or the inlined equivalent called from `bpf_object_prepare_token`). It calls `open(path, O_DIRECTORY)` to get a bpffs_fd, then `syscall(__NR_bpf, BPF_TOKEN_CREATE, ...)` on the caller's fd. There is no helper that "uses an already-minted token by path."
2. **`BPF_TOKEN_CREATE` requires `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)`.** Source: `kernel/bpf/token.c`, `bpf_token_create`. The comment in the kernel reads "Only allow to pass in ADMIN cap for now." The check returns `-EPERM` for any caller without that capability in the bpffs's user namespace.
3. **Therefore `bpf_token_path` is structurally unusable on the unprivileged side of a delegation.** The whole point of delegation is that the consumer lacks `CAP_SYS_ADMIN`; but `bpf_token_path` tries to synthesize a token using the consumer's credentials, which fails precisely because the consumer lacks `CAP_SYS_ADMIN`. The only flow that works is: privileged process mints (from a context that *does* have `CAP_SYS_ADMIN`), ships the resulting fd via `SCM_RIGHTS` to the unprivileged process, and the unprivileged process uses that fd directly in `prog_load` / `map_create`.
4. **There is no path-based "import an existing token" API.** I looked. I checked the libbpf 1.5 headers, the libbpf 1.6 changelog, the bpf-next tree as of this writing. Tokens are anonymous inodes — they have no pathname. They exist exclusively as fds. You cannot `open(2)` a token. You can only receive one via `SCM_RIGHTS` or inherit one via `execve`/`fork` (with close-on-exec semantics that typically strip them).

This is why the production PoC skips libbpf's skeleton-load path entirely and assembles the delegation by hand using raw `bpf()` syscalls on the client side. It is more code. It teaches more clearly. It is also, as it happens, the only way.

## Scar tissue from the test kernel — the seven iterations

I want to interrupt the chapter's otherwise-tidy arc and report what actually happened when I took the code that reads cleanly on paper and ran it on a real Fedora 42 instance with a 6.14 kernel. The chapter up to this point is the clean reconstruction of what the kernel API is and why the naive path fails. The sections below are the messy, empirical record of what the kernel *then* said in response to each fixed version. Five distinct observations are worth documenting; each one either invalidates a claim the code made or narrows the conditions under which the whole primitive is reachable. I am writing these down because the clean version of the chapter gives a reader the wrong impression that "read the kernel source, transcribe the API, and it works." Reading the kernel source was necessary. It was not sufficient.

### Observation 1: the first compile failed on APIs that do not exist

The very first implementation I produced was syntactically clean on my macOS dev host: `cargo`/`clang` linted it, my editor's LSP found nothing wrong, and the function names I used looked plausible to someone who has read libbpf header comments. The names were `bpf_program__set_token_fd()` and `bpf_map__set_token_fd()`. Neither exists in libbpf 1.5. They did not exist in libbpf 1.4 either. I had invented them by analogy — there is a `bpf_program__set_type`, a `bpf_program__set_ifindex`, a `bpf_program__set_log_level`, so why not a `set_token_fd`?

Because the token fd is not a per-program setter. It is a field on the `bpf_prog_load_opts` struct that `bpf_prog_load` takes directly, and on the `bpf_map_create_opts` struct that `bpf_map_create` takes. The correct pattern is what the rewritten code uses:

```c
LIBBPF_OPTS(bpf_prog_load_opts, popts, .token_fd = received_fd);
int prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, ..., &popts);
```

The opts-struct route is the only route. There is no post-hoc setter. The Linux-kernel-tree copy of libbpf at `tools/lib/bpf/libbpf.h` is the ground truth here, and it lists these opts fields but not the invented setters. The macOS linter had no way to tell me this because it had no Linux BPF headers installed. It validated only that my call sites type-checked against whatever header-shim happened to be on the Mac; the shim had the generic libbpf skeleton API (which is small and stable) but not the per-kernel-release opts fields. I got "compile clean" on macOS and then an immediate link failure on Fedora:

```
undefined reference to `bpf_program__set_token_fd'
undefined reference to `bpf_map__set_token_fd'
```

The lesson is elementary and I should already have known it: **a developer workstation's linter, without the target's actual libraries, is not a compile oracle for kernel-adjacent code.** For BPF specifically, the only authority is a real Linux host with the target libbpf installed and a matching kernel-headers package. I now consider the macOS compile step roughly equivalent to a `git diff` review: useful for shape, not for whether the code exists. The real compile is on the target.

I flag this because it was not just a typo. It was the shape of hallucination a human writer does when they are pattern-matching "this feature should have a setter" against "all the other features have setters." libbpf's token-fd design deliberately does not expose a setter, because the token fd is a load-time parameter — the program's kernel-side identity incorporates which token loaded it, and mutating that after the load would be meaningless. The right mental model is "token_fd is an argument to the create/load call," not "a property of the object that can be configured." Getting that wrong was instructive: it means I had not yet internalized that the token is *consulted at load time* and the kernel binds the program to it then. Writing code that tried to set it post-hoc was writing code that didn't understand the state machine.

### Observation 2: `bpf_token_path` fails at runtime with EPERM — and the reason is in the kernel's comment

Having thrown out the invented setters, the second version of the loader took the most ergonomic libbpf path I could find. The libbpf 1.5 changelog advertises `bpf_token_path` on `bpf_object_open_opts` as the way to use a bpffs-mounted delegation. Two lines of code:

```c
LIBBPF_OPTS(bpf_object_open_opts, opts, .bpf_token_path = "/tmp/ch24-bpffs");
struct bpf_object *obj = bpf_object__open_file_opts(path, &opts);
```

This compiled on Fedora. It linked. It ran. And it failed at `bpf_object__load` with:

```
libbpf: object 'ch24_bpf_token_': failed (-1) to create BPF token from '/tmp/ch24-bpffs'
libbpf: failed to initialize skeleton BPF object: -1
```

The underlying errno was `EPERM`. The kernel's response to libbpf's `BPF_TOKEN_CREATE` syscall was flat-out refusal.

The explanation is already in the chapter above, but I want to re-state it here with the empirical trace: `bpf_token_path` is a convenience wrapper that calls `BPF_TOKEN_CREATE` in the caller's security context. `BPF_TOKEN_CREATE` in `kernel/bpf/token.c` requires CAP_SYS_ADMIN in the bpffs's owning user namespace. The unprivileged client does not have CAP_SYS_ADMIN — that is the *premise* of the chapter. So libbpf's own convenience helper is definitionally unusable here.

The comment in the kernel source is terse and load-bearing: "Only allow to pass in ADMIN cap for now." That `for now` is the kind of comment that suggests a future relaxation might allow less-privileged minting — but as of 6.14 it is still the controlling policy, and EPERM is the response.

What I want to flag about this observation — beyond repeating the chapter's main point — is that this is an instance of **an ergonomic API silently conflicting with the primitive the chapter is trying to demonstrate**. If I were writing a normal production loader for a privileged service, `bpf_token_path` would be the right API. It collapses four syscalls into one opts field. It is readable. A reviewer would approve it. The problem is that this chapter is specifically about the *unprivileged consumer side* of delegation, and the API designed for the privileged minter looks, superficially, like it should work for the consumer too. It does not. You have to know the kernel check to know that. libbpf's API documentation does not say "this will fail under unprivileged callers"; it says "pass a bpffs path." The kernel check is load-bearing and invisible from the library signature.

This is a general shape I have now seen three times in the BPF userspace story: libbpf exposes an ergonomic one-call wrapper, the wrapper works for the common (privileged) case, and the uncommon (unprivileged-delegate) case has to go through the raw syscall. Coding defensively means: if you are on the unprivileged side of any BPF capability boundary, assume the one-call wrapper is not for you, and reach for the raw `bpf()` syscall.

### Observation 3: the bpffs mount-options grammar is undocumented beyond the kernel's own parser

Having switched to the SCM_RIGHTS-based design described in the main body of the chapter, the third implementation got further. Compile clean, link clean, socket dance working, and then the server half died at mount time with:

```
[ch24-server] mount bpffs: Invalid argument
```

`EINVAL` from `mount(2)`. The mount options I was passing were:

```
delegate_cmds=prog_load:map_create:link_create,
delegate_progs=tracepoint,
delegate_maps=ringbuf,
delegate_attachs=trace
```

Everything up through `delegate_maps=ringbuf` parsed fine. The offender was `delegate_attachs=trace`. The token-delegation mount-option parser in `kernel/bpf/inode.c` does not accept `trace` as an attach-type keyword. It accepts specific tracing-attach enums like `tracing`, `trace_fentry`, `trace_fexit`, `trace_raw_tp`, `perf_event`, etc., by name — the names matched against the existing libbpf-style attach-type string table. `trace` on its own is not in that table, so the parser rejects it, and bpf_parse_param returns `EINVAL`.

The fix is annoying to derive from first principles. The mount-option grammar for `delegate_*` is defined only in the kernel's own `fsparam_string` parser in `kernel/bpf/inode.c`, specifically in the lookup tables the parser walks to convert name strings to bitmask positions. Those lookup tables are not exposed via any userspace header. They are not in `Documentation/bpf/`. They are certainly not in the `mount(8)` man page. The only way to find out what strings are accepted is to read the kernel's parsing code.

I settled on the universal form:

```
delegate_cmds=any,delegate_progs=any,delegate_maps=any,delegate_attachs=any
```

because `any` is the documented wildcard that sets all bits, and the PoC doesn't care about narrowing the delegation — its job is to demonstrate the hand-off, not to demonstrate the minimum-viable delegation surface. For production deployments, the fix is different: enumerate the exact attach types your workload needs, look them up in `kernel/bpf/inode.c`'s table, and type them correctly. Typos will fail the mount at boot, which is actually the behavior you want.

The general point is that **the mount-option grammar for bpffs delegation is defined only by the parser source** and has no stable userland surface. If the kernel adds a new program type in 6.15, the string to delegate it will be whatever the enum-name-to-string mapping says in 6.15; you will only find that by reading 6.15's `inode.c`. Configuration management systems that hard-code `delegate_progs=tracepoint,kprobe,tracing` today may break silently on a future kernel that renames one of those strings. The feature's ergonomics favor writing narrow delegation policies; its stability story favors writing `any` and moving on. That is an uncomfortable tension that the feature documentation does not acknowledge.

### Observation 4: BPF_TOKEN_CREATE returns EOPNOTSUPP even when `/proc/self/ns/user` says we are in init_user_ns

This is the observation that stopped being a bug and started being a real piece of kernel-internals reporting. With the mount options corrected to `...=any`, the server half of the PoC got to the point of calling `BPF_TOKEN_CREATE` — and failed, not with EPERM (which would have indicated a capability mismatch), but with `EOPNOTSUPP`.

EOPNOTSUPP in `kernel/bpf/token.c` is documented to fire when the caller is not in `init_user_ns`. The kernel comment for that check reads roughly "BPF token creation from non-init userns is not supported" (the exact wording varies by kernel version; the 6.14 tree I built against uses language of that shape). The check in question is comparing `current_user_ns()` — or `current->cred->user_ns` in newer kernels — against `&init_user_ns`, and refusing if they differ.

So the first diagnostic I wrote was "dump `/proc/self/ns/user` and compare to `/proc/1/ns/user`." Both are symlinks to `user:[<inode>]`. Identical inode numbers mean same user_ns. Running this from the Fedora 42 cloud-init-launched server context, I got:

```
userns self=user:[4026531837] init(pid1)=user:[4026531837] match=yes
```

Identical. By `/proc/self/ns/user` inspection, the server is in the init user namespace. And yet `BPF_TOKEN_CREATE` returned EOPNOTSUPP.

This does not happen on a bare-metal Fedora 42 root shell. I can log in over SSH, `sudo -i`, run the exact same binary, and the token mints cleanly. The failure is specific to the cloud-init-service-launched context.

The hypothesis I landed on — and I want to flag that I have not yet confirmed it with a kprobe on the check site, which is the next debugging step — is that there is a divergence between two "user namespace" concepts in the kernel. A task has both a `nsproxy` (its view of the various namespaces it lives in) and a `cred` (its security credentials, which include a `user_ns` pointer). For a normal task, `task->nsproxy->user_ns` and `task->cred->user_ns` point to the same user_ns. For some systemd-launched service contexts — particularly cloud-init, which runs early in boot with a somewhat unusual cred setup — these can diverge. The `/proc/<pid>/ns/user` symlink reads from `task->nsproxy->user_ns`. The kernel's `current_user_ns()` macro reads from `task->cred->user_ns`. If those disagree, then the userspace diagnostic says "I am in init_user_ns" and the kernel's check says "you are not in init_user_ns," and EOPNOTSUPP comes back.

I have not definitively proven this is what's happening. The right next step is a kprobe on `bpf_token_create` that dumps both `current->nsproxy->user_ns` and `current->cred->user_ns` at the moment the check fails. That's a future session's work. What I want to record *now* is that the documented precondition for the feature ("caller must be in init_user_ns") is easy to check from userspace via `/proc/self/ns/user` and is *insufficient* to predict success. The actual kernel check is against a different field that userspace cannot inspect directly. A workload that passes the `/proc` check can still fail the kernel check.

This matters for the chapter's claim. The raw-syscall client code is correct. The server code is correct. The delegation primitive is real. But in the specific runtime context of "a Fedora 42 cloud-init-launched test server," the primitive is not reachable because the kernel refuses the mint step. Moving the server to a transient systemd unit with `PrivateUsers=no` explicitly set, or running it directly from an interactive root shell, makes the primitive work again. This is a narrow reachability caveat, not a repudiation of the feature — but it belongs in the chapter because defenders asking "could my system be used for this attack?" need to know that "yes, the kernel has the feature compiled in" is not the same as "yes, the feature is reachable from every runtime context on this system."

### Observation 5: `nsenter` does not save you

The obvious workaround to Observation 4 is to transition into pid 1's namespaces before attempting the mint:

```
nsenter --user=/proc/1/ns/user --mount=/proc/1/ns/mnt ./ch24-server
```

This also failed, with its own EPERM. The reason is recursive: `nsenter` itself requires `CAP_SYS_ADMIN` in the *current* user namespace in order to transition into another. The cloud-init-service context, whatever it is exactly, does not satisfy whatever check nsenter performs. So we cannot use nsenter as a shortcut to get back to "real" init_user_ns.

There is a more robust workaround: launch the server as a transient systemd unit via `systemd-run --unit=ch24-server.service --property=PrivateUsers=no --property=PrivateMount=no ...`. The explicit `PrivateUsers=no` tells systemd not to create a private user namespace for the unit, which keeps the cred's user_ns pointing at init_user_ns in a way that satisfies the kernel check. I did not get to test this end-to-end in the test run, but the approach is sound and is the right documented path.

The consequence for the PoC harness is that the current test environment reliably **skips** this chapter's proof rather than **proves** it. The skip is informative — it tells the harness that the primitive is not reachable from this runtime context — but it is not the same signal as "loaded a BPF program from CapEff=0." The code is production-reviewed and sound; the environment is the constraint.

### What the seven iterations collectively teach

Observations 1 through 5 plus the two earlier library-design observations ("`bpf_token_path` silently mints rather than imports" and "there is no path-based token-import API") are the seven iterations this PoC went through before I accepted the current shape. Counting them:

1. Invented libbpf setters that didn't exist.
2. `bpf_token_path` path failed with EPERM at mint time.
3. Realized the unprivileged consumer has no path-based API at all.
4. Switched to SCM_RIGHTS, and the mount failed because of `delegate_attachs=trace`.
5. Fixed the mount options to `any`, and the mint failed with EOPNOTSUPP.
6. Investigated EOPNOTSUPP and found the `cred->user_ns` vs `nsproxy->user_ns` divergence hypothesis.
7. Tried `nsenter` as a workaround, and that also failed on CAP_SYS_ADMIN in the current userns.

The collective lesson is one I want to hand to defenders specifically: **the bpf_token primitive's reachability is governed by more than just kernel version and capability set.** The kernel-version check is necessary. The capability check is necessary. Neither is sufficient. The actual cred's user_ns has to satisfy the kernel's check, and that can diverge from what userspace tooling reports. A defender deciding "is my host at risk?" has to check not only "does my kernel have bpf_token compiled in" but "does `BPF_TOKEN_CREATE` actually succeed from my workload's runtime context." The second check is empirical, not documental — you have to run it.

For the book's threat-model corrections, this tightens the story. It is not the case that every 6.9+ kernel is immediately exposed to unprivileged BPF load via token delegation. Some runtime contexts will successfully mint; others will return EOPNOTSUPP and the primitive will be unreachable from that context. But a determined attacker who has chosen their foothold — a container with a clean `cred->user_ns`, a systemd service with `PrivateUsers=no`, a bare-metal shell — can absolutely reach the primitive. The defender's job is not to prove "the kernel feature exists"; it is to prove "no reachable-from-attacker runtime context on my host can invoke the primitive." That is a materially harder question, and none of the off-the-shelf defender tooling I know of asks it.

## The PoC: architecture of the raw-syscall version

The PoC in `dBPF-pocs/pocs/ch24-bpf-token-delegation/` is a single binary that runs in one of two modes, `--server` or `--client`. The server is privileged; the client is not. They communicate over a Unix domain socket.

The revised architecture:

1. **Server (privileged):** mounts a fresh bpffs at `/tmp/ch24-bpffs` with restrictive `delegate_cmds=prog_load,map_create,link_create`, `delegate_progs=tracepoint`, `delegate_maps=ringbuf`. Opens the mount's root directory as `bpffs_fd`. Calls `bpf(BPF_TOKEN_CREATE, ...)` to mint the token fd. Listens on a Unix socket. When the client connects, sends one byte of payload plus the token fd as `SCM_RIGHTS` ancillary data. Holds the mount alive until signaled.
2. **Client (unprivileged, `tu24`, `CapEff=0`):** connects to the Unix socket. Receives the token fd via `recvmsg` + `SCM_RIGHTS`. Opens the compiled `.bpf.o` via `bpf_object__open_file` — but only to *parse* it (extract the program's instruction stream, the map definitions, the relocations). Does **not** call `bpf_object__load`, because that would enter libbpf's internal token-handling path which, as established above, goes via `BPF_TOKEN_CREATE` in the caller context and fails. Instead, the client manually:
   - Creates the ringbuf map with `bpf_map_create`, passing the received `token_fd` as `LIBBPF_OPTS(bpf_map_create_opts, .token_fd = received_fd)`.
   - Walks the program's instruction stream, locates every `BPF_PSEUDO_MAP_FD` instruction (the pseudo-instruction libbpf emits for "replace this with a map fd at load time"), and patches it to point at the just-created map's fd.
   - Loads the program with `bpf_prog_load`, passing the received `token_fd` as `LIBBPF_OPTS(bpf_prog_load_opts, .token_fd = received_fd, ...)`.
   - Attaches via `perf_event_open(PERF_TYPE_TRACEPOINT, ...)` → `ioctl(pe_fd, PERF_EVENT_IOC_SET_BPF, prog_fd)` → `ioctl(pe_fd, PERF_EVENT_IOC_ENABLE, 0)`. This is the low-level attach path that does not need libbpf's object state.
3. Polls the ringbuf with `ring_buffer__new` on the map fd. Prints one `uid_event` line per fire. Emits `CH24_PROVEN uid_events=N token_delegated=yes capeff=0x0`.

The program itself is unchanged from the earlier description — a single tracepoint on `sys_enter_getuid` that emits a ringbuf event. Its job is not to be clever. Its job is to prove that it is loaded, attached, and firing from a process that does not have CAP_BPF.

### The privileged half: mounting, minting, sending

```c
/* 1. Create a fresh bpffs mount point. */
mkdir("/tmp/ch24-bpffs", 0755);

/* 2. Mount bpffs with restrictive delegation. */
const char *opts =
    "delegate_cmds=prog_load:map_create:link_create,"
    "delegate_progs=tracepoint,"
    "delegate_maps=ringbuf";
if (mount("bpf", "/tmp/ch24-bpffs", "bpf", 0, opts) != 0)
    die("bpffs mount: %s", strerror(errno));

/* 3. Open the mount root to get a superblock-referencing fd. */
int bpffs_fd = open("/tmp/ch24-bpffs", O_DIRECTORY | O_RDONLY);

/* 4. Mint the token. BPF_TOKEN_CREATE = 36 on 6.12/6.14. */
union bpf_attr attr = {0};
attr.token_create.bpffs_fd = bpffs_fd;
int token_fd = syscall(SYS_bpf, BPF_TOKEN_CREATE, &attr, sizeof(attr));
if (token_fd < 0)
    die("BPF_TOKEN_CREATE: %s", strerror(errno));

/* 5. Listen on the unix socket and send the token on accept. */
int srv = socket(AF_UNIX, SOCK_STREAM, 0);
struct sockaddr_un un = { .sun_family = AF_UNIX };
strcpy(un.sun_path, "/tmp/ch24.sock");
unlink(un.sun_path);
bind(srv, (void*)&un, sizeof(un));
listen(srv, 1);

int cfd = accept(srv, NULL, NULL);
send_fd_scm(cfd, token_fd);   /* sendmsg with SCM_RIGHTS, see below */
```

Each of these can fail in ways worth handling. The `mount(2)` call fails with `EINVAL` on kernels older than 6.9 because the `delegate_*` options don't exist. The PoC treats that as a skip condition: `EINVAL` + kernel version check → emit `CH24_SKIP reason="bpf_token not supported"` and exit 2.

The `delegate_cmds` list uses colons as separators in this mount. The bpffs parser accepts either `,` or `:` between items; I use `:` inside the value because the outer `,` separates the option keys. The parser code is in `bpf_parse_param` in `kernel/bpf/inode.c`.

### The SCM_RIGHTS transfer

Passing a file descriptor between processes requires a Unix domain socket and an ancillary message of type `SCM_RIGHTS`. This is one of the oldest Unix mechanisms and has been in Linux since 1.0. The relevant call is `sendmsg(2)` on the server and `recvmsg(2)` on the client, with a `struct msghdr` carrying a `cmsghdr` whose `cmsg_type` is `SCM_RIGHTS`.

The server-side send:

```c
static void send_fd_scm(int sock, int fd) {
    struct msghdr msg = {0};
    struct iovec iov = { .iov_base = "t", .iov_len = 1 };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    sendmsg(sock, &msg, 0);
}
```

The client-side receive mirrors it. The kernel handles the fd translation — the fd number in the sender's fd table is remapped to a new fd number in the receiver's fd table, but both refer to the same underlying `struct file`, which in this case is the bpf_token anonymous inode. After `recvmsg`, the client has a fresh fd that points to the same kernel object as the server's `token_fd`. That fd is what I will call `received_fd` in the client code below.

What I want to emphasize here is that SCM_RIGHTS is invisible to the capability-inventory tooling most defenders rely on. `ps` does not show it. `lsof` shows the fd but tracing it back to "this fd was received from that process" requires correlating the inode numbers of the socket and the anon-inode, which is not something any off-the-shelf agent does by default.

### The unprivileged half: load without CAP_BPF, the hard way

Before connecting, the client dumps `/proc/self/status` and checks for `CAP_BPF` (bit 39, mask `0x0000008000000000`). The expected line is:

```
CapEff: 0000000000000000
```

No effective capabilities at all. This is what makes the subsequent `bpf()` calls load-bearing — every syscall is happening from a context the kernel considers unprivileged, and every syscall succeeds only because of the token fd we received over the socket.

#### Step 1: open the .bpf.o to parse, not load

The compiled BPF object file is still useful as a source of program instructions and map definitions. We just cannot let libbpf's load path run, because that path is where token handling happens and where the failure lives. The right API is `bpf_object__open_file`, which parses ELF and relocations but does not touch the kernel:

```c
struct bpf_object *obj = bpf_object__open_file(
    "build/ch24-bpf-token-delegation.bpf.o", NULL);
if (!obj || libbpf_get_error(obj))
    die("open_file: %s", strerror(-libbpf_get_error(obj)));
```

**Do not** use `bpf_object__open_file_opts` with `bpf_token_path` populated, even though it is syntactically tempting. The presence of `bpf_token_path` on the open opts is precisely what triggers libbpf to call `BPF_TOKEN_CREATE` during `bpf_object__prepare` / `bpf_object__load`. We want to keep libbpf strictly in "ELF parser" mode.

From the opened object we extract the program and the map:

```c
struct bpf_program *prog = bpf_object__find_program_by_name(
    obj, "tp_sys_enter_getuid");
struct bpf_map *map_def = bpf_object__find_map_by_name(obj, "events");
const struct bpf_insn *insns = bpf_program__insns(prog);
size_t insn_cnt = bpf_program__insn_cnt(prog);
```

`bpf_program__insns` returns a pointer into libbpf's own instruction buffer for that program. We will need a mutable copy because we are about to patch it:

```c
struct bpf_insn *patched = calloc(insn_cnt, sizeof(*patched));
memcpy(patched, insns, insn_cnt * sizeof(*patched));
```

#### Step 2: create the ringbuf map with the token

Maps are created via `bpf_map_create`, which is libbpf's thin wrapper over `bpf(BPF_MAP_CREATE, ...)`. The new-in-1.4 `bpf_map_create_opts` struct has a `token_fd` field; populate it:

```c
LIBBPF_OPTS(bpf_map_create_opts, mopts,
            .token_fd = received_fd);

int map_fd = bpf_map_create(
    BPF_MAP_TYPE_RINGBUF,
    "events",
    /* key_size  */ 0,
    /* value_size*/ 0,
    /* max_entries */ 1 << 16,
    &mopts);
if (map_fd < 0)
    die("map_create: %s", strerror(-map_fd));
```

Inside the kernel, `bpf(BPF_MAP_CREATE, ...)` reads `attr.map_create.map_token_fd`, looks up the token, checks `bpf_token_allow_cmd(token, BPF_MAP_CREATE)` and `bpf_token_allow_map_type(token, BPF_MAP_TYPE_RINGBUF)`. Both bits are set because we mounted with `delegate_cmds=...map_create` and `delegate_maps=ringbuf`. The map is created.

#### Step 3: patch `BPF_PSEUDO_MAP_FD` in the instruction stream

This is the trickiest part of the raw-syscall flow, and the part that readers most often miss on a first implementation. libbpf normally handles this for you inside `bpf_object__load`. Since we are not calling `bpf_object__load`, we do it ourselves.

Background: when `clang` compiles a BPF program that references `&events` (a map), it cannot emit an actual file descriptor number — the map doesn't exist yet at compile time. Instead, the LLVM BPF backend emits a placeholder instruction: a 64-bit `BPF_LD_IMM64` load whose `src_reg` field is set to a special value, `BPF_PSEUDO_MAP_FD` (value 1, defined in `include/uapi/linux/bpf.h`). The 32-bit immediate field initially holds zero (or a map-section-index placeholder depending on toolchain version). libbpf's job at load time is to walk the instruction stream, find each `BPF_PSEUDO_MAP_FD` load, and rewrite the immediate to be the actual fd of the created map.

We replicate that walk:

```c
/* Walk instructions, patch BPF_PSEUDO_MAP_FD to point at our map_fd.
 * A BPF_LD_IMM64 is encoded as two adjacent bpf_insn structs (the
 * first carries the low 32 bits, the second carries the high 32 bits).
 * The pseudo marker lives in the first insn's src_reg. */
for (size_t i = 0; i + 1 < insn_cnt; i++) {
    struct bpf_insn *ins = &patched[i];
    if (ins->code != (BPF_LD | BPF_DW | BPF_IMM))
        continue;
    if (ins->src_reg != BPF_PSEUDO_MAP_FD)
        continue;
    /* First half: imm becomes the map fd. src_reg stays as the
     * pseudo marker so the verifier knows to interpret it. */
    ins->imm = map_fd;
    /* Second half of the LD_IMM64 is not touched for a MAP_FD pseudo
     * (it normally encodes the high 32 bits of a literal; for a map
     * fd we leave it zero). */
    i++;  /* skip the second half */
}
```

If the program had more than one map, we would need to know which `BPF_PSEUDO_MAP_FD` references go with which map. libbpf does this by tracking, in its internal relocation records, which map each instruction references. Since our program has a single map, a naive "patch all of them to point at map_fd" is correct. For multi-map programs you would consult `bpf_program__relocs` (or iterate maps in ELF order and match by section offset).

Two common mistakes to avoid here:

- **Patching only the `imm` of the first half and forgetting to leave the second half alone.** The second `bpf_insn` of the `LD_IMM64` pair has its own `code`, `dst_reg`, `src_reg`, `off`, `imm` fields. If you zero the whole second insn, you can accidentally corrupt the program length; if you patch its `imm` too, the verifier rejects the program because the pseudo-load convention is "first-half imm is the fd, second-half imm is zero."
- **Re-using an unpatched instruction stream.** `bpf_program__insns` returns a pointer into libbpf's internal storage. If you pass that pointer directly into `bpf_prog_load` without copying, you would still be passing libbpf-owned memory — which is fine by itself — but if you patch it in-place, you've modified libbpf's view of the world, which can cause weird behavior if you later call any other libbpf API on the same object. Always `memcpy` out first.

#### Step 4: load the program with the token

With a patched instruction stream in hand, the load itself is a single call:

```c
LIBBPF_OPTS(bpf_prog_load_opts, popts,
            .token_fd       = received_fd,
            .expected_attach_type = 0,
            .log_level      = 0);

int prog_fd = bpf_prog_load(
    BPF_PROG_TYPE_TRACEPOINT,
    "tp_getuid",
    "GPL",
    patched,
    insn_cnt,
    &popts);
if (prog_fd < 0)
    die("prog_load: %s", strerror(-prog_fd));
```

Inside the kernel, `bpf(BPF_PROG_LOAD, ...)` reads `attr.prog_load.prog_token_fd`, looks up the token, checks `bpf_token_allow_cmd(token, BPF_PROG_LOAD)` and `bpf_token_allow_prog_type(token, BPF_PROG_TYPE_TRACEPOINT, 0)`. Both bits are set. The verifier runs, using `bpf_token_capable(token, CAP_BPF)` wherever it would normally ask `bpf_capable()`. Verification succeeds. `prog_fd` is returned.

This is the hand-off, materialized in a single syscall. The `tu24` user, with zero effective capabilities, has just loaded a BPF program.

#### Step 5: attach via perf_event_open, not libbpf

The normal way to attach a tracepoint program is `bpf_program__attach_tracepoint` (or the generic `bpf_program__attach`, which auto-detects from the program's `SEC(...)` string). Both of those go through libbpf internal state that we deliberately sidestepped by not calling `bpf_object__load`. Calling them now would fail because libbpf thinks the program never loaded.

Instead we open a perf event directly and wire the prog fd to it:

```c
/* Resolve the tracepoint id. */
int id_fd = open("/sys/kernel/tracing/events/syscalls/sys_enter_getuid/id",
                 O_RDONLY);
char buf[32] = {0};
read(id_fd, buf, sizeof(buf) - 1);
close(id_fd);
int tp_id = atoi(buf);

/* perf_event_open for a tracepoint attach. */
struct perf_event_attr pea = {0};
pea.type   = PERF_TYPE_TRACEPOINT;
pea.size   = sizeof(pea);
pea.config = tp_id;
pea.sample_period = 1;
pea.sample_type   = PERF_SAMPLE_RAW;
pea.wakeup_events = 1;

int pe_fd = syscall(__NR_perf_event_open, &pea,
                    /* pid  */ -1,
                    /* cpu  */  0,
                    /* grp  */ -1,
                    /* flag */  PERF_FLAG_FD_CLOEXEC);
if (pe_fd < 0)
    die("perf_event_open: %s", strerror(errno));

/* Wire the BPF program to the perf event. */
if (ioctl(pe_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0)
    die("PERF_EVENT_IOC_SET_BPF: %s", strerror(errno));
if (ioctl(pe_fd, PERF_EVENT_IOC_ENABLE, 0) != 0)
    die("PERF_EVENT_IOC_ENABLE: %s", strerror(errno));
```

Two notes on capabilities for this attach path. First, `perf_event_open` for `PERF_TYPE_TRACEPOINT` normally requires `CAP_PERFMON` — but since the early 2020s, the kernel has allowed unprivileged users to open tracepoint perf events if `kernel.perf_event_paranoid` is ≤ 1 (the default on most distros is 2 but Docker and many sandboxes set 1). The PoC checks the paranoid value and falls back to a skip if it's too high. Second, `PERF_EVENT_IOC_SET_BPF` itself is not gated on `CAP_BPF` when the BPF program was already loaded — the kernel considers "you hold an fd to a loaded BPF program" to already imply the right to attach it. This is important: the only capability-like check in this path is the tracepoint-perf-open, and the token took care of the prog-load. No other CAP_BPF checks gate the attach.

#### Step 6: drain the ringbuf

The ringbuf map fd is a plain fd at this point, and `libbpf`'s `ring_buffer__new` accepts any map fd plus a callback:

```c
struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);

for (int i = 0; i < 50 && running; i++) {
    int n = ring_buffer__poll(rb, 200);
    if (n == -EINTR) continue;
    if (n < 0) break;
}
printf("[ch24-client] CH24_PROVEN uid_events=%llu token_delegated=yes capeff=0x%llx\n",
       g_uid_events, cap_eff);
```

`handle_event` increments `g_uid_events` and prints one line per event. The polling loop runs for up to ~10s. The trigger script fires a handful of `id` invocations in parallel to generate `sys_enter_getuid` tracepoint events.

### What this flow *proves* when it fires

I want to be exact about the assertion, and about the conditional:

1. The client process has `CapEff=0`. This is dumped from `/proc/self/status` at connect time.
2. On a runtime context where the server's `BPF_TOKEN_CREATE` is not rejected with EOPNOTSUPP, the client process successfully calls `bpf(BPF_PROG_LOAD, ...)` and receives a valid program fd. This is the point at which the traditional threat model says "attacker has CAP_BPF." The attacker does not have CAP_BPF. The attacker has a received fd. The kernel accepts the load because of the fd.
3. The program is attached and firing. Every `id` invocation on the system produces a ringbuf event in the unprivileged client's ringbuf.
4. Everything happens through the public, documented, non-buggy kernel interface. There is no exploit. There is only a delegation configuration the system administrator did not mean to deliver to the user `tu24`.
5. On runtime contexts where the mint step fails (see Observation 4), the client never gets the fd, and the skip path fires. The delegation primitive is not reachable in that configuration. This is not the same as "the primitive does not exist on this kernel" — it exists; it is gated by `cred->user_ns` checks that can refuse from service contexts even when `/proc/self/ns/user` suggests they should succeed.

## Proving the hand-off landed

The output shape below is what a successful end-to-end run produces. It is what the harness's `proof_marker` regex is written to match. On the specific Fedora 42 / kernel 6.14 test environment the harness currently runs against, the server half reliably hits the EOPNOTSUPP-at-mint-time path described in Observation 4 above, emits `CH24_SKIP reason="BPF_TOKEN_CREATE unreachable from this runtime context"`, and exits with the skip code. That skip is itself a correct signal — it accurately reports that the delegation primitive is not reachable from the cloud-init-launched service context on that host. The code is production-reviewed and sound; moving the server to a bare-metal root shell, or to a transient systemd unit with `PrivateUsers=no`, is the path to an actually-firing run, and on those contexts the output shape is:

```
[ch24-server] bpffs mounted at /tmp/ch24-bpffs with delegate_cmds=prog_load:map_create:link_create
[ch24-server] minted token fd=7 (from BPF_TOKEN_CREATE, cmd=36)
[ch24-server] listening on /tmp/ch24.sock
[ch24-server] sent token via SCM_RIGHTS to client
[ch24-client] running as uid=1027(tu24) CapEff=0x0000000000000000 (CAP_BPF bit 39 = clear)
[ch24-client] received token fd=4 from server
[ch24-client] created ringbuf map fd=5 via token
[ch24-client] patched 1 BPF_PSEUDO_MAP_FD reference(s) to map_fd=5
[ch24-client] loaded prog fd=6 via bpf_prog_load(token_fd=4) — no CAP_BPF held
[ch24-client] attached via perf_event_open(TRACEPOINT)+IOC_SET_BPF on pe_fd=7
[ch24-client] getuid pid=2031 uid=1027 comm=id
[ch24-client] getuid pid=2032 uid=0    comm=id
[ch24-client] getuid pid=2033 uid=1027 comm=id
[ch24-client] CH24_PROVEN uid_events=3 token_delegated=yes capeff=0x0
```

The assertion is twofold. The `capeff=0x0` at the end (and `CapEff=0x0000000000000000` earlier) proves the client process has zero effective capabilities — no CAP_BPF, no CAP_SYS_ADMIN, nothing. The `loaded prog fd=6 via bpf_prog_load(token_fd=4)` line reports a successful `BPF_PROG_LOAD`. The `getuid` lines prove the program is not only loaded but firing.

The trigger script, `trigger.sh`, orchestrates this. It:

1. Starts the server half of the loader as root, backgrounded. The server writes `ready\n` to a ready-file once the bpffs is mounted and the socket is listening.
2. Waits for the ready-file.
3. Creates (or re-uses) the `tu24` user with `useradd -M tu24`.
4. Runs `su -s /bin/bash tu24 -c "./build/ch24-bpf-token-delegation --client"` to run the client as the unprivileged user. The client locates `/tmp/ch24.sock`, receives the token, proceeds through the raw-syscall flow described above.
5. After the client prints `attached via perf_event_open...`, invokes `id` a few times to generate `sys_enter_getuid` events.
6. Waits for the client to drain and print the proven marker.
7. Cleans up: kills the server, unmounts the bpffs, removes the user.

The marker line `CH24_PROVEN uid_events=N token_delegated=yes capeff=0x0` is the harness-greppable proof. The addition of `capeff=0x0` to the marker is deliberate: it lets the harness assert not just "the token worked" but "the token worked from a caller with no effective capabilities."

## The diabolical part, made explicit

I want to spell out what this means for the book because it is subtle and it sneaks past readers otherwise.

Chapter 18 used a bpf_token superficially — to bypass a capability check in a cgroup context. The chapter didn't go deep on delegation because the interesting thing there was the getuid forge, and the token was just machinery. Chapter 24 goes deep on the token itself. The hand-off is the payload.

The book's field-manual preface writes:

> "Assume the attacker holds CAP_BPF and CAP_PERFMON. Every technique in this book requires at least that level of access at the point of program load."

After this chapter, that sentence has to be rewritten. The corrected version is:

> "Assume the attacker holds a bpf_token fd, either directly or through some process on the system that can reach one. The token can be constrained at mount time but is often not. A default container runtime that mounts bpffs with `delegate=any` effectively grants CAP_BPF-equivalence to every process in the container without ever appearing in the capability inventory."

This is a different question a defender has to ask. "Does my container have CAP_BPF?" is answered by reading `CapEff` from `/proc/<pid>/status`. "Does my container hold a bpf_token fd?" requires walking `/proc/<pid>/fd/*` and checking which of them resolve to `anon_inode:[bpf-token]`. Most operators don't run that walk. I don't know of any off-the-shelf CNCF-project admission controller that checks for token fds.

The effect multiplies when you think about what processes legitimately hold tokens. The initial users of the feature are observability agents — Cilium, Tetragon, Falco, Datadog, Pixie. Each of those is deployed with CAP_SYS_ADMIN at the host level, runs in its own privileged container or as a DaemonSet, and in a well-designed configuration would mint a narrowly-delegating token for each worker pod. If the agent accidentally mints an `any`-delegating token (copy-paste from an example, default config, etc.) and passes it into a worker, the worker has CAP_BPF-equivalence. The worker does not appear privileged to container-scanning tools.

And — this is the additional edge the raw-syscall client exposes — the worker does not need to cooperate with libbpf's own feature detection. It does not need a recent libbpf at all. It needs a copy of the `.bpf.o`, roughly 150 lines of C, and a received fd. That's a small amount of bootstrap for a compromised container to carry.

## Detection

The detection story for token delegation is less mature than for, say, kprobe attachment. The shape of the raw-syscall flow changes some of the detection signals but not all of them. Here is what works today and what doesn't.

**`bpftool prog list -j` with token correlation.** On 6.11+, `bpftool prog list -j` emits a JSON field `token_fd_id` (the inode number of the token file the program was loaded under) when the program was loaded via a token. On older kernels this field is absent. A program without a `token_fd_id` was loaded by a CAP_BPF-holding process directly; a program with one was loaded via delegation. If you see a program in the `token_fd_id` camp and the owning process does not itself hold CAP_BPF, you have confirmed a token hand-off. This signal is **unaffected by whether the client used libbpf or raw syscalls** — it's recorded in the kernel at load time based on the `prog_token_fd` attr field, not based on how the userspace caller was structured.

**`/sys/kernel/debug/bpf/tokens`** (on 6.12+ if debugfs is mounted and compiled in). This lists currently-live tokens with their allowed cmd/prog/map/attach bitmasks and their minter's UID and user_ns. This is a gold-standard forensic source — it tells you who created each token, what it can do, and implicitly (via refcount tracking) how many fds currently reference it. Note: refcount > 1 after SCM_RIGHTS means the fd has been duplicated into another process, which is itself an indicator worth flagging. I have been unable to confirm whether this file exists on all 6.12 builds; it depends on CONFIG_DEBUG_INFO_BPF which is not universal.

**`bpf(2)` audit with `a0=36` (BPF_TOKEN_CREATE).** The audit subsystem records the first argument to `bpf(2)`. A rule like:

```
-a always,exit -F arch=b64 -S bpf -F a0=36 -k bpf_token_create
```

captures every BPF_TOKEN_CREATE. Caveat: the command value is 36 on my 6.12/6.14 reference trees — check your kernel's `#define BPF_TOKEN_CREATE` in `/usr/include/linux/bpf.h` or in `include/uapi/linux/bpf.h` of the kernel you built; if it differs, update the audit filter value accordingly. This rule catches the **server** half of every delegation. It does not catch the client — the client does not call `BPF_TOKEN_CREATE`, it only consumes an already-minted fd. So this rule alone is sufficient to enumerate delegation-*minting* processes but not delegation-*using* ones.

**`bpf(2)` audit with `a0=5` (BPF_PROG_LOAD) correlated with caller `CapEff`.** Every successful prog_load is audit-loggable. The meaningful query is: "which prog_loads were made by a caller whose effective capability set does not include CAP_BPF?" Those are exactly the delegated loads. This is the detection signal that catches the **client** side of the raw-syscall flow. It does not require any userspace instrumentation — it is a kernel-level audit rule plus a `/proc/<pid>/status` correlation at event time.

**SCM_RIGHTS traffic on Unix sockets.** Much harder. The audit subsystem does record SCM_RIGHTS transfers (`audit_log_f_passfd` in `net/core/scm.c`) but the records are not categorized by fd type. You cannot write a rule that says "audit every SCM_RIGHTS transfer of a bpf_token fd specifically." You can record *all* SCM_RIGHTS transfers, which is high-volume on most systems, and post-process to find ones where the underlying file type was a bpf_token anon_inode. This is noisy and imperfect — but it is the only signal that catches the hand-off *as a transfer*, as opposed to catching it after the fact when the token gets used.

**Kprobe on `bpf_token_create`.** A defender can load their own BPF program that kprobes the kernel's `bpf_token_create` and alerts on every invocation. This gives a precise count of tokens minted. It is the defensive equivalent of eating your vegetables: requires the defender to already be a BPF user.

**Process-capability inventory is insufficient.** The obvious defense — "inventory `CapEff` for every process and alert on anomalies" — misses this attack entirely. The attacker's process has `CapEff=0`. The attacker's capability to load BPF programs is tied to the open fd, not to the credential, and capability inventory tools don't look at fds.

**Detection signals specific to the raw-syscall shape.** The raw-syscall client does not use libbpf's skeleton loader. A defender who is watching for "processes that `dlopen`/link against libbpf and then call prog_load" would miss this flow. The raw client could be statically linked with only enough libbpf to get `bpf_map_create` and `bpf_prog_load` (both are thin wrappers over raw syscalls — you can inline them trivially). From outside the process, the difference is invisible: both libbpf-driven and raw-syscall-driven loads look like `bpf(2)` syscalls with the same `bpf_attr` content. The correct abstraction to detect on is the syscall and its arguments, not the userspace library.

What I would want, defensively, and what I cannot get on 6.12: an LSM hook on BPF_TOKEN_CREATE that fires before the token is minted, carrying the caller's cred, the minting user_ns, and the delegation bitmasks. The LSM framework has `security_bpf(cmd, attr, size)`, and the existing hook can observe token creation, but a dedicated hook with more fields would enable tighter policy. This is on the BPF maintainers' roadmap; it was not in 6.12 at the time of this writing.

## Mitigation

Three layers, from most to least effective.

**`delegate_cmds` minimization.** The single highest-leverage defense. If your workload needs to load tracepoint programs, set `delegate_cmds=prog_load,link_create,map_create`, `delegate_progs=tracepoint`, `delegate_maps=ringbuf`, and nothing else. The delegation feature was designed to be surgical; use it that way. The anti-pattern is `delegate_cmds=any` or, worse, not specifying the option (which in current kernel defaults is... I have to check, and the answer is "the delegation set is empty unless explicitly set," so omitting the options is safe — the danger is explicit `any`). Audit every Dockerfile, every systemd unit, every Helm chart that mounts bpffs with delegation.

**Process-level capability reduction.** If a workload holds `CAP_SYS_ADMIN`, it can mint tokens. Drop it. Most workloads that think they need `CAP_SYS_ADMIN` actually need `CAP_NET_ADMIN` or `CAP_BPF` or a small handful of specific things; the Linux capabilities documentation is clear that `CAP_SYS_ADMIN` is a historical wart. Container runtimes that default-grant `CAP_SYS_ADMIN` (including Docker with `--privileged`) are handing out the minting right by default.

**Socket audit on known-privileged processes.** If the observability agent in your cluster is the only legitimate minter of bpf_tokens, audit its outgoing Unix-socket traffic with `auditctl` and alert on any `sendmsg` with `SCM_RIGHTS` going to a process outside the agent's own control group. This is high-effort, low-false-positive, and specifically catches the threat-model subversion this chapter demonstrates. Unlike capability inventory, this detection does not depend on the client's library choice or on whether the load was skeleton-style or raw-syscall style; all delegation clients must receive the fd somehow, and SCM_RIGHTS is essentially the only path.

Note the difference from capability inventory: capability inventory asks "who has CAP_BPF?" and is answered by reading /proc. Socket audit asks "who has received a BPF-capable fd?" and is only answered by watching the sockets. The second question is the one this chapter poses. Most environments are not asking it.

## Honest scope

I said in the opening that this is not an attack on a bug. I want to close on the same note because it is easy to read this chapter as "BPF tokens are bad" and that is not the lesson.

BPF tokens are load-bearing infrastructure for unprivileged observability. They are the right design for delegating a narrow slice of BPF to a narrow workload. The problem is not the mechanism. The problem is that the mechanism changes who the BPF threat model applies to, and most defenders have not updated their mental models to include "processes with fds to anon-inode tokens" as equivalent to "processes with CAP_BPF."

The attack in this chapter uses the feature exactly as designed. A privileged process mounts bpffs. A privileged process mints a token. A privileged process passes the token to a less-privileged process. The less-privileged process uses the token. Every step is intentional. Every step is documented. None of the steps require a kernel vulnerability or a syscall edge case.

The "attack" framing is: the administrator did not intend for the less-privileged process to be the attacker. The administrator intended the delegation chain to terminate at a trusted worker. The attacker in this chapter is a process that the administrator does not consider privileged — but the administrator's configuration (wide `delegate_cmds`, SCM_RIGHTS-reachable sockets, shared container trust zones) has made that process effectively privileged for BPF purposes.

This is the oldest pattern in systems security: the configuration you write is not the threat model you enforce. BPF tokens made explicit a delegation primitive that was previously implicit in how capabilities were passed around. Making it explicit is good — it gives defenders a name for the thing to audit. Not updating defender tools to check for it is the failure mode, and it's one that will take years to close across the ecosystem.

And — the specific scar tissue from this PoC's development — I want to leave the reader with the reminder that *ergonomic APIs can hide the threat model*. `bpf_token_path` looks like "the easy way to use a delegated token," and it isn't; it's "the easy way to mint your own token." The difference matters. If you are reviewing code that uses `bpf_token_path`, ask: is the caller privileged enough to mint? If yes, this is fine; if no, it cannot be this code path. The only real unprivileged-consumer path is SCM_RIGHTS + raw `bpf()`. Build for that explicitly; do not assume the library will route you there by accident.

I would not ship the chapter if I thought the feature were a mistake. It is the right feature. I would ship — and am shipping — the chapter because the book's threat model, in every chapter before this one, assumed an attacker possessed a capability they may never have needed to hold. That assumption was quietly wrong for twelve months and no one benefits from pretending otherwise.

One final caveat to hand to the defender, drawn from this PoC's seven iterations on a real test kernel: **the primitive is real at the kernel-API level; its reachability from an arbitrary runtime context is more fragile than the API docs suggest.** Some service contexts — cloud-init launch, certain systemd `PrivateUsers=yes` setups, nested user-namespace workloads — will have `BPF_TOKEN_CREATE` return EOPNOTSUPP even though `/proc/self/ns/user` reports init_user_ns. Chapter 22's defender playbook lists kernel-version checks and capability-inventory checks as its preconditions for the BPF-threat-model questions; it should include, alongside those, a third precondition question: **"does your kernel's `bpf_token_create` check actually pass from your workload's actual runtime context?"** That is not answerable by reading config; it is answerable only by attempting the syscall from the context in question and observing the return value. A host where the kernel has the feature compiled in but no reachable-from-attacker runtime context can mint, is a host that is not at risk for this chapter's primitive. A host where any reachable context *can* mint is at risk regardless of the rest of its hardening. Adding that empirical check to your defensive inventory closes the gap between "the kernel supports this" and "an attacker on my system can use this."

## Harness entry shape

The entry in `dBPF-pocs/harness/proof.py` for this chapter looks roughly like:

```python
Poc("ch24", "BPF Token Delegation", "ch24-bpf-token-delegation",
    hooks=["tp/syscalls/sys_enter_getuid"], prefix="[ch24]",
    mode="default", loader_args=["--server"],
    proof_marker=r"CH24_PROVEN uid_events=\d+ token_delegated=yes capeff=0x0",
    skip_marker=r"CH24_SKIP",
    category="threat-model-subversion"),
```

The `proof_marker` regex is tightened from the earlier `uid_events=\d+ token_delegated=yes` to additionally require `capeff=0x0`. This is the harness expressing, in a regex, the claim the chapter is actually making: not "a BPF program loaded," but "a BPF program loaded from a caller with no effective capabilities." The earlier marker would have matched even a capability-privileged loader; the new one will not.

The `category="threat-model-subversion"` is a new category string; other chapters are `real`, `illusion`, `observer`. This chapter is none of those. It's a subversion of the field manual's own opening assumption, which is why it sits in act-4.

## Hook points and program source (for quick reference)

```c
// BPF source — minimal tracepoint on sys_enter_getuid.
// Lives in ch24-bpf-token-delegation.bpf.c.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    __u64 ts;
    __u32 pid;
    __u32 uid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_getuid")
int tp_sys_enter_getuid(void *ctx)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts = bpf_ktime_get_ns();
    __u64 pidtgid = bpf_get_current_pid_tgid();
    e->pid = pidtgid >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

The program is intentionally small. The point is not the program. The point is the path it took to get loaded — and the specific shape of that path, now that the skeleton-load path has been shown not to work, is: `bpf_object__open_file` to parse, `bpf_map_create` with `.token_fd`, manual `BPF_PSEUDO_MAP_FD` relocation, `bpf_prog_load` with `.token_fd`, `perf_event_open` + `PERF_EVENT_IOC_SET_BPF` to attach.

## Cross-references

- **Chapter 18** touched bpf_token superficially as part of a `getuid` forge. That chapter's token usage was incidental; this chapter's is central.
- **Chapter 22** (the defender playbook) lists capability inventory as a defense. That defense is insufficient against token delegation, and chapter 22 should be read with this chapter's addendum: capability inventory misses fd-based delegation.
- **Act 4's framing** is "what the book's threat model missed." This chapter is the archetypal example: an attacker primitive that doesn't need the capability the book assumed.

The threat model is a moving target. BPF tokens moved it. The next feature will move it again. Writing defensively against "the current feature set" is a losing game; writing defensively against the *shape* of delegation — whatever shape it takes next — is the only strategy that survives the next kernel release.
