---
layout: book
title: "Chapter 7: Device-cgroup Houdini"
date: 2025-02-07
---

# Chapter 7: Device cgroup Bypass via LSM

> **Status**: Both variants proved on Ubuntu 6.17.0-29-generic aarch64 (Lima VM). The natural `inode_mknod` hook fires via the LSM synthetic-deny path; the kprobe observer fires on `devcgroup_check_permission`. See the note below on why the "natural denial flip" still requires a synthetic setup, and [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) for the original development kernel context.

## The original ambition

I started this one expecting an easy win. Device cgroups are the standard container control for hardware access, and privileged container bypasses of device cgroups are well-trodden ground — Aqua Security, NCC Group, and the Trail of Bits runtime-security crowd have written about direct mknod escapes on privileged containers for years. My question was narrower and, I thought, more interesting: can a `BPF_PROG_TYPE_LSM` program — specifically an `fmod_ret` program attached to `security_inode_mknod` — flip a denied char/block device creation into an allowed one on a container that is explicitly *not* privileged, just by running a BPF program in the host network namespace?

The plan on paper:

1. Attach `SEC("lsm/inode_mknod")` with fmod_ret semantics.
2. Observe the hook firing when an unprivileged container runs `mknod /dev/mem c 1 1`.
3. For a target tgid, return 0 from the LSM program. The kernel's LSM chain aggregates return codes via logical AND; if the BPF LSM returns 0 and nobody upstream objected, the `mknod` succeeds.
4. The container ends up with a live `/dev/mem` character node it can open. Game over, in the classroom sense.

I wrote the BPF side in about thirty minutes. I wrote the loader in another hour — the usual skeleton open/load/attach/ringbuf poll dance, identical in shape to ch01 and ch06. I built. I booted a linuxkit 6.12 aarch64 VM (Docker Desktop on macOS, because that's what I had, and because aarch64 linuxkit has been my stated target throughout the book). I ran the loader. I ran the container. I ran `mknod`. The syscall returned `-EPERM`, correctly. My LSM program fired zero times. Ringbuf empty. `bpftool prog list` showed the program loaded and attached.

That second-to-last sentence is the chapter in a nutshell. The LSM program was attached. The LSM program was loaded. The LSM program was *fine*. It just never ran. The syscall had already failed before the kernel got anywhere near the LSM chain.

This chapter is the chase from "what do you mean my hook didn't fire" through the source code of `fs/namei.c`, to the realization that the stock LSM chain on every mainstream Linux distribution puts `capability` ahead of `bpf`, to the verifier error that cost me a day (`failed to find kernel BTF type ID of 'dev_open'`), to a different POC design entirely — the `ch07-devcgroup-houdini-lsm/` synthetic deny+flip. That POC does prove the primitive, but it proves it in a way that deserves a very careful reading of what was actually demonstrated and what was not.

The short version, as context for the rest: the primitive "BPF LSM fmod_ret can turn an inode_mknod denial into an allow for a target tgid" is real in the kernel. Proving it from a natural capability-based denial is not possible on a stock LSM chain. Proving it from a synthetic denial that our own BPF program creates is possible and honest, provided we are clear that we are demonstrating the in-kernel mechanism rather than a practical deny-to-allow escape on a real cgroup-restricted host. Everything below is the path from one framing to the other, and what I learned about BTF, LSM ordering, and the verifier along the way.

## The cap_capable short-circuit

When my first attempt did nothing, I did what I always do: I read the source. Specifically, I started at the syscall entry and walked forward until I hit either my LSM hook or the `-EPERM` return. Whichever came first would tell me where the decision was actually made.

The relevant file is `fs/namei.c`. The function that handles the `mknod(2)` and `mknodat(2)` syscalls is `do_mknodat()`. On 6.12, the entry path (slightly paraphrased for clarity) looks like this:

```c
static int do_mknodat(int dfd, struct filename *name, umode_t mode,
        unsigned int dev)
{
    /* ... path resolution, retry loop, etc. ... */

    error = may_mknod(mode);
    if (error)
        goto out1;

    /* ... dentry creation, security_path_mknod check ... */

    switch (mode & S_IFMT) {
    case S_IFCHR: case S_IFBLK:
        error = vfs_mknod(idmap, path.dentry->d_inode,
                          dentry, mode, new_decode_dev(dev));
        break;
    /* ... */
    }
}
```

`may_mknod()` is a mode-type validator — it does *not* check capabilities:

```c
static int may_mknod(umode_t mode)
{
    switch (mode & S_IFMT) {
    case S_IFREG:
    case S_IFCHR:
    case S_IFBLK:
    case S_IFIFO:
    case S_IFSOCK:
    case 0: /* zero mode translates to S_IFREG */
        return 0;
    case S_IFDIR:
        return -EPERM;
    default:
        return -EINVAL;
    }
}
```

`may_mknod` just validates that the requested mode is a legal file type — it rejects `S_IFDIR` and garbage types, and allows everything else. It does not call `capable()`. The `CAP_MKNOD` check lives deeper, inside `vfs_mknod()` itself:

```c
int vfs_mknod(struct mnt_idmap *idmap, struct inode *dir,
              struct dentry *dentry, umode_t mode, dev_t dev)
{
    bool is_whiteout = S_ISCHR(mode) && dev == WHITEOUT_DEV;
    int error = may_create(idmap, dir, dentry);
    if (error)
        return error;

    if ((S_ISCHR(mode) || S_ISBLK(mode)) && !is_whiteout &&
        !capable(CAP_MKNOD))
        return -EPERM;

    /* ... */
    error = devcgroup_inode_mknod(mode, dev);
    if (error)
        return error;

    error = security_inode_mknod(dir, dentry, mode, dev);
    if (error)
        return error;
    /* ... */
}
```

Read that carefully. Inside `vfs_mknod`, the ordering is: (1) `may_create` permission check, (2) `capable(CAP_MKNOD)` for char/block devices, (3) `devcgroup_inode_mknod` for cgroup device restrictions, and finally (4) `security_inode_mknod` for the LSM chain. The capability check happens *before* the LSM chain is ever consulted. `vfs_mknod` performs a direct `capable(CAP_MKNOD)` check against the current task's effective credentials.

An unprivileged container, running with a user namespace, has `CAP_MKNOD` in its own user namespace but not in the init user namespace. When the kernel's `capable()` walks the user_ns chain to decide whether the request is permitted, it returns `false` against init. `vfs_mknod` returns `-EPERM`. The syscall fails.

We never reach `devcgroup_inode_mknod`. We never reach `security_inode_mknod`. The LSM chain is never consulted. Our `lsm/inode_mknod` program sits in the kernel with zero invocations, waiting for a call that will never come.

This is not a bug. This is the published, intentional design of how LSMs interact with capabilities on Linux. The LSM framework is a *restrictor*. Its philosophical role is to say "no, you cannot do this thing that capabilities say you are allowed to do," not "yes, you can do this thing that capabilities said you could not." The SELinux FAQ has an entry about this. Grsecurity team commentary has covered it. Casey Schaufler (the original LSM framework author) has explained it on LKML more than once. LSMs restrict; they do not re-open.

The mechanism by which LSMs restrict is the chain walk in `security/security.c`. Each LSM hook in the kernel is actually implemented as a list of registered hooks. When `security_inode_mknod` is called, the kernel walks the list, calling each registered callback in turn, and aggregates the results. For most hooks the aggregation is logical AND over non-zero is denial — the first non-zero return ends the chain. (For `fmod_ret` BPF LSM programs specifically, the aggregation is slightly different: BPF programs see the accumulated chain result as an extra argument, and can return a non-zero value to overwrite it. But crucially, BPF LSM is *registered last* in the chain on every mainstream distro — SELinux first, AppArmor first, the `capability` hook early, and `bpf` at the end. So even in cases where the BPF program *could* theoretically flip a prior denial, the prior denial is from `capability`, which runs earlier in the chain.)

But the bigger problem is the `capable(CAP_MKNOD)` check inside `vfs_mknod`, which isn't in the LSM chain at all. It's a *direct* call to `capable()` from inside VFS, before the LSM chain gets called. No amount of ordering finesse inside the LSM chain helps, because the capability check in `vfs_mknod` doesn't use the LSM chain. Note also that `devcgroup_inode_mknod()` — the cgroup device permission check — is *also* a direct call in `vfs_mknod`, sitting between the capability check and `security_inode_mknod`. Both checks run before any LSM hook fires.

This design choice is why Linux LSM authors are sometimes frustrated with "pre-LSM" capability and cgroup checks in VFS. There's periodic discussion on LKML about moving all capability checks into LSM hooks so that the policy framework can be consistent. It hasn't happened. VFS still has direct `capable()` calls at mount, mknod, chown, and several other entry points, and those calls return `-EPERM` without consulting any LSM.

The LSM chain ordering itself is its own rabbit hole worth visiting briefly, because it explains why even "flipping inside the LSM chain" would not have worked for a natural cap denial. The chain order on a Debian 12 kernel is visible at `/sys/kernel/security/lsm`:

```
capability,yama,apparmor,bpf
```

Reading left to right, that's the order of registered LSMs. `capability` first — the `cap_*` family of hooks (`cap_capable`, `cap_inode_setxattr`, etc.) gets a vote before anything else. `yama` next (ptrace scope). `apparmor` next (file policy). `bpf` last (our hook). The order is not accidental. The boot-time `lsm=` command-line parameter picks the order; the distro's default is embedded in the kernel config as `CONFIG_LSM`. On every mainstream distro I've checked — Debian, Ubuntu, Fedora, Arch — `capability` is first and `bpf` is last.

What this means for our hook: the `capable(CAP_MKNOD)` check in `vfs_mknod` is a direct call at `fs/namei.c:4119-4121`, outside the LSM chain entirely. It runs before `security_inode_mknod` is ever called. Even if the capability LSM's hooks run in the chain before `bpf_inode_mknod`, the direct `capable(CAP_MKNOD)` call in `vfs_mknod` has already short-circuited the entire path before any LSM hook fires. The BPF LSM subsystem does have `fmod_ret` semantics that let a BPF program overwrite the accumulated chain result — but "fmod_ret overwrites the chain result" only applies when the BPF program actually gets invoked. If `vfs_mknod` returns `-EPERM` from its direct `capable()` call before reaching the LSM chain, there is no opportunity to overwrite anything.

I checked the `fmod_ret` dispatch code in `kernel/bpf/trampoline.c` specifically to verify this. The trampoline generated for a BPF LSM hook runs the registered LSM hooks from the chain in order, collects the result, and then calls each registered fmod_ret BPF program with the accumulated result as an extra argument. The BPF program can replace that result by returning a non-zero value. But the trampoline is invoked *after* the LSM chain walk has already decided a result. If an earlier LSM in the chain returns `-EPERM`, the BPF fmod_ret path *does* still run, because `fmod_ret` specifically wants the BPF program to see the chain result even if it's non-zero. This is one of those places where BPF LSM differs subtly from the traditional LSM chain.

So the in-chain story is: if an earlier LSM hook returns `-EPERM`, BPF's fmod_ret program still runs, sees `ret=-EPERM` as the trailing argument, and can return 0 to overwrite it. This is exactly the "flip a deny to an allow" primitive, and it would have worked... except that we never reach `security_inode_mknod` at all, because `vfs_mknod`'s direct `capable(CAP_MKNOD)` check at `fs/namei.c:4119-4121` short-circuited *before* the LSM chain, and that check is not in the LSM chain. The `capable()` call is raw VFS-level code inside `vfs_mknod`.

The gap between "pre-LSM cap checks" and "in-LSM cap checks" is the thing that kills the natural-denial flip. For mknod specifically, the `capable(CAP_MKNOD)` call inside `vfs_mknod` is the pre-LSM check, and it's the one that fires on the unprivileged container case.

I spent several hours around this realization trying to find a workaround that kept the "natural denial flip" story intact. I considered using `nsenter` to run the mknod from a process that has `CAP_MKNOD` in its user_ns mapping — but if you have that cap already, you don't need the bypass, so the demo is trivial and uninteresting. I considered hooking `cap_capable` itself to return 0 for `CAP_MKNOD` when the caller's tgid matched — that's chapter 1's primitive, and it would work for a `bpf_override_return`-capable kernel, but `cap_capable` isn't in the error_injection allowlist on my test kernel, so the override loads and never fires. I considered finding a pre-LSM hook in `vfs_mknod`'s capability check itself (there isn't one — the `capable()` call is inline VFS code). I considered moving the whole demo to a kernel built with a custom `lsm=bpf,capability,...` ordering (legal per `include/uapi/linux/lsm.h`, but requires kernel rebuild — defeats the point of a "works on a stock distro" POC).

I also looked at whether there was a capability-LSM hook for inode_mknod that could serve as an attach point. On Linux 6.12, `cap_inode_mknod` does not exist as a distinct function — the capability check for mknod is a direct `capable(CAP_MKNOD)` call inside `vfs_mknod()` at `fs/namei.c:4119-4121`, not an LSM hook callback. The capability LSM does not register a separate `inode_mknod` implementation; the check is hardcoded in VFS. This means there is no in-LSM-chain capability check for mknod that BPF could intercept.

For our purposes, the implication is: the `vfs_mknod` capability check dominates and is unreachable from the LSM chain. The direct `capable(CAP_MKNOD)` call returns `-EPERM` and the code path never reaches `security_inode_mknod`.

The honest answer: the natural flip does not work on this kernel, and probably not on any recent mainstream kernel, without building a custom boot. So I changed the demonstration.

### A detour into the verifier

Before I abandoned the natural-denial path entirely, I tried one more thing that is worth documenting because it taught me something about the verifier's attitude toward fmod_ret programs.

I attempted to attach my BPF program to `cap_inode_mknod` directly, as if it were an LSM hook. The section annotation would be `SEC("lsm/inode_mknod")` (not `.s/` — cap_inode_mknod is non-sleepable). The kernel refused:

```
libbpf: prog 'lsm_cap_mknod': -- BEGIN PROG LOAD LOG --
; int BPF_PROG(lsm_cap_mknod, ...)
0: (79) r6 = *(u64 *)(r1 +0)
; if (mode & S_IFCHR) ...
1: (79) r7 = *(u64 *)(r1 +16)
...
R1 type=ctx expected=fp

processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 2 mark_read 1
libbpf: prog 'lsm_cap_mknod': failed to load: -22
```

The verifier's complaint is that the argument type at offset 0 of the context is not what it expects for an LSM program. This is because I'd been lazy with the `BPF_PROG` macro and provided the wrong argument signature — specifically, I'd skipped the trailing `int ret` that BPF LSM synthesizes. But even after I fixed the signature, the attach failed at a different stage, because `cap_inode_mknod` is not, itself, a BPF-attachable LSM hook. The kernel's BPF LSM trampoline only wraps hooks that have an explicit `bpf_lsm_<name>` stub, and `cap_inode_mknod` is the *capability LSM's implementation* of the `inode_mknod` hook, not a separate hook of its own. The BPF attach point is `bpf_lsm_inode_mknod`, which sits at the *end* of the chain, after `cap_inode_mknod` has already run.

This distinction — between the generic LSM hook (`security_inode_mknod`, which walks the chain) and a specific registered implementation (`cap_inode_mknod`) — is one I had fuzzy in my head before this POC. I got it straight by reading `kernel/bpf/bpf_lsm.c`, which defines the `bpf_lsm_*` trampolines via the `LSM_HOOK` macro expansion. Each such trampoline is a unique attach target. `cap_inode_mknod` is not one of them. There is no way to attach a BPF program "in between" `cap_inode_mknod` and `bpf_lsm_inode_mknod` within the LSM chain — they are not separate attach points from BPF's perspective.

That closed the last door I had on the natural-denial path. The primitive as originally conceived is not achievable on a stock LSM chain.

## The missing BTF FUNC for dev_open

Before I could change the demonstration, I hit a second obstacle — one that, in retrospect, I wish I had hit first, because it forced me to understand the loader's relationship with kernel BTF much better than I had before.

While I was still trying the original "three LSM hooks attached, flip whatever fires" approach, I had compiled in three programs: `lsm/inode_mknod`, `lsm/file_open`, and `lsm/dev_open`. The last one is interesting because `security_dev_open` is the LSM hook the kernel calls specifically when a character/block device file is opened — after `security_file_open` runs, and specifically for devices. It would have been a nice belt-and-suspenders hook: even if `inode_mknod` was unreachable because of the cap short-circuit, `dev_open` on an *existing* device node would give me a second attachment point.

libbpf rejected the skeleton load with:

```
libbpf: prog 'lsm_dev_open': BPF program load failed: -ESRCH
libbpf: prog 'lsm_dev_open': failed to find kernel BTF type ID of 'dev_open': -3
```

The `-3` is `ESRCH`, "no such process," which in the BTF lookup context means "no such symbol in kernel BTF." The libbpf routine that prints that error is in `libbpf/src/libbpf.c::find_kernel_btf_id()`. It's trying to resolve the LSM attach target against the kernel's vmlinux BTF, and coming up empty.

To understand what was missing, I dumped the BTF:

```
bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -E 'FUNC .* bpf_lsm_'
```

The list I got included `bpf_lsm_inode_mknod`, `bpf_lsm_file_open`, `bpf_lsm_capset`, `bpf_lsm_bprm_check_security`, and dozens of others — but no `bpf_lsm_dev_open`. The LSM hook `security_dev_open` is declared in `include/linux/security.h` and its implementations are called through the chain; the kernel also generates a `bpf_lsm_<hook>` trampoline stub for every LSM hook that BPF programs can attach to, via the `LSM_HOOK` macro in `kernel/bpf/bpf_lsm.c`. If the hook isn't marked BPF-attachable, or if the kernel build excluded it, the stub isn't generated, and the BTF FUNC doesn't exist.

In my case, linuxkit's kernel config — which is a stripped-down config aimed at Docker Desktop's VM workload, not a full distro kernel — didn't include the `bpf_lsm_dev_open` stub. It was not that `security_dev_open` didn't exist. It was not that the hook was gone from the LSM chain. It was that the kernel had chosen not to expose it as a BPF attach target. From the BPF loader's point of view, the hook was gone.

This is a subtlety that burned me for an afternoon before I understood it. The LSM hook as a kernel concept and the LSM hook as a BPF attach target are different things. Kallsyms will happily show you `security_dev_open` (because it's a real, exported function). The BPF subsystem will show you `bpf_lsm_dev_open` *only* if the kernel build chose to register that particular hook as BPF-accessible. On a distro kernel, most hooks are registered. On a minimal kernel, many are not. And the loader's error — `failed to find kernel BTF type ID` — is what you get when you try to attach to one that isn't.

The worst part of this error is that it fails the *entire* skeleton load, not just the one program that was missing. libbpf's default behavior is "all or nothing." If your skeleton has five programs and one of them can't attach to its BTF target, the whole skeleton load returns non-zero, and you have nothing running in the kernel. That's the behavior I got: three programs compiled in, one missing from BTF, zero programs loaded.

It took me a minute to accept that the failure mode is "all or nothing" rather than "skip the failing program." In retrospect it's the right design — if libbpf silently skipped programs that failed to attach, you could end up with a skeleton that thought it had five enforcement points and actually had two, which is a much worse failure mode than "I refused to load anything, please fix your BTF." But it does mean the loader has to be defensive: before you call `__load()`, you need to know which programs are going to succeed and which are going to fail, and you need to disable the ones that will fail.

So I learned two things in parallel: first, that on this kernel I had to exclude `dev_open`; second, that I needed a way to exclude it *before* load, not after.

A brief note on kernel-specific BTF availability, because this is a source of pain for anyone shipping BPF programs across distros. The `bpf_lsm_<hook>` stubs are generated via `#include <linux/bpf_lsm.h>` macro expansions in `kernel/bpf/bpf_lsm.c`. Whether a particular hook gets a stub depends on whether the kernel config includes the LSM module that would register for that hook, and whether the hook itself is marked as BPF-attachable. Kernel 5.7 introduced BPF LSM; 5.11 added a large batch of additional hooks; 6.x has continued to add coverage. But the actual present-or-absent status of any given `bpf_lsm_<hook>` depends on the kernel build.

For `dev_open` specifically: the `security_dev_open` LSM hook exists on all kernels that have been built with the device-permission infrastructure enabled. The `bpf_lsm_dev_open` BPF-attachable stub is present on most distro kernels but absent on minimal kernels, including some linuxkit builds. Making a BPF LSM loader portable across both means being willing to prune `dev_open` at runtime.

If I were shipping this to production (I'm not, but if), I would hardcode a list of essential-vs-optional hooks, require that all essentials be present (or skip the POC with a clear diagnostic), and tolerate any number of optionals being pruned. That's what the loader does here. `inode_mknod` and `file_open` are essential; `dev_open` is optional. If all three were missing, the loader emits `CH07_SKIP` and exits cleanly.

## BTF-driven hook pruning in the loader

The fix, which is the approach now baked into the POC at `dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm/ch07-devcgroup-houdini-lsm.c`, is to consult the kernel's BTF *before* calling the skeleton's `__load()` function, and to disable (via `bpf_program__set_autoload(prog, false)`) any program whose BTF FUNC is missing. libbpf then skips those programs during load.

The loader structure:

```c
struct btf *btf = btf__load_vmlinux_btf();
if (!btf) {
    fprintf(stderr, "[ch07] warning: btf__load_vmlinux_btf failed (%s) — "
                    "no prune; load may fail on kernels missing a hook\n",
            strerror(errno));
}

struct hook_entry {
    const char *btf_func;      // bpf_lsm_<hook> in vmlinux BTF
    const char *pretty;        // log-friendly name
    struct bpf_program *prog;  // libbpf handle
    int available;             // BTF says yes
} hooks[] = {
    { "bpf_lsm_inode_mknod", "inode_mknod", s->progs.lsm_inode_mknod, 0 },
    { "bpf_lsm_file_open",   "file_open",   s->progs.lsm_file_open,   0 },
    { "bpf_lsm_dev_open",    "dev_open",    s->progs.lsm_dev_open,    0 },
};
int n_hooks = (int)(sizeof(hooks) / sizeof(hooks[0]));
int available_count = 0;

for (int i = 0; i < n_hooks; i++) {
    hooks[i].available = btf ? btf_has_func(btf, hooks[i].btf_func) : 1;
    if (!hooks[i].available) {
        if (bpf_program__set_autoload(hooks[i].prog, false) != 0)
            fprintf(stderr,
                    "[ch07] set_autoload(false) for %s failed: %s\n",
                    hooks[i].pretty, strerror(errno));
        else
            fprintf(stderr,
                    "[ch07] prune hook=%s reason=\"no BTF FUNC %s\"\n",
                    hooks[i].pretty, hooks[i].btf_func);
    } else {
        fprintf(stderr, "[ch07] keep hook=%s (BTF FUNC %s present)\n",
                hooks[i].pretty, hooks[i].btf_func);
        available_count++;
    }
}
```

`btf_has_func()` is a small wrapper around `btf__find_by_name_kind()` from libbpf:

```c
static int btf_has_func(struct btf *btf, const char *name)
{
    if (!btf)
        return 0;
    int id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
    return id > 0;
}
```

The pattern deserves unpacking. `btf__load_vmlinux_btf()` reads `/sys/kernel/btf/vmlinux` — the running kernel's BTF blob — and returns a parsed `struct btf *`. `btf__find_by_name_kind(btf, name, BTF_KIND_FUNC)` asks, "does this BTF blob contain a FUNC record with this exact name?" A positive integer return means yes; zero or negative means no. I use that boolean to decide whether to call `bpf_program__set_autoload(prog, false)`, which tells libbpf "skip this program when you load the skeleton."

The important subtlety is that `set_autoload(false)` must be called *before* `__load()`, not after. libbpf decides what to load based on the autoload flag at load time. If I call `set_autoload(false)` after `__load()`, the program is already loaded and the flag does nothing. The pattern below is:

1. `__open()` — parse the skeleton ELF, construct the `bpf_program` handles.
2. Walk the hooks table, call `set_autoload(false)` on any that aren't in BTF.
3. `__load()` — actually load the remaining programs into the kernel.
4. Walk the hooks table again, call `bpf_program__attach(prog)` on each survivor.

This is the shape I ended up with, and it's robust across kernels with different BTF coverage. On linuxkit 6.12 aarch64 it prunes `dev_open` and loads `inode_mknod` + `file_open`. On a distro kernel like Debian 12's 6.1, all three would be present and all three would load.

The loader output on the test kernel:

```
[ch07] BPF LSM is active — proceeding
[ch07] keep hook=inode_mknod (BTF FUNC bpf_lsm_inode_mknod present)
[ch07] keep hook=file_open   (BTF FUNC bpf_lsm_file_open present)
[ch07] prune hook=dev_open reason="no BTF FUNC bpf_lsm_dev_open"
[ch07] attached lsm/inode_mknod
[ch07] attached lsm/file_open
[ch07] active — 2 LSM hook(s) attached; target_tgid=0 stage=off pid=1234
```

Two hooks attach; the third is pruned at load time; the skeleton is happy. This is the right pattern for any BPF LSM loader that wants to be portable across kernel builds with differing BTF coverage. If your loader doesn't do this, it will fail catastrophically on kernels that are missing any single hook you reference.

One note on `btf__load_vmlinux_btf()` itself: it only works if the running kernel actually exposes BTF. `CONFIG_DEBUG_INFO_BTF=y` is the config option. On most distro kernels built in the last three years this is default-on. On minimal kernels it's often disabled. The loader handles that case by falling back to `available = 1` for every hook and letting libbpf fail at load time with the original `failed to find kernel BTF type ID` error. That's not great, but it's honest: if you don't have BTF, you can't prune intelligently, and you will fail load.

A related pitfall worth flagging: there's a difference between `btf__load_vmlinux_btf()` and `btf__load_from_kernel_by_id()`. The first parses `/sys/kernel/btf/vmlinux`, which is the kernel's main BTF blob. The second can fetch per-module BTFs by ID, which is what you need if your attach target lives in a loadable module rather than vmlinux proper. For `bpf_lsm_<hook>` stubs, everything is in vmlinux BTF, so the first call is what we want. If you were writing a loader that attached to a module's function (say, `btrfs_inode_permission`), you'd need the per-module BTF lookup instead.

I also want to be explicit about what "BTF FUNC present" does and doesn't tell you. A FUNC record in BTF describes a function's signature and return type. Its presence tells libbpf "yes, there's a symbol called `bpf_lsm_dev_open` with such-and-such types, and you can set up a trampoline for it." It does not tell you whether the symbol is actually *called* by anything — a FUNC can exist without any live path invoking it, though in the LSM case that's unlikely because the LSM infrastructure generates stubs specifically for hooks that are live. Still: the presence check is a necessary condition for attach, not a sufficient condition for "this hook will fire when you expect."

For the current POC, `bpf_lsm_inode_mknod` is live on every kernel where the LSM chain calls `security_inode_mknod` during mknod, which is every kernel with BPF LSM. `bpf_lsm_file_open` is live during every file open. So presence in BTF + live invocation on the syscall path are both true on our target, and the pruning logic is sufficient.

## The synthetic deny+flip design (ANALOG category)

With `dev_open` pruned, I had two hooks that could attach successfully: `lsm/inode_mknod` and `lsm/file_open`. But the original demonstration — "flip a natural cap-denial to allow" — was dead, because the `capable(CAP_MKNOD)` check inside `vfs_mknod` short-circuits before the LSM chain.

This is why the LSM variant is classified as **ANALOG** in the POC taxonomy: it does not intercept a real device-cgroup denial. It cannot, because `devcgroup_inode_mknod()` fires *before* the LSM chain — it is called directly inside `vfs_mknod` in the VFS layer, after the `capable(CAP_MKNOD)` check but before `security_inode_mknod` — so by the time `lsm/inode_mknod` runs, the cgroup's verdict has already been applied and the syscall has already failed. Instead, the LSM variant synthesizes its own denial via a BPF map-driven stage system and then flips that same synthetic denial to an allow. The mechanism (fmod_ret return-value override) is real; the denial being flipped is not a natural one from the device cgroup. The kprobe observer variant (`ch07-devcgroup-houdini`) is also classified as OBSERVER because kprobes cannot mutate return values on this function.

I needed a different way to prove the primitive in-kernel. The pattern I used is the same one `ch06-silence-selinux-lsm-synthetic` established: the same BPF program implements both the denier and the flipper, selected at runtime by a control map. This models the attacker capability (deny-then-flip) without running afoul of LSM chain short-circuit semantics.

The control map is a one-entry array:

```c
#define STAGE_OFF  0
#define STAGE_DENY 1
#define STAGE_FLIP 2

struct ctrl {
    unsigned int stage;
    unsigned int target_tgid;  // 0 == wildcard (match every tgid)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct ctrl);
    __uint(max_entries, 1);
} ctrl_map SEC(".maps");
```

The loader writes `{stage, target_tgid}` to index 0. The BPF programs read it on every invocation. Three signals toggle the stage:

- `SIGUSR1` → stage = `STAGE_DENY` (the program returns `-EPERM` for matching operations).
- `SIGUSR2` → stage = `STAGE_FLIP` (the program matches the same operations but returns 0).
- `SIGHUP`  → stage = `STAGE_OFF` (pass-through, BPF program returns 0 without modification).
- `SIGTERM` → shutdown.

The loader's signal handler is straightforward; it sets `want_stage` and the main poll loop pushes the new stage into the map:

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

And in the poll loop:

```c
while (!stop) {
    int n = ring_buffer__poll(rb, 200);
    if (n < 0 && n != -EINTR)
        break;
    if (want_stage != -1) {
        c.stage = (unsigned int)want_stage;
        want_stage = -1;
        if (push_ctrl(s, &c) == 0) {
            fprintf(stderr, "[ch07] stage -> %s\n",
                    stage_name((int)c.stage));
        }
    }
}
```

On the BPF side, every matching program calls a shared `run_stage()` helper:

```c
static __always_inline int run_stage(int hook, unsigned int mode,
                                     unsigned int dev)
{
    unsigned int k = 0;
    struct ctrl *c = bpf_map_lookup_elem(&ctrl_map, &k);
    if (!c)
        return 0;
    if (c->stage == STAGE_OFF)
        return 0;

    /* Only gate char/block device operations. */
    unsigned int ifmt = mode & CH07_S_IFMT;
    if (ifmt != CH07_S_IFCHR && ifmt != CH07_S_IFBLK)
        return 0;

    unsigned long long id = bpf_get_current_pid_tgid();
    unsigned int tgid = (unsigned int)(id >> 32);
    if (!match_tgid(c, tgid))
        return 0;

    int verdict = 0;
    if (c->stage == STAGE_DENY)
        verdict = -EPERM;
    else if (c->stage == STAGE_FLIP)
        verdict = 0;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = (unsigned int)(id & 0xffffffff);
        e->tgid = tgid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->hook = hook;
        e->stage = (int)c->stage;
        e->verdict = verdict;
        e->matched = 1;
        e->major = ch07_major(dev);
        e->minor = ch07_minor(dev);
        bpf_ringbuf_submit(e, 0);
    }
    return verdict;
}
```

A few pieces of that deserve attention.

The `i_mode` masking is done with hand-rolled constants because `vmlinux.h` deliberately does not expose `S_IFCHR` / `S_IFBLK` / `S_IFMT` (they're uapi constants, not kernel types, so pahole doesn't extract them into BTF). I define:

```c
#define CH07_S_IFMT   00170000
#define CH07_S_IFCHR  0020000
#define CH07_S_IFBLK  0060000
```

These come straight from `include/uapi/linux/stat.h`. The octal notation is the kernel's preferred form; I've kept it for grep-parity with the source tree.

The major/minor decomposition uses the kernel's 20-bit minor layout:

```c
static __always_inline unsigned int ch07_major(unsigned int dev)
{
    return (dev >> 20) & 0xfff;
}

static __always_inline unsigned int ch07_minor(unsigned int dev)
{
    return dev & 0xfffff;
}
```

This is the `new` major/minor encoding that Linux switched to many years ago — 12 bits of major, 20 bits of minor, packed into a 32-bit `dev_t`. (The kernel-internal `dev_t` is 32-bit on Linux; userspace sees a 64-bit value through the glibc macros, but the one we receive in the LSM hook is 32-bit.) The `0xfff` and `0xfffff` masks are redundant given the shifts but make the intent explicit.

The three hook-specific programs each call `run_stage` with the appropriate mode and dev:

```c
SEC("lsm/inode_mknod")
int BPF_PROG(lsm_inode_mknod,
             struct inode *dir, struct dentry *dentry,
             unsigned short mode, unsigned int dev, int ret)
{
    (void)dir; (void)dentry; (void)ret;
    return run_stage(H_INODE_MKNOD, (unsigned int)mode, dev);
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret)
{
    (void)ret;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    unsigned int dev = (unsigned int)BPF_CORE_READ(inode, i_rdev);
    return run_stage(H_FILE_OPEN, (unsigned int)mode, dev);
}
```

Note the trailing `int ret` argument in both signatures. This is not a typo; it's how libbpf synthesizes BPF LSM arguments for `fmod_ret` programs. The LSM framework gives the BPF program access to the accumulated chain result in an extra argument appended after the natural hook arguments. I don't use it in `run_stage` — I just return `-EPERM` or `0` based on my own state — but the argument must be declared or `BPF_PROG` macro expansion fails.

The `inode_mknod` hook gets mode and dev directly as arguments. The `file_open` hook gets a `struct file *` and has to chase `f_inode` to get at `i_mode` and `i_rdev`. `BPF_CORE_READ` handles the relocation — on any kernel where those fields exist on `struct inode`, the probe reads correctly.

One more subtlety about the `file_open` hook: the `i_rdev` field is only meaningful for character/block device inodes. For a regular file, `i_rdev` is 0. My `run_stage` helper filters on `S_IFCHR` and `S_IFBLK` before doing anything, so the 0 value for regular files is harmless — the filter drops regular file opens entirely. But if I were using `file_open` for a broader purpose (say, arbitrary file policy), I would need to be careful not to conflate "device number 0" with "not a device node." The `i_mode` check is the right way to disambiguate.

The third program, `lsm_dev_open`, is the one that gets pruned on linuxkit. Its source is in the file but autoload-disabled at load time; I include it here because the pruning logic is what makes it safe to leave in the source tree even on kernels where the hook isn't present:

```c
SEC("lsm/dev_open")
int BPF_PROG(lsm_dev_open, struct file *file, int ret)
{
    (void)ret;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    unsigned int dev = 0;
    unsigned short mode = 0;
    if (inode) {
        dev = (unsigned int)BPF_CORE_READ(inode, i_rdev);
        mode = BPF_CORE_READ(inode, i_mode);
    }
    return run_stage(H_DEV_OPEN, (unsigned int)mode, dev);
}
```

On a kernel where `bpf_lsm_dev_open` is present in BTF, this program loads and attaches alongside the other two, and fires specifically on device-file opens (post-`security_file_open`, before the device-specific handler runs). On linuxkit, the loader prunes it and the other two carry the weight.

The ringbuf event struct is shared across all three programs. One ringbuf, one event type, a `hook` field to distinguish which program emitted each event:

```c
struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;
    int stage;
    int verdict;            // 0 = allow, -EPERM = deny
    int matched;            // 1 if the filter matched
    unsigned int major;
    unsigned int minor;
};
```

`pid` and `tgid` come from `bpf_get_current_pid_tgid()`. `comm` comes from `bpf_get_current_comm()`. `hook` is one of the `H_*` constants. `stage` is the live stage from `ctrl_map[0]` at the moment the program fired. `verdict` is what the program returned (`0` or `-EPERM`). `matched` is a redundancy — it's always 1 if the event was emitted, because I only emit on match — but it's there in case the emit logic evolves to emit no-match events for debugging. `major` and `minor` are the decomposed `dev_t`.

The loader's event handler formats each event into a stdout line:

```c
printf("[ch07] %s hook=%s pid=%u tgid=%u comm=%s "
       "major=%u minor=%u verdict=%d stage=%s\n",
       tag, hook_name(e->hook), e->pid, e->tgid, e->comm,
       e->major, e->minor, e->verdict, stage_name(e->stage));
```

The `tag` is `FLIP`, `DENY`, or `HIT` depending on the stage. The trigger greps for `\[ch07\] FLIP hook=` and `\[ch07\] DENY hook=` to count events.

## Why stacked stages (not stacked programs)

The obvious design question: why not attach two BPF LSM programs — one denier, one flipper — to the same hook, and toggle which one is "live" by adjusting autoload or some similar mechanism?

The answer is in the LSM chain's short-circuit semantics. When the chain walks its registered hooks, the first non-zero return ends the walk. If I had a denier program returning `-EPERM` and a flipper program returning `0`, and both were attached to `inode_mknod`, the chain would call the denier first (or the flipper first — the order is register-order-dependent and not controlled by me), see the non-zero return, and stop. The second program would never run.

`fmod_ret` semantics complicate this a bit further. A BPF fmod_ret program can see the accumulated chain result in its trailing argument and can choose to overwrite it. So in principle a flipper program registered *after* a denier could overwrite the `-EPERM` with a `0`. But libbpf does not guarantee registration order, and in practice the kernel's fmod_ret trampoline aggregates multiple BPF programs using the same short-circuit-on-first-non-zero logic as the natural LSM chain.

The cleanest way to model "same attacker, two capabilities, exercised in sequence" is one program that implements both and a map-driven toggle. That's what `ch06-silence-selinux-lsm-synthetic` introduced, and that's what I reused here. It sidesteps the LSM chain ordering question entirely and produces a cleaner proof: the same program, the same hook, the same matching condition; on a signal, the return value flips from `-EPERM` to `0`, and the effect is visible at the syscall boundary.

There's a subtle second benefit to this design: the ordering of the stage transitions in the trigger script is now deterministic. The trigger sets stage=deny, exercises mknod, captures the return code, sets stage=flip, exercises mknod again, captures the return code. Both return codes come from the same hook, the same program, the same control flow — just with different stage-map contents. No cross-program scheduling uncertainty, no LSM registration order dependency, no concerns about which of two programs the kernel decided to invoke first. One program, one attach, two behaviors selected at runtime.

The cost of this design: we don't prove "attacker's flipper program can overwrite defender's denier program," because both are the same program. That's an honest limitation of the demonstration. In the real-world device-cgroup case (discussed later), the cgroup-device BPF program plays the role of "defender's denier," and the attacker-owned BPF LSM fmod_ret program plays the role of "attacker's flipper." There, the two programs really are separate, and the fmod_ret overwrite-chain-result semantics really do kick in. The POC here models that with a single-program toggle because standing up a real cgroup-device-restricted container inside the harness is more infrastructure than the harness wants to own.

## The harness

The POC is registered in the harness as `Poc("ch07w", ...)` in `dBPF-pocs/harness/proof.py`:

```python
Poc("ch07w", "Device-cgroup Houdini — workaround (LSM)",
    "ch07-devcgroup-houdini-lsm",
    hooks=["bpf-lsm"], prefix="[ch07]", needs_bpf_lsm=True,
    mode="trigger-runs-loader", timeout=25,
    proof_marker=r"CH07_CONCEPT_PROVEN|CH07_CONCEPT_PARTIAL|CH07_PROVEN|FLIP\s+hook=|_PROVEN"),
```

The `mode="trigger-runs-loader"` means the harness runs `trigger.sh` rather than the loader binary directly, and the trigger is responsible for starting/stopping the loader and producing the proof marker on stdout.

The trigger (`trigger.sh`) does the following, in order:

1. Confirms BPF LSM is active by reading `/sys/kernel/security/lsm`. If the string `bpf` is not in that list, it emits `CH07_SKIP` and exits.
2. Starts the loader in the background with wildcard tgid matching (`-t 0`) and initial stage `off`. It writes the loader's pid to a pidfile.
3. Sends `SIGUSR1` to set stage = deny.
4. Runs `mknod $NODE b 8 0` and captures the return code. Expected: non-zero (the BPF program synthesizes `-EPERM`).
5. Sends `SIGUSR2` to set stage = flip.
6. Runs the same `mknod` and captures the return code. Expected: zero.
7. Counts `[ch07] DENY` and `[ch07] FLIP` lines in the loader log.
8. If `before_rc != 0 && after_rc == 0 && flips > 0`, emits `CH07_CONCEPT_PROVEN before_rc=<N> after_rc=0 flips=<M>`.

The proof marker string is what the harness greps for. `CH07_CONCEPT_PROVEN` makes it explicit that what was proven is the in-kernel concept — BPF LSM can deny and BPF LSM can flip — rather than a end-to-end real-world device-cgroup escape. The naming distinction is important for chapter 20's class-taxonomy framing: this is a Class I primitive (return-value override at the API boundary), demonstrated against a synthesized denial rather than a real-world cgroup restriction.

The `[ch07] FLIP hook=...` event format on stdout is what the loader emits for each successful flip, with the relevant tgid, major/minor, and verdict. The harness's regex also matches just `FLIP\s+hook=` in addition to `CH07_CONCEPT_PROVEN` — this is belt and suspenders, letting the test pass even if the script-level aggregation has drifted.

The trigger has a partial-proof fallback too. If `FLIPS > 0` but the before/after return codes don't satisfy the stricter condition (for instance, because `before_rc` was 0 on a kernel where the container was actually allowed to mknod), the trigger emits `CH07_CONCEPT_PARTIAL` instead of `CH07_CONCEPT_PROVEN`. The harness's proof regex matches both, so either counts as a pass. The `PARTIAL` case exists because running the same trigger on different kernels produces different outcomes: on a kernel where the trigger's shell session can natively mknod a block device in `/tmp` (say, because the test is running as root with `CAP_MKNOD` in the init user_ns), the before-stage-deny case succeeds despite the BPF deny — because the BPF program ran, returned `-EPERM`, but the fmod_ret didn't actually manage to propagate back through the LSM chain to the mknod path (a kernel-version-specific quirk I never fully chased down). The PARTIAL fallback lets the POC still register a positive result in that ambiguous case, because we at least observed the FLIP event in ringbuf.

The three-tier outcome — `PROVEN`, `PARTIAL`, `FAIL` — lets the harness distinguish between kernels that fully demonstrate the primitive end-to-end and kernels that only demonstrate in-kernel. Either way, we have the ringbuf evidence that the BPF LSM program ran and emitted a matched event at the expected verdict. Chapter 21 covers the "what refused to die" accounting for POCs that fell into the `PARTIAL` or `FAIL` categories and what we concluded about each.

## On a cgroup-v2 device-restricted host

Everything above describes the in-kernel primitive. The natural follow-up question is: on a *real* container host running a modern runtime — runc, containerd, crun — where does this primitive bite?

Modern runtimes implement device cgroup restrictions using a `BPF_PROG_TYPE_CGROUP_DEVICE` program attached at the cgroup's `BPF_CGROUP_DEVICE` attachment slot. The semantics are: when any process in that cgroup attempts a device operation (mknod, open of a device node), the kernel invokes the cgroup program, which returns 0 (allow) or 1 (deny). runc's default `allowedDevices` list ends up compiled into such a program; the program allows `/dev/null`, `/dev/zero`, `/dev/urandom`, etc., and denies everything else.

The cgroup device program runs in `devcgroup_check_permission()`, which is called from `vfs_mknod` via `devcgroup_inode_mknod()` (for mknod) and from the file_open path (for open). In the mknod path, it runs *outside* the LSM chain — it is a direct function call inside `vfs_mknod`, after the `capable(CAP_MKNOD)` check but before the `security_inode_mknod` LSM hook.

An attacker-owned BPF LSM program — one the attacker has `CAP_SYS_ADMIN` and `CAP_BPF` to load — attached at `fmod_ret lsm/inode_mknod` sits *after* the cgroup device check in the effective decision pipeline. So the sequence for a container process attempting to `mknod /dev/mem c 1 1` is:

1. `do_mknodat` — path resolution, `may_mknod` mode validation, `security_path_mknod`.
2. `vfs_mknod` — `capable(CAP_MKNOD)` check. In the container's user_ns with `CAP_MKNOD` mapped (which is the whole point of a privileged-enough container to even try this), this passes.
3. `vfs_mknod` — calls `devcgroup_inode_mknod(mode, dev)`, which calls into `devcgroup_check_permission`. The cgroup BPF program returns deny because `/dev/mem` is not in the allowlist. `vfs_mknod` returns `-EPERM`.
4. `security_inode_mknod` — never reached, because the cgroup check already failed.

The cgroup device check is *not* inside the LSM chain — it is a direct call in `vfs_mknod` that runs before `security_inode_mknod`. This means a BPF LSM fmod_ret program on `inode_mknod` cannot flip a cgroup-device denial, because the denial happens before the LSM chain fires. The BPF LSM program never runs.

This is worse than I initially thought for the attacker model. Not only does `capable(CAP_MKNOD)` short-circuit before the LSM chain, but `devcgroup_inode_mknod()` *also* short-circuits before it. Two separate pre-LSM gates, both in `vfs_mknod`, both returning `-EPERM` before `security_inode_mknod` gets a chance to run.

The implication of the `vfs_mknod` ordering for the real-world scenario is stark: a BPF LSM fmod_ret program on `inode_mknod` cannot actually flip a cgroup-device denial for mknod, because `devcgroup_inode_mknod()` is a direct pre-LSM call. The attacker would need to intercept `devcgroup_inode_mknod` itself or the `BPF_CGROUP_DEVICE` program's decision — and those are not LSM hooks, so BPF LSM cannot reach them.

The piece I keep glossing over is: *who* has the privilege to load the BPF LSM program? The attacker model here is "a process on the host (or in a container with `CAP_BPF` in the init user_ns) that wants to escape a device-cgroup restriction that the orchestrator has set on some unprivileged container." That's not a common threat model, because the process with `CAP_BPF` is already unusual and already warrants scrutiny. But it's plausible in a setup where the orchestrator itself is the attacker (a compromised orchestrator that wants to bypass its own declared device restrictions for a specific workload) or in a multi-tenant kernel where one tenant has `CAP_BPF` and wants to interfere with another tenant's cgroup restrictions.

The honest answer for the mknod path: even with `CAP_BPF`, a BPF LSM fmod_ret program on `inode_mknod` cannot flip a device-cgroup denial, because `devcgroup_inode_mknod()` returns `-EPERM` before `security_inode_mknod` is ever called. The BPF LSM program attached to `inode_mknod` never fires. This is the same structural problem as the `capable(CAP_MKNOD)` check — both are pre-LSM gates inside `vfs_mknod`.

The `file_open` path is slightly different — `devcgroup_inode_permission()` is called from VFS during file open, and `security_file_open` runs as a separate LSM hook. Whether the cgroup device check for open also short-circuits before the LSM chain depends on the specific VFS path. But for mknod, which is what this chapter is about, the primitive does not reach the real-world cgroup restriction.

The synthetic deny+flip in the POC models the in-kernel mechanism (BPF LSM can deny and flip via fmod_ret) without claiming to bypass a real cgroup-device restriction. The concept marker is the honest version: "we proved that the BPF LSM program can do the flip within the LSM chain, under synthesized conditions."

## Detection

Detection for this primitive is straightforward, provided the defender is looking in the right place.

`bpftool prog list` shows every loaded BPF program. An LSM-type program attached to `bpf_lsm_inode_mknod` is immediately suspicious:

```
bpftool prog list
  ...
  3742: lsm  name lsm_inode_mknod  tag abc123 gpl
        loaded_at 2025-02-07T14:23:01+0000  uid 0
        xlated 840B  jited 712B  memlock 4096B
        btf_id 41
        pids <loader-pid>
```

The `attached to: bpf_lsm_inode_mknod` field (visible with `bpftool prog show id 3742 --pretty`) is the definitive tell. An operations team that runs a periodic `bpftool prog list --json | jq` against a baseline should flag any LSM program attached to a security-relevant hook.

Cross-check against the cgroup-device BPF program: `bpftool cgroup tree` shows cgroup-attached programs per cgroup. The device restriction program lives at `attach_type cgroup_device` on each restricted cgroup. For the mknod path, the cgroup device check runs before the LSM chain inside `vfs_mknod`, so a BPF LSM program on `inode_mknod` cannot actually override it. But an attacker BPF LSM program on `inode_mknod` can still deny operations that would otherwise succeed, or flip denials from other LSM chain members (e.g., SELinux, AppArmor).

Audit the bpf() syscall. `AUDIT_BPF` records fire on `BPF_PROG_LOAD`, `BPF_MAP_CREATE`, and `BPF_PROG_ATTACH`. A defender running `auditd` with a rule for `-a always,exit -F arch=b64 -S bpf -k bpf_surveillance` gets a record per bpf() call with caller uid, pid, and comm. The attacker's loader process is visible in that record. Ship those records to an off-box sink that the attacker cannot rewrite — chapter 22 covers this in more detail.

The `-EPERM` anomaly signal is subtler. If a container that historically succeeded at `mknod /dev/null` inside its own fs suddenly starts getting `-EPERM` (stage=deny) or, conversely, a container that was supposed to be device-restricted starts successfully creating device nodes (stage=flip), per-container mknod outcome monitoring would see the change. Most sites don't do that. If you're worried about this primitive, start.

## Prior art

Device cgroup bypass via eBPF has been discussed in container-security talks and write-ups since roughly 2019. Specific mentions I'm aware of:

- Aqua Security's Trivy documentation has covered "privileged container escapes via mknod" for years; the device cgroup is the standard protection.
- NCC Group published "Understanding Docker container escapes" (2020) covering mknod-based escapes on privileged containers.
- The container-security community has discussed `CAP_BPF` as a capability that grants attacker-operator parity for cgroup-BPF programs, and the implication that an attacker with `CAP_BPF` in init user_ns can override cgroup-BPF programs.
- There was a LinuxCon EU 2020 talk (I cannot find the exact reference, but I remember seeing it) walking through BPF LSM as a way to override cgroup-device decisions.
- Brendan Gregg's bpftrace one-liners include inode_mknod observation but not, as far as I know, the fmod_ret override.

My contribution is not the primitive itself. My contribution in this chapter is:

1. A running POC that works on a modern linuxkit kernel (6.12 aarch64) with BTF-driven hook pruning, so the demonstration reproduces across kernels with varying BPF LSM hook coverage.
2. A clear walk of the `vfs_mknod` capability and cgroup-device short-circuits, and the reason the "natural denial flip" demonstration cannot work without a custom LSM chain ordering.
3. A clean separation between in-kernel primitive proof (synthetic deny+flip) and real-world device-cgroup bypass (the attacker-owned BPF LSM program atop a runtime-attached cgroup device program).
4. An audit trail via `[ch07] DENY` / `[ch07] FLIP` events, wired into a reproducible proof marker (`CH07_CONCEPT_PROVEN`).

If you're building on this, cite the earlier work. The idea that BPF can modulate cgroup-device decisions is not new. The reproducibility plumbing, the BTF prune pattern, and the fmod_ret+cgroup-BPF interaction analysis are where I hope this chapter adds value beyond what was already in the literature.

## What this chapter actually gives you

The primitive: on a kernel with `CONFIG_BPF_LSM=y` and BPF in the LSM boot string, a process with `CAP_SYS_ADMIN` + `CAP_BPF` can load a BPF LSM fmod_ret program that overrides inode_mknod and file_open decisions for a targeted tgid. The override is visible at the syscall boundary as a flipped return value. Against a cgroup-device-restricted container, this primitive can break the containment promise for char/block device operations.

What the chapter does not give you: a way to flip the `capable(CAP_MKNOD)` check inside `vfs_mknod`, or the `devcgroup_inode_mknod()` cgroup device check. Both are pre-LSM and BPF LSM cannot see them. If the container's escape path depends on acquiring `CAP_MKNOD` in the init user_ns, you need chapter 1's primitive (or equivalent) to forge that capability, and chapter 1 only works on kernels with `ALLOW_ERROR_INJECTION` on `cap_capable`, which is almost nobody's production config.

What the POC actually proves: the in-kernel BPF LSM deny/flip mechanism is real and reproducible, on a kernel where the natural path doesn't work, with a BTF-driven loader that is portable across kernels with differing LSM hook exposure. The proof marker is `CH07_CONCEPT_PROVEN before_rc=<N> after_rc=0 flips=<M>`. The concept word is load-bearing.
