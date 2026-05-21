---
layout: book
title: "Chapter 1: The Mirror Controls"
date: 2025-01-31
---

# Chapter 1: The Mirror Controls

> **See also**: [Blog post]({{ site.baseurl }}/the-mirror-controls.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch01-mirror-controls-lsm) · [Legacy kprobe variant](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch01-mirror-controls)

> **Proof status**: Both `ch01-mirror-controls` (kprobe+kretprobe) and `ch01-mirror-controls-lsm` (BPF LSM fmod_ret) have been proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). The kprobe variant was updated to deliver `bpf_send_signal(SIGUSR1)` to the target process on every capability denial; the ringbuf event records this in the `signal_sent` field under tag `FLIP`. The `-a` wildcard flag was added to the userspace loader to arm wildcard targeting. The LSM variant required no changes.

I started this chapter wanting to override a capability check from BPF, spent a week figuring out why that does not work on a stock kernel, and ended up writing two proofs of concept. The second one — a BPF LSM program that returns `0` from `lsm/inode_permission` where the kernel would have returned `-EACCES` — is the one that actually grants access. That is the primary for this chapter. The first one (the kprobe on `cap_capable` with `bpf_send_signal`) is a cautionary tale and lives in a sidebar near the end.

The primitive, stated plainly: on a kernel with `CONFIG_BPF_LSM=y` and `bpf` present in `/sys/kernel/security/lsm`, a BPF program can attach as a fmod_ret hook on `security_inode_permission`, and its return value replaces the kernel's. If the kernel was going to deny a VFS access with `-EACCES`, the BPF program returns `0` and the read or write proceeds. There is no error-injection allowlist to clear, no silent no-op, no illusion layered on top of a real deny. The kernel actually permits the access, and the caller's subsequent code runs against real filesystem state. That is what I could not do with a kprobe.

## Preconditions and the skip story

The LSM fmod_ret path only exists on kernels that were built and booted to accept it. Three knobs matter:

1. **`CONFIG_BPF_LSM=y`** at kernel build time. Without this, the `BPF_PROG_TYPE_LSM` program type is not registered and the loader fails at `BPF_PROG_LOAD` with `-EINVAL`. Fedora 38+ ships it on by default; Ubuntu LTS and Debian stable ship it off historically but have been turning it on in recent spins; Docker Desktop's linuxkit VM does not ship it.
2. **`bpf` in `/sys/kernel/security/lsm`**. The kernel is built with LSM stacking support, and the active LSM set is determined by the `lsm=` boot cmdline (or the CONFIG default). The BPF LSM has to be in that active set or fmod_ret programs have no chain to attach into. The loader reads `/sys/kernel/security/lsm`, looks for the substring `bpf`, and exits with `CH01_SKIP reason="BPF LSM not active"` if it is absent. The trigger does the same check with `grep -q bpf /sys/kernel/security/lsm` before it does anything else.
3. **Kernel 6.14+ for `lsm/inode_permission` specifically.** I tried `lsm/capable` first. On kernels where `security_capable` short-circuits around the LSM chain for non-root processes — which is the common case from about 6.12 onward — a BPF LSM program attached to `capable` never fires on the calls that would actually matter. `inode_permission` is called from inside `do_inode_permission`, which is invoked on every `vfs_read` / `vfs_write` and on every path that opens a file. That hook fires reliably. On 6.14+ the fmod_ret machinery around it is stable; on older kernels the attach succeeds but the trampoline behavior has enough edge cases that I would not trust it without retesting per-version.

If any of the three is missing, the honest thing to do is skip. The loader and the trigger both do. `trigger.sh` emits `=== CH01_SKIP reason="BPF LSM not active in /sys/kernel/security/lsm" ===` and exits zero; the loader emits `[ch01-lsm] CH01_SKIP reason="BPF LSM not active"` and exits with a non-zero code. There is no fallback to the kprobe variant inside this PoC. A reader on linuxkit or on a default Debian kernel will see the skip and move on, which is what I wanted — the chapter's claim is about what you can do on a kernel with BPF LSM, not about what you can fake on one without.

## The BPF program, line by line

The whole kernel-side program is 97 lines in `ch01-mirror-controls-lsm.bpf.c`. The load-bearing parts are the SEC string, the return-value convention, the target-tgid filter, and the uid-0 guard.

The section name:

```c
SEC("lsm/inode_permission")
int BPF_PROG(lsm_inode_permission, struct inode *inode, int mask, int ret)
```

The `lsm/` prefix is what gets the program classified as `BPF_PROG_TYPE_LSM`. The suffix names the LSM hook — here, `inode_permission` — and libbpf resolves that against the BTF of `security_inode_permission` at load time. If the kernel does not have BTF for that hook, load fails. The prefix would be `lsm.s/` for a sleepable LSM program; `inode_permission` is non-sleepable on 6.14, so we use the plain `lsm/` form. A mismatch here fails attach with `-EINVAL` and a kernel log line about the hook not being sleepable, which is the trap that cost me an afternoon.

The `BPF_PROG` macro handles the argument unpacking. The important thing about the signature is the third parameter: `int ret`. fmod_ret programs are passed the return value the hook chain has accumulated so far — the verdict the kernel is currently about to act on. The program can inspect it, decide, and return its own value. **The program's return value replaces the hook's return value.** That is the fmod_ret convention and it is the load-bearing fact of this chapter. Return `0` and the access is permitted; return a negative errno and it is denied.

The filter decision is straightforward:

```c
static __always_inline int is_target(void)
{
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    unsigned int *hit = bpf_map_lookup_elem(&target_tgids, &tgid);
    unsigned int zero = 0;
    return (hit || bpf_map_lookup_elem(&target_tgids, &zero)) ? 1 : 0;
}
```

Two lookups against the same hash map. The first is keyed on the current TGID; the second is keyed on `0`, which the loader uses as the wildcard sentinel. If either hits, the current process is a target. The map is populated from userspace via `bpf_map__update_elem` (see the walkthrough of the loader below). A process whose TGID is not in the map, and for which the wildcard key is not set, returns the kernel's original verdict untouched — the BPF program is effectively a pass-through for everyone except the targets.

The uid-0 guard lives just inside the hook:

```c
unsigned long long uid_gid = bpf_get_current_uid_gid();
unsigned int uid = uid_gid & 0xffffffff;
if (uid == 0)
    return ret;
```

Flipping a root-side `-EACCES` is almost always a bad idea. Root's denials on `inode_permission` tend to come from LSMs that have a specific reason — SELinux saying "this type cannot open that type," AppArmor enforcing a profile, the capability module refusing an operation the task lacks a capability for. Overriding those breaks system services in ways that are loud, confusing, and not what the PoC is trying to demonstrate. The demo targets an unprivileged user (`t01lsm` in the trigger), so the guard is a safety rail, not a correctness constraint. Drop it and the program flips root denials too; I would not recommend it.

The flip itself:

```c
int flipped = 0;
int new_ret = ret;
if (ret != 0) {
    new_ret = 0;  // flip denial to allow
    flipped = 1;
}
```

Three lines. `ret` is the verdict the kernel handed us; if it is non-zero the access was going to be denied; we set `new_ret` to `0`. The `flipped` flag is local state used only to decide whether to emit a ringbuf event — `inode_permission` fires thousands of times per second on a busy system, and emitting on every call fills a 256 KB ringbuf in milliseconds. The PoC only emits on actual flips, which turns the trace from noise into evidence.

At the bottom of the function:

```c
return new_ret;
```

That is the fmod_ret replacement. Control returns from the BPF trampoline back into the kernel's LSM machinery with `new_ret` as the verdict. `do_inode_permission` sees a `0`, `vfs_read` proceeds into the actual filesystem read path, and the bytes come back to the caller. No illusion, no forged payload, no userspace fiction: the kernel does the read.

The event emit path is there for observability — it reads the dentry via a couple of `BPF_CORE_READ` hops to recover the filename, stashes it in a 32-byte buffer, and submits the ringbuf record. The fields are `pid`, `tgid`, `comm`, `hook` (hardcoded to `1` because this program only has one hook), `orig_ret`, `flipped`, `mask` (the `MAY_READ` / `MAY_WRITE` bitmask from the hook's second argument), and `fname`. That is what the loader prints on stdout when it sees a flip.

## The loader and the target-tgid arming

The userspace loader is in `ch01-mirror-controls-lsm.c`, about 114 lines. The argument parsing is the interesting part:

```c
while ((c = getopt(argc, argv, "t:ah")) != -1) {
    switch (c) {
    case 't':
        if (ntargets < 1024) targets[ntargets++] = atoi(optarg);
        break;
    case 'a': wildcard = 1; break;
    default: usage(argv[0]); return c == 'h' ? 0 : 2;
    }
}
```

Two modes. `-t <tgid>` adds a specific TGID to the target list and can be repeated up to 1024 times. `-a` turns on wildcard mode, which in this PoC means "flip denials for every non-root caller." After the LSM-active check, after `open_and_load`, the loader arms the map:

```c
if (wildcard) {
    unsigned int z = 0, one = 1;
    bpf_map__update_elem(s->maps.target_tgids, &z, sizeof(z), &one, sizeof(one), BPF_ANY);
    fprintf(stderr, "[ch01-lsm] mode=wildcard\n");
}
for (int i = 0; i < ntargets; i++) {
    unsigned int t = targets[i], one = 1;
    bpf_map__update_elem(s->maps.target_tgids, &t, sizeof(t), &one, sizeof(one), BPF_ANY);
}
```

Wildcard mode writes the sentinel entry at key `0` — which is the key `is_target()` checks when the per-TGID lookup misses. Targeted mode writes each TGID as its own key with a nominal value of `1`. The value is not read; the presence of the entry is the signal. The arming happens *before* `ch01_mirror_controls_lsm_bpf__attach(s)` so that by the time the program is wired to the hook, the filter map already has its contents. Attach-then-arm would leave a race window where the hook fires but the filter has not been populated yet.

The attach call itself is where the kernel version and LSM-config requirements land:

```c
int err = ch01_mirror_controls_lsm_bpf__attach(s);
if (err) {
    fprintf(stderr, "[ch01-lsm] CH01_SKIP reason=\"attach: %s\"\n", strerror(-err));
    ch01_mirror_controls_lsm_bpf__destroy(s);
    return 1;
}
```

If the kernel does not support fmod_ret on `inode_permission`, or if `CAP_SYS_ADMIN` is not held, or if BPF LSM is off in a way the earlier `/sys/kernel/security/lsm` check did not catch, this is where the PoC gives up. The error from libbpf surfaces the errno; the loader emits a `CH01_SKIP` line and returns. Again, no pretending: if the attach does not take, the chapter does not run.

Everything after attach is plumbing: install a SIGINT/SIGTERM handler, create a ring buffer consumer with `ring_buffer__new` on the `events` map fd, and poll it in a loop with a 200 ms timeout until signaled. Each event that comes back with `flipped != 0` is printed as a `FLIP` line and the `flips` counter is incremented. When the loop ends, the final `[ch01-lsm] flips=%llu` count is written to stderr.

The trigger script demonstrates the effect in the simplest possible way. It creates an unprivileged user `t01lsm`, runs `su t01lsm -c 'cat /etc/shadow 2>&1 | head -1; echo ret=$?'` as a baseline (expect `Permission denied` and a non-zero return), starts the loader with `-a` in the background, waits a second, and runs the same `cat` again. On a BPF-LSM-enabled kernel, the second read succeeds. The loader's stdout log shows one or more `[ch01-lsm] FLIP pid=... file=shadow mask=4 orig=-13` lines. `orig=-13` is `-EACCES`; `mask=4` is `MAY_READ`.

## Why this is not an illusion

The distinction between this PoC and the kprobe variant (sidebar below) is worth being precise about. When the fmod_ret hook returns `0`, the kernel's LSM dispatcher treats the hook chain as having verdicted "allow." `do_inode_permission` passes through normally. `vfs_read` continues into the real file_operations `->read_iter`, which for an ext4 inode traverses real page cache and real on-disk blocks. The bytes that the `read(2)` syscall returns to the caller are the actual bytes of `/etc/shadow` as they exist in the filesystem at that moment. Not a template, not a synthetic payload, not a modified version intercepted in userspace.

The caller's subsequent code then runs against that real state. If `cat` pipes the contents into `head -1`, `head` sees the real first line. If the program is `getpwnam` parsing the file, it gets real entries. If the process writes the bytes into a pipe or a socket, what comes out the other end is what was on disk. There is no post-processing layer inside the kernel that would re-redact or rewrite the data — the hook said "allow," and the read path ran as if the original DAC check had never failed.

That is what makes this a real override. The kprobe-plus-signal variant cannot say this, as the sidebar explains. The override changes kernel state (the return value of a security hook); everything downstream flows from that changed state through the normal code paths.

## The kprobe-plus-signal variant that does not mutate

The first PoC I wrote for this chapter is still in the tree under `ch01-mirror-controls/` (without the `-lsm` suffix). It is a kprobe on `cap_capable` paired with a kretprobe, which is a classic pattern for observing capability decisions, plus a pivot: on denials matching a target TGID the kretprobe calls `bpf_send_signal(SIGUSR1)` to deliver a signal to the caller. I kept it in the repo because the process of building it taught me most of what I know about why capability override does not work from a kprobe. What it does not do is grant the capability. It is not the primary for this chapter anymore.

The original plan was to override the return of `cap_capable` itself using `bpf_override_return(ctx, 0)` in the kretprobe. The program compiles. The verifier accepts it. `bpftool prog show` lists it. `/sys/kernel/debug/kprobes/list` shows the kretprobe attached at `cap_capable+0x0`. The target process runs, `capset` fails with `EPERM`, the ringbuf records `flipped=1` for every denial that matched — and the syscall still returns `EPERM`. The override is a silent no-op.

The mechanism is the `ALLOW_ERROR_INJECTION` allowlist. `bpf_override_return` only takes effect when the target function is annotated `ALLOW_ERROR_INJECTION(fn, ERRNO)` in kernel source. The set of annotated functions is deliberately small and excludes every security-decision function in the tree: `cap_capable`, `security_capable`, `avc_has_perm`, `apparmor_capable`, `security_inode_permission`, and so on. The maintainers' reasoning, when this comes up on the list, is consistent: a BPF override on a decision function is a policy bypass around the LSM architecture, and the LSM architecture is the supported policy layer. BPF LSM is the answer; `bpf_override_return` on `cap_capable` is not.

The runtime check is in the kprobe dispatch path: `bpf_override_return` stores the desired return value in per-kprobe state, and then the kprobe return path checks whether the target function is on the error-injection list before substituting the register. `cap_capable` fails that check and the stored override is discarded with no error, no tracepoint, no dmesg line. The silence is intentional — a program built against a kernel where the function was allowlisted should not fail loudly on a kernel where it is not — but it is also the exact failure mode that makes the technique useless for attack.

Confronted with that, I pivoted to `bpf_send_signal(SIGUSR1)` as the "real effect" instead of an override. The signal does get delivered. The loader's ringbuf records `signal=1` on the events where `bpf_send_signal` returned zero. The target process receives the signal and its signal handler (or the default action) runs. That is a real, observable side effect that originates from kernel-side BPF and lands on a specific userspace process.

But a signal is not a capability grant. The `capset` that triggered the denial still fails with `EPERM`. The subsequent code path in the caller — the one that was guarded by the capability check — does not run. If the original intent was to let an unprivileged process do something privileged, `bpf_send_signal` does not get it there. It demonstrates that a BPF program on a non-allowlisted decision function can still have a side effect; it does not demonstrate capability override. Calling it "mirror controls" in the chapter's sense — a primitive that flips the kernel's verdict — was a stretch, and the LSM PoC is what justifies the chapter title honestly.

If you want to reproduce the negative result yourself, the code is in `ch01-mirror-controls/ch01-mirror-controls.bpf.c`. The loader and trigger there run the same BEFORE/AFTER structure as the LSM PoC but with a `signals=N` count instead of `flips=N`, and the target's privileged operation continues to fail after the signal arrives. It is a fine observation primitive and a fine way to annoy a process. It is not an override.

## Detection

The LSM PoC is entirely legible to a defender who knows what to look for. The attach is declared; the subsystem is explicit by design; there is no covert BPF-LSM attachment.

- `bpftool prog show --type lsm` lists every LSM BPF program. The chapter's program appears as type `lsm` with attach target `inode_permission`.
- `cat /sys/kernel/debug/tracing/enabled_functions` may show the BPF trampoline at `security_inode_permission`.
- `auditd` with `-a always,exit -F arch=b64 -S bpf -k bpf_syscall` captures the `BPF_PROG_LOAD` call and the loader's `comm`, `exe`, `pid`, and `auid`.
- A sudden absence of `-EACCES` denials for a specific process — in `auditd`'s `AVC` records or in application-level error logs — is a behavioral tell, because this program removes the denials rather than masking them.
- Baseline-diff of `bpftool prog show --json` catches the new program within one diff interval.

Any defender who is already watching BPF program loads — which, if they care about BPF at all, they are — will see this one. The primitive is not stealthy. It is powerful because it is supported, not because it is hidden. Stealth is a later chapter's problem.

## Harness run and markers

The trigger script's output on a BPF-LSM-enabled host looks roughly like this:

```
=== baseline (no BPF) ===
cat: /etc/shadow: Permission denied
ret=1
=== starting LSM loader (--all) ===
=== with BPF LSM fmod_ret override: read should succeed ===
root:!:19000:0:99999:7:::
ret=0
=== loader log ===
[ch01-lsm] BPF LSM is active — proceeding
[ch01-lsm] active — file_permission denials will be flipped
[ch01-lsm] FLIP	pid=4422	comm=cat	file=shadow	mask=4	orig=-13
[ch01-lsm] flips=1
```

The load-bearing lines are the two `cat /etc/shadow` attempts. The first returns `ret=1` and the "Permission denied" message the kernel's DAC check produced. The second returns `ret=0` and the actual first line of `/etc/shadow`. Between the two, the only thing that changed is that the BPF LSM program is now attached with wildcard targeting. The loader's `FLIP` line records the event that corresponds to the successful read: `mask=4` is `MAY_READ`, `orig=-13` is `-EACCES`, `file=shadow` is the dentry name the program recovered via `BPF_CORE_READ`.

On a host where BPF LSM is not active, the trigger emits its skip line and exits:

```
=== CH01_SKIP reason="BPF LSM not active in /sys/kernel/security/lsm" ===
```

That is the honest outcome on linuxkit, on a default Debian VM, and on any other host where the kernel was not built with `CONFIG_BPF_LSM=y` and booted with `bpf` in the LSM list.

## Running the harness yourself

For readers who want to reproduce the chapter's output on a host that supports BPF LSM:

```bash
cd dBPF-pocs
# from a Fedora 38+ host, or a VM booted with lsm=...,bpf
cd pocs/ch01-mirror-controls-lsm
make
sudo ./build/ch01-mirror-controls-lsm -a &     # wildcard, background
sudo bash trigger.sh
```

Or, under the harness:

```bash
cd dBPF-pocs
docker compose up -d
docker exec -it dbpf-harness bash
cd /work/pocs/ch01-mirror-controls-lsm
make
./trigger.sh
```

The container will most likely print the `CH01_SKIP` line because Docker Desktop's linuxkit VM does not ship `CONFIG_BPF_LSM=y`. To see the override in action, the harness has to run on a kernel that does. The PoC does not pretend otherwise.

Variations worth trying on a supported host:

- Replace `-a` with `-t <tgid>` in the loader invocation and observe that only the specified tgid's reads get flipped. Any other unprivileged process hitting `-EACCES` sees the original deny.
- Change the target from `/etc/shadow` to another root-only file (`/root/.bashrc`, `/etc/sudoers`) and confirm the flip covers any VFS read, not just a specific path.
- Add a write attempt (`su t01lsm -c 'echo x > /etc/shadow'`) and observe that `mask=2` (`MAY_WRITE`) flips are also produced — `inode_permission` is the hook for both directions.
- Comment out the uid-0 guard, rebuild, and watch the system misbehave in creative ways as root-side denials get overridden. I do not recommend running this for more than a few seconds.

## What this chapter gives you

A supported, first-class override primitive for VFS access checks. The BPF LSM fmod_ret path is the answer the kernel maintainers point to whenever someone asks "can I override `cap_capable`?" This chapter is the worked example of taking them at their word: attach to a real LSM hook, return the verdict you want, watch the kernel act on it. The preconditions are real and the PoC is explicit about them — if BPF LSM is not in the LSM list, the chapter skips.

The broader lesson, and the one the sidebar exists to reinforce: decision functions in the kernel are not overridable from a kprobe. `bpf_override_return` is for error injection, not policy bypass, and the allowlist is where that distinction is enforced. If you want to change a security decision, you attach as an LSM. If you attach as a kprobe, the best you can do is observe — or, as the kprobe variant demonstrates, pivot to a side effect like `bpf_send_signal` that does not actually change the decision. Chapter 2 moves to a function that *is* on the error-injection allowlist, where the kprobe override path does work, and the contrast with this chapter's sidebar is the point.
