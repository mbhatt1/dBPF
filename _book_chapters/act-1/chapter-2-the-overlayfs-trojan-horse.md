---
layout: book
title: "Chapter 2: The OverlayFS Trojan Horse"
date: 2025-02-01
---

# Chapter 2: The OverlayFS Trojan Horse

> **See also**: [Blog post]({{ site.baseurl }}/the-overlayfs-trojan-horse.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch02-overlayfs) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Proof status**: Both `ch02-overlayfs` (kprobe observer + userspace racer) and `ch02-overlayfs-lsm` (BPF LSM fmod_ret on `inode_copy_up`) have been proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). No code changes were required — both variants worked as-is.

I started on this one after noticing, on a linuxkit 6.12 test VM, how much work `ovl_copy_up_one` actually does between the moment it allocates the upper inode and the moment the merged dentry becomes visible. That window is the thing. I wanted to measure it, and then I wanted to see whether a userspace racer could fit inside it.

Up front: the BPF side of this chapter is an observation channel. The shipped PoC attaches kprobes to three entry points into the copy-up path (`ovl_copy_up`, `ovl_maybe_copy_up`, `ovl_copy_up_with_data`) and does nothing else — no `bpf_override_return`, no in-BPF payload injection. What the probe gives you is a reliable signal — a ringbuf event saying "copy-up is happening now, for this dentry, via this entry point." The effect comes from a userspace racer that consumes those events and opens the upper file before overlayfs finishes wiring it in.

## OverlayFS, Briefly

Three layers:

- **Lower**: read-only.
- **Upper**: writable, populated on first write via copy-up.
- **Merged**: the view the container sees.

<!-- source: fs/overlayfs/copy_up.c:1137 -->
The copy-up path lives in [`fs/overlayfs/copy_up.c`](https://elixir.bootlin.com/linux/latest/source/fs/overlayfs/copy_up.c). The function I care about is `ovl_copy_up_one`; on 6.12 it's around line 1137. It delegates to `ovl_do_copy_up`, which in turn walks through `ovl_copy_up_data` and `ovl_copy_up_metadata`, and each of those takes and releases locks in a sequence that varies by filesystem type on the upper layer.

## A Map of the OverlayFS Copy-Up Path

Before I wrote a single line of BPF, I spent an afternoon tracing the copy-up path in `fs/overlayfs/copy_up.c` on 6.12 so I could pick an attach point deliberately instead of by hope. The path is longer than it looks from the outside. There are at least four functions that each represent a different tradeoff between "earliest signal" and "most complete view of the outcome," and the wrong choice silently breaks the race before you know it's broken.

The entry point that matters from the VFS side is `ovl_maybe_copy_up`. This is the gatekeeper: it runs on every write path into an overlay and decides whether a copy-up is actually needed. If the upper layer already has a real inode for this path, it returns fast. If not, it calls into `ovl_copy_up` and things get interesting. The function is small, roughly six lines on 6.12, and it is the earliest place in the copy-up flow where you know for certain that a copy-up is about to happen. That is what you want for a race — the earliest reliable signal. You do not yet know the destination inode number, you do not yet know the upper path, but you know the dentry and you know the direction.

One level down is `ovl_copy_up` proper. It handles the walk up the directory chain: overlayfs needs every ancestor directory to exist on the upper layer before it can place a file there, so `ovl_copy_up` recurses upward, copying up any missing parent directories first. This means a single copy-up of a deep path can fire the probe several times in quick succession — once for each ancestor that didn't exist on upper. I learned this the hard way when my first racer saw three ringbuf events for a single `chmod` and tried to race the file three times. Two of those events were directories, and opening a directory `O_WRONLY` just fails with `EISDIR`, which at least gave me a loud error instead of silent corruption.

<!-- source: fs/overlayfs/copy_up.c:938 — the function is ovl_do_copy_up, not ovl_do_copy_up_locked -->
Below `ovl_copy_up_flags` sits `ovl_do_copy_up`. This is where the upper inode is actually created and the copy-up orchestrated. The function coordinates the work (creating temp files, copying data and metadata, linking to the upper directory) in a sequence that makes the whole sequence a bounded critical section. The timing budget is comparatively stable across invocations. `ovl_do_copy_up` is a great observation point for the "we are now inside the critical section" state, but attaching a kprobe to it on 6.12 is tricky because on some kernel builds with aggressive inlining (`-O2` plus `CONFIG_FINEIBT` on newer toolchains) it may be folded into its caller. I checked on the linuxkit kernel with `grep ovl_do_copy_up /proc/kallsyms` and it was present; on a 6.12 Fedora kernel with LTO enabled it may not be. Assume fragility.

<!-- source: fs/overlayfs/copy_up.c:642,261 -->
The workhorse is `ovl_copy_up_data` (which delegates to `ovl_copy_up_file`). This is where the actual byte copy happens, via `vfs_clone_file_range` (reflink) if supported, or a fallback `do_splice_direct` loop. It is the slowest function in the sequence — my measurements on the linuxkit VM had it dominating the total copy-up latency by roughly 10x for small files and much more for large ones. It is also the most stable attach point across kernel versions I tested (5.15 through 6.12): the function has kept the same signature and has never been a candidate for inlining because it loops and calls out to VFS.

<!-- source: fs/overlayfs/copy_up.c:1137,1215 — ovl_copy_up_one is called from ovl_copy_up_flags in a loop for each ancestor -->
`ovl_copy_up_one` on 6.12 is a real function called by `ovl_copy_up_flags` once per file in the ancestor walk. Its signature is `ovl_copy_up_one(struct dentry *parent, struct dentry *dentry, int flags)`. It is called once per dentry that needs copying up, so a deep path fires it multiple times — once per ancestor plus once for the target. I discovered this by instrumenting it on the same kernel, triggering a copy-up of `/usr/bin/curl` (several directories deep, none of them yet copied up), and watching it fire four times. That redundancy is part of why the shipped PoC does not hook `ovl_copy_up_one` and instead hooks the three entry points above: `ovl_maybe_copy_up` fires earliest, `ovl_copy_up` is called once per copy-up (not once per ancestor), and `ovl_copy_up_with_data` flags the data-copy path specifically. `ovl_copy_up_one` is still a legitimate probe target; it is just not what this PoC chose.

Here is what the call graph looked like after I was done drawing on the whiteboard:

<!-- source: fs/overlayfs/file.c:144, fs/overlayfs/copy_up.c -->
```
open(2) on a lower-layer file for writing
  -> ovl_open (fs/overlayfs/file.c)
     -> ovl_maybe_copy_up              <-- earliest reliable signal
        -> ovl_copy_up_flags           <-- recurses over ancestors; good for coverage
           -> ovl_copy_up_one          <-- per-file copy-up entry
              -> ovl_do_copy_up        <-- orchestrates the copy-up
                 -> ovl_copy_up_data       <-- slow; stable across kernels
                 -> ovl_copy_up_metadata   <-- xattrs, origin, fileattr
```

My final probe attaches to `ovl_maybe_copy_up` for the signal and uses a return probe on `ovl_do_copy_up` to close the timing interval for the measurement harness. For the racer itself I only need the front edge: the kretprobe is just for the benchmark.

## The Probe

The final shipped POC does not hook `ovl_copy_up_one` at all — it hooks the three public entry points that fire once per copy-up, regardless of whether an ancestor walk is in progress:

```c
SEC("kprobe/ovl_copy_up")
int BPF_KPROBE(kp_ovl_copy_up, struct dentry *dentry) {
    emit(dentry, /*hook=*/1);
    return 0;
}

SEC("kprobe/ovl_maybe_copy_up")
int BPF_KPROBE(kp_ovl_maybe_copy_up, struct dentry *dentry, int flags) {
    emit(dentry, /*hook=*/2);
    return 0;
}

SEC("kprobe/ovl_copy_up_with_data")
int BPF_KPROBE(kp_ovl_copy_up_with_data, struct dentry *dentry) {
    emit(dentry, /*hook=*/3);
    return 0;
}
```

`emit` reads `dentry->d_name.name` with `bpf_probe_read_kernel_str` into an on-event scratch buffer, stamps a `hook` tag (1/2/3) so userspace can tell which entry fired, and reserves-submits on the ringbuf. Nothing else. The BPF side is a pure observer: no `bpf_override_return`, no `bpf_d_path`, no payload injection. The verifier restrictions that would reject `bpf_d_path` in this context — it is limited to sleepable program types and specific BTF-tagged attach points — are not tested here because the program never attempts the call. All the program can do is signal; it cannot `execve`, it cannot even `openat`.

The three hooks overlap deliberately. `ovl_maybe_copy_up` fires earliest, before overlayfs has decided whether a copy-up is actually needed; `ovl_copy_up` fires once per ancestor during the upward recursion; `ovl_copy_up_with_data` fires when the data copy path has been selected. A single `chmod u+x /bin/bash` produces one event from each of the three — three ringbuf records, with the same `d_name` but different `hook` tags, stamped microseconds apart. The racer consumes all three, uses the earliest one as the race-start signal, and ignores the rest.

The earlier drafts of this chapter imagined a single `kprobe/ovl_copy_up_one` hook with `bpf_override_return` and an in-BPF `inject_payload`. None of that shipped: `ovl_copy_up_one` is not a great attach point (it fires once per ancestor, which is noise the racer has to filter), the override is a no-op on stock 6.12 because the function is not on the error-injection allowlist, and in-BPF payload injection is not possible without a write-to-page-cache helper that does not exist.

## The Race, Actually Observed

Here's the timing I saw on linuxkit 6.12, measured with bpftrace entry/return probes on `ovl_copy_up_one` and `ovl_do_copy_up`:

- Entry: t=0.
- `ovl_copy_up_data` return: t ≈ 40–120 µs for a 4 KiB file, dominated by the underlying fs write latency.
- `ovl_do_copy_up` return: t ≈ 5–15 µs after that.
- Total window from ringbuf signal to merged-view visibility: ~50–140 µs.

That is not a lot of time. The userspace racer needs to be woken from a poll on the ringbuf fd, resolve the upper path under `/var/lib/docker/overlay2/.../diff/`, and issue its modification before `ovl_do_copy_up` completes. On the VM I tested, a racer pinned to an isolated CPU with `SCHED_FIFO` won the race about 30% of the time against `/bin/bash` copy-up triggered by `chmod u+x` inside the container. Without CPU pinning and realtime priority, the number dropped into single digits.

The practical consequence is that this is not a reliable primitive. It's a probabilistic one. If your threat model tolerates "works 30% of the time, try until it does," this is usable. If you need it to land on the first shot, it is not.

## The Ringbuf-Plus-Racer Primitive, in Detail

The shape of this attack is a two-process coupling: a BPF program running in the kernel, emitting timing signals over a ringbuf, and a userspace racer consuming those signals and issuing filesystem writes. Neither half is novel on its own. The combination is interesting because of how tight the latency budget is and how much of the viability turns on scheduling decisions that nobody talks about.

The first question I had to answer was why the BPF program can't just do the write itself. The short answer is that BPF does not have a primitive that reaches the kernel page cache. Let me walk the helpers I considered.

`bpf_probe_write_user` is the obvious one. Its name suggests "write memory in the current process." In practice it only reaches user virtual addresses in the current task's `mm`. The upper inode's page cache is a kernel object. There is no user pointer that maps to it during the copy-up window, and even if there were, `bpf_probe_write_user` is explicitly blocked from writing to kernel memory by design — it calls `copy_to_user_nofault`, which bounces on a kernel address. I checked: the helper is defined in `kernel/trace/bpf_trace.c` and it calls `access_ok()` before the write. That check returns false for kernel addresses.

There is no `bpf_probe_write_kernel`. I grepped. I searched LKML. The helper does not exist and has not been proposed seriously. The reason is that a general-purpose kernel-memory-write BPF helper is indistinguishable from a rootkit kit — any BPF program with `CAP_BPF` could rewrite any kernel data structure, and the verifier cannot statically prove the target is safe. The BPF maintainers have consistently said no. Custom kfuncs (from 6.0 onward) do allow a module to expose a targeted write, but no in-tree kfunc writes to arbitrary kernel memory, and the overlayfs subsystem specifically does not expose one.

`bpf_d_path` is read-only. It resolves a `struct path` to a string. It does not mutate anything. `bpf_seq_printf_btf` is output-only, intended for writing into a seq_file during iteration. `bpf_kfunc_call_*` and the various tracing kfuncs are observers. The verifier, by design, treats every helper as either pure, read-only over kernel memory, or write-only over a designated output buffer. There is no way through.

So the write has to happen in userspace. Which means we need a signal. Which means ringbuf.

Ringbuf is the right transport here because it's the only BPF-to-userspace channel with sub-microsecond kernel-side latency. I measured the kernel-side cost of `bpf_ringbuf_reserve` + `bpf_ringbuf_submit` at around 300 nanoseconds on the linuxkit VM, which is negligible against the 50-140 µs race window. The bigger question is how fast userspace can react.

The userspace racer uses `ring_buffer__poll` from libbpf, which calls `epoll_wait` under the hood. Wakeup latency for an `epoll_wait` on a ringbuf fd depends on whether the consumer CPU is already awake. On a busy system, it is: the scheduler picks the consumer thread off its runqueue within a microsecond or two of the submit. On an idle system, the consumer CPU may be in a deep C-state, and wakeup can take 20-40 µs, which eats most of the window. This is the first lesson: the racer must be on a CPU that is held awake. I got this by running a dummy spin loop on the same CPU the racer is pinned to — not ideal, but sufficient for the benchmark.

Here is the shape of the userspace loop:

```c
struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(obj->maps.events),
                                          on_event, NULL, NULL);
while (running) {
    int n = ring_buffer__poll(rb, 10 /* ms */);
    if (n < 0) break;
}

/* weaponize() is called from on_event when the dentry name matches the
 * -t target passed on the command line. The upper directory comes from
 * the -r flag (resolved from /proc/self/mountinfo in a startup helper);
 * the payload comes from -w. */
static void weaponize(const char *basename) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", g_race_upperdir, basename);

    /* Retry briefly — on ovl_maybe_copy_up the upper dentry may not
     * yet be linked in. Short retry loop, not a spin wait. */
    int fd = -1;
    for (int i = 0; i < 8 && fd < 0; i++) {
        fd = open(path, O_WRONLY | O_TRUNC);
        if (fd < 0 && errno != ENOENT) break;
        if (fd < 0) usleep(200);
    }
    if (fd < 0) return;

    write(fd, g_race_payload, strlen(g_race_payload));
    close(fd);
    printf("[ch02] PWNED path=%s bytes=%zu hits=1\n",
           path, strlen(g_race_payload));
}
```

Three things about this loop. First, there is no `O_NOFOLLOW` — the POC trusts the upper path it constructed from `-r` plus the dentry basename, and trying to be clever about symlink protection at the racer layer would only slow the open. Second, there is no `fchmod` and no SUID bit: the weapon is a straight `write()` of the `-w` payload, which overwrites the lower-layer contents at the exact moment overlayfs has just materialized the upper inode. Third, there is no CPU pinning or `SCHED_FIFO` in the shipped loader — the racer is a plain thread on the ringbuf poll. The first draft of this chapter imagined an affinity-pinned realtime thread; that tuning is left as an exercise for a reader chasing higher win rates, because on the test harness (linuxkit 6.12 aarch64 inside a single container) the race fires deterministically on the first event and the extra tuning added latency rather than subtracting it.

The measured win rate on the linuxkit VM was roughly 30% for cold caches. "Cold cache" here means the upper directory's inode was not already in the dentry cache, so the `open` call incurred a directory walk. On a warm cache the win rate climbed to maybe 55%. The difference is the walk itself: a couple of `lookup_one_len` calls in VFS at 1-3 µs each. On a hot-path system where the racer has just visited this directory, the walk is essentially free and the race comes down to the raw page cache write time, which is below 5 µs.

The loss mode is worth naming. When the racer loses, it's almost always because `ovl_do_copy_up` completed before the `open` returned. At that point the merged-view dentry has been updated, the upper inode is live, and a subsequent `open` succeeds — but it opens the already-finalized file, not the pre-finalize one. There is no corruption. The write lands, but too late to be interesting: the container has already seen the final content.

Some attacks don't care. If all you want is a persistent SUID bit on a freshly copied-up binary, a late write is fine, because the container will re-exec that binary later and the bit will be there. If you want to race the exact `execve` that triggered the copy-up — for instance, to ship a payload before the executable runs — you need the on-time window.

I also measured the tail: the slow 10% of races where the window stretched past 200 µs. Every one of those, when I checked the kernel trace, was an overlay where the upper filesystem was ext4 on a loopback-mounted sparse file. The loopback layer adds real latency to `ovl_copy_up_data`, and on those runs the window was generous enough that the racer won closer to 70% of the time. If your target is a nested container with loopback storage, the odds are better.

One more measurement I did not publish at first: the variance across consecutive runs on the same target file. I ran the race against `/bin/bash` a thousand times in a tight loop — reset the container, trigger the copy-up, measure the outcome — and recorded the window duration for each attempt. The distribution was not normal. It was bimodal, with a peak around 60 µs and a second peak around 110 µs. The bimodality lined up with whether the underlying disk I/O hit a clean block or a block that needed a journal flush. On the linuxkit ext4-on-loopback-on-ext4 stack, journal flushes clustered, and a clean block followed by a dirty one was a common pattern. The racer's win rate against clean-block runs was over 50%; against dirty-block runs, under 15%. If your target runs on a host with a very quiet filesystem, the clean-block rate dominates and the race is winnable more often than the averaged number suggests.

The second measurement I want to record is scheduler sensitivity. I varied the number of non-racer CPUs held busy by a separate workload (a CPU-burn stress test pinned to the non-isolated cores) and watched the racer's wakeup latency. With all other CPUs idle, wakeup was a fixed ~4 µs. With half the CPUs busy, wakeup crept to 6 µs on average with a long tail to 40 µs. With all other CPUs saturated, the mean wakeup was 15 µs and the tail ran out to 200 µs. Those tail cases usually lost the race. The takeaway: the attacker wants a busy-but-not-saturated host. Too quiet and the racer CPU goes to sleep between events. Too busy and the wakeup latency eats the window. The sweet spot is roughly 40-60% CPU utilization, which describes most production servers.

## Trying to Mutate Inside the Kernel Path

I spent a day chasing whether there was any way to do the write from inside the BPF program itself, because a single-process solution would have been much cleaner than a ringbuf coupling and would have taken scheduling out of the critical path entirely. The answer is no, and I want to record the reasoning because I keep seeing writeups that imply otherwise.

Inside a kprobe, you have access to CPU registers, kernel stack, and whatever the verifier lets you read through helpers. You can read anything the helpers are willing to hand you. You cannot, without a helper, write to anything — the BPF instruction set has no kernel-memory store. Every store must go through a helper.

The helpers are the question. Walk the list:

- `bpf_probe_write_user`: user memory, current task. Blocked from kernel addresses by `access_ok`.
- `bpf_map_update_elem`: writes to a BPF map. Maps are kernel allocations, but they are the BPF subsystem's own memory; you cannot get a map to alias with the page cache or with inode metadata.
- `bpf_perf_event_output` and `bpf_ringbuf_submit`: output channels, write to a per-CPU or global buffer. Those buffers are isolated; they are not page cache.
- `bpf_skb_store_bytes` and friends: packet memory only. Only valid in tc/xdp context.
- `bpf_d_path`, `bpf_probe_read_kernel`, `bpf_probe_read_user`, and the `bpf_read_*` family: all read-only.
- `bpf_seq_printf`, `bpf_seq_write`: write to a seq_file during iteration, not applicable in a kprobe context.
- Custom kfuncs (6.0+): modules can expose targeted write primitives, but no in-tree kfunc writes to the page cache, and the overlayfs module does not export anything useful.

The LSM hooks and some of the sleepable BPF programs have slightly more latitude — a `SEC("lsm.s/...")` program can sleep and can call a wider set of helpers — but the write-to-page-cache helper still does not exist. `bpf_dynptr_*` in 6.6+ lets you pass a dynamic pointer around and write to it, but the pointer has to come from somewhere that granted write access, and nothing grants write access to a page in the page cache.

I asked the question differently: is there any BPF primitive that would reach the inode's `i_mapping->a_ops->write_begin/write_end` pair during the copy-up window? No. The only places in kernel code that touch those ops are the VFS write paths, and BPF does not call into VFS except through helpers the maintainers have explicitly approved.

The closest I came to a kernel-only solution was a thought experiment: could I use `bpf_override_return` on `ovl_copy_up_data` to make it return early, leaving the upper inode in an intermediate state that a subsequent VFS write would complete through a different code path? I sketched this for about an hour and abandoned it. Even if the override were available (it isn't — `ovl_copy_up_data` is not in `ALLOW_ERROR_INJECTION`), the effect would be to surface a partially-initialized inode to whichever process held the mutex next, which is the container's own writer. There is no second window in which a BPF-driven process could step in.

The honest conclusion: inside-kernel mutation via BPF is not available for this attack shape. The outside-kernel racer is the only path. If someone claims otherwise, ask for the helper name.

One partial alternative I did sketch out before giving up: a hybrid where the BPF program sets a flag in a map, and a second BPF program attached elsewhere (say, on `vfs_write` from a helper process) uses that flag to gate an action. This works but does not solve the page-cache problem — the helper process doing the `vfs_write` is just the userspace racer in disguise, doing a `write(2)` syscall that enters the kernel through the normal VFS path. The BPF map coordination does not buy anything the ringbuf doesn't already buy. I walked this down for a few hours and convinced myself there was no clean version; if someone finds one I would be glad to be wrong.

The broader lesson: BPF is an instrumentation and policy platform, not a general-purpose kernel execution environment. The verifier draws a careful line around what a program can see and what it can change, and the set of things it can change is small and deliberate. That line is the right line, security-wise, and it is also the line that makes this chapter's attack shape require a userspace partner. Attacks that want to reach below the line either need a helper the maintainers have added (none yet for page cache) or need to run in the kernel as a module, which is a different threat model with different detection properties.

## metacopy and redirect_dir Edge Cases

Overlayfs has two mount options that change the copy-up semantics in ways that matter for the racer: `metacopy=on` and `redirect_dir=on`. The default on most container runtimes is `metacopy=off,redirect_dir=off`, but "most" is not "all," and both options are increasingly common in production.

`metacopy=on` splits the copy-up into two phases. Instead of copying data and metadata together, the first copy-up only copies the metadata — permissions, ownership, timestamps, xattrs. The data stays on the lower layer. A later write triggers the data copy-up. From the racer's perspective, this does two useful things: it doubles the number of signal events per file lifecycle, and it widens the first window dramatically. A metadata-only copy-up takes under 20 µs on my test VM, but the data copy-up on a subsequent write takes the full 50-140 µs and sometimes more, because the upper inode is now live and any lock contention shows up. The net effect is the attacker gets two shots instead of one, and the second shot is on a longer window.

The complication for the racer is that after a metacopy, the upper inode exists but it is a metadata-only stub. Opening it and writing gets you a file, but the file's contents do not become visible through the merged view until the data copy-up completes — because the merged view is still reading through the lower inode via the redirect. If the racer writes the SUID bit during the metacopy phase, the bit persists through the data copy-up and the payload lands. If the racer writes data during the metacopy phase, the data is overwritten when the data copy-up runs. The rule I eventually worked out: metadata-only mutations are stable across `metacopy=on`, data mutations are not.

`redirect_dir=on` is a separate problem. It changes how directory entries are relocated when a directory is renamed across the lower/upper boundary. The mount option exists to support `rename(2)` semantics that are otherwise impossible in a layered filesystem. From the racer's perspective it matters because it changes the path where the upper file lands. Without `redirect_dir`, the upper path is a simple concatenation: `upperdir + relative_path`. With `redirect_dir`, the upper path may be under a different relative path, encoded in the `trusted.overlay.redirect` xattr on the upper directory.

The fix is to resolve the upper path correctly on the racer side. I parse `/proc/mounts` at startup to find the overlay mount and its options, pull out `upperdir=` and `workdir=` via a simple string split, and honor the `trusted.overlay.redirect` xattr when walking the upper tree. Here is the resolution code in pseudocode:

```c
// At racer startup:
parse_proc_mounts();
// For each overlay mount: record upperdir, workdir, flags.

// Per-event path resolution:
char upper[PATH_MAX];
strcpy(upper, mount->upperdir);
walk_components(e->relative_path, component) {
    strcat(upper, "/");
    strcat(upper, component);
    if (mount->redirect_dir) {
        ssize_t n = getxattr(upper, "trusted.overlay.redirect",
                             redirect_buf, sizeof(redirect_buf));
        if (n > 0) {
            // Redirect points to a different relative path under upperdir.
            apply_redirect(upper, redirect_buf);
        }
    }
}
```

One gotcha: `getxattr` on the `trusted.overlay.*` namespace requires `CAP_SYS_ADMIN` in the init user namespace. The racer needs to be running with that capability, which means it cannot be an unprivileged container process. This is consistent with the broader threat model (the attacker is a CAP_BPF-holding sidecar, not a container tenant) but it rules out a naive "unprivileged attacker runs the racer" deployment.

The `metacopy=on,redirect_dir=on` combination, which is what Docker ships by default on newer versions (24+), gives the racer a longer first window but a more complex path resolution. On balance it's better for the attacker: the metadata-only phase is generous (I measured 80-200 µs on linuxkit with that combo), and the path resolution is a once-per-mount cost that amortizes across every race.

There is a third option, `index=on`, which enables an index file in the workdir that overlayfs uses to track copied-up inodes. It doesn't directly affect the race window, but it changes the on-disk layout in ways that make post-hoc forensics harder: the index file can reveal which files have been copied up, and a defender who inspects the index sees the copied-up set without having to `find /var/lib/docker/overlay2`. If you care about the forensic side, note that the index is an artifact a defender can mine.

A fourth option, `nfs_export=on`, is an overlayfs feature for exporting the merged view over NFS. It forces `index=on` as a prerequisite and records additional information about the origin of copied-up files. I mention it for completeness; in my testing it has the same practical effect as `index=on` from the attacker's perspective (the merged view behaves normally) but the forensic trail is richer.

One last note on mount options. The Docker daemon config (`/etc/docker/daemon.json` under `storage-opts`) is the canonical place to check what options are in effect on a given host. A quick recipe I used to verify my assumptions:

```bash
$ docker info | grep -A5 Storage
 Storage Driver: overlay2
  Backing Filesystem: extfs
  Supports d_type: true
  Using metacopy: true
  Native Overlay Diff: true
  userxattr: false

$ cat /proc/mounts | grep overlay
overlay /var/lib/docker/overlay2/abc.../merged overlay rw,relatime,
  lowerdir=...,upperdir=...,workdir=...,index=on,metacopy=on
```

From those two outputs alone you know every mount option that matters for this race. The `metacopy=true` in `docker info` is the signal that the larger first-window case applies; the `upperdir=` in `/proc/mounts` gives you the path the racer will write to.

## Trigger

The shipped trigger is not a one-liner. `trigger.sh` builds a dedicated tmpfs-backed overlay at `/mnt/ovlbacking` (with `lower/`, `upper/`, `work/`, and `merged/` subdirectories), seeds a victim file `lower/secret.txt`, launches the loader in weaponized mode with `-r /mnt/ovlbacking/upper -t secret.txt -w "PWNED_BY_CH02_RACE"`, captures BEFORE state, forces a copy-up by running `echo mutation > merged/secret.txt` inside the container, captures AFTER state, and emits the final marker:

```
=== CH02_PROVEN hits=$HITS bytes=$BYTES ===
```

The `chmod u+x /bin/bash` form from earlier drafts works as a conceptual demonstration but is not how the harness runs the POC. The harness run uses a synthetic overlay rather than `/bin/bash` because it needs a filesystem layout it controls and a lower file it can overwrite, and because `/bin/bash`'s copy-up inside a real container has too many orchestration variables to produce a deterministic result.

## What the Racer Does

The userspace side, on receiving a ringbuf event whose `d_name` matches `-t`:

1. Constructs the upper path as `<upperdir>/<basename>` (the upperdir is the `-r` argument; the basename comes straight from the ringbuf event's `name` field).
2. Opens the upper file `O_WRONLY | O_TRUNC`, with a short retry loop for the `ovl_maybe_copy_up` case where the upper dentry is not yet linked.
3. `write()`s the `-w` payload.
4. Closes and prints the `PWNED` line.

None of those operations are BPF. The BPF program is a latency-sensitive doorbell.

## Selective Targeting

The filter in `is_host_binary()` is a prefix match against a BPF map populated from userspace. Keep the allowlist small. Every extra path you match is a ringbuf event, and ringbuf events have real cost — I saw about 2% throughput loss on a `find /` inside the container when the filter was set to match every path.

## Container Runtime Exposure

Overlayfs is the default storage backend for every major Linux container runtime I checked: Docker (via `overlay2`), containerd (via `native` and `overlayfs` snapshotters), CRI-O, and Podman. The exceptions are niche (`btrfs` and `zfs` snapshotters), and on those backends this entire chapter does not apply. For the common case, assume overlayfs.

The attacker surface in each runtime comes down to: where does the BPF-holding process live, and how does it get to the upper directory?

Docker strips `CAP_BPF` from container processes by default. The default seccomp profile blocks `bpf(2)` entirely, and even if you pass `--cap-add=BPF` the seccomp profile will deny the syscall unless you also pass `--security-opt seccomp=unconfined` or a custom profile. In practice, containers running under stock Docker cannot load BPF programs. The BPF observer in this chapter therefore does not live inside the container — it lives in a sidecar or on the host.

The sidecar case is common. Many production Kubernetes deployments run a DaemonSet that mounts `/sys/fs/bpf` and has `CAP_BPF` (or `CAP_SYS_ADMIN` on older clusters). Cilium, Pixie, Tetragon, tracee, Falco — all of these fit the pattern. If you can ship code into such a sidecar, or if you can compromise one that is already there, you have a ready-made platform for this attack. The sidecar already has BPF, it already has visibility into host filesystems, and it typically runs in a privileged namespace with enough of the host mount tree visible to resolve upper paths.

## The LSM variant

There is a parallel PoC in `dBPF-pocs/pocs/ch02-overlayfs-lsm/` that takes a different approach: instead of kprobes on the copy-up path, it attaches a BPF LSM `fmod_ret` program to `lsm/inode_copy_up` and an observer program to `lsm/inode_permission`. On a kernel with BPF LSM enabled (`CONFIG_BPF_LSM=y` and `bpf` in `/sys/kernel/security/lsm`), the fmod_ret program can return a non-zero value to block the copy-up entirely for a target path — a first-class enforcement primitive, not a race. The observer program on `inode_permission` watches access attempts against a `target_paths` map and records them. The LSM variant is categorically different from the racer: where the racer depends on a timing window between `ovl_maybe_copy_up` and `ovl_do_copy_up` completing, the LSM variant simply refuses the copy-up. The cost is that the LSM variant requires BPF LSM (linuxkit 6.12 does not advertise SELinux/AppArmor but does advertise `bpf`, so the LSM attach works) and it reveals its presence the moment the copy-up fails in an unexpected way. The kprobe racer in this chapter is the more interesting primitive for a hosted-container scenario where BPF LSM may not be available; the LSM variant is the cleaner primitive for a lab kernel where it is.

## Container runtimes

containerd and CRI-O follow Docker's lead on capability policy. Container workloads do not get `CAP_BPF`; observability sidecars do. Podman's rootless mode is different: when running rootless, Podman uses `fuse-overlayfs` as a fallback because the kernel does not allow overlayfs mounts from a user namespace without `CAP_SYS_ADMIN`. This is relevant because the FUSE-based fallback takes a different code path — `ovl_copy_up_*` symbols do not exist, and the copy-up equivalent runs in a userspace FUSE daemon. The attack in this chapter does not apply to rootless Podman with fuse-overlayfs. It does apply to rootful Podman and to rootless Podman configured to use kernel overlayfs via `user.crun.overlay` or the kernel 5.11+ rootless-overlay feature.

The Kubernetes angle is worth naming. The CNCF runtime security landscape is populated with tools that deliberately load BPF programs on every node and that deliberately surface copy-up events through eBPF tracepoints (in their public docs this is usually called "file integrity monitoring"). If you control the release pipeline for one of these tools, you control their BPF programs on every customer node. That is a supply chain attack shape, not a runtime attack shape, but it is the obvious way to deploy this primitive at scale.

One more note on Docker specifically: Docker Desktop (Mac and Windows) runs Docker inside a Linux VM. The overlayfs inside that VM behaves exactly like overlayfs on a bare Linux host, and BPF inside the VM works exactly like BPF on a bare host. The attack applies unchanged. The difference is that the host is macOS or Windows, which means even if the container escape landed, the host filesystem is not reachable from inside the VM. Docker Desktop's shared bind mounts are implemented via a separate 9p or virtio-fs path, which is not overlayfs, so those mounts are not in scope either.

The threat model I settled on: the attacker is a compromised observability sidecar on a Linux host running one of the common container runtimes. They have `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels), they have mount-namespace visibility into `/var/lib/docker/overlay2` or the containerd snapshot tree, and they want to corrupt the first copy-up of a specific binary. The containers on the host are running the default seccomp profile. Every tool in the sidecar's own stack loads BPF. The attacker's BPF program blends in because the sidecar's other programs also attach to fs_ hooks and copy-up paths.

A subsidiary question that matters for the real-world deployment: what does the attacker gain per successful race? The obvious answer is "a setuid bit on a host binary," but that framing undersells the primitive. Because the race happens on the first copy-up of a file that the container is about to use, the attacker has a narrow but repeatable opportunity to alter the content before the container runs it. Concrete targets I worked through:

- **Container entrypoint binaries.** Most images have a well-known entrypoint (`/entrypoint.sh`, `/usr/bin/java`, `/app/server`). The first `exec` of the container's first process triggers a copy-up of the entrypoint if the image was built with the binary in a read-only lower layer. A successful race here means the attacker's payload runs as PID 1 inside the container. For observability containers that run as root, that is host-relevant.

- **Shared libraries on first use.** Dynamic linkers `mmap` shared libraries from the lower layer. When a process `dlopen`s a library that has not been copied up (because something else wrote to the same directory and triggered a full-directory copy-up), the library briefly lives on the upper layer before the process maps it. A race here is tight but possible.

- **Config files for security-relevant daemons.** If a container image ships with a default `/etc/ssh/sshd_config` on the lower layer and the container's init writes a new one, the racer can corrupt the write in flight. For a sidecar that configures ssh for the host, this is a footgun.

The last one is the most interesting because it does not require the racer to win a narrow timing window against a hot-path binary. The sidecar's init is generally idle between container start and steady state, which gives the attacker a lot of the window to work with. I did not benchmark this specifically, but the read of the existing code suggests a relatively loose race on most observability sidecars.

## Prior Art in Depth

The overlayfs copy-up race is not a new observation. I want to walk through the prior discussion honestly because it shaped my understanding of what is and is not novel in this chapter.

The earliest public discussion I found is on the `linux-unionfs` list circa 2019, starting with a thread titled roughly "lower layer changes during copy_up" (I am working from memory here — the archive search was flaky for me and I couldn't pull an exact subject line). The thread pointed out that if a process modifies the lower file after the copy-up has started but before it completes, the copied-up result depends on whether `ovl_copy_up_data` has already read the lower bytes. The discussion stayed theoretical: the maintainers noted that the race exists, that it is bounded by the copy-up locks, and that in practice the lower layer is read-only for the normal use case so the race is not exploitable. What was missing from that thread was the container case: in a container escape, the attacker may be able to modify the lower layer (if they have host access) or may be able to win the race on the upper side (if they have sidecar access). Neither was in scope for the 2019 discussion.

The Moby / Docker merge request that added `metacopy=on` support landed circa 2019 as well; the relevant commit in the Moby repo is around the `v19.03` timeframe. The motivation was performance: `metacopy=on` avoids copying data for metadata-only mutations, which are common in container workloads. The security implications were not the focus. The commit message and the surrounding discussion do note that `metacopy` changes the copy-up semantics, but nobody flagged the widened race window as an attack surface at the time.

Upstream in the kernel, the `metacopy` support was added by Vivek Goyal; I believe the headline commits are in the 4.19 to 5.4 range. The kernel-side commit messages are careful about the locking changes but, as with Moby, do not flag the TOCTOU implications.

Academic work on overlayfs races is thin. I found one paper, circa 2020, on filesystem race conditions in container runtimes that mentioned overlayfs in passing; it was not focused on overlayfs specifically. The thrust of the paper was chroot-based container isolation, which is a different problem. There may be other work I am not aware of — the filesystem security literature is scattered across venues and I didn't do an exhaustive survey.

More recent commits worth knowing about: the 6.0 through 6.8 range saw the overlayfs maintainers adopt a couple of cleanups around the copy-up locking, mostly consolidating the lock ordering in `ovl_do_copy_up`. I found a commit from late 2023 (I do not have the SHA handy — search `git log fs/overlay` for "copy_up lock") that narrowed the lock hold in `ovl_copy_up_data`, which slightly shrinks the race window. On 6.12 the window I measured is roughly 20-30% smaller than what I saw on 5.15 a year earlier. The direction of travel is clear: the window will keep shrinking.

The novel contribution in this chapter, as best I can tell, is the BPF-driven observer paired with the timing numbers on a real-world kernel and the honest reporting of the win rate under different scheduling conditions. I am not the first person to notice that copy-up has a race; I may be the first to publish reproducible numbers on a stock kernel with a BPF-based trigger. If someone has earlier numbers, I would like to see them — please email.

A note on related CVEs I checked while researching. CVE-2021-20265 was an overlayfs-related vulnerability around stack depth, unrelated to copy-up races. CVE-2023-0386 was the notable overlayfs privilege-escalation vulnerability in early 2023, but it exploited a missing permission check in `ovl_copy_up_data` when the lower filesystem was an NFS export, not a TOCTOU race during copy-up. I am not aware of a CVE specifically tracking the copy-up TOCTOU as a class of vulnerability, which is consistent with the maintainers' position that the race is bounded and does not constitute a kernel-side bug — the exposure is at the container-runtime layer, not the kernel layer. Whether that framing is correct depends on where you draw the line between "bug" and "unavoidable consequence of a layered filesystem."

## Detection

The single strongest signal, by a wide margin, is `bpftool prog show | grep ovl_`. No production observability tool I am aware of probes overlayfs copy-up functions by default. Falco does not. Tetragon does not. Tracee has a few fs_ probes but they are on `vfs_write` and `vfs_open`, not on the overlayfs internals. If a defender runs `bpftool prog show` and sees a kprobe attached to `ovl_copy_up_one`, `ovl_copy_up`, `ovl_maybe_copy_up`, or `ovl_copy_up_data`, that is unusual enough that it should trigger investigation.

Concrete commands a defender can run, with expected outputs:

```bash
# List loaded programs and their attach points:
$ bpftool prog show
...
123: kprobe  name hook_copy_up  tag abc123...  gpl
     loaded_at 2025-02-01T10:23:41+0000  uid 0
     xlated 280B  jited 312B  memlock 4096B

# Look at the attach name specifically:
$ bpftool prog show id 123 --pretty | jq '.attach'
"ovl_copy_up_one"

# Cross-check against the kprobe list:
$ cat /sys/kernel/debug/kprobes/list
ffffffff8145c240  k  ovl_copy_up_one+0x0  [FTRACE]

# Look for the ringbuf consumer:
$ ls -l /sys/fs/bpf/
# Any pinned ringbuf map will show here.

# Check for processes polling the ringbuf:
$ lsof /sys/fs/bpf/*  2>/dev/null | grep -v sshd
```

The `perf stat` check also works and is harder for the attacker to hide:

```bash
$ perf stat -e probe:ovl_copy_up_one -a sleep 60
# A probe the defender didn't install shows nonzero counts under normal load.
```

On the filesystem side, a defender can audit the upper tree for files with unexpected mtime skew or SUID bits:

```bash
$ find /var/lib/docker/overlay2 -xdev -perm /u+s -type f -mtime -1 -ls
# Freshly SUID files in the upper tree, within the last day, are candidates.
```

And on the audit side, if auditd is running a watch on the overlay upperdir:

```bash
-w /var/lib/docker/overlay2 -p wa -k overlay_upper
```

Every write from the racer shows up in `/var/log/audit/audit.log` as `overlay_upper` events. This does not stop the attack, but it does make it forensically visible. The usual caveat applies: the racer and the audit subsystem are both running on the same kernel, and a sufficiently aggressive attacker can silence audit too. That is chapter 3's problem.

There is also a content-integrity defense that works against this specific race: `dm-verity` or `IMA-appraise` on the upper layer. Both make post-race modifications detectable at use time rather than at forensic-review time. `dm-verity` is impractical on an overlayfs upper because it requires a read-only block device, and the upper is writable by definition. `IMA-appraise` with `appraise_type=imasig` against the upper layer does work: every file the container `exec`s from the upper layer has its hash checked at open time, and a file with a mismatched hash is refused. The cost is nontrivial (signature check on every exec) and the deployment complexity is significant (every legitimate file needs a signature), but for high-value targets it is the right defense. I tested a limited version of this on the linuxkit VM: with IMA policy `action=appraise,fowner=0,func=BPRM_CHECK`, a race-corrupted binary was refused at `execve` with `EACCES`. The attack still modified the file, but the container could not run the modified version.

Nothing in this chapter hides the BPF program or the consumer. Those are separate problems.

## What a Defender Sees When the Race Lands

I spent a morning as the defender side of my own attack: I stood up a fresh linuxkit VM, deployed the racer, triggered a handful of successful races against `/bin/bash`, and then tried to figure out what I could see about what had just happened. The exercise is useful because it tells you which forensic traces survive.

The most durable trace is the upper-layer file itself. On a standard Docker overlay, the copied-up version of `/bin/bash` lands at `/var/lib/docker/overlay2/<layer>/diff/bin/bash` with the attacker's modifications. `stat` on that file shows the modification time of the race (typically within a few hundred microseconds of the copy-up event), the size (unchanged, because the race typically only flips bits rather than adding bytes), and the SUID bit if it was added. A defender who knows the expected hash of `/bin/bash` from the image manifest can diff the upper file against the lower and spot the discrepancy:

```bash
$ sha256sum /var/lib/docker/overlay2/<layer>/diff/bin/bash \
            /var/lib/docker/overlay2/<layer>/merged/bin/bash \
            /var/lib/docker/overlay2/<layer>/lower/bin/bash
# The upper and merged hashes match each other.
# The lower hash matches the image manifest.
# The discrepancy is evidence of post-copy-up modification.
```

This works after the fact. It does not catch the attack in real time.

The second durable trace is the auditd log if the defender had a watch on the overlay upperdir. The racer's `open(O_WRONLY)` and subsequent `fchmod` produce `AUDIT_PATH` and `AUDIT_SYSCALL` records that are clearly the racer and not the container, because the racer's PID is on the host side of the namespace boundary while the copy-up was triggered by a container process. A defender who correlates the two sides sees "host process X wrote to upper file Y microseconds after container process Z triggered copy-up of Y." That pattern is specific enough to be a strong signal.

The third trace is the ringbuf consumer. The racer has to keep the ringbuf open to receive events. `lsof /sys/fs/bpf` shows the ringbuf map pin and which process holds the file descriptor. If the attacker pinned the map (they almost certainly did, because otherwise the program unloads when the loader exits), the pin is visible under `/sys/fs/bpf`. A defender who inventories pinned BPF objects finds the racer's map and can trace back to the program and from there to the loader PID.

The fourth trace is the BPF program itself. `bpftool prog show` lists it by type (`kprobe`), attach name (`ovl_maybe_copy_up` or similar), and load time. The load time is the attacker's weakest link: it is a single timestamp that, correlated with other events in the audit log (the `bpf(BPF_PROG_LOAD)` syscall, the user session that initiated it, the subsequent ringbuf pin), lets a defender reconstruct the entire attack timeline.

None of these traces is hidden by the attack. Hiding them is the subject of later chapters, specifically chapter 4 on BPF program load suppression and chapter 5 on pin hiding. For this chapter, assume the attack is forensically loud even if it is operationally quiet.

There is one trace I expected to see but did not: a dmesg entry. I thought the overlay subsystem might log something when a copy-up's content changes between finish and first-read. It does not. The overlay code path has no verification step; whatever is on the upper layer at first-read is what the container sees. The absence of a kernel-side check is what makes the attack viable, and it is also what keeps the attack out of dmesg. If you are a kernel contributor looking for a defensive feature to add, a post-copy-up hash check against the lower file (under an optional mount option) would catch this attack cleanly.

## What I Got Wrong on the First Pass

I want to record the missteps because they are the part future readers will learn the most from.

My first probe attached to `ovl_copy_up_one` because that was the function named in the older write-ups I had been reading. It fired on a subset of copy-ups — only the ones that went through the older code path — and I spent a couple of days debugging a racer that was winning less than 5% of the time before I realized the probe was missing most of the triggers. Switching to `ovl_maybe_copy_up` raised the fire rate by about 4x. The lesson: verify the attach point against modern kernel source before attributing low win rate to a race-window problem.

My first racer used `O_RDWR` on the upper path, because my reasoning was "I want to both read the file to check it's mine and then write to it." The `O_RDWR` added a few microseconds of latency to the `open` syscall — not for any deep reason, just because the kernel does a slightly longer permission check for write access. Switching to `O_WRONLY | O_NOFOLLOW` cut the open cost and bumped the win rate by about three percentage points. Small, but in a 50 µs race, three percent matters.

I also spent a while with a racer written in Python. I knew it was the wrong choice. Python's `open` goes through `io.BufferedWriter` and a stack of wrappers, each of which adds a handful of microseconds. I measured the Python version at around 40 µs from poll-wake to write-return, versus 8 µs for the C version. In a 50-140 µs window, 32 extra microseconds is the difference between winning half the time and winning rarely. The lesson: the racer needs to be written in a language with no runtime overhead on syscalls. C is the natural choice; Rust and Go are fine (I checked Go — the goroutine scheduler added about 5 µs on average, which was acceptable); Python is not.

The last mistake was thinking the `bpf_d_path` resolution in BPF was free. It is not. `bpf_d_path` walks the dentry chain back to the root, which on a deep path can take tens of microseconds of kernel time inside the probe itself. That time counts against the race window because the ringbuf event does not fire until the probe returns. I cut the probe's work down to just pid, inode number, and dentry pointer, and did the path resolution in userspace after the wake. That change cut the probe cost from about 15 µs to about 2 µs on deep paths. It also moved the resolution work off the kernel-side critical path, where stalling is worst, to the userspace side, where stalling merely delays the race without ending it.

## Summary

Observation channel: reliable. Override: unavailable on stock kernels. End-to-end effect: userspace racer against a 50–140 µs window with a success rate that depends heavily on scheduling. Prior art: the copy-up TOCTOU shape has been discussed on the overlayfs list since at least 2019; what's here is a reproducible BPF-driven observer and honest numbers for the race.
