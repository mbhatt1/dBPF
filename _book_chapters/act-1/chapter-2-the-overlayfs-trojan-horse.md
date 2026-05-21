---
layout: book
title: "Chapter 2: The OverlayFS Trojan Horse"
date: 2025-02-01
---

# Chapter 2: The OverlayFS Trojan Horse

> **See also**: [Blog post]({{ site.baseurl }}/the-overlayfs-trojan-horse.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch02-overlayfs) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Proof status**: Both `ch02-overlayfs` (kprobe observer + userspace racer) and `ch02-overlayfs-lsm` (BPF LSM fmod_ret on `inode_copy_up`) have been proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). No code changes were required; both variants worked as-is.

I started on this one after noticing, on a linuxkit 6.12 test VM, how much work `ovl_copy_up_one` actually does between allocating the upper inode and the merged dentry becoming visible. The interesting question was whether a userspace process with the ringbuf could win the race against the container process whose write triggered the copy-up.

Up front: the BPF side of this chapter is an observation channel. The shipped POC attaches kprobes to three entry points into the copy-up path and does nothing else; no `bpf_override_return`, no in-BPF payload injection. What the probe gives you is a reliable signal: a ringbuf event saying "copy-up is happening now, for this dentry, via this entry point." The effect comes from a userspace racer that consumes those events and opens the upper file before overlayfs finishes wiring it in.

Observed timings on the test VM: the window between the first kprobe and the container read is 50–140 µs. A `SCHED_FIFO` + CPU-pinned racer wins ~30% of the time on cold caches, higher when the container process yields.

## Mechanism

### BPF side; three kprobes, one ringbuf

```c
SEC("kprobe/ovl_maybe_copy_up")
int BPF_KPROBE(kp_mcu, struct dentry *d, int flags) {
    emit_copy_up_event(d, HOOK_MAYBE);
    return 0;
}

SEC("kprobe/ovl_copy_up")
int BPF_KPROBE(kp_cu, struct dentry *d) {
    emit_copy_up_event(d, HOOK_SYNC);
    return 0;
}

SEC("kprobe/ovl_copy_up_with_data")
int BPF_KPROBE(kp_cud, struct dentry *d) {
    emit_copy_up_event(d, HOOK_WITH_DATA);
    return 0;
}
```

`emit_copy_up_event` walks `d->d_name.name`, `d->d_inode->i_ino`, `d->d_inode->i_mode` via `BPF_CORE_READ`, stamps `bpf_get_current_pid_tgid()` and `bpf_get_current_comm()`, and pushes a ringbuf record. The three hooks overlap deliberately. `ovl_maybe_copy_up` fires earliest, before overlayfs has decided whether a copy-up is actually needed. `ovl_copy_up` fires once per ancestor during the upward recursion. `ovl_copy_up_with_data` flags when the data copy path has been selected. A single write produces one event from each of the three.

The earlier drafts imagined a single `kprobe/ovl_copy_up_one` hook with `bpf_override_return` and in-BPF payload injection. None of that shipped. `ovl_copy_up_one` fires once per ancestor, which is noise the racer has to filter. The override is a no-op on stock 6.12 because the function is not on the error-injection allowlist. In-BPF payload injection is not possible without a write-to-page-cache helper that does not exist.

### Userspace racer

```c
while (ring_buffer__poll(rb, 100) >= 0) {
    struct evt *e = ...;
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", upperdir, e->name);
    int fd = open(path, O_WRONLY|O_TRUNC, 0);
    if (fd >= 0) {
        write(fd, PAYLOAD, sizeof(PAYLOAD));
        close(fd);
        fprintf(stderr, "[ch02] PWNED path=%s bytes=%zu hits=%d\n",
                path, sizeof(PAYLOAD), ++hits);
    }
}
```

The racer runs as a privileged peer to the container. `bpf_probe_write_user` can't reach kernel page cache, and `bpf_probe_write_kernel` does not exist; so the BPF side is purely a trigger for the userspace write.

I tried to find a kernel-only solution. The helpers the BPF verifier permits all break in the same place: `bpf_probe_write_user` is blocked from kernel addresses by `access_ok()`; there is no `bpf_probe_write_kernel`; `bpf_skb_store_bytes` only applies to packet memory; `bpf_dynptr_*` can only write to pointers that came from somewhere that granted write access, and nothing grants write access to a page cache page. The write has to happen in userspace. Which means we need a signal. Which means ringbuf.

## Hook points

- `kprobe/ovl_copy_up`; synchronous promotion path.
- `kprobe/ovl_maybe_copy_up`; pre-check before the synchronous path; earliest reliable signal.
- `kprobe/ovl_copy_up_with_data`; data-carrying promotion (used when `metacopy` is off).

All three exist in `/proc/kallsyms` on 6.12 aarch64 linuxkit. On older kernels the set varies; the loader autoloads whichever are present and logs misses.

## The race, measured

Timing on linuxkit 6.12 with bpftrace entry/return probes on `ovl_copy_up_one` and `ovl_do_copy_up`:

- Entry: t=0.
- `ovl_copy_up_data` return: t ≈ 40–120 µs for a 4 KiB file.
- `ovl_do_copy_up` return: t ≈ 5–15 µs after that.
- Total window from ringbuf signal to merged-view visibility: ~50–140 µs.

A `SCHED_FIFO` + CPU-pinned racer wins the race about 30% of the time against `/bin/bash` copy-up on cold caches. Without CPU pinning and realtime priority, that drops into single digits. The practical consequence is that this is a probabilistic primitive, not a reliable one.

Loss mode: the racer loses when `ovl_do_copy_up` completes before the `open` returns. At that point the merged-view dentry is already updated and the write lands too late. No corruption. The file is modified, but after the container has already seen the original content.

The slow 10% of races where the window stretched past 200 µs were all cases where the upper filesystem was ext4 on a loopback-mounted sparse file. The loopback layer adds real latency to `ovl_copy_up_data`, and on those runs the racer won closer to 70% of the time.

## metacopy and redirect_dir edge cases

`metacopy=on` splits the copy-up into two phases: metadata first, data on the next write. From the racer's perspective this doubles the number of signal events per file lifecycle and widens the first window. Metadata-only copy-up takes under 20 µs; data copy-up takes the full 50–140 µs. The attacker gets two shots instead of one. Docker ships `metacopy=on` by default on versions 24+.

`redirect_dir=on` changes where the upper file lands, encoded in the `trusted.overlay.redirect` xattr on the upper directory. The racer must resolve the xattr-adjusted upper path at startup by parsing `/proc/mounts` and honoring redirects when walking the upper tree. Getting the `trusted.overlay.*` xattr requires `CAP_SYS_ADMIN` in the init user namespace, which is consistent with the threat model but rules out unprivileged container processes.

The `metacopy=on,redirect_dir=on` combination gives the racer a longer first window but a more complex path resolution. Whether the metacopy variant offers a net advantage was not tested by the shipped POC; the metadata-only phase measured at 80–200 µs on linuxkit with that combination, but end-to-end win-rate comparison against the baseline was not performed.

## What I got wrong on the first pass

My first probe attached to `ovl_copy_up_one`; the function named in the older write-ups I had been reading. It fired on a subset of copy-ups and I spent two days debugging a racer winning less than 5% of the time before I realized the probe was missing most triggers. Switching to `ovl_maybe_copy_up` raised the fire rate by about 4x.

My first racer used `O_RDWR`. The `O_RDWR` added a few microseconds to the `open` syscall due to a slightly longer permission check. Switching to `O_WRONLY | O_NOFOLLOW` bumped the win rate by about three percentage points. In a 50 µs race, three percent matters.

I also wrote the first racer in Python. Python's `open` goes through `io.BufferedWriter`, each wrapper adding microseconds. I measured 40 µs from poll-wake to write-return versus 8 µs for the C version. In a 50–140 µs window, 32 extra microseconds is the difference between winning and rarely winning.

## Reproduction

```bash
cd dBPF-pocs/pocs/ch02-overlayfs
make
sudo bash trigger.sh
# ... victim writes "mutation" to merged/secret.txt, reads it back
# expected AFTER: content = "pwned-by-bpf-racer"
```

Prior art on overlayfs copy-up timing goes back to 2019 lkml discussions about lower-layer TOCTOU. The contribution here is a reproducible harness with BEFORE/AFTER markers and honest numbers for the race.

## The LSM variant

There is a parallel POC in `dBPF-pocs/pocs/ch02-overlayfs-lsm/` that attaches a BPF LSM `fmod_ret` program to `lsm/inode_copy_up`. On a kernel with BPF LSM enabled, this can return a non-zero value to block the copy-up entirely for a target path; a first-class enforcement primitive, not a race. The LSM variant is categorically different from the racer: where the racer depends on a timing window, the LSM variant simply refuses the copy-up. The cost is that it requires BPF LSM and reveals its presence the moment the copy-up fails in an unexpected way. The kprobe racer is the more interesting primitive for a hosted-container scenario where BPF LSM may not be available.

## Detection

- `bpftool prog show | grep ovl_copy_up`; unusual probe targets for most fleets. Falco, Tetragon, and Tracee do not probe overlayfs copy-up internals by default.
- Unexpected `open()` activity on `<upperdir>/` from a privileged peer process. Look for non-container UIDs writing into overlay upperdirs.
- If auditd has a watch on the overlay upperdir (`-w /var/lib/docker/overlay2 -p wa -k overlay_upper`), every racer write appears in the audit log.
- Mount-time option `-o redirect_dir=on` changes the upper path, which a naive racer misses. Defenders on modern kernels can also move to `-o metacopy=on` which changes the copy-up timing; though as noted above, this actually widens the first window.

Ultimately `CAP_BPF` on the host gives the attacker everything above. Restrict who holds it and audit `bpf(2)` loads.

## Scope

This is a Class V primitive from chapter 20: kernel event + userspace racer. The race is real but not deterministic. This is a probabilistic attack even with CPU-pinning and realtime priority; expect 30–70% hit rate on a loaded host.

---

**Related material**

- Blog post: [The OverlayFS Trojan Horse]({{ site.baseurl }}/the-overlayfs-trojan-horse.html)
- POC source: [dBPF-pocs/pocs/ch02-overlayfs/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch02-overlayfs)
- Harness entry: search for `Poc("ch02", ...)` in `dBPF-pocs/harness/proof.py`
