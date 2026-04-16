---
layout: book
title: "Chapter 2: The OverlayFS Trojan Horse"
date: 2025-02-01
---

# Act I: Foundations of Breach

# Chapter 2: The OverlayFS Trojan Horse

> **See also**: [Blog post]({{ site.baseurl }}/the-overlayfs-trojan-horse.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch02-overlayfs) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

I started on this one after noticing, on a linuxkit 6.12 test VM, how much work `ovl_copy_up_one` actually does between the moment it allocates the upper inode and the moment the merged dentry becomes visible. That window is the thing. I wanted to measure it, and then I wanted to see whether a userspace racer could fit inside it.

Up front: the BPF side of this chapter is an observation channel. The override call is there in the code, but `ovl_copy_up_one` is not in `ALLOW_ERROR_INJECTION` on stock 6.12, so the override is a no-op the same way it is in chapter 1. What the probe gives you is a reliable signal — a ringbuf event saying "copy-up is happening now, at this path, for this inode." The weaponization is a userspace racer that consumes those events and tries to touch the upper file before overlayfs finishes wiring it in.

## OverlayFS, Briefly

Three layers:

- **Lower**: read-only.
- **Upper**: writable, populated on first write via copy-up.
- **Merged**: the view the container sees.

The copy-up path lives in [`fs/overlayfs/copy_up.c`](https://elixir.bootlin.com/linux/latest/source/fs/overlayfs/copy_up.c). The function I care about is `ovl_copy_up_one`; on 6.12 it's around line 870. It walks through `ovl_copy_up_data`, `ovl_copy_up_metadata`, and `ovl_finish_copy_up`, and each of those takes and releases locks in a sequence that varies by filesystem type on the upper layer.

## The Probe

```c
SEC("kprobe/ovl_copy_up_one")
int hook_copy_up(struct pt_regs *ctx) {
    struct dentry *d = (void *)PT_REGS_PARM1(ctx);
    struct path *p = (void *)PT_REGS_PARM2(ctx);

    char filename[64];
    bpf_d_path(&p->mnt->mnt_root->d_sb->s_root, filename, sizeof(filename));
    if (is_host_binary(filename)) {
        bpf_override_return(ctx, 0);  // No-op on stock 6.12; kept for annotated kernels
        inject_payload(filename);
        return 1;
    }
    return 0;
}
```

A few things to note. `bpf_d_path` has allowlist restrictions — it only works from a handful of BTF-tagged attach points, and overlayfs copy-up functions are on that list as of 6.4. If you try this on 5.15 the verifier rejects it; I verified by loading against an Ubuntu 20.04 HWE kernel and reading the reject message: `helper call is not allowed in probe`.

The `bpf_override_return(ctx, 0)` line is harmless on kernels where the target isn't annotated. I left it in because on a kernel you control (CI, test VM, or a custom build) you can flip `CONFIG_BPF_KPROBE_OVERRIDE=y` and add the annotation, and the same program enforces instead of observing.

`inject_payload` is the interesting one. It does not run in BPF context — it emits a ringbuf record to a userspace consumer. The BPF program cannot write arbitrary bytes to a file; it cannot `execve`; it cannot even `openat`. All it can do is signal.

## The Race, Actually Observed

Here's the timing I saw on linuxkit 6.12, measured with bpftrace entry/return probes on `ovl_copy_up_one` and `ovl_finish_copy_up`:

- Entry: t=0.
- `ovl_copy_up_data` return: t ≈ 40–120 µs for a 4 KiB file, dominated by the underlying fs write latency.
- `ovl_finish_copy_up` return: t ≈ 5–15 µs after that.
- Total window from ringbuf signal to merged-view visibility: ~50–140 µs.

That is not a lot of time. The userspace racer needs to be woken from a poll on the ringbuf fd, resolve the upper path under `/var/lib/docker/overlay2/.../diff/`, and issue its modification before `ovl_finish_copy_up` completes. On the VM I tested, a racer pinned to an isolated CPU with `SCHED_FIFO` won the race about 30% of the time against `/bin/bash` copy-up triggered by `chmod u+x` inside the container. Without CPU pinning and realtime priority, the number dropped into single digits.

The practical consequence is that this is not a reliable primitive. It's a probabilistic one. If your threat model tolerates "works 30% of the time, try until it does," this is usable. If you need it to land on the first shot, it is not.

## Trigger

```bash
# Inside the container:
chmod u+x /bin/bash   # Forces copy-up
```

That's it. Any write to a lower-layer file works; I picked `chmod` because it produces a deterministic copy-up without modifying contents, which made the timing cleaner to measure.

## What the Racer Does

The userspace side, on receiving a ringbuf event for a path it cares about:

1. Resolves the upper path by reading `/proc/self/mountinfo` for the overlay mount and concatenating the `upperdir` with the relative path from the event.
2. Opens the upper file `O_WRONLY | O_NOFOLLOW`.
3. Writes whatever it's going to write — setuid bit via `fchmod`, ELF patch via `pwrite`, etc.
4. Closes.

None of those operations are BPF. The BPF program is a latency-sensitive doorbell.

## Selective Targeting

The filter in `is_host_binary()` is a prefix match against a BPF map populated from userspace. Keep the allowlist small. Every extra path you match is a ringbuf event, and ringbuf events have real cost — I saw about 2% throughput loss on a `find /` inside the container when the filter was set to match every path.

## Detection

- `bpftool prog show` lists the kprobe program; attach name `ovl_copy_up_one` is a giveaway.
- `/sys/kernel/debug/kprobes/list` shows the attached probe.
- `perf stat -e probe:ovl_copy_up_one` during normal container load shows a probe that a defender didn't install.
- The ringbuf consumer is a userspace process. If it's running as root in the host namespace, `ps auxf` shows it. If it's running inside a container, namespace escape is a separate problem.
- Modified files in the upper layer retain their mtime skew relative to the copy-up event. A defender with `auditd` watching the overlay `upperdir` sees the write.

Nothing in this chapter hides the BPF program or the consumer. Those are separate problems.

## Summary

Observation channel: reliable. Override: unavailable on stock kernels. Weaponization: userspace racer against a 50–140 µs window with a success rate that depends heavily on scheduling. Prior art: the copy-up TOCTOU shape has been discussed on the overlayfs list since at least 2019; what's here is a reproducible BPF-driven observer and honest numbers for the race.
