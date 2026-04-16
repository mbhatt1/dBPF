---
layout: book
title: "Inode Cloak"
date: 2025-02-10
---

Act II: Kernel Intrusion

**Chapter 11: Making Files Vanish from getdents64**

> **See also**: [Blog post]({{ site.baseurl }}/inode-cloak.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch10-inode-cloak) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

This one isn't new. The d_reclen-swallow trick for hiding dirents inside the `getdents64` return buffer has been in rootkit proof-of-concepts for years — Jiska Classen, the kovid/reveng'd crowd, and various LKM rootkits have used variants of it since at least 2016. My contribution here is narrower: a modern CO-RE reproduction on 6.12 aarch64 using two syscall tracepoints, with ringbuf evidence and honest testing against `ls`, `find`, and `stat`.

The primitive: when `getdents64` returns, each entry in the user buffer carries its own `d_reclen` field telling userspace how many bytes to skip to reach the next record. If I extend the previous entry's `d_reclen` so it covers the one I want to hide, every userspace reader — libc, Python, Go — will stride right over the hidden name without ever seeing it. No file is deleted. No inode is touched on disk. `open("/tmp/cloak/.backdoor")` still works because name resolution goes through a different path.

I hooked two tracepoints:

- `tp/syscalls/sys_enter_getdents64` — stash the userspace `dirp` pointer in a per-(pid,tgid) hash map.
- `tp/syscalls/sys_exit_getdents64` — walk the returned stream, match names against a `hidden` hash, and rewrite `d_reclen` on the preceding entry.

What `bpf_probe_write_user` can and can't do here is worth being explicit about. It can write to the current task's userspace pages because on syscall exit the buffer is still resident and owned by the caller. It can't re-scan indefinitely because the verifier caps loops — I bounded the dirent walk to 64 entries per call, which is the ceiling I could convince the verifier to accept with the linear probe pattern. Directories with more than 64 entries per `getdents64` return can leak names past the bound, and a large directory split across multiple syscalls is fine because each call gets its own bounded walk.

Edge case I had to handle: if the hit is the very first entry in the buffer, there is no predecessor to extend. Best-effort there is zeroing `d_ino` so a naive reader that treats ino=0 as "skip" drops it on the floor. That's weaker than the swallow trick. I logged both paths to ringbuf so I could tell them apart in the evidence.

```c
SEC("tp/syscalls/sys_enter_getdents64")
int sys_enter_getdents64(struct trace_event_raw_sys_enter *ctx) {
    // stash userspace dirp pointer keyed by pid_tgid
    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int sys_exit_getdents64(struct trace_event_raw_sys_exit *ctx) {
    // walk up to 64 dirents, extend prev->d_reclen to swallow matches
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

Evidence on Docker Desktop linuxkit aarch64, with hidden set `{.backdoor, evil.so}`:

```
=== ls -la /tmp/cloak (BPF rewrites d_reclen here) ===
-rw-r--r-- 1 root root 0 Apr 14 12:00 notes.txt
-rw-r--r-- 1 root root 0 Apr 14 12:00 visible
=== find /tmp/cloak (also calls getdents64) ===
/tmp/cloak/notes.txt
/tmp/cloak/visible
=== stat .backdoor (still resolvable by name) ===
  File: /tmp/cloak/.backdoor
[cloak] pid=1234	comm=ls	hiding=.backdoor
[cloak] pid=1235	comm=find	hiding=evil.so
```

The honest limits of the cloak: it runs on `getdents64` only. Legacy `getdents` (32-bit) is not hooked. `stat`, `open`, `inotify`, `fanotify`, and anything that reads the raw filesystem image see the file normally. A defender who does `debugfs -R 'ls /tmp/cloak' /dev/sda1` or reads the directory entries off the block device walks around the cloak entirely.

Detection. `bpftool prog show` lists both tracepoint programs. `bpftool map dump name hidden` prints the cloaked filename set in cleartext — this is the loudest tell, because the attacker has to keep the map populated for the cloak to fire. `strace -e getdents64` observes the post-mutation buffer, but a syscall-level comparator (a second tracepoint at higher priority, or a userspace reader that mmaps `/proc/self/mem` of a tracer) can diff against the unmodified stream. Cross-referencing `ls` output with `find -inum` or with `readdir` via a different code path exposes the discrepancy.

Factual note: the chapter draft I started from described hooks at `iterate_dir` and `vfs_stat`. Those aren't the hooks I ended up using, and they don't implement this primitive. `iterate_dir` runs inside the kernel, before the entries are copied to userspace, and kprobing it to filter would require modifying the in-kernel dir_context — a much harder problem and one I didn't solve. The tracepoint-plus-`bpf_probe_write_user` path is the one that actually works, and it's the one the POC ships.
