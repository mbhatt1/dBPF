---
layout: book
title: "Chapter 7: Device-cgroup Houdini"
date: 2025-02-07
---

**Chapter 8: Device cgroup Bypass via LSM**

> **Note**: This primitive's natural hook did not fire on the test kernel. See [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) and the surviving workaround variant at [dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs).

I started this one expecting an easy win. Device cgroups are the standard container control for hardware access, and privileged container bypasses are well-trodden ground — Aqua and NCC Group have written about direct mknod escapes for years. My question was narrower: can a `BPF_PROG_TYPE_LSM` program flip a denied `/dev/mem` open into an allowed one without the container being privileged?

The honest answer is: not the way I first tried.

My initial plan was to hook `devcgroup_check_permission()` with a kprobe and return 0. That does work, but it's a kprobe override, not an LSM decision, and it requires `CONFIG_BPF_KPROBE_OVERRIDE=y` plus `ALLOW_ERROR_INJECTION` on the target — neither is set on the stock Debian bookworm 6.1 kernel I was testing against. So I moved to the LSM hook `security_inode_mknod` instead, which is a proper BPF LSM attach point.

That's when I hit the real problem. I ran the unprivileged container, called `mknod /dev/mem c 1 1`, and my LSM program was never invoked. The syscall failed with `EPERM` before my hook ran.

I went to the source. In `fs/namei.c`, `vfs_mknod()` sits behind `do_mknodat()`, and the capability check happens much earlier. The relevant line is in `do_mknodat()` around line 4050 in 6.1:

```
if (!IS_POSIXACL(path.dentry->d_inode))
    mode &= ~current_umask();
error = may_mknod(mode, dev);
```

`may_mknod()` short-circuits on `capable(CAP_MKNOD)` before any inode operation. In an unprivileged user namespace, `CAP_MKNOD` against the init user_ns is false, so `may_mknod` returns `-EPERM` and we never reach `security_inode_mknod`. The LSM hook only fires if capability already allowed the call.

This is a known kernel design choice — LSMs restrict what capability permits, they don't re-open what capability denies. Grsecurity and SELinux FAQ material have pointed this out for years. But it means my pure "flip deny to allow" LSM program can't see the request in the first place.

So the workaround is ugly but honest: I issue a synthetic `mknod` from a process that already has `CAP_MKNOD` in its user_ns (a short-lived helper in a `userns` where uid 0 is mapped), let the LSM hook observe it, and use bpf_map state set by my attacker process to decide the return. The LSM program returns 0 to allow, or an engineered -EACCES that my trigger detects and retries. It's not an escape of cgroup enforcement so much as a cooperative bypass riding on an existing capability.

```c
SEC("kprobe/devcgroup_check_permission")
int override_device_check(struct pt_regs *ctx) {
    // Always grant access to our processes
    return 0;
}

char LICENSE[] SEC("license") = "GPL";