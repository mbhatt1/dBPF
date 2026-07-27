---
layout: book
title: "Chapter 7: Device-cgroup Houdini"
date: 2025-02-07
---

# Chapter 7: Device cgroup Bypass via LSM

> **See also**: [Blog post]({{ site.baseurl }}/device-cgroup-houdini.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm) · [Chapter 21; Skip Accounting]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)

> **Proof status**: The synthetic deny+flip is proved on Ubuntu 6.17.0-29-generic aarch64 (Lima VM). The natural denial flip — intercepting a real device-cgroup denial — is not achievable on a stock LSM chain, because `capable(CAP_MKNOD)` and `devcgroup_inode_mknod()` both run inside `vfs_mknod` before `security_inode_mknod` is ever called. The POC is honest about this and uses a staged synthetic design. See [Chapter 21]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) for skip accounting.

The idea was straightforward: attach an LSM fmod_ret program to `security_inode_mknod` and return `0` whenever the device-cgroup controller would have denied. I wrote the BPF side in about thirty minutes, the loader in another hour, built, booted, ran the loader, ran `mknod` from inside an unprivileged container. The syscall returned `-EPERM`. My LSM program fired zero times. Ringbuf empty. `bpftool prog list` showed the program loaded and attached.

The program was loaded, attached, and fine. It just never ran. The syscall had already failed before the kernel got anywhere near the LSM chain.

## Why the hook never fires

Reading `fs/namei.c` on 6.12 shows the problem. Inside `vfs_mknod`, the ordering is: (1) `may_create` permission check, (2) `capable(CAP_MKNOD)` for char/block devices, (3) `devcgroup_inode_mknod` for cgroup device restrictions, and finally (4) `security_inode_mknod` for the LSM chain.

An unprivileged container has `CAP_MKNOD` in its own user namespace but not in the init user namespace. `capable(CAP_MKNOD)` returns false against init. `vfs_mknod` returns `-EPERM`. We never reach `devcgroup_inode_mknod`. We never reach `security_inode_mknod`. The LSM chain is never consulted.

This is not a bug. LSMs restrict; they do not re-open. The BPF LSM slot is registered after `capability` in the LSM chain on every mainstream distro. Even for fmod_ret, which does let a BPF program see and overwrite the accumulated chain result, the call to `security_inode_mknod` has to happen first. If `vfs_mknod` returns `-EPERM` before that call, there is nothing to overwrite.

I checked `/sys/kernel/security/lsm` on Debian: `capability,yama,apparmor,bpf`. Reading left to right, `capability` is first, `bpf` is last. The direct `capable(CAP_MKNOD)` call in `vfs_mknod` is not even in the LSM chain; it is raw VFS code that fires before `security_inode_mknod` is called at all.

The same applies to `devcgroup_inode_mknod()`. Both gates are pre-LSM. A BPF LSM fmod_ret on `inode_mknod` cannot flip a device-cgroup denial for mknod because the denial happens before the LSM chain fires.

## The missing BTF FUNC for dev_open

While I was still on the original approach, I had compiled in three programs: `lsm/inode_mknod`, `lsm/file_open`, and `lsm/dev_open`. libbpf rejected the skeleton load with:

```
libbpf: prog 'lsm_dev_open': failed to find kernel BTF type ID of 'dev_open': -3
```

The linuxkit BTF dump does not contain a `bpf_lsm_dev_open` FUNC entry. The kernel had chosen not to expose that hook as a BPF attach target. And libbpf's default is all-or-nothing; one missing hook takes down the whole load.

The fix is to pre-check BTF for each hook name via `btf__find_by_name_kind(btf, "bpf_lsm_<hook>", BTF_KIND_FUNC)` and call `bpf_program__set_autoload(prog, false)` on missing targets before `__load()`. With `dev_open` pruned, `inode_mknod` and `file_open` attach fine.

## What the POC does instead

With the natural-denial path blocked and `dev_open` pruned, the POC falls back to the synthetic two-stage design `ch06` established. A single BPF program implements both the denier and the flipper, selected at runtime by a control map. Three signals toggle the stage: `SIGUSR1` / `SIGUSR2` / `SIGHUP`.

```c
SEC("lsm.s/inode_mknod")
int BPF_PROG(inode_mknod, struct inode *dir, struct dentry *dentry,
             umode_t mode, dev_t dev, int ret) {
    u32 *stage = bpf_map_lookup_elem(&ctrl_map, &KEY_STAGE);
    if (!stage) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *target = bpf_map_lookup_elem(&ctrl_map, &KEY_TARGET_TGID);
    if (target && *target != 0 && *target != pid) return 0;

    if (*stage == STAGE_DENY && S_ISBLK(mode)) {
        emit_flip_event(dentry, mode, dev, /*verdict=*/-EPERM);
        return -EPERM;
    }
    if (*stage == STAGE_FLIP && S_ISBLK(mode)) {
        emit_flip_event(dentry, mode, dev, /*verdict=*/0);
        return 0;
    }
    return 0;
}
```

One program, same kernel, same user. Only the stage changes. The fmod_ret mechanism is real. The denial being flipped is synthetic; our own BPF program creates and then flips it.

## On kernels where the device cgroup does enforce

Modern runtimes implement device cgroup restrictions using a `BPF_PROG_TYPE_CGROUP_DEVICE` program at the cgroup's `BPF_CGROUP_DEVICE` slot. runc's default `allowedDevices` list gets compiled into one of these; it allows `/dev/null`, `/dev/zero`, `/dev/urandom`, and denies everything else. When a container process attempts `mknod /dev/mem c 1 1`, the kernel invokes the cgroup program in `devcgroup_check_permission()`, which is called from `vfs_mknod` via `devcgroup_inode_mknod()`.

The attack shape for `mknod` doesn't land. The cgroup device check is a direct call inside `vfs_mknod`, after `capable(CAP_MKNOD)` but before `security_inode_mknod`. The sequence the kernel actually runs: capability check → cgroup device check → LSM chain. A BPF LSM fmod_ret on `inode_mknod` runs after both pre-LSM gates. If the cgroup program denies, `devcgroup_inode_mknod()` returns early, `vfs_mknod` returns `-EPERM`, and `security_inode_mknod` is never called. The BPF LSM program never runs.

The `file_open` path is wired differently. `security_file_open` is a real LSM hook, and the cgroup device check for open (`devcgroup_inode_permission`) runs through the VFS `inode_permission` path, not as a pre-LSM short-circuit inside `vfs_mknod`. A BPF LSM fmod_ret on `file_open` can see device file opens from container processes; that path is reachable from the LSM chain. The attack surface for the real bypass is opening a pre-existing device node, not creating one.

The attacker privilege model here is specific: a process on the host (or in a container with `CAP_BPF` in the init user namespace) that wants to escape device-cgroup restrictions set by the orchestrator on some other container. That's a narrow threat model, but a plausible one in compromised-orchestrator scenarios or multi-tenant kernels where one tenant holds `CAP_BPF`. At that privilege level, the attacker doesn't need this primitive for most goals; but device access that the cgroup table forbids is the specific thing it buys.

## Detection

- `cat /sys/kernel/security/lsm` shows `bpf` enabled.
- `bpftool prog list` shows LSM attach types and the exact `bpf_lsm_<hook>` names.
- Cross-check: if `mknod` inside a container succeeds for a device the container's cgroup v2 devices program would normally deny, something above that program flipped the decision.

## Scope

Class I primitive (return-value override at an LSM hook). The fmod_ret mechanism is real and demonstrated: a BPF LSM program can see and overwrite the accumulated LSM chain return value. What is not demonstrated — and cannot work via the mknod path — is bypassing an actual device cgroup denial. For mknod, `capable(CAP_MKNOD)` and `devcgroup_inode_mknod()` both fire inside `vfs_mknod` before `security_inode_mknod` is ever called; the LSM chain is never consulted when the pre-LSM gates deny. The POC proves the flip on a self-synthesized denial, not on a real device cgroup denial.

The `file_open` path is structurally different — `security_file_open` is a genuine LSM hook that a BPF fmod_ret program can reach — but that path was not exercised here and the bypass is not demonstrated. The proof marker is `CH07_CONCEPT_PROVEN`; the concept word is load-bearing and accurately scopes what was shown.

The takeaway is a clearer map of the pre-LSM checks in `vfs_mknod`, and a reminder that fmod_ret only helps once you can actually reach the hook. The flip machinery works. Reaching a hook that fires on a real denial is the harder part, and on the `file_open` path it remains untested here.

> **See also**: [POC source; ch07-devcgroup-houdini-lsm](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm) · Harness entry: `Poc("ch07", ...)` in `dBPF-pocs/harness/proof.py`
