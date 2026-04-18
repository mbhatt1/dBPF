---
layout: book
title: "Device-cgroup Houdini"
date: 2025-02-07
poc_dir: dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm
---

# Device-cgroup Houdini

> **See also**: [Book chapter]({{ site.baseurl }}/book/act-2/chapter-7-device-cgroup-houdini.html) · [Skip accounting (Ch 21)]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) · [Workaround variant](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm)

The idea was straightforward: attach an LSM fmod_ret program to `security_inode_mknod` and return `0` whenever the device-cgroup controller would have denied. On linuxkit that doesn't land, for a specific and interesting reason.

Reading `fs/namei.c::do_mknodat()` on 6.12 shows that `may_mknod()` is called before `security_inode_mknod`. `may_mknod()` calls `capable(CAP_MKNOD)` directly — if the caller lacks the capability, `-EPERM` is returned *before* the LSM chain is consulted. The BPF LSM slot is registered after `capability` in the LSM chain on every mainstream distro, so a natural cap-based denial never reaches our program.

Additionally, the POC tried to attach a third hook `SEC("lsm/dev_open")`. The linuxkit BTF dump does not contain a `bpf_lsm_dev_open` FUNC entry — libbpf reports `failed to find kernel BTF type ID of 'dev_open': -3` and the whole program load fails. The fix in the loader is to pre-check BTF for each hook name via `btf__find_by_name_kind(BTF_KIND_FUNC, "bpf_lsm_<hook>")` and call `bpf_program__set_autoload(prog, false)` on missing targets. With `dev_open` pruned, `inode_mknod` and `file_open` attach fine.

With the load working, the remaining question was how to produce a denial for the program to observe. The honest answer: on this kernel, with the `capability` LSM intercepting first, there is no natural denial at the BPF LSM slot. The POC therefore uses the same synthetic two-stage design as the ch6 variant — ctrl_map with `STAGE_OFF` / `STAGE_DENY` / `STAGE_FLIP`. One program, same kernel, same user; only the stage changes. Signal-driven stage control via SIGUSR1/SIGUSR2/SIGHUP.

## Mechanism

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

The loader reads vmlinux BTF, prunes hooks whose target FUNC is missing, and attaches the rest. Per-hook attach errors don't take down the whole loader.

## On kernels where the device cgroup does enforce

The primitive shape lands naturally. Modern container runtimes rely on the cgroup v2 `devices` BPF program to restrict `mknod` inside containers. A defender-owned BPF program at that slot says "allow character 1:3 (`/dev/null`), deny everything else." An attacker-owned LSM fmod_ret above that slot returns `0` for the target tgid on any device, flipping the container's device cgroup restriction to permissive for one specific process.

## Detection

- `cat /sys/kernel/security/lsm` shows `bpf` enabled.
- `bpftool prog list` shows LSM attach types and the exact `bpf_lsm_<hook>` names.
- Cross-check: if `mknod` inside a container succeeds for a device the container's cgroup v2 devices program would normally deny, something above that program flipped the decision.

## Scope

Class I primitive (return-value override at an LSM hook). Real and weaponizable where the device cgroup is actually restrictive. Synthetic on the linuxkit test kernel because the cap check short-circuits before the LSM slot is consulted.

---

**Related material**

- Full chapter: [Chapter 7 — Device-cgroup Houdini]({{ site.baseurl }}/book/act-2/chapter-7-device-cgroup-houdini.html)
- Workaround POC: [dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm)
- Harness entry: `Poc("ch07w", ...)` in `dBPF-pocs/harness/proof.py`
