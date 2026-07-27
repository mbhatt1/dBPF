---
layout: book
title: "Silencing SELinux"
date: 2025-02-06
poc_dir: dBPF-pocs/pocs/ch06-silence-selinux-lsm-synthetic
---

# Silencing SELinux

> **See also**: [Book chapter]({{ site.baseurl }}/book/act-1/chapter-6-silencing-selinux.html) · [Skip accounting (Ch 21)]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) · [Synthetic LSM variant](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch06-silence-selinux-lsm-synthetic)

The honest finding first: on linuxkit 6.12 aarch64 there's no SELinux policy loaded. `cat /sys/kernel/security/lsm` lists `capability,bpf` and nothing else. The LSM hooks `security_file_permission` and `security_inode_permission` still get called, but the `capability` and `bpf` LSMs don't produce natural denials at those sites — so a fmod_ret program meant to flip a denial has nothing to flip. It loads, attaches, and sits there watching silence.

That's a genuine negative result on this kernel. But the primitive shape — "LSM fmod_ret flips a denial into an allow" — can be shown without SELinux in the picture at all. The synthetic POC at `dBPF-pocs/pocs/ch06-silence-selinux-lsm-synthetic/` loads a single LSM program with three stages driven by a control map: `STAGE_OFF` (no-op), `STAGE_DENY` (returns `-EACCES` for a sentinel path), and `STAGE_FLIP` (returns `0` for the same path). SIGUSR1 / SIGUSR2 / SIGHUP toggle the stage at runtime.

The test sequence is straightforward: set stage=DENY, have an unprivileged user `cat` the sentinel file, watch it return rc=1 and `EACCES`. Set stage=FLIP, have the same user `cat` the same file, watch it return rc=0 and the file contents. Same program, same kernel, same user, same file — only the stage changed. That proves the fmod_ret flip works, using a synthetic denial because this test kernel has no real one to offer.

## Mechanism

```c
SEC("lsm.s/file_open")
int BPF_PROG(file_open, struct file *file, int ret) {
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    u32 *target_uid = bpf_map_lookup_elem(&ctrl_map, &KEY_TARGET_UID);
    if (!target_uid || uid != *target_uid) return 0;

    char path[128] = {};
    bpf_d_path(&file->f_path, path, sizeof(path));

    u32 *sentinel_off = bpf_map_lookup_elem(&ctrl_map, &KEY_SENTINEL);
    // bounded compare against sentinel path

    u32 *stage = bpf_map_lookup_elem(&ctrl_map, &KEY_STAGE);
    if (*stage == STAGE_DENY) return -EACCES;
    if (*stage == STAGE_FLIP) return 0;
    return 0;
}
```

Verifier note: `lsm.s/file_open` (sleepable) was needed to call `bpf_d_path` for exact path matching. `lsm/inode_permission` (non-sleepable) only gives `struct inode *` with no cheap path — you'd fall back to inode-number comparison.

## On kernels where SELinux IS enforcing

The same shape applies. Attach `SEC("lsm/file_permission")` or `SEC("lsm/inode_permission")`, check the target tgid against an allowlist map, and return `0` unconditionally for those processes. Natural AVC denials get intercepted and flipped. On an SELinux-active host this isn't theoretical — you'd load the `-lsm` variant of the POC, not the `-synthetic` one.

## Detection

- `cat /sys/kernel/security/lsm` shows `bpf` in the LSM list — necessary for BPF LSM programs to attach.
- `bpftool prog list` shows the LSM attach type.
- `bpftool prog show id <id> --pretty` gives the attach function (`bpf_lsm_file_open`, etc.).
- On an SELinux-active host, a defender can cross-check `ausearch -m AVC` against actual behavior — if AVC says deny but the operation succeeded, something flipped it.

## Scope

Class I primitive from Chapter 20 (return-value override at the API boundary). The primitive is real and lands cleanly on SELinux-active kernels. On linuxkit the synthetic variant proves the flip mechanism; the real attack is waiting for a kernel with policy loaded.

---

**Related material**

- Full chapter: [Chapter 6 — Silencing SELinux]({{ site.baseurl }}/book/act-1/chapter-6-silencing-selinux.html)
- Synthetic LSM variant: [dBPF-pocs/pocs/ch06-silence-selinux-lsm-synthetic/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch06-silence-selinux-lsm-synthetic)
- Harness entry: `Poc("ch06s", ...)` in `dBPF-pocs/harness/proof.py`
