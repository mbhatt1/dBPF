---
layout: book
title: "Chapter 6: Silencing SELinux"
date: 2025-02-06
---

# Chapter 6: Silencing SELinux

> **Note**: Three PoC variants ship with this chapter. `ch06-silence-selinux-lsm` (REAL mutation, BPF LSM fmod_ret on three hooks) is the primary; it fires on an SELinux-enforcing kernel and skips cleanly everywhere else. `ch06-silence-selinux` (REAL observer, kprobes on AVC internals) is the secondary reconnaissance variant; registered in the harness as `ch06o`. `ch06-silence-selinux-lsm-synthetic` is a portability variant described below.

> **Proof status**: All three variants proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). The primary LSM variant fires natively on a Fedora 42 aarch64 QEMU VM driven by `dBPF-pocs/run-qemu-tests.sh`. The synthetic variant proves the fmod_ret flip mechanism on kernels where SELinux is compiled in but no policy is loaded. See [Chapter 21]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) for skip accounting.

The honest finding first: on linuxkit 6.12 aarch64 there is no SELinux policy loaded. `cat /sys/kernel/security/lsm` lists `capability,bpf` and nothing else. The LSM hooks `security_file_permission` and `security_inode_permission` are called, but the `capability` and `bpf` LSMs don't produce natural denials at those sites, so a fmod_ret program that would flip a denial has nothing to flip. The program loads, attaches, and watches silence.

That's a real and honest negative result on this kernel. The primary PoC checks `/sys/kernel/security/lsm` at startup, finds no `selinux` token, emits `CH06_SKIP`, and exits. No synthetic denial is manufactured to paper over the absence.

## Where it actually fires

The kernel where the primary PoC fires is a Fedora 42 aarch64 QEMU VM driven by `dBPF-pocs/run-qemu-tests.sh`. That script boots a SELinux-enforcing image, creates a file labeled `shadow_t` in a tmpfs:

```bash
chcon system_u:object_r:shadow_t:s0 "$SECRET"
```

Then it runs `runcon user_u:user_r:user_t:s0 cat "$SECRET"` to provoke a genuine AVC denial; `user_t` doesn't have read permission on `shadow_t`. Starts the loader. Re-runs the access. The three `lsm/` programs flip the would-be deny to an allow. The `cat` succeeds and outputs the file contents.

That last point matters: SELinux's policy evaluation runs before the BPF program. The AVC denial is logged regardless. The user-visible behavior says the access succeeded; the audit log says SELinux denied it. The inconsistency is the detection signal, and it's also why audit log suppression (ch03) pairs naturally with this primitive.

## Mechanism

The primary variant's hook set is three non-sleepable programs on `lsm/file_permission`, `lsm/inode_permission`, and `lsm/bprm_check_security`. Three hooks because SELinux routes different access paths through different LSM entry points: `file_permission` covers already-open descriptors, `inode_permission` covers open-time path walks, `bprm_check_security` covers `execve`. A flipper that only covers one path leaves the others exposed.

```c
SEC("lsm.s/file_open")
int BPF_PROG(file_open, struct file *file, int ret) {
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    u32 *target_uid = bpf_map_lookup_elem(&ctrl_map, &KEY_TARGET_UID);
    if (!target_uid || uid != *target_uid) return 0;

    char path[128] = {};
    bpf_d_path(&file->f_path, path, sizeof(path));

    u32 *stage = bpf_map_lookup_elem(&ctrl_map, &KEY_STAGE);
    if (*stage == STAGE_DENY) return -EACCES;
    if (*stage == STAGE_FLIP) return 0;
    return 0;
}
```

The `fmod_ret` semantic is what makes the override real. BPF LSM programs run after the static LSMs. When SELinux returns `-EACCES` and the BPF program returns `0`, the chain result is `0` and the call allows. The `bpf_lsm_hooks` allowlist in `kernel/bpf/bpf_lsm.c` includes all three hooks; they are documented targets for BPF-side verdict modification.

`lsm.s/file_open` (sleepable) was needed to call `bpf_d_path` for exact path matching. `lsm/inode_permission` (non-sleepable) only gives `struct inode *` with no cheap path; inode-number comparison is the fallback. Mixing sleepable and non-sleepable programs in the same skeleton is fine; the attach type on each program governs individually.

## The observer variant

`ch06-silence-selinux` attaches kprobes to `avc_denied` and `avc_audit`; the functions inside the AVC (Access Vector Cache) that run when SELinux reaches a denial decision. It doesn't flip anything. It reads `struct av_decision` CO-RE fields and emits the target class, requested permissions, and whether the decision came from cache or policy lookup. On the Fedora VM, every AVC miss streams through this observer before the primary flipper's return-value override takes effect. The two variants run cleanly alongside each other; the observer is a reconnaissance tool, the LSM variant is the weapon.

## The synthetic variant

`ch06-silence-selinux-lsm-synthetic` exists because some kernels have `selinux` compiled in and its symbols present in `/proc/kallsyms`, but `selinux_loaded()` returns 0; no policy is active. The standard trigger catches this and emits `CH06_SKIP`.

The synthetic variant eliminates the `selinux_loaded()` gate. Instead it loads a single LSM program driven by a control map with three stages: `STAGE_OFF` (no-op), `STAGE_DENY` (returns `-EACCES` for a sentinel path), and `STAGE_FLIP` (returns `0` for the same path). SIGUSR1/SIGUSR2/SIGHUP toggle the stage at runtime.

The test sequence: set stage=DENY, have an unprivileged user `cat` the sentinel file, observe rc=1 and `EACCES`. Set stage=FLIP, have the same user `cat` the same file, observe rc=0 and the file contents. Same program, same kernel, same user, same file; only the stage changed. That proves the fmod_ret flip works, using a synthetic denial because the test kernel has no real one.

This is not a change in the primary primitive; the fmod_ret override path still requires both `bpf` and `selinux` in the active LSM list. The synthetic variant proves the flip mechanism on kernels where no live policy enforcement context exists. It emits `CH06_SYNTH_PROVEN` when at least one flip event is captured.

## Detection

- `cat /sys/kernel/security/lsm` shows `bpf` in the LSM list; necessary for BPF LSM programs to attach. Removing `bpf` from the `lsm=` kernel parameter at boot prevents the primitive entirely.
- `bpftool prog list --type lsm` enumerates every attached BPF LSM program. On Amazon Linux 2023 and RHEL 9 defaults, no BPF LSM programs are attached; any non-empty output is anomalous.
- `bpftool prog show id <id> --pretty` gives the attach function (`bpf_lsm_file_permission`, `bpf_lsm_inode_permission`, `bpf_lsm_bprm_check_security`).
- On an SELinux-active host: `ausearch -m AVC -ts recent` combined with observation of the corresponding syscall outcome. If the AVC record says deny and the syscall returned success, something flipped it. This is the strongest runtime detection signal; no other mechanism produces the AVC-versus-outcome inconsistency without also suppressing the audit log, which is a separate and detectable operation.

## Scope

Class I primitive from Chapter 20 (return-value override at the API boundary). The primitive is real and lands cleanly on SELinux-active kernels. On linuxkit the synthetic variant proves the flip mechanism; the real attack is waiting for a kernel with policy loaded.

This is the first Class I primitive in the book. Chapters 1 and 3 were Class III because their targets (`cap_capable`, `audit_log_start`) are not in `ALLOW_ERROR_INJECTION`. BPF LSM was explicitly designed to allow runtime verdict modification for a specific allowlist of hooks, and `file_permission`, `inode_permission`, and `bprm_check_security` are all on it. The design intent and the attack primitive align exactly.
