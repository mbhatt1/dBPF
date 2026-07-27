---
layout: book
title: "Chapter 6: Silencing SELinux"
date: 2025-02-06
---

# Chapter 6: Silencing SELinux

> **Note**: Three PoC variants ship with this chapter. `ch06-silence-selinux-lsm` (REAL mutation, BPF LSM fmod_ret on three hooks) is the primary; it fires on an SELinux-enforcing kernel and skips cleanly everywhere else. `ch06-silence-selinux` (REAL observer, kprobes on AVC internals) is the secondary reconnaissance variant; registered in the harness as `ch06o`. `ch06-silence-selinux-lsm-synthetic` is a portability variant described below.

> **Proof status**: All three variants proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). The primary LSM variant fires natively on a Fedora 42 aarch64 QEMU VM driven by `dBPF-pocs/run-qemu-tests.sh`. The synthetic variant proves the fmod_ret flip mechanism on kernels where SELinux is compiled in but no policy is loaded. See [Chapter 21]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) for skip accounting.

The honest finding first: on linuxkit 6.12 aarch64 there's no SELinux policy loaded. `cat /sys/kernel/security/lsm` lists `capability,bpf` and nothing else. The LSM hooks `security_file_permission` and `security_inode_permission` still get called, but the `capability` and `bpf` LSMs don't produce natural denials at those sites — so a fmod_ret program that's meant to flip a denial has nothing to flip. It loads, attaches, and sits there watching silence.

That's a genuine negative result on this kernel, and the primary PoC treats it as one: it checks `/sys/kernel/security/lsm` at startup, finds no `selinux` token, emits `CH06_SKIP`, and exits. It does not manufacture a synthetic denial to paper over the absence.

## Where it actually fires

The kernel where the primary PoC fires is a Fedora 42 aarch64 QEMU VM driven by `dBPF-pocs/run-qemu-tests.sh`. To produce a genuine AVC denial to flip, that script boots a SELinux-enforcing image and creates a file labeled `shadow_t` in a tmpfs:

```bash
chcon system_u:object_r:shadow_t:s0 "$SECRET"
```

Then it runs `runcon user_u:user_r:user_t:s0 cat "$SECRET"` to provoke the denial — `user_t` doesn't have read permission on `shadow_t`. Starts the loader. Re-runs the access. The three `lsm/` programs flip the would-be deny to an allow. The `cat` succeeds and outputs the file contents.

That last point matters. SELinux's policy evaluation runs before the BPF program, so the AVC denial gets logged either way. The user-visible outcome says the access succeeded; the audit log says SELinux denied it. That contradiction is the detection signal — and it's exactly why audit-log suppression (ch03) pairs so naturally with this primitive.

## Mechanism

The primary variant covers three access paths because SELinux routes different operations through different LSM entry points: `file_permission` handles already-open descriptors, `inode_permission` handles open-time path walks, and `bprm_check_security` handles `execve`. Cover only one and the other two stay exposed. The program that handles path-based decisions looks like this:

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

The `fmod_ret` semantic is what makes the override real. BPF LSM programs run after the static LSMs, so when SELinux returns `-EACCES` and the BPF program returns `0`, the chain result is `0` and the access goes through. All three hooks are on the `bpf_lsm_hooks` allowlist in `kernel/bpf/bpf_lsm.c` — they're documented targets for BPF-side verdict modification.

`lsm.s/file_open` (sleepable) was needed to call `bpf_d_path` for exact path matching. `lsm/inode_permission` (non-sleepable) only gives `struct inode *` with no cheap path; inode-number comparison is the fallback. Mixing sleepable and non-sleepable programs in the same skeleton is fine; the attach type on each program governs individually.

## The observer variant

`ch06-silence-selinux` attaches kprobes to `avc_denied` and `avc_audit` — the functions inside the AVC (Access Vector Cache) that run when SELinux lands on a denial. It flips nothing. It reads `struct av_decision` CO-RE fields and reports the target class, the requested permissions, and whether the decision came from cache or a policy lookup. On the Fedora VM, every AVC miss passes through this observer before the primary flipper's return-value override kicks in. The two run cleanly side by side: the observer is reconnaissance, the LSM variant is the one that actually changes the verdict.

## The synthetic variant

`ch06-silence-selinux-lsm-synthetic` exists because some kernels have `selinux` compiled in and its symbols present in `/proc/kallsyms`, but `selinux_loaded()` returns 0 — no policy is active. The standard trigger catches this and emits `CH06_SKIP`.

The synthetic variant eliminates the `selinux_loaded()` gate. Instead it loads a single LSM program driven by a control map with three stages: `STAGE_OFF` (no-op), `STAGE_DENY` (returns `-EACCES` for a sentinel path), and `STAGE_FLIP` (returns `0` for the same path). SIGUSR1/SIGUSR2/SIGHUP toggle the stage at runtime.

The test sequence: set stage=DENY, have an unprivileged user `cat` the sentinel file, observe rc=1 and `EACCES`. Set stage=FLIP, have the same user `cat` the same file, observe rc=0 and the file contents. Same program, same kernel, same user, same file — only the stage changed. That proves the fmod_ret flip works, using a synthetic denial because the test kernel has no real one.

This doesn't change the primary primitive: the fmod_ret override path still needs both `bpf` and `selinux` in the active LSM list. What the synthetic variant does is prove the flip mechanism on kernels that have no live policy-enforcement context to test against. It emits `CH06_SYNTH_PROVEN` once it captures at least one flip event.

## Detection

- `cat /sys/kernel/security/lsm` shows `bpf` in the LSM list; necessary for BPF LSM programs to attach. Removing `bpf` from the `lsm=` kernel parameter at boot prevents the primitive entirely.
- `bpftool prog list --type lsm` enumerates every attached BPF LSM program. On Amazon Linux 2023 and RHEL 9 defaults, no BPF LSM programs are attached; any non-empty output is anomalous.
- `bpftool prog show id <id> --pretty` gives the attach function (`bpf_lsm_file_permission`, `bpf_lsm_inode_permission`, `bpf_lsm_bprm_check_security`).
- On an SELinux-active host: `ausearch -m AVC -ts recent` combined with observation of the corresponding syscall outcome. If the AVC record says deny and the syscall returned success, something flipped it. This is the strongest runtime detection signal; no other mechanism produces the AVC-versus-outcome inconsistency without also suppressing the audit log, which is a separate and detectable operation.

## Scope

This is a Class I primitive from Chapter 20 (return-value override at the API boundary). The primitive is real and lands cleanly on SELinux-active kernels. On linuxkit the synthetic variant proves the flip mechanism; the real attack is waiting for a kernel with policy loaded.

It's also the first Class I primitive in the book where the design intent is fully on the surface. Chapters 1 and 3 hit dead ends because their targets (`cap_capable`, `audit_log_start`) aren't in `ALLOW_ERROR_INJECTION` and aren't in the `security_` namespace. BPF LSM, by contrast, was built to allow runtime verdict modification for a specific allowlist of hooks — and `file_permission`, `inode_permission`, and `bprm_check_security` are all on it. So the mechanism here isn't a gap or a trick; it's the documented behavior of BPF LSM, pointed at SELinux. That's precisely what makes the capability grant matter on any production system where SELinux is the enforcement layer.

---

**Related material**

- POC source: [dBPF-pocs/pocs/ch06-silence-selinux-lsm/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch06-silence-selinux-lsm)
- Harness entry: search for `Poc("ch06", ...)` in `dBPF-pocs/harness/proof.py`
