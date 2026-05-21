---
layout: book
title: "Chapter 21: Skip Accounting — Primitives That Needed Another Kernel"
date: 2026-01-11
---

# Chapter 21: Skip Accounting — Primitives That Needed Another Kernel

> **See also**: [Blog post]({{ site.baseurl }}/skip-accounting.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20 — Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)

Four primitives did not produce effects on linuxkit 6.12 aarch64. Not because the BPF was wrong — each one loaded, each one verified, most attached cleanly. They did not fire because the kernel environment did not host the surface the primitive needed to grip.

linuxkit 6.12 aarch64 is a specific shape: Docker Desktop's VM with a minimal config, no ACPI, no powercap, no module signature enforcement, no SELinux in enforcing mode. On that shape, some primitives sat idle. On a RHEL host with `setenforce 1`, a different set would be idle and these would fire. The skip list sorts into a few shapes, and each shape is a lesson about where primitives gain or lose traction.

The full across-environment count: **24 PROVEN, 1 SKIP (ch24)**. The skip is a build-configuration gap, not a runtime rejection.

## No enforcement point active

Ch06 and ch12 are the canonical examples. Both load and attach cleanly on linuxkit. Both sit idle.

**Ch06 (BPF LSM fmod_ret on SELinux hooks).** The program attaches to `selinux_file_permission` and loads perfectly. But linuxkit does not run SELinux enforcing:

```
$ cat /sys/kernel/security/lsm
capability,bpf
```

`selinux` is not in the stack. There is no AVC, no natural `-EACCES` return to observe or flip. The hook attaches to a silent wire. Marker: `CH06_SKIP reason=selinux_not_enforcing`.

On the Fedora 42 aarch64 QEMU VM, SELinux is enforcing with `bpf` registered after `selinux` in the LSM chain. A confined `user_u` login reading a sentinel file outside its allowed types produces an organic AVC denial. The ch06 `fmod_ret` program observes the `-EACCES` and overrides it to `0`. The read succeeds. Marker: `CH06_PROVEN hook=... flip=yes`.

**Ch12 (BPF LSM fmod_ret on `kernel_read_file`).** The program attaches to `kernel_read_file` with class `FIRMWARE`. Linuxkit builds without `CONFIG_MODULE_SIG_FORCE`, so `mod_verify_sig` never returns a denial the LSM chain would see. No natural `-EBADMSG` for the BPF program to flip.

On the Fedora 42 QEMU VM with `module.sig_enforce=1`, feeding an unsigned `.ko` blob through `finit_module(2)` produces an organic `-EBADMSG` at the signature check. The ch12 `fmod_ret` program overrides it to `0`, letting the loader proceed past the signature gate. Marker: `CH12_PROVEN flipped=N hook=kernel_read_file baseline=EBADMSG override=ENOEXEC`.

The errno shift from `EBADMSG` to `ENOEXEC` is the evidence that the LSM gate fired and was flipped. If the override had not fired, the errno would remain `EBADMSG`. The intermediate shift is precisely the signature that the *gate* was bypassed but the payload still failed downstream validation.

The harness also registers `ch12s`: a kretprobe on `__arm64_sys_finit_module` that rewrites the syscall return value. `__arm64_sys_finit_module` is on the error-injection allowlist, so `bpf_override_return(ctx, 0)` fires. The kernel's actual module loader still rejects the bytes; `lsmod` shows no new module. Only a caller that trusts the `finit_module(2)` return value is fooled. Marker: `CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no`. The two PoCs are complements: ch12 (LSM, Fedora-only) defeats kernel-state observers that check `/sys/module/`; ch12s (syscall illusion, fires on linuxkit) defeats naive userspace consumers that trust the syscall return.

## Feature not compiled in

**Ch24 (bpf_token delegation).** `CONFIG_BPF_TOKEN=n` on Ubuntu 6.17 and Fedora 6.17 kernels. `BPF_TOKEN_CREATE` returns `ENOSYS` — the command does not exist in the `bpf()` dispatch table. The feature landed in kernel 6.9 but requires an explicit build-time opt-in that no mainstream distro has yet enabled by default.

An earlier test on Fedora 42 / kernel 6.14 hit a different failure mode: `BPF_TOKEN_CREATE` returned `EOPNOTSUPP` rather than `ENOSYS`, indicating the feature was compiled in but the kernel's `cred->user_ns` check refused the mint from the cloud-init-launched service context. That is a separate shape — feature present but runtime-rejected from a specific execution context — documented in chapter 24's iteration log. The Ubuntu/Fedora 6.17 case is more fundamental: the command is absent. Marker: `CH24_SKIP reason="CONFIG_BPF_TOKEN=n on all available kernels"`.

The C code is production-reviewed and correct. Any kernel built with `CONFIG_BPF_TOKEN=y` will demonstrate the primitive.

## Not a skip: ch23 and ch25

Ch23 (TPM unseal heist) was previously described as a potential skip on all environments. Final verification on Ubuntu 6.17 aarch64 (Lima VM) shows `tpm2_unseal_trusted` present in kallsyms and the kprobe attaching and firing entry intercept events — **ch23 is PROVEN**. The Lima VM's vTPM proxy was not boot-registered, so the `keyctl add trusted` path is unavailable, but the BPF primitive itself is confirmed: `CH23_PROVEN hook=attached kind=kprobe-on-tpm2_unseal_trusted sym-confirmed`. Linuxkit has no TPM device at all — the PoC skips there because the symbol is absent.

Ch25 (IMDS credential capture via XDP) is **PROVEN** on the Ubuntu 6.17 aarch64 Lima VM via XDP mock IMDSv2 on `lo`: `CH25_PROVEN access_key_captures=1 token_captures=1 role=demo-role`. Linuxkit skips because the interface arrangement in the primary harness container does not expose a suitable attach interface in default mode.

## The pattern

Skips aren't failures; they're the book's credibility anchor. Any catalog that claims 100% hit rate on a single test kernel is either running against a kernel built to host the catalog, or it is hiding the cases that did not fire.

A kernel is a specific build config, a specific LSM stack, a specific BTF completeness level, and a specific set of loaded subsystems. Primitives grip surfaces that kernels optionally provide. The honest book reports both — the ones that fired and the ones that sat idle and why. The ones that sat idle on this kernel are live elsewhere, and the chapter says where.

The skip list sorts by shape:

- **No enforcement point active (linuxkit):** ch06, ch12. The BPF program loads and attaches; the surrounding policy never produces the decision the program was written to flip. Both fire on Fedora 42 QEMU.
- **Feature not compiled in:** ch24. `CONFIG_BPF_TOKEN=n` on all available kernels. The command is absent. Any kernel with `CONFIG_BPF_TOKEN=y` will fire.

The honest final ledger: 18 on linuxkit; 2 (ch06, ch12) on Fedora 42 QEMU; 2 (ch23, ch25) on Ubuntu 6.17 Lima VM; 1 (ch24) SKIP in all environments. Cross-environment total: **24 PROVEN, 1 SKIP.**

## For red-team readers

Environmental pre-flight is not optional. Before claiming a primitive works on a target, scan four axes:

**`/proc/kallsyms`** for every function symbol the program attaches to. Missing symbols mean the subsystem is not compiled in. If the symbol is absent, no attach is possible regardless of BTF, LSM stack, or error-injection state.

**`/sys/kernel/security/lsm`** for the active LSM stack. If `bpf` is absent, no `fmod_ret` is possible. If `selinux` is absent, ch06's SELinux hooks never produce decisions. The order of the stack matters too.

**`/sys/kernel/debug/error_injection/list`** for `bpf_override_return` targets. If the target is not on this list, the override is rejected at verifier time. `__arm64_sys_finit_module` being on the list is what enables ch12s on linuxkit; it would be absent on a kernel without `CONFIG_FUNCTION_ERROR_INJECTION`.

**BTF visibility** for every struct the program dereferences. `bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep "FWD 'key'"` tells you whether `struct key` is fully defined or forward-declared. A FWD in the LSM hook's function signature disarms `fmod_ret` against that hook — switch to kprobe against a function that imports the full type.

Any of those four axes can silently disarm a primitive. The BPF program will load, the attach will succeed, and the trigger will print nothing interesting — which is worse than a loud failure, because it looks like the kernel is immune when it is only uncooperative to this specific attach path. Mistaking "no output" for "the primitive doesn't work anymore" is a common field misdiagnosis.

## For blue-team readers

The attack surface for BPF-based primitives is the intersection of four axes: hook availability, enforcement-point activity, BTF completeness, and subsystem presence. Minimizing any axis shrinks the surface independently.

**Strip BTF for production kernels that do not need CO-RE tooling.** `CONFIG_DEBUG_INFO_BTF=n`. BPF programs that depend on CO-RE type resolution cannot load without it.

**Disable `CONFIG_FUNCTION_ERROR_INJECTION=n` on non-test kernels.** This removes `bpf_override_return` as a primitive entirely, disarming all Class I overrides that do not go through BPF LSM. Error injection is a test feature. This is the most composable hardening available — it costs almost nothing in production.

**Boot without `bpf` in the `lsm=` cmdline** if no workload needs BPF LSM. Removes the entire `fmod_ret` attack class without rebuilding.

**Do not ship debug hooks like `test_firmware` in production images.** Drop x86-specific subsystems on aarch64 builds where not needed.

For monitoring: audit `bpf()` syscall enrollments for `BPF_PROG_TYPE_LSM` and `BPF_PROG_TYPE_KPROBE` attach events. A privileged process attaching `fmod_ret` to `security_key_permission` or `kernel_read_file` is a high-signal event. The load itself is the first observable action in the chain. Catching it before the primitive fires is the only reliable detection posture for Class I and II primitives.

The four-axis model is useful beyond the skips in this chapter. Any claim about BPF-based offensive capability should be evaluated against all four axes simultaneously. A primitive that "works" on a benchmark kernel may fail on every axis when tested against a hardened one, and vice versa. The skip list for any given kernel is a function of which axes that kernel tightened and which it left open.

---

**Related material**
- Companion: [Ch 20 Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html), [Ch 22 Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
- Harness: `dBPF-pocs/harness/proof.py`
