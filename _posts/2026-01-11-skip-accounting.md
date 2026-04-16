---
layout: book
title: "Skip Accounting"
date: 2026-01-11
---

# Skip Accounting

> **See also**: [Full chapter with investigation notes]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 20 — The Taxonomy]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-3/chapter-22-the-defender-playbook.html)

Six chapters didn't fire on the test kernel. Not because the BPF was wrong — each one loaded, each one verified, most attached cleanly. They didn't fire because the kernel environment didn't host the surface the primitive gripped. linuxkit 6.12 aarch64 is a specific shape: Docker Desktop's VM with a minimal config, no ACPI, no powercap, no module signature enforcement, no SELinux in enforcing mode, and BTF that resolves most but not all symbols. On that shape, six primitives sat idle. On a RHEL host with `setenforce 1`, a different six would be idle and these six would fire. The skip list sorts into three shapes, and each shape is a lesson about where primitives gain or lose traction.

## No enforcement point active

Ch06 and ch12 are the canonical examples. The BPF LSM `fmod_ret` program for ch06 attaches to `selinux_file_permission` and loads perfectly — but linuxkit does not run SELinux enforcing, so the hook never returns non-zero on a realistic target, and the override has nothing to flip. `CH06_SKIP reason=selinux_not_enforcing`. Ch12 is similar: the LSM hook for `kernel_read_file` loads, but the kernel has `CONFIG_MODULE_SIG=n`, so the refusal path the override was designed to flip never gets walked. The primitives are alive on any kernel that runs those enforcement points live; the synthetic variants (`ch06-silence-selinux-lsm-synthetic`, `ch12-signed-driver-swap-syscall`) manufacture the conditions to prove the concept, but the honest accounting says: no live enforcement, no live bypass.

## BTF or hook symbol missing

Ch07 tried to attach to `dev_open` directly. libbpf returned `failed to find kernel BTF type ID of 'dev_open': -3` — the symbol's BTF entry was not exported in this build. The LSM variant of the same primitive attaches `devcgroup_inode_permission` instead and fires cleanly (it is in chapter 20's proven set). Ch08's fentry variant hit a subtler shape: the verifier refused with `arg0 type FWD is not a struct`. BTF had a forward declaration of `struct key` but not the full definition, because linuxkit does not build BTF with `--btf_gen_all` the way distro kernels do. The kprobe variant of ch08 attaches by symbol name, sidesteps BTF type resolution, and fires. The pattern: the verifier refuses programs that dereference struct fields whose type is not fully described in BTF, and whether a type is fully described is a kernel-build-time decision you cannot change from userspace.

## Target subsystem absent

Ch13's primitive grips the powercap RAPL subsystem — Intel-only, x86-only, and not compiled into linuxkit. `powercap_get_max_power_uw` is not in `/proc/kallsyms`. libbpf refuses to resolve the symbol; the program cannot attach. The analog variant demonstrates the same primitive against a stand-in sysfs hook and emits `CH13_ANALOG_PROVEN ... disclaimer="same primitive as RAPL override; real RAPL is x86-only"`. Ch17 is structurally identical: linuxkit aarch64 has no ACPI SSDT, no `/sys/firmware/acpi/`, and no `acpi_evaluate_integer` symbol. The full primitive fires on x86 distro kernels with Dell/HP laptop WMI drivers loaded. The analog substitutes the `firmware_loader` path to prove the attach-and-override shape.

## The pattern

Skips aren't failures; they're the book's credibility anchor. Any catalog that claims 100% hit rate on a single test kernel is lying or is testing in an environment that was curated for the catalog. A kernel is a specific build config, a specific LSM stack, a specific BTF completeness level, and a specific set of loaded subsystems. Primitives grip surfaces that kernels optionally provide. The honest book reports both — the ones that fired and the ones that sat idle and why. The ones that sat idle on this kernel are live elsewhere, and the chapter says where: RHEL with enforcing SELinux, a distro with `MODULE_SIG_FORCE=y`, x86 with Intel RAPL, a laptop with ACPI/WMI. Cold case here, live case there.

## For red and blue

For the red team, environmental pre-flight is not optional. Before claiming a primitive works on a target, scan four axes: `/proc/kallsyms` for function symbols the program attaches to, `/sys/kernel/security/lsm` for the active LSM stack, `/sys/kernel/debug/error_injection/list` for `bpf_override_return` targets, and `bpftool btf dump file /sys/kernel/btf/vmlinux` for every struct the program dereferences. Any one of those axes can silently disarm a primitive — and silent disarm is much worse than loud failure because it looks like the kernel is immune when it is only uncooperative to this specific variant. For the blue team, the attack surface is the intersection of hook availability × enforcement-point activity × BTF completeness × subsystem presence. Minimize any axis and the surface shrinks: strip BTF from production kernels where CO-RE is not required, disable BPF LSM if no workload needs it, enforce `MODULE_SIG_FORCE=y` with the signing key off-target, drop x86-specific subsystems (powercap, ACPI/WMI, RAPL) on aarch64 builds, and do not ship debug hooks like `test_firmware` in production images. Each of those independently removes primitives from the toolkit.

---

**Related material**
- Full chapter: [Chapter 21 — Skip Accounting: Primitives That Needed Another Kernel]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html)
- Companion chapters: [Ch 20]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html), [Ch 21]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html), [Ch 22]({{ site.baseurl }}/book/act-3/chapter-22-the-defender-playbook.html)
- Harness: `dBPF-pocs/harness/proof.py`
