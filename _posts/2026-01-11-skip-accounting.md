---
layout: book
title: "Skip Accounting"
date: 2026-01-11
---

# Skip Accounting

> **See also**: [Full chapter with investigation notes]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 20 — The Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)

Of the 26 registered PoCs, 25 reproduce in the reference environment (Ubuntu 6.17 aarch64) and exactly one skips: ch24. That is the whole skip list. But "reproduces" is not the same as "means the same thing everywhere," and a few primitives are worth flagging for what their reference-environment result actually shows versus what a production host would show. This post sorts them: the one real skip, and the primitives whose weight depends on a surface being present.

## The one skip: ch24

Ch24 is the only primitive that has not run on any kernel I had access to. Its reference kernel is built with `CONFIG_BPF_TOKEN=n`, so `BPF_TOKEN_CREATE` returns `ENOSYS` and there is nothing to exercise. The marker is honest about it: `CH24_SKIP reason=...`. This is not a BPF bug or a subtle kernel behavior — it is a feature flag that no mainstream distro has yet shipped enabled. The code is ready; the kernel is not, yet. Build a kernel with `CONFIG_BPF_TOKEN=y` (the code landed in 6.9) and the exercise is to see whether a delegated token can be scoped loosely enough to load `BPF_PROG_TYPE_LSM` from an unprivileged container. That is the open threat model.

## Reproduces, but needs live enforcement to matter (ch06, ch06s, ch06o, ch12)

The BPF LSM `fmod_ret` program for ch06 attaches to the SELinux hooks and loads fine, but it only flips a *real* denial where SELinux is enforcing. Ch12 is the same story for `kernel_read_file` and module-signature enforcement. In the reference environment these reproduce via the synthetic scaffold (`ch06-silence-selinux-lsm-synthetic`, registered as ch06s, an observer) that manufactures the condition so the mechanism can be shown; on a Fedora host with `setenforce 1` or `module.sig_enforce=1`, the same override flips a genuine refusal. The honest accounting: the primitive is real, the reproduction is real, and whether the *bypass* is real depends on whether there was a decision to bypass.

## Reproduces, but the full payload needs the real surface (ch23, ch25)

Ch23 attaches a kprobe to `tpm2_unseal_trusted` and captures entry-intercept events in the reference environment, but it does not capture plaintext key bytes there, because the VM's TPM backend is not registered at boot. Ch25 harvests IMDSv2 credentials off a mock exchange on `lo` rather than a live cloud metadata endpoint. Both reproduce as registered; taking them to a real captured key or a real role credential is an exercise on a host that actually plays the role — a machine with a boot-registered TPM, or a cloud instance where IMDSv2 traffic flows.

## A note on BTF and symbols

Some primitives ship in two variants for a reason worth spelling out. Ch08's fentry form can hit `arg0 type FWD is not a struct` where BTF carries only a forward declaration of `struct key`; the kprobe variant (ch08k) attaches by symbol name and sidesteps type resolution. Ch03 ships both a kprobe form and an fentry form (ch03f) for the same reason. The pattern: the verifier refuses programs that dereference struct fields whose type is not fully described in BTF, and whether a type is fully described is a kernel-build-time decision you cannot change from userspace. The two-variant design is how the catalog stays reproducible across builds with different BTF completeness.

## The pattern

A catalog that claims a 100% identical result on every kernel is either lying or testing on an environment curated for the catalog. A kernel is a specific build config, a specific LSM stack, a specific BTF completeness level, and a specific set of loaded subsystems. Primitives grip surfaces that kernels optionally provide. The honest report says which primitives reproduce (25 of 26), which one does not yet (ch24), and which reproduced primitives need a live enforcement point or a real hardware/cloud surface before their bypass means anything. (Two earlier drafts, ch13 powercap/RAPL and ch17 ACPI-WMI, were x86-only and never had an honest aarch64 reproduction; they were retired rather than carried as permanent skips, and are not among the 26.)

## For red and blue

For the red team, environmental pre-flight is not optional. Before claiming a primitive works on a target, scan four axes: `/proc/kallsyms` for function symbols the program attaches to, `/sys/kernel/security/lsm` for the active LSM stack, `/sys/kernel/debug/error_injection/list` for `bpf_override_return` targets, and `bpftool btf dump file /sys/kernel/btf/vmlinux` for every struct the program dereferences. Any one of those axes can silently disarm a primitive — and silent disarm is much worse than loud failure because it looks like the kernel is immune when it is only uncooperative to this specific variant. For the blue team, the attack surface is the intersection of hook availability × enforcement-point activity × BTF completeness × subsystem presence. Minimize any axis and the surface shrinks: strip BTF from production kernels where CO-RE is not required, disable BPF LSM if no workload needs it, enforce `MODULE_SIG_FORCE=y` with the signing key off-target, keep the error-injection list minimal on production builds, and do not ship debug hooks like `test_firmware` in production images. Each of those independently removes primitives from the toolkit.

---

**Related material**
- Full chapter: [Chapter 21 — Skip Accounting: Primitives That Needed Another Kernel]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)
- Companion chapters: [Ch 20]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html), [Ch 21]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html), [Ch 22]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
- Harness: `dBPF-pocs/harness/proof.py`
