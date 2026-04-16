---
layout: book
title: "Chapter 21: Skip Accounting — Primitives That Needed Another Kernel"
date: 2026-01-11
---

# Chapter 21: Skip Accounting — Primitives That Needed Another Kernel

> **See also**: [Blog post]({{ site.baseurl }}/skip-accounting.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20 — Taxonomy]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-3/chapter-22-the-defender-playbook.html)

Six primitives did not produce effects on linuxkit 6.12 aarch64. Not because the BPF code was wrong; because the kernel environment did not host the surface the primitive needed to grip. There are three shapes of refusal in play: (a) no enforcement point was active at runtime, (b) BTF or the hook's target symbol was missing, (c) the target subsystem was absent from this kernel build. Each of the six is a cold case on this kernel and a live case on someone else's. The goal of this chapter is to make that distinction reproducible.

## ch06 — SELinux silencer against a permissive LSM stack

The claim was that the BPF LSM `fmod_ret` variant could flip `selinux_file_permission` and let an otherwise-denied open succeed. The program loaded and the hook attached, but the linuxkit build does not run SELinux in enforcing mode — the check the override was trying to flip never returned non-zero on a realistic target, so there was nothing to flip. The trigger emits `CH06_SKIP reason=selinux_not_enforcing` and exits.

The BPF code itself is correct on this kernel: the attach succeeded, the fmod_ret program was accepted, and the synthetic variant (`ch06-silence-selinux-lsm-synthetic`) which manufactures a denial in a test hook does fire and print `CH06_CONCEPT_PROVEN denial_injected=yes flip_applied=yes`. The full primitive fires on a distro kernel with SELinux enforcing and full BTF — RHEL, Fedora, or Amazon Linux with `setenforce 1`.

## ch07 — devcgroup Houdini against a missing dev_open symbol

The first attach attempt targeted `dev_open` directly. `libbpf` refused to resolve the symbol in BTF: `libbpf: failed to find kernel BTF type ID of 'dev_open': -3`. Investigation showed that the linuxkit kernel's `fs/char_dev.c` had a slightly different name resolution path and the BTF entry for the specific function was not exported. The LSM variant of the same primitive, which attaches `devcgroup_inode_permission` instead, fires cleanly on 6.12 and is included in chapter 20's proven set.

The original `dev_open`-based variant fires on any kernel where the symbol is exported in BTF, which is most distro kernels built with `CONFIG_DEBUG_INFO_BTF=y`. The skip here is narrow: one attach path refused, an equivalent attach path proven.

## ch08 — keyring heist fentry variant against a FWD-typed struct

The fentry-based variant of ch08 tried to attach to `keyctl_read_key` with a BPF program whose first argument was typed as `struct key *`. The verifier refused: `arg0 type FWD is not a struct`. This is BTF saying "I have a forward declaration of `struct key`, not the full definition." Distro kernels compile BTF with `--btf_gen_all` which resolves forward decls; linuxkit does not. The kprobe variant (attaching by symbol, not by BTF type) fires cleanly on 6.12 and is in chapter 20's proven set.

The fentry variant fires on kernels with complete BTF for the keyring subsystem.

## ch12 — signed driver swap against an empty module-load path

The claim was that `kernel_read_file` LSM hook + `bpf_override_return` could make `init_module` accept a forged module by flipping `EBADMSG` to `ENOEXEC` (or to 0). The hook attached; the override loaded; the trigger tried to `finit_module(2)` a crafted file. The linuxkit kernel has `CONFIG_MODULE_SIG=n` and no module-signature-enforcement path to short-circuit, so the baseline error code was different from the one the override expected, and the LSM chain returned 0 from other hooks before `kernel_read_file` was reached. The syscall-override variant (`ch12-signed-driver-swap-syscall`) demonstrates the concept by forging the syscall return directly — marker `CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no` — which honestly records that the primitive lied to userspace without achieving actual module load.

The full primitive fires on a kernel with `CONFIG_MODULE_SIG_FORCE=y` and `kernel_read_file` participating in the refusal path.

## ch13 — powercap override against an absent powercap subsystem

Linuxkit does not compile `CONFIG_POWERCAP` or expose `/sys/class/powercap/`. The attach targeted `powercap_get_max_power_uw`, which is not present in `/proc/kallsyms` on this kernel. libbpf refused to resolve the symbol, the trigger short-circuited to the analog variant (`ch13-powercap-override-analog`) which demonstrates the same primitive against a stand-in sysfs hook and emits `CH13_ANALOG_PROVEN before_climb=X after=Y zero_reads=N patched_events=M disclaimer="same primitive as RAPL override; real RAPL is x86-only"`.

The full primitive fires on x86 kernels with Intel RAPL exposed.

## ch17 — ACPI WMI against a non-ACPI platform

Linuxkit aarch64 has no ACPI SSDT and no `/sys/firmware/acpi/`. The `acpi_evaluate_integer` symbol is not exported; the attach fails. The trigger prints `CH17_SKIP reason=no_acpi_on_aarch64_linuxkit` and runs the analog variant (`ch17-acpi-wsmi-analog`) which substitutes the `firmware_loader` path, producing `ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader`.

The full primitive fires on x86 distro kernels with Dell/HP laptop WMI drivers loaded.

## ch08 (LSM variant on other kernels), ch12-lsm on other kernels

Short note: the LSM variants of ch08 and ch12 that did not fire on this specific kernel fire elsewhere. `ch12-signed-driver-swap-lsm` emits `CH12_PROVEN flipped=N hook=kernel_read_file baseline=EBADMSG override=ENOEXEC` on kernels where the refusal path actually routes through `kernel_read_file` with a signed-module baseline. This is the same chapter, different kernel environment, different outcome. The taxonomy class does not change — it is still Class I — only the attach availability does.

## The pattern

The six skips sort into three shapes:

- **No enforcement point active at runtime**: ch06 (SELinux not enforcing), ch12 (no module signature enforcement).
- **BTF or hook symbol missing**: ch07 (no BTF for dev_open), ch08 fentry variant (forward-declared struct), ch13 (no powercap_get_max_power_uw symbol).
- **Target subsystem absent**: ch13 (no powercap), ch17 (no ACPI on aarch64), arguably ch08 fentry (no keyring BTF detail).

## What this teaches for red team

Environmental pre-flight is not optional. Before claiming a primitive works on the target, scan four axes:

1. `/proc/kallsyms` for the function symbols the program attaches to.
2. `/sys/kernel/security/lsm` for the active LSM stack.
3. `/sys/kernel/debug/error_injection/list` for `bpf_override_return` targets.
4. BTF visibility for every struct the program dereferences — `bpftool btf dump file /sys/kernel/btf/vmlinux` and grep.

Any of those four axes can silently disarm a primitive. The BPF program will load, the attach will succeed, and the trigger will print nothing interesting — which is much worse than a loud failure, because it looks like the kernel is immune when it is only uncooperative to this specific variant.

## What this teaches for blue team

The attack surface is the intersection of hook availability × enforcement-point activity × BTF completeness × subsystem presence. Minimizing any axis shrinks the surface:

- Disable BPF LSM (`CONFIG_BPF_LSM=n`) if no workload needs it.
- Strip BTF from production kernels (`CONFIG_DEBUG_INFO_BTF=n`) where `CO-RE` tooling is not required.
- Enforce module signatures (`CONFIG_MODULE_SIG_FORCE=y`) and keep the signing key off the target.
- Drop x86-specific subsystems (powercap, ACPI/WMI, RAPL) on aarch64 builds.
- Do not ship `test_firmware` or similar debug hooks in production images.

Each of those independently removes primitives from the toolkit.

## Onward

Chapter 22 is the full defender playbook, ordered from highest-leverage to lowest.
