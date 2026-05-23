---
layout: book
title: "Chapter 21: Skip Accounting; Primitives That Needed Another Kernel"
date: 2026-01-11
---

# Chapter 21: Skip Accounting; What Needed Another Kernel

> **See also**: [Blog post]({{ site.baseurl }}/skip-accounting.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20; Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21; Skip Accounting]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22; Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)

The final count across all environments: **22 PROVEN, 1 SKIP (ch24)**. The skip is not a failure of the BPF code. It is a kernel build configuration that no mainstream distro has yet shipped with the relevant option enabled. The code is ready. The kernel is not, yet.

Five primitives did not produce effects on linuxkit 6.12 aarch64 and required a different kernel to prove; ch06, ch06o, and ch12 on Fedora 42 aarch64 QEMU, ch23 and ch25 on Ubuntu 6.17 Lima VM. The rest of this chapter is for readers who want to reproduce the primitives that needed alternate environments, and for the one that remains open for anyone with the right kernel.

This is not a consolation section. Everything below has working code. The setup cost is real but bounded. If you run these, you are not following a trail I blazed; you are doing the work the linuxkit constraint prevented here, and you may find things I missed.

## The Fedora exercises (ch06, ch06o, ch12)

All three primitives in this group needed SELinux in enforcing mode with `bpf` active in the LSM chain. linuxkit runs neither. That constraint is not a criticism of linuxkit — it is the right minimal environment for most of this book — but these three primitives are specifically about what happens when policy enforcement is live, which means they need a kernel that has live policy. Fedora 42 aarch64 runs both by default, making it the natural secondary environment.

Boot a Fedora 42 aarch64 VM or use `dBPF-pocs/run-qemu-tests.sh` to drive one. The script handles image download and boot. Once the VM is running with SELinux enforcing:

**Ch06; Silencing SELinux.** Create a sentinel file and label it `shadow_t`. Run `runcon user_u:user_r:user_t:s0 cat <sentinel>`; you will get an AVC denial. Start the ch06 loader. Run the same access again. The read succeeds. `ausearch -m AVC -ts recent` still shows the denial. The AVC-versus-outcome inconsistency is the proof.

What to verify: the fmod_ret override is real, the audit log still records the pre-flip decision, and any consumer that trusts `ausearch` output will see a denial while the syscall returned success. That gap is the actual attack surface. How big is it in your environment? Which services trust AVC denials as authoritative and which cross-check syscall outcomes?

**Ch12; Signed-driver swap.** Boot the Fedora VM with `module.sig_enforce=1` in the kernel cmdline (or set `MODULE_SIG_FORCE=y` at build time). Prepare a test `.ko` binary that is not signed. Without the loader: `insmod test.ko` fails with `EBADMSG`; signature check failed. Start the ch12 LSM loader. `insmod test.ko` again. The errno shifts from `EBADMSG` to `ENOEXEC`. The module does not load; the payload fails ELF validation after the signature gate; but the gate itself was bypassed. `EBADMSG` → `ENOEXEC` is the signature of the flip.

What to verify: the signature gate is the last blocker between you and arbitrary code in the kernel on an enforcing system. After this flip, only ELF validation stands between an unsigned blob and `init_module`. Can you craft a valid ELF that passes ELF validation but has no meaningful module body? What does the kernel accept? I did not finish this thread. The harness proves the gate flip; the question of what comes after the gate is left open.

## The Ubuntu exercises (ch23, ch25)

These two primitives target boundaries that linuxkit simply does not have: a TPM-backed trusted-key subsystem and outbound cloud-metadata traffic. Neither is a linuxkit limitation in any meaningful sense — linuxkit is a container runtime environment, not a cloud instance. For ch23 and ch25, the right test environment is a VM that is actually playing the role the primitive targets.

These ran on Ubuntu 6.17 aarch64 (Lima VM) and proved on that kernel. If you are running them from linuxkit; the linuxkit harness path; they will skip because the symbols are absent. Set up a Lima VM (`limactl start --name=dbpf`), build from source inside it, and run the harness there.

**Ch23; TPM unseal heist.** The Lima VM proves the kprobe attachment on `tpm2_unseal_trusted` and emits entry intercept events; `CH23_PROVEN hook=attached`. What it does not prove is capturing actual key material, because the VM's TPM backend is not initialized at boot. That is an exercise.

Set up a Linux host (bare metal or VM) with a real TPM 2.0 device, or configure a VM with a software TPM (`swtpm`) registered before the kernel initializes the IMA/trusted-key subsystem; meaning it must be present at boot, not added post-boot. Create a sealing policy. Seal a key with `keyctl add trusted`. Run the ch23 loader during a real unseal operation. The kretprobe on `tpm2_unseal_trusted` should capture the unsealed key bytes from the payload structure before the caller sees them.

This is the highest-value exercise in the chapter. TPM-sealed keys are the trust root for disk encryption, measured boot, and credential stores on hardened deployments. A kprobe that fires before the key material is zeroed can capture the plaintext before the sealing abstraction's security guarantee takes effect. I could not finish the proof on this kernel. The code is correct; the environment was the constraint.

**Ch25; IMDS credential capture.** Proved via XDP mock on `lo`. The real exercise is a VM running in a cloud environment (AWS, GCP, Azure) where IMDSv2 traffic actually flows. Attach the ch25 XDP program to the host interface before the VM's metadata client makes its credential refresh. Capture a real role credential.

The IMDSv2 token requirement (the `PUT` that precedes `GET`) is meant to block SSRF-based IMDS access. It does not block an XDP program on the same host that intercepts the response after the token check has already been satisfied. Which cloud metadata services have equivalent pre-response validation that XDP would bypass? That is an open question.

## The open exercise (ch24)

Ch24 is the only primitive that has not run on any kernel I had access to. `CONFIG_BPF_TOKEN=n` on every available build. This is not a BPF bug or a subtle kernel behavior; it is a feature flag that no mainstream distro enables. The harness code is production-reviewed. The logic is correct. The kernel just does not have the command yet.

The exercise: build a kernel from source with `CONFIG_BPF_TOKEN=y`. The relevant code landed in 6.9. On 6.17 it is present and gated. Run the ch24 harness. The expected behavior is that `BPF_TOKEN_CREATE` mints a token from the initial user namespace, and a child namespace can use that token to load BPF programs that would otherwise require `CAP_BPF` in the init namespace. The token is the mechanism for delegating BPF capability without delegating full root.

The security question is whether the token is scoped tightly enough. The specification says a token can be bound to a pinned BPF filesystem path and constrained to specific `cmd` types. In practice: can you create a token that allows `BPF_PROG_LOAD` with `BPF_PROG_TYPE_LSM`? If so, an unprivileged container with a delegated token could attach LSM programs. That is the threat model. I do not know if the current implementation allows it or whether the cmd-type constraint blocks it. That is the exercise.

## What the skips actually say

The skips are not gaps in the argument. They are information.

Every skip says something true about the primitive. Ch06, ch06o, and ch12 skip on linuxkit because they need policy enforcement to flip, and linuxkit has none; which means the primitive is useless in zero-enforcement environments and dangerous in high-enforcement ones. The skip is also the environment fingerprint: a primitive that skips on linuxkit and fires on Fedora is a primitive that separates development environments (minimal policy) from production ones (enforcing policy). That separation is itself a detection signal for defenders.

Ch24 skipping on all available kernels means it is a future-tense primitive. Something in production by the time this book is outdated. Note when it ships.

The harness proof markers exist so you can reproduce all of this without reading my notes. If you fire `CH24_PROVEN` before I do, that is a better outcome than if I had manufactured a proof on an unsupported kernel.

---

**Related material**
- Companion: [Ch 20 Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html), [Ch 22 Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
- Harness: `dBPF-pocs/harness/proof.py`
