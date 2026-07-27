---
layout: book
title: "Chapter 21: Skip Accounting; Primitives That Needed Another Kernel"
date: 2026-01-11
---

# Chapter 21: Skip Accounting; What Needed Another Kernel

> **See also**: [Blog post]({{ site.baseurl }}/skip-accounting.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20; Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21; Skip Accounting]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22; Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)

The count is clean: of the 26 registered PoCs, **25 reproduce in the reference environment and one skips (ch24)**. That skip is not a failure of the BPF code. It is a kernel build configuration — `CONFIG_BPF_TOKEN=n` — that no mainstream distro I had access to shipped with the option enabled. The code is ready; the kernel is not, yet.

The other 25 all reproduce as registered, but a handful of them only *mean* something when the surface they grip is actually present. Ch06, ch06s, ch06o, and ch12 flip a real decision only where SELinux is enforcing or module-signature enforcement is on; where it is not, they demonstrate the mechanism against a synthetic condition. Ch23 attaches to the TPM unseal path and captures entry-intercept events, but capturing plaintext key bytes needs a host with a boot-registered TPM backend. Ch25 runs against a mock IMDSv2 exchange rather than a live cloud endpoint. None of these are skips. This chapter is for the reader who wants to take each one from "reproduces" to "operationally real," and for the single primitive (ch24) that has not run anywhere yet.

This is not a consolation section. Everything below has working code, and the setup cost is real but bounded. If you run these, you may find things I missed.

(For the record: ch13 powercap/RAPL and ch17 ACPI-WMI were retired, not skipped. They were x86-only surfaces that never had an honest aarch64 reproduction, so rather than carry them as permanently-skipping stubs they were removed from the catalog. They are not among the 26.)

## Making the enforcement primitives real (ch06, ch06s, ch06o, ch12)

These primitives are about what happens when policy enforcement is live. To see the *real* flip rather than the synthetic scaffold, you need a kernel that has live policy: SELinux in enforcing mode with `bpf` in the LSM chain, or module-signature enforcement turned on. A Fedora aarch64 VM gives you both by default; you can drive one with `dBPF-pocs/run-qemu-tests.sh`, which handles image download and boot. Once the VM is running with SELinux enforcing:

**Ch06; Silencing SELinux.** Create a sentinel file and label it `shadow_t`. Run `runcon user_u:user_r:user_t:s0 cat <sentinel>`; you will get an AVC denial. Start the ch06 loader. Run the same access again. The read succeeds. `ausearch -m AVC -ts recent` still shows the denial. The AVC-versus-outcome inconsistency is the proof.

What to verify: the fmod_ret override is real, the audit log still records the pre-flip decision, and any consumer that trusts `ausearch` output will see a denial while the syscall returned success. That gap is the actual attack surface. How big is it in your environment? Which services trust AVC denials as authoritative and which cross-check syscall outcomes?

**Ch12; Signed-driver swap.** Boot the Fedora VM with `module.sig_enforce=1` in the kernel cmdline (or set `MODULE_SIG_FORCE=y` at build time). Prepare a test `.ko` binary that is not signed. Without the loader: `insmod test.ko` fails with `EBADMSG`; signature check failed. Start the ch12 LSM loader. `insmod test.ko` again. The errno shifts from `EBADMSG` to `ENOEXEC`. The module does not load; the payload fails ELF validation after the signature gate; but the gate itself was bypassed. `EBADMSG` → `ENOEXEC` is the signature of the flip.

What to verify: the signature gate is the last blocker between you and arbitrary code in the kernel on an enforcing system. After this flip, only ELF validation stands between an unsigned blob and `init_module`. Can you craft a valid ELF that passes ELF validation but has no meaningful module body? What does the kernel accept? I did not finish this thread. The harness proves the gate flip; the question of what comes after the gate is left open.

## Taking the Act 4 primitives further (ch23, ch25)

Ch23 and ch25 both reproduce in the reference environment, but each targets a boundary whose full weight only shows up on a host actually playing the role: a TPM-backed trusted-key subsystem for ch23, live cloud-metadata traffic for ch25. The reference run demonstrates the mechanism; the exercises below take it to the real thing.

**Ch23; TPM unseal heist.** In the reference environment, ch23 attaches a kprobe to `tpm2_unseal_trusted` and emits entry-intercept events (`CH23_PROVEN hook=attached`). What it does not do there is capture actual key material, because the VM's TPM backend is not initialized at boot. That is the exercise.

Set up a Linux host (bare metal or VM) with a real TPM 2.0 device, or configure a VM with a software TPM (`swtpm`) registered before the kernel initializes the IMA/trusted-key subsystem; meaning it must be present at boot, not added post-boot. Create a sealing policy. Seal a key with `keyctl add trusted`. Run the ch23 loader during a real unseal operation. The kretprobe on `tpm2_unseal_trusted` should capture the unsealed key bytes from the payload structure before the caller sees them.

This is the highest-value exercise in the chapter. TPM-sealed keys are the trust root for disk encryption, measured boot, and credential stores on hardened deployments. A kprobe that fires before the key material is zeroed can capture the plaintext before the sealing abstraction's security guarantee takes effect. I could not finish the proof on this kernel. The code is correct; the environment was the constraint.

**Ch25; IMDS credential capture.** Proved via XDP mock on `lo`. The real exercise is a VM running in a cloud environment (AWS, GCP, Azure) where IMDSv2 traffic actually flows. Attach the ch25 XDP program to the host interface before the VM's metadata client makes its credential refresh. Capture a real role credential.

The IMDSv2 token requirement (the `PUT` that precedes `GET`) is meant to block SSRF-based IMDS access. It does not block an XDP program on the same host that intercepts the response after the token check has already been satisfied. Which cloud metadata services have equivalent pre-response validation that XDP would bypass? That is an open question.

## The open exercise (ch24)

Ch24 is the only primitive that has not run on any kernel I had access to. `CONFIG_BPF_TOKEN=n` on every available build. This is not a BPF bug or a subtle kernel behavior; it is a feature flag that no mainstream distro enables. The harness code is production-reviewed. The logic is correct. The kernel just does not have the command yet.

The exercise: build a kernel from source with `CONFIG_BPF_TOKEN=y`. The relevant code landed in 6.9. On 6.17 it is present and gated. Run the ch24 harness. The expected behavior is that `BPF_TOKEN_CREATE` mints a token from the initial user namespace, and a child namespace can use that token to load BPF programs that would otherwise require `CAP_BPF` in the init namespace. The token is the mechanism for delegating BPF capability without delegating full root.

The security question is whether the token is scoped tightly enough. The specification says a token can be bound to a pinned BPF filesystem path and constrained to specific `cmd` types. In practice: can you create a token that allows `BPF_PROG_LOAD` with `BPF_PROG_TYPE_LSM`? If so, an unprivileged container with a delegated token could attach LSM programs. That is the threat model. I do not know if the current implementation allows it or whether the cmd-type constraint blocks it. That is the exercise.

## What the one skip, and the caveats, actually say

The single skip and the environment caveats are not gaps in the argument. They are information.

The enforcement-sensitive primitives (ch06, ch06s, ch06o, ch12) tell you something true: they only flip a real decision where policy enforcement is live, which makes them near-useless in zero-enforcement environments and genuinely dangerous in high-enforcement ones. That sensitivity is also an environment fingerprint — a primitive whose behavior differs between a minimal development image and an enforcing production host is, by that difference, a detection signal for defenders.

Ch24 skipping on every kernel I had means it is a future-tense primitive: something that will be in production by the time this book is outdated. Note when `CONFIG_BPF_TOKEN` ships enabled on your distro.

The harness proof markers exist so you can reproduce all of this without reading my notes. If you fire `CH24_PROVEN` before I do, that is a better outcome than if I had manufactured a proof on an unsupported kernel.

---

**Related material**
- Companion: [Ch 20 Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html), [Ch 22 Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
- Harness: `dBPF-pocs/harness/proof.py`
