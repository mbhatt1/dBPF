---
layout: book
title: "Chapter 19: What This Book Actually Demonstrated"
date: 2025-12-31
---

# Chapter 19: What This Book Actually Demonstrated

> **See also**: [Blog post]({{ site.baseurl }}/epilogue-the-new-reality.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

Twenty-three POCs, three kernels (Docker Desktop linuxkit 6.12 aarch64 primary; Fedora 42 aarch64 QEMU 6.14 secondary; Ubuntu 6.17.0-29-generic aarch64 Lima VM for final verification), one harness. This chapter draws a line under what was actually shown and what was not.

**Final tally across all environments: 22 PROVEN, 1 SKIP.** The skip is ch24 ; `CONFIG_BPF_TOKEN=n` on all available kernels. That is a build-configuration gap, not a code failure. Every other primitive fired in at least one environment.

## What was demonstrated

Eighteen POCs produce `_PROVEN` proof markers on linuxkit. Two more (ch06 LSM, ch12 LSM) skip on linuxkit at runtime because linuxkit does not run SELinux enforcing and is not built with `CONFIG_MODULE_SIG_FORCE`; both fire on the Fedora 42 aarch64 QEMU VM secondary. Two Act 4 PoCs (ch23, ch25) are PROVEN on the Ubuntu 6.17 aarch64 Lima VM ; ch23 via kprobe attachment with entry intercept events, ch25 via XDP mock IMDSv2 on `lo`. One (ch24) skips in all environments.

The proof-marker format is deliberately boring. Every proven run emits a line of the form `CHxx_*_PROVEN <key>=<value> ...` on stdout before the loader is torn down. A sample:

```
ch01:  CH01_WEAPON_PROVEN flips=3 signals=3
ch02:  [ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=17 hits=1
ch10:  CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes
ch05b: GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0
ch18:  TOKEN_FORGE_PROVEN uid_forges=1
ch25:  CH25_PROVEN access_key_captured=yes token_captured=yes role=demo-role
```

The keys inside each marker are quantitative. `before_count=4 after_count=2 hidden=2` carries the BEFORE and AFTER state explicitly; the numbers have to tally. `dropped=2 tcpdump=0` is the Class-IV honesty field ; two packets vanished while tcpdump saw zero. If the marker prints, the primitive fired. If it does not, it did not.

Chapter 20 walks the proven cases and organizes them into five primitive classes. Chapter 21 accounts for every skip. If you read nothing else after this, read those two.

## What was not demonstrated

- **No DAC, LSM, or capability check was defeated without `CAP_BPF`.** Drop the capability and every chapter stops working. Literally none of the primitives are reachable from an unprivileged process. Run them without `CAP_BPF` and every loader fails at `bpf(BPF_PROG_LOAD)` with `EPERM`.
- **No kernel bug was found.** No CVEs were reported off the back of this work because there were none to report. Every override that landed did so because the target function was in the kernel maintainers' `ALLOW_ERROR_INJECTION` list. Every `bpf_probe_write_user` wrote to a user page that was writable, in a window the kernel deliberately leaves open.
- **No BPF verifier invariant was bypassed.** Every program that attached was accepted by the verifier doing its job. Where the verifier refused a program, the chapter records the refusal.
- **No privilege escalation into `CAP_BPF`.** Every chapter assumed the attacker already held `CAP_BPF` and usually `CAP_PERFMON` or `CAP_SYS_ADMIN`. How that capability was obtained is outside the scope of this book.

The story is not "an attacker got root." The story is "an attacker who was already granted a privileged capability used it in ways the capability grants." If your operational concern is "who on my fleet holds that capability" ; and it should be ; chapter 22 is the playbook.

## The correct mental model

`CAP_BPF` grants three motions.

1. **Override the API return.** A kretprobe with `bpf_override_return` on a function in the error-injection list rewrites what the function returns to its caller. The kernel's computation completes normally; the caller receives a different answer. Class I primitives.

2. **Rewrite the user buffer.** A tracepoint or kretprobe with `bpf_probe_write_user` writes arbitrary bytes into the caller's userspace memory during a syscall window. The kernel's view of reality is unchanged. The caller sees the rewrite when it reads the buffer back. Class II primitives.

3. **Copy the decision out-of-band.** A BPF program reads kernel-internal state through BTF-assisted pointer walks and ships it to a privileged userspace drainer via ringbuf. The kernel does not know the drain happened. Class III primitives.

XDP and LSM `fmod_ret` are specializations of these three. XDP drops and redirects are a packet-path variant of the override motion (Class IV). Class V ; watch a kernel event, race userspace to the outcome ; composes all three motions into a pattern rather than a primitive in its own right.

Every chapter in the book is a demonstration that granting `CAP_BPF` grants access to all three motions across a representative surface of kernel subsystems. Act 4 extends that surface to hardware-rooted key material and off-host cloud-metadata boundaries. The taxonomy is what chapter 20 formalizes. Reread it if you forgot.

## Six recommendations for operators

Expanded in chapter 22:

- Inventory `CAP_BPF` holders across the fleet. Know who is asking.
- Pin loaded BPF programs at boot and diff the set against the boot baseline on a timer.
- Use BPF LSM policies to gate program load by attach type and caller credential.
- Audit `/sys/kernel/debug/error_injection/list` on production kernels; restrict debugfs visibility where feasible.
- Audit the `bpf(2)` syscall to a tamper-evident sink that itself does not run with `CAP_BPF`.
- Do not trust userspace syscall return values for security-critical decisions. Consult `current->cred` at the kernel enforcement point. Chapter 18's `uid=0 gid=1001` tell is the canonical example of why.

Each one closes a meaningful fraction of the primitives in this book. The combination closes almost all of them. None is novel; all are under-deployed in practice. That gap is where the primitives live.

## The durable artifact

Individual primitives in this book will age as kernels move. Error-injection lists will gain or lose symbols. BTF will land on more platforms. LSM policies will become more common. The thing that should outlive the POCs is the five-class taxonomy in chapter 20:

- Class I ; return-value override at the API boundary.
- Class II ; userspace buffer rewrite.
- Class III ; ringbuf exfiltration of kernel-internal state.
- Class IV ; packet-path interception.
- Class V ; kernel-event-triggered userspace racer.

Three motions run through all five: override the API return, rewrite the user buffer, copy the decision out-of-band. If you read only one chapter, read 20.

## Prior art

Most primitives here have prior art in rootkit POCs, conference talks, and tools like `bcc/capable.py`. The contribution is a reproducible harness, an honest taxonomy, and explicit scope ; not novelty. Ch15's cross-namespace XDP redirect is a hostile reuse of a pattern Cilium has shipped since ~2019. Ch18's `getuid` forgery is the eBPF restatement of a bug class older than eBPF.

The harness is a Python driver (`dBPF-pocs/harness/proof.py`) that runs all POCs sequentially in a sealed container, regenerating `vmlinux.h` from the running kernel's BTF for each. One Dockerfile, one command, one exit status. Setting up a reproducible BPF harness on aarch64 linuxkit took a week; running it once it works takes minutes. That repeatability is the artifact.

---

**Related material**
- [Chapter 20 ; The Autopsy: What We Proved]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html)
- [Chapter 21 ; The Autopsy: What Refused to Die]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)
- [Chapter 22 ; The Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
