---
layout: book
title: "Chapter 19: What This Book Actually Demonstrated"
date: 2025-12-31
---

# Chapter 19: What This Book Actually Demonstrated

> **See also**: [Blog post]({{ site.baseurl }}/epilogue-the-new-reality.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

The catalog holds 26 registered PoCs, verified against one reference kernel (Ubuntu 6.17.0-29-generic aarch64, run in a Lima VM) driven by a single reproducible harness. This chapter draws a line under what was actually shown and what was not.

**The honest tally: of the 26 registered PoCs, 25 reproduce in the reference environment and one skips.** The skip is ch24, because `CONFIG_BPF_TOKEN=n` on every kernel I had access to — a build-configuration gap, not a code failure. Everything else fires. (Two earlier drafts, ch13 powercap/RAPL and ch17 ACPI-WMI, were retired rather than carried as x86-only stubs; they are not in the catalog and are not counted here. See the skip accounting in Chapter 21 for why.)

## What was demonstrated

It is worth being precise about what "demonstrated" means. Each PoC emits a proof marker — a line printed to stdout before the loader tears down — that carries quantitative evidence. If the marker prints, the primitive fired; if it doesn't, it didn't. There is nothing to interpret.

Twenty-five of the 26 produce `_PROVEN` markers in the reference environment. Only ch24 skips, and it skips for a reason the marker states plainly (`CH24_SKIP reason=...`): the kernel was not built with `CONFIG_BPF_TOKEN`, so `BPF_TOKEN_CREATE` is not available to test against. A few primitives are worth flagging for how much their reference-environment result depends on the surface being present: ch06 and ch12 only flip a *real* decision where SELinux is enforcing or module-signature enforcement is on, ch23 demonstrates kprobe attachment and entry-intercept events on the TPM unseal path without capturing key bytes (that needs a boot-registered TPM backend), and ch25 runs against a mock IMDSv2 exchange on `lo` rather than a live cloud metadata endpoint. None of those are skips; they reproduce as registered. Chapter 21 accounts for each caveat.

The proof-marker format is deliberately boring. Every proven run emits a line of the form `CHxx_*_PROVEN <key>=<value> ...` on stdout before the loader is torn down. A sample:

```
ch01:  CH01_WEAPON_PROVEN flips=3 signals=3
ch02:  [ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=17 hits=1
ch10:  CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes
ch05b: GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0
ch18:  TOKEN_FORGE_PROVEN uid_forges=1
ch25:  CH25_PROVEN access_key_captured=yes token_captured=yes role=demo-role
```

The keys inside each marker are quantitative. `before_count=4 after_count=2 hidden=2` carries the BEFORE and AFTER state explicitly, and the numbers have to tally. `dropped=2 tcpdump=0` is the Class IV honesty field: two packets vanished while tcpdump saw zero.

Chapter 20 walks the reproduced cases and organizes them into five primitive classes. Chapter 21 accounts for the single skip and the environment caveats. If you read nothing else after this, read those two.

## What was not demonstrated

Just as important as what fired is what did not — and why.

- **No DAC, LSM, or capability check was defeated without `CAP_BPF`.** Drop the capability and every chapter stops working. Literally none of the primitives are reachable from an unprivileged process. Run them without `CAP_BPF` and every loader fails at `bpf(BPF_PROG_LOAD)` with `EPERM`.
- **No kernel bug was found.** No CVEs were reported off the back of this work because there were none to report. Every override that landed did so because the target function was in the kernel maintainers' `ALLOW_ERROR_INJECTION` list. Every `bpf_probe_write_user` wrote to a user page that was writable, in a window the kernel deliberately leaves open.
- **No BPF verifier invariant was bypassed.** Every program that attached was accepted by the verifier doing its job. Where the verifier refused a program, the chapter records the refusal.
- **No privilege escalation into `CAP_BPF`.** Every chapter assumed the attacker already held `CAP_BPF` and usually `CAP_PERFMON` or `CAP_SYS_ADMIN`. How that capability was obtained is outside the scope of this book.

The story is not "an attacker got root." The story is "an attacker who already held a privileged capability used it in ways that capability grants." If your operational concern is who on your fleet holds that capability — and it should be — chapter 22 is the playbook.

## The correct mental model

`CAP_BPF` grants three motions.

1. **Override the API return.** A kretprobe with `bpf_override_return` on a function in the error-injection list rewrites what the function returns to its caller. The kernel's computation completes normally; the caller receives a different answer. Class I primitives.

2. **Rewrite the user buffer.** A tracepoint or kretprobe with `bpf_probe_write_user` writes arbitrary bytes into the caller's userspace memory during a syscall window. The kernel's view of reality is unchanged. The caller sees the rewrite when it reads the buffer back. Class II primitives.

3. **Copy the decision out-of-band.** A BPF program reads kernel-internal state through BTF-assisted pointer walks and ships it to a privileged userspace drainer via ringbuf. The kernel does not know the drain happened. Class III primitives.

XDP and LSM `fmod_ret` are specializations of these three. XDP drops and redirects are a packet-path variant of the override motion (Class IV). Class V — watch a kernel event, then race userspace to the outcome — composes all three motions into a pattern rather than being a primitive in its own right.

Every chapter is a demonstration that granting `CAP_BPF` grants all three motions across a representative sample of kernel subsystems. Act 4 extends that surface to hardware-rooted key material and off-host cloud-metadata boundaries. Chapter 20 formalizes the taxonomy.

## Six recommendations for operators

These six recommendations map directly to the primitives in this book. Each closes a meaningful fraction of the attack surface. The combination closes almost all of it. Chapter 22 expands every one of them with working commands.

- **Inventory `CAP_BPF` holders across the fleet.** Know who is asking. Every chapter in this book starts with a process that already holds the capability; the list of those processes is the threat model.
- **Pin loaded BPF programs at boot and diff the set against the boot baseline on a timer.** Late-loaded programs are the signature of post-compromise activity. A new attachment that wasn't there at boot is a finding.
- **Use BPF LSM policies to gate program load by attach type and caller credential.** BPF LSM sits at the exact entry point every primitive in this book passed through; it is the highest-leverage control available.
- **Audit `/sys/kernel/debug/error_injection/list` on production kernels; restrict debugfs visibility where feasible.** Class I primitives depend on this list. Knowing which symbols are on it for your kernel is a prerequisite for understanding your exposure.
- **Audit the `bpf(2)` syscall to a tamper-evident sink that itself does not run with `CAP_BPF`.** An audit pipeline running on the same host as the attacker's ringbuf reader is part of the attack surface, not outside it.
- **Do not trust userspace syscall returns for security-critical decisions. Consult `current->cred` at the kernel enforcement point.** Chapter 18's `uid=0 gid=1001` tell is the canonical example of why.

None of these controls is novel. All are under-deployed in practice. That gap is where the primitives live.

## The durable artifact

Individual primitives will age as kernels move. Error-injection lists will gain or lose symbols. BTF will land on more platforms. LSM policies will become more common. The thing that should outlive the PoCs is the five-class taxonomy in chapter 20:

- Class I — return-value override at the API boundary.
- Class II — userspace buffer rewrite.
- Class III — ringbuf exfiltration of kernel-internal state.
- Class IV — packet-path interception.
- Class V — kernel-event-triggered userspace racer.

Three motions run through all five: override the API return, rewrite the user buffer, copy the decision out of band. If you read only one chapter, read 20.

## Prior art

Most primitives here have prior art in rootkit POCs, conference talks, and tools like `bcc/capable.py`. The contribution is a reproducible harness, an honest taxonomy, and explicit scope; not novelty. Ch15's cross-namespace XDP redirect is a hostile reuse of a pattern Cilium has shipped since ~2019. Ch18's `getuid` forgery is the eBPF restatement of a bug class older than eBPF.

The harness is a Python driver (`dBPF-pocs/harness/proof.py`) that runs all PoCs sequentially in a sealed container, regenerating `vmlinux.h` from the running kernel's BTF for each. One Dockerfile, one command, one exit status. Getting a reproducible BPF harness working on aarch64 took a week; running it once it works takes minutes. That repeatability is the artifact.

---

**Related material**
- [Chapter 20; The Autopsy: What We Proved]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html)
- [Chapter 21; The Autopsy: What Refused to Die]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)
- [Chapter 22; The Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
