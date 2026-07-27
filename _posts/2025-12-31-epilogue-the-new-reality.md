---
layout: book
title: "Epilogue: What This Book Actually Demonstrated"
date: 2025-12-31
---

# Epilogue: What This Book Actually Demonstrated

> **See also**: [Chapter 19 — What This Book Actually Demonstrated]({{ site.baseurl }}/book/act-7/chapter-19-the-new-reality.html) · [Chapter 22 — The Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)

Twenty-six registered PoCs, one reference kernel (Ubuntu 6.17.0-29-generic aarch64, in a Lima VM), one reproducible harness. This epilogue draws a line under what was actually shown and what was not.

## What was demonstrated

Of the 26 registered PoCs, 25 reproduce in the reference environment and one skips. Each PoC prints a proof marker to stdout — lines like `CH01_WEAPON_PROVEN flips=N`, `[ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt`, `CLOAK_PROVEN before_count=4 after_count=2 hidden=2`, `GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0`. The one skip is ch24: the reference kernel is built with `CONFIG_BPF_TOKEN=n`, so `BPF_TOKEN_CREATE` is not available to exercise. (Two earlier drafts, ch13 powercap/RAPL and ch17 ACPI-WMI, were retired as x86-only stubs and are not part of the 26-entry catalog.) Chapter 20 walks the reproduced set and organizes it into five primitive classes; Chapter 21 accounts for the skip and the environment caveats. If you read nothing else, read those two.

## What was not demonstrated

- **No DAC, LSM, or capability check was defeated without `CAP_BPF`.** Drop the capability and every chapter stops working. None of the primitives are reachable from an unprivileged process.
- **No kernel bug was found.** No CVEs were reported off the back of this work because there were none to report.
- **No BPF verifier invariant was bypassed.** Every program that attached was accepted by the verifier doing its job. Where the verifier refused a program, the chapter records the refusal (ch15 skb-writes-from-kprobe is the clearest example).
- **No privilege escalation into `CAP_BPF`.** Every chapter assumed the attacker already held `CAP_BPF` and usually `CAP_PERFMON` or `CAP_SYS_ADMIN`. Paths into that capability are outside scope.

## The correct mental model

`CAP_BPF` is a privileged capability. Granting it grants the ability to:

1. Read arbitrary kernel memory via `kprobe` / `tracepoint` + `BPF_CORE_READ`.
2. Override the return value of any function listed in `/sys/kernel/debug/error_injection/list` via `bpf_override_return`.
3. Rewrite userspace memory in certain syscall windows via `bpf_probe_write_user`.
4. Take over netdev ingress via `XDP`.

This is the capability operating as designed. Any surprise at the consequences is proportional to how much modern observability agents silently request `CAP_BPF`.

## Six recommendations for operators

Expanded in chapter 22:

- Inventory `CAP_BPF` holders across the fleet. Know who is asking.
- Pin loaded BPF programs at boot and diff the set against the boot baseline on a timer.
- Use BPF LSM policies to gate program load by attach type and caller credential.
- Audit `/sys/kernel/debug/error_injection/list` on production kernels; restrict debugfs visibility where feasible.
- Audit the `bpf(2)` syscall to a tamper-evident sink that itself does not run with `CAP_BPF`.
- Do not trust userspace syscall return values for security-critical decisions. Consult `current->cred` at the kernel enforcement point. Chapter 18's `uid=0 gid=1001` tell is the canonical example of why.

## The durable artifact

Individual primitives in this book will age as kernels move. Error-injection lists will gain or lose symbols. BTF will land on more platforms. LSM policies will become more common. The thing that should outlive the POCs is the five-class taxonomy in chapter 20:

- Class I — return-value override at the API boundary.
- Class II — userspace buffer rewrite.
- Class III — ringbuf exfiltration of kernel-internal state.
- Class IV — packet-path interception.
- Class V — kernel-event-triggered userspace racer.

Three motions run through all five: override the API return, rewrite the user buffer, copy the decision out-of-band. If you end up reading only one chapter, read 20.

## Prior art

Most primitives here have prior art in rootkit POCs, conference talks, and existing tools like `bcc/capable.py`. The contribution is a reproducible harness, an honest taxonomy, and explicit scope — not novelty. Ch15's cross-namespace XDP redirect is a hostile reuse of a pattern Cilium has shipped since ~2019. Ch18's `getuid` forgery is the eBPF restatement of a bug class older than eBPF.

---
**Related material**
- [Chapter 19 — What This Book Actually Demonstrated]({{ site.baseurl }}/book/act-7/chapter-19-the-new-reality.html)
- [Chapter 20 — The Autopsy: What We Proved]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html)
- [Chapter 21 — The Autopsy: What Refused to Die]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)
- [Chapter 22 — The Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
