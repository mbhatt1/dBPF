---
layout: book
title: "Chapter 0: What CAP_BPF Actually Permits"
date: 2025-01-01
---

# Chapter 0: What CAP_BPF Actually Permits

> **See also**: [Full preface in the book]({{ site.baseurl }}/book/act-1/chapter-0-field-manual-preface.html) · [Defender playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)

This book is a catalog of what `CAP_BPF` plus `CAP_PERFMON` (or `CAP_SYS_ADMIN`) actually permits on a modern aarch64 Linux kernel. Every chapter assumes the attacker already holds that capability. No chapter documents escalation without it.

Each chapter ships with a reproducible POC, a scripted trigger that prints observable BEFORE and AFTER state, and a machine-grep-able proof marker. Failures are documented honestly in [chapter 21]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html). The harness is `dBPF-pocs/harness/proof.py`, driven from a privileged Docker container.

## Intended reader

Operators deciding whether to grant `CAP_BPF` to a workload, and what to configure when they do. Security engineers auditing observability stacks that quietly ask for the capability at install time. Defenders looking for concrete hardening recipes. Researchers looking for a reproducible taxonomy of what the eBPF surface can be shaped into.

## What this book is not

- Not a zero-day catalog. Nothing here is a CVE.
- Not a "the kernel is broken" argument. Every program in the book was accepted by a BPF verifier doing its job correctly.
- Not a privilege-escalation guide. CAP_BPF is a prerequisite, not an output.
- Not novel research. Prior art exists for most individual primitives (`d_reclen` rewrite for readdir hiding goes back to 2016 in rootkit PoCs; XDP covert channels were discussed in research from ~2019 onward; PID-ns side channels via `sched_process_fork` appear in earlier academic work). The contribution is a reproducible harness, honest scope, and a durable taxonomy.

## The taxonomy

Every primitive in the book is one of three motions:

- **Change the syscall return** (Class I — kretprobe / LSM fmod_ret / XDP_DROP). The kernel's decision stands; the caller sees a different answer.
- **Rewrite the userspace buffer** (Class II — `bpf_probe_write_user` during `sys_exit`). Kernel state unchanged; userspace reads are corrupted post-return.
- **Copy the decision out of band** (Class III — ringbuf from a tracepoint or kprobe). Kernel state and decisions are untouched; confidentiality is lost.

Two additional classes specialize these — **Class IV** (XDP packet-path interception) is a Class I variant at the netdev layer; **Class V** (ringbuf + userspace racer) is Class III used as a trigger signal. Full taxonomy is in [chapter 20]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html).

## The operational lesson

CAP_BPF grants every motion above. Granting it to a workload means granting that workload the ability to read arbitrary kernel memory, override the return of any function on `/sys/kernel/debug/error_injection/list`, rewrite userspace memory in certain syscall windows, and take over netdev ingress via XDP. That is the capability operating as documented. Surprise is proportional to how much of modern observability silently depends on it.

---

**Related material**

- Taxonomy: [Chapter 20]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html)
- Skip accounting: [Chapter 21]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)
- Defender playbook: [Chapter 22]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
