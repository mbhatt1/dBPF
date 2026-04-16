---
layout: book
title: "Chapter 0: What CAP_BPF Actually Permits"
date: 2025-01-01
---

# Chapter 0: What CAP_BPF Actually Permits

> **See also**: [Blog post]({{ site.baseurl }}/chapter-0-what-cap-bpf-actually-permits.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

This book documents what `CAP_BPF` plus `CAP_PERFMON` (or `CAP_SYS_ADMIN`) actually permits on a modern aarch64 Linux kernel. Every technique here assumes the attacker already holds that capability. That assumption is load-bearing. Nothing in this book demonstrates escalation from an unprivileged process; nothing here is a zero-day; nothing here is a verifier bug.

The reason I wrote it is that the gap between "CAP_BPF is a privileged capability" and "here is what a process holding CAP_BPF can actually do" keeps producing surprised operators. Modern observability agents routinely request the capability, and the consequences of granting it are more direct than the docs tend to spell out.

Each chapter ships with a reproducible trigger that runs under the Docker harness in `dBPF-pocs/`. Every claim has a BEFORE line and an AFTER line printed on stdout, plus a machine-grep-able marker like `CH01_WEAPON_PROVEN flips=N` or `PWNED path=...`. The harness records both. Failures — verifier rejections, missing BTF symbols, inactive enforcement points — are documented honestly inside the chapter and tallied in chapter 21.

The intended audience is operators deciding whether to grant `CAP_BPF` to a workload and what guardrails to configure when they do. The second audience is researchers who want a reproducible baseline to extend.

## Non-claims

- **Not novel research.** The `d_reclen` swallow trick for hiding directory entries (chapter 10) has prior art in rootkit POCs going back to at least 2016. XDP as a covert exfil channel (chapter 5b, chapter 15) is a well-trodden path. PID-namespace sidechannels (chapter 9) have appeared in prior container-escape work. The contribution here is a reproducible harness on current kernels, an honest taxonomy, and explicit scope — not novelty.
- **Not an escalation path.** Remove `CAP_BPF` from the threat model and every chapter stops working. There is no "but what if the attacker does not have the capability" section, because the answer is: they cannot do any of this.
- **Not a verifier bug catalog.** Every program that attached in this book was accepted by the verifier doing its job. Where the verifier refused a program, the chapter records the refusal and moves on. If you came here for a verifier exploit, you are in the wrong manual.

## How to read this

Start with the chapter you are worried about. If you want the overview, jump to chapter 20 for the five-class taxonomy of primitives that actually fired on kernel 6.12.54-linuxkit aarch64, chapter 21 for the six primitives that did not fire and the specific kernel-environment reasons they were refused, and chapter 22 for the defender playbook derived from the taxonomy.