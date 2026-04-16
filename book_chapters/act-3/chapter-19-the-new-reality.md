---
layout: book
title: "Chapter 19: What This Book Actually Demonstrated"
date: 2025-12-31
---

# Act III: Total Control

# Chapter 19: What This Book Actually Demonstrated

Eighteen chapters, one kernel, one harness. This chapter draws a line under what was actually shown and what was not.

## What was demonstrated

Nineteen primitives ran under the reproducible Docker harness on kernel 6.12.54-linuxkit aarch64. Thirteen produced BEFORE/AFTER proof markers on stdout — lines like `CH01_WEAPON_PROVEN flips=N`, `[ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt`, `CLOAK_PROVEN before_count=4 after_count=2 hidden=2`, `GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0`. Six skipped with documented kernel-environment reasons: missing BTF symbol, absent subsystem, inactive enforcement point. Chapter 20 walks the proven set and organizes them into five primitive classes. Chapter 21 accounts for the six skips. If you read nothing else, read those two.

## What was not demonstrated

- **No DAC, LSM, or capability check was defeated without `CAP_BPF`.** Drop the capability and every chapter in this book stops working. Literally none of the primitives are reachable from an unprivileged process.
- **No kernel bug was found.** I did not report any CVEs off the back of this work because there were none to report.
- **No BPF verifier invariant was bypassed.** Every program that attached in this book was accepted by the verifier doing its job. Where the verifier refused a program, the chapter records the refusal.
- **No privilege escalation.** Every chapter assumed the attacker already had `CAP_BPF` and usually `CAP_PERFMON` or `CAP_SYS_ADMIN`. Escalation paths into CAP_BPF are outside scope.

## The correct mental model

`CAP_BPF` is a privileged capability. Granting it grants the ability to:

1. Read arbitrary kernel memory via `kprobe` / `tracepoint` + `BPF_CORE_READ`.
2. Override the return value of any function listed in `/sys/kernel/debug/error_injection/list` via `bpf_override_return`.
3. Rewrite userspace memory in certain syscall windows via `bpf_probe_write_user`.
4. Take over netdev ingress via `XDP`.

This is the capability operating as designed. Any surprise at the consequences is proportional to how much modern observability agents silently request `CAP_BPF`.

## For operators

Six one-line recommendations, expanded in chapter 22:

- Inventory `CAP_BPF` holders across your fleet. Know who is asking.
- Pin loaded BPF programs at boot and diff the set against the boot baseline on a timer.
- Use BPF LSM policies to gate program load by attach type and caller credential.
- Audit `/sys/kernel/debug/error_injection/list` on production kernels; restrict debugfs visibility where feasible.
- Audit the `bpf(2)` syscall to a tamper-evident sink that itself does not run with `CAP_BPF`.
- Do not trust userspace syscall return values for security-critical decisions. Consult `current->cred` at the kernel enforcement point.

## For researchers

The five-class taxonomy in chapter 20 (Class I: return-value override at the API boundary; Class II: userspace buffer rewrite; Class III: ringbuf exfiltration of kernel-internal state; Class IV: packet-path interception; Class V: kernel-event-triggered userspace racer) is the durable artifact of this work. Three motions run through all five classes: override the API return, rewrite the user buffer, copy the decision out-of-band. Individual primitives age as kernels move; that taxonomy should survive.

## Prior art

Most of the primitives in this book have prior art in rootkit POCs, conference talks, and existing tools like `bcc/capable.py`. The contribution is a reproducible harness, an honest taxonomy, and explicit scope — not novelty.