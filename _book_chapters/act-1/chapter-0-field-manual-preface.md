---
layout: book
title: "Chapter 0: What CAP_BPF Actually Permits"
date: 2025-01-01
---

# Chapter 0: What CAP_BPF Actually Permits

> **See also**: [Blog post]({{ site.baseurl }}/chapter-0-what-cap-bpf-actually-permits.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

This book is a catalog of what `CAP_BPF` plus `CAP_PERFMON` (or `CAP_SYS_ADMIN`) actually permits on a modern aarch64 Linux kernel. Every chapter assumes the attacker already holds that capability. No chapter documents escalation without it.

Each chapter ships with a reproducible POC, a scripted trigger that prints observable BEFORE and AFTER state, and a machine-grep-able proof marker. Failures are documented honestly in [chapter 21]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html). The harness is `dBPF-pocs/harness/proof.py`, driven from a privileged Docker container.

The reason I wrote it is that the gap between "CAP_BPF is a privileged capability" and "here is what a process holding CAP_BPF can actually do" keeps producing surprised operators. Modern observability agents routinely request the capability at install time. The consequences of granting it are more direct than the docs spell out.

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

## A brief history of CAP_BPF

Before kernel 5.8, loading a BPF program meant holding `CAP_SYS_ADMIN`. Commit `2c78ee898d8f` in 5.8 split the BPF surface out into its own capability. `CAP_BPF` covered most program and map types; `CAP_PERFMON` covered tracing. The split was motivated by least-privilege: observability tooling did not need the full `CAP_SYS_ADMIN` surface.

The lwn.net coverage at the time noted the counterargument: if the new capability lets a program call `bpf_probe_read_kernel`, granting it to an observability agent is not meaningfully different from granting root. Alexei Starovoitov's position was that the verifier's constraints — type-safety, memory-safety, bounded loops, helper allowlisting — are the actual safety boundary. This book is designed to stress-test that position. The answer turns out to be a lot more than most operators expect when they check the "grant CAP_BPF" box in their DaemonSet manifest.

The distribution-wide `unprivileged_bpf_disabled` flip to `2` in 2021 set the cultural baseline that BPF load is a privileged operation. Granting `CAP_BPF` is, in practice, the re-enabling of that privilege for a specific workload.

## The capability grant, in practice

`CAP_BPF + CAP_PERFMON` is the standard grant pattern. Cilium's docs recommend it. Pixie's helm chart sets it. Tetragon asks for it on default install. It is also the exact grant required for every technique in chapters 1 through 18 that does not explicitly call out a need for `CAP_SYS_ADMIN`.

```bash
# Typical observability DaemonSet
securityContext:
  capabilities:
    add:
    - CAP_BPF
    - CAP_PERFMON
    - CAP_NET_ADMIN  # for tc-bpf, XDP via netlink
```

```bash
# Verify a running process holds what you think
getpcaps $(pgrep my-agent)
# my-agent: cap_net_admin,cap_perfmon,cap_bpf=ep
```

`CAP_PERFMON` is the capability that makes most of this book possible. It covers `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_TRACEPOINT`, and `BPF_PROG_TYPE_PERF_EVENT`. Every chapter that uses `SEC("kprobe/...")` needs it. `CAP_BPF` alone does not get you kprobes.

`CAP_NET_ADMIN` is required additionally for XDP attachment via netlink. A process with only `CAP_BPF + CAP_PERFMON` cannot attach an XDP program to an interface. This is why XDP-based techniques are narrower in practice than kprobe-based ones.

## ALLOW_ERROR_INJECTION

`ALLOW_ERROR_INJECTION` is a macro defined in `include/asm-generic/error-injection.h`. A kernel function annotated with it is recorded at build time into a special section, and the resulting list is exposed at `/sys/kernel/debug/error_injection/list`. The BPF helper `bpf_override_return` only takes effect on functions in that list. If the target is not annotated, the helper runs and its effect is silently discarded.

```bash
# On a linuxkit 6.12 VM
cat /sys/kernel/debug/error_injection/list | head
# do_unlinkat EI_ETYPE_NULL
# do_mkdirat EI_ETYPE_NULL
# do_renameat2 EI_ETYPE_NULL
```

The annotated set is notably skewed toward syscall entries and filesystem operations. `cap_capable` is not annotated. `security_file_permission` is not annotated. Every security-decision function is deliberately excluded. This was the original failure mode I hit in Chapter 1 — until I found a different primitive at the same hook point.

The workflow before writing a POC: check `/sys/kernel/debug/error_injection/list`. If the target is not there, rewrite the technique around observation rather than override.

## The operational lesson

CAP_BPF grants every motion in the taxonomy above. Granting it to a workload means granting that workload the ability to read arbitrary kernel memory, override the return of any function on the error-injection list, rewrite userspace memory in certain syscall windows, and take over netdev ingress via XDP. That is the capability operating as documented. Surprise is proportional to how much of modern observability silently depends on it.

## The target environment

The kernel is 6.12.54-linuxkit, aarch64 — the kernel shipped by Docker Desktop on Apple Silicon as of late 2024. Key config entries:

- `CONFIG_BPF_LSM=y`
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_KPROBES=y`, `CONFIG_KPROBE_EVENTS=y`
- `CONFIG_BPF_KPROBE_OVERRIDE=y`
- `CONFIG_FUNCTION_ERROR_INJECTION=y`

`CONFIG_BPF_KPROBE_OVERRIDE=y` is worth calling out. On kernels where it is not set, `bpf_override_return` is not even exposed to programs at verification time. The linuxkit default enables it, which is why Chapter 1 can get as far as "the override loads and silently no-ops" rather than "the override is rejected at load time."

The harness at `dBPF-pocs/harness/proof.py` orchestrates the test matrix. For each chapter it builds the POC, loads it into a Docker container, runs the trigger, and collects BEFORE/AFTER output. Reproducing the book's claims means running the harness and checking the result.

## Non-claims

- **Not novel research.** `d_reclen` hiding goes back to 2016. XDP as a covert channel has prior art from ~2019. PID-namespace side channels appear in earlier academic work. The contribution is a reproducible harness on current kernels, an honest taxonomy, and explicit scope.
- **Not an escalation path.** Remove `CAP_BPF` from the threat model and every chapter stops working.
- **Not a verifier bug catalog.** Every program that attached was accepted by the verifier doing its job. Where the verifier refused a program, the chapter records the refusal and moves on.
- **Not a zero-day drop.** Everything uses documented helpers, documented attach points, and documented program types.

## How to read this book

Start with the chapter you are worried about. The taxonomy in Chapter 20 is the navigation aid. Chapter 21 is the honest-failures list.

**If you are an operator** deciding whether to grant `CAP_BPF`: read this chapter, skip to Chapter 22 for the defender playbook, then walk Chapters 1 through 18.

**If you are a researcher** extending the taxonomy: read Chapter 0, then Chapter 20 for the seven-class framing, then the failure catalog in Chapter 21.

**If you are on a red team**: pick the chapter whose primitive matches your goal, check Chapter 21 to see if that primitive's failure mode applies to your target kernel, then read the chapter.

The honest form of this book's claim is narrower than "CAP_BPF grants enormous power." The honest form is: CAP_BPF grants the exact power listed in the taxonomy, subject to the failure modes listed in Chapter 21. Some techniques that sound powerful are silently no-ops. Some techniques that sound restricted are fully operational. The distinction is why the harness exists.

---

**Related material**

- Taxonomy: [Chapter 20]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html)
- Skip accounting: [Chapter 21]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)
- Defender playbook: [Chapter 22]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
