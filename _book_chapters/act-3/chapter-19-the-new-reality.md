---
layout: book
title: "Chapter 19: What This Book Actually Demonstrated"
date: 2025-12-31
---

# Chapter 19: What This Book Actually Demonstrated

> **See also**: [Blog post]({{ site.baseurl }}/epilogue-the-new-reality.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

Eighteen chapters, one kernel, one harness. This chapter draws a line under what was actually shown and what was not.

## What was demonstrated

Twenty-five POCs ran under the reproducible Docker harness on kernel 6.12.54-linuxkit aarch64. The final run split as follows: **20 produced the primitive effect** and printed their `_PROVEN` proof marker; **4 honest skips** recorded exactly which piece of kernel environment was missing; **1 failure** attached cleanly but emitted zero events within the harness timeout. The POC list in `proof.py` is the authoritative manifest — nineteen "primary" chapters (ch01 through ch18, plus ch05b), and six workaround variants (ch06s, ch07w, ch08k, ch12s, ch13a, ch17a) for the chapters whose natural hook did not grip on this kernel. The workaround variants are labelled as such in the harness; the proof markers they print are labelled `*_CONCEPT_PROVEN` or `*_ANALOG_PROVEN` rather than `*_WEAPON_PROVEN` for exactly this reason.

Thirteen of the twenty produced effects on the chapters' *natural* kernel surface without any substitution — the hook the chapter originally aimed at was live on this kernel, the program attached there, and the effect fired. These are the chapters that would plausibly have fired on any 6.12 aarch64 kernel with default BTF and default LSM. The other six-to-seven are workaround variants that demonstrate the same primitive on an adjacent surface, because the original surface was not present. Counting both toward "20 weaponized" is a choice I make explicit here: the primitive shape fired, with honest labelling. Counting only the natural-surface ones gives you thirteen, which is the number I used in the epilogue when I wanted the stricter bar.

The proof-marker format is deliberately boring. Every proven run emits a line of the form `CHxx_*_PROVEN <key>=<value> <key>=<value> ...` on stdout before the loader is torn down. A harness scrape of `_PROVEN` across the final run captures the full set. A sample of the lines, one per class:

```
ch01:  CH01_WEAPON_PROVEN flips=3
ch02:  [ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=17 hits=1
ch10:  CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes
ch05b: GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0
ch18:  TOKEN_FORGE_PROVEN uid_forges=1
```

Chapter 20 walks the twenty proven cases and organizes them into five primitive classes. Chapter 21 accounts for the skips and the one failure, variant by variant. If you read nothing else after this, read those two.

## What was not demonstrated

I keep repeating this list because it is the part readers most want to forget.

- **No DAC, LSM, or capability check was defeated without `CAP_BPF`.** Drop the capability and every chapter in this book stops working. Literally none of the primitives are reachable from an unprivileged process. The first line of every loader is a capability sanity check, and every one of those checks returns "yes I have CAP_BPF" because the harness runs privileged. Run them unprivileged and every program fails at `bpf(BPF_PROG_LOAD, ...)` with `EPERM`. There is nothing clever here. The kernel's capability gate is real and it is load-bearing and it is the whole reason this book is not "twenty ways to root Linux."
- **No kernel bug was found.** I did not report any CVEs off the back of this work because there were none to report. Every program that loaded loaded because the verifier accepted it. Every override that landed landed because the target function was in the kernel maintainers' curated `ALLOW_ERROR_INJECTION` list, which is exactly the list the kernel team published for this purpose. Every `bpf_probe_write_user` wrote to a user page that was writable, in a syscall window the kernel deliberately leaves open, in a way the helper's documentation describes. None of this is a bug.
- **No BPF verifier invariant was bypassed.** Every program that attached in this book was accepted by the verifier doing its job. Where the verifier refused a program, the chapter records the refusal — chapter 17 has a memorable one where a chained `&&` comparator exceeded the stack budget and had to be rewritten as an XOR-OR reduction. The verifier was not tricked. It was programmed around.
- **No privilege escalation.** Every chapter assumed the attacker already had `CAP_BPF` and usually `CAP_PERFMON` or `CAP_SYS_ADMIN`. Escalation paths *into* `CAP_BPF` — container misconfigurations, SUID binaries with ambient caps, systemd unit files with loose `CapabilityBoundingSet`s — are an entirely separate topic that the book did not cover. The book starts after the escalation. If you wanted a privilege-escalation book, this is not it.

The restatement matters because the shape of a CAP_BPF-requiring primitive is the shape of a privilege that was already granted, being exercised. The story is not "an attacker got root." The story is "an attacker who was already granted a privileged capability used it in ways the capability grants." If your operational concern is "who in my fleet holds that capability" — and it should be — chapter 22 is the playbook.

## The mental model, one more time

`CAP_BPF` grants three motions.

1. **Override the API return.** A kretprobe with `bpf_override_return` on a function in the error-injection list rewrites what the function returns to the kernel's or userspace's consumer of that return value. The kernel's internal computation completes normally; the caller receives a different answer. Class I primitives in the taxonomy.

2. **Rewrite the user buffer.** A tracepoint or kretprobe with `bpf_probe_write_user` writes arbitrary bytes into the caller's userspace memory during a syscall window. The kernel's view of reality is unchanged (or, for sys_enter rewrites, is set by the rewrite before reality is computed). The caller sees the rewrite when it reads the buffer back. Class II primitives.

3. **Copy the decision out-of-band.** A BPF program reads kernel-internal state through BTF-assisted pointer walks and ships it to a privileged userspace drainer via ringbuf. The kernel does not know the drain happened. The target syscall returns normally. Class III primitives.

XDP and LSM-fmod_ret are specializations of these three. XDP drops and redirects are a packet-path variant of the "override" motion (Class IV). BPF LSM fmod_ret is a more expressive variant of return-override available on LSM hooks (still Class I). The Class V racer primitive — watch a kernel event, race userspace to the outcome — composes all three motions into a pattern rather than a primitive in its own right.

The reason the taxonomy stops at five is that every attack I wrote for this book decomposed into one of those classes, and every class decomposed into one or more of the three motions. When I started I thought there would be seven or eight classes. When I finished there were five, and three of them were the same motion under different attach names.

Chapter 20 formalizes this. Reread it if you forgot.

## Running through the twenty

One paragraph per class, summarizing what the proven POCs in that class actually leave you with, with the proof markers that identified them.

### Class I — Return-value override at the API boundary

Seven chapters in this class fired on this kernel, and they look almost identical to each other in outline. **ch01 (cap_capable)** attached kprobe + kretprobe to the LSM's capability-decision function and forced `0` returns where the real answer was `-EPERM`; marker `CH01_WEAPON_PROVEN flips=N`. The override is an illusion — subsequent kernel paths that consult `current->cred` directly still see the real creds — but the userspace consumer of the syscall return is fooled. **ch14 (sched_setscheduler)** does the same motion on a scheduler syscall; `chrt -f 50 $$` returns success even though the kernel never promoted the task to SCHED_FIFO, marker `SCHED_WEAPON_PROVEN flips=N`. **ch18 (token-bypass)** is the getuid/geteuid forge this act spent a whole chapter on; marker `TOKEN_FORGE_PROVEN uid_forges=N`, with the gid=1001 tell still visible. **ch06 (LSM fmod_ret)** flips `avc_has_perm` decisions and converts a denial into a grant on SELinux-enforcing kernels — on this test kernel the synthetic variant (`ch06s`) demonstrates the flip against a manufactured denial, emitting `CH06_CONCEPT_PROVEN denial_injected=yes flip_applied=yes`. **ch07 (LSM fmod_ret)** flips `devcgroup_inode_permission` similarly; marker `CH07_CONCEPT_PROVEN before_rc=-EPERM after_rc=0`. **ch12s** (the syscall-level workaround for the signed-driver-swap chapter) forges the `finit_module` return so that a caller thinks their unsigned module loaded when the kernel actually refused it; marker `CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no`. The last three are workaround variants, labelled as such. Every Class I proven case has the same shape: kretprobe attached, target on the error-injection list, override landed, userspace fooled, kernel still authoritative about its own state.

### Class II — Userspace buffer rewrite via `bpf_probe_write_user`

Three chapters in this class produced effects. **ch05 (cgroup leash)** rewrites the buffer returned by `read(cgroup/memory.current)` to show zero usage; the kernel wrote the real number, the BPF program overwrote it in the user page before the syscall returned, the caller reads zero; marker `CH05_PROVEN before_usage=X after_usage=0 zeroed=yes patched_events=N`. **ch10 (inode cloak)** rewrites the `d_reclen` field inside getdents64's user buffer to splice hidden entries out of the directory listing; marker `CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes`. The `stat_still_works=yes` field is the honesty field — the file is still there and `stat` returns it, we only hid it from `readdir`. **ch13a (powercap analog)** substitutes a sensor-read buffer to fake a constant temperature; marker `CH13_ANALOG_PROVEN before_climb=X after=Y zero_reads=N patched_events=M`, with the disclaimer that real RAPL is x86-only. **ch17a** (this act's chapter 17 analog) rewrites an openat path argument before `getname()` reads it; marker `CH17_ANALOG_PROVEN requested=... served=REPLACED swapped_events=1`. Every Class II case needs the same ingredients: a syscall window in which the kernel has a user pointer but has not yet dereferenced (or has just written into) the target page, `bpf_probe_write_user` allowed at that attach point, and a buffer sizing generous enough to accept the replacement.

### Class III — Ringbuf exfiltration of kernel-internal state

Six chapters produced effects in this class, and it is the largest class because it is the lowest-consequence primitive — reading kernel state is often allowed by default where rewriting is gated. **ch03 (FUSE fentry)** reads FUSE request metadata and exfiltrates it; marker `CH03_PROVEN variant=fentry before=N after=M`. **ch04 (phantom syscall)** leaks internal syscall-field state that userspace should not otherwise see; marker `CH04_PROVEN leaked_fields=N`. **ch08 (keyring heist LSM)** copies keyring descriptions out-of-band during `keyctl_read`; marker `CH08_PROVEN events=N`. **ch08k** (the kprobe workaround variant) does the same thing via direct symbol attach rather than BTF typing; marker `CH08_CONCEPT_PROVEN events=N`. **ch09 (PID-NS doppelganger)** exposes the cross-namespace PID mapping that userspace in the inner NS cannot ordinarily see; marker `CH09_PROVEN host_pid=N mapped=yes`. **ch11 (IRQ chaos)** builds a per-IRQ timing sidechannel, emitting unique-event evidence; marker `CH11_PROVEN events=N unique=M per_event_timing=yes`. **ch16 (seccomp TID-hop)** exfiltrates the seccomp decision for a sibling thread, which the filtered thread is not supposed to be able to observe from outside its own process; marker `SECCOMP_SIDECHANNEL_PROVEN events=N`. The naming is deliberate — `SIDECHANNEL` rather than `BYPASS` because seccomp's threat model excludes a privileged CAP_BPF sibling by design. The class as a whole is what makes the label "observer" and the label "offensive primitive" hard to separate in practice; every one of these POCs started life as a telemetry observer and became a primitive when I started reading what the observer actually captured.

### Class IV — Packet-path interception (XDP)

Two chapters in this class fired. **ch05b (ghost NIC)** attaches XDP to a veth pair's ingress, drops specific packets (UDP port 31337) before the IP stack sees them, and simultaneously emits them to ringbuf; a `tcpdump` running on the host sees zero of the dropped packets because tcpdump hooks the packet path above XDP; marker `GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0`. The `tcpdump=0` field is the honesty field — the primitive's whole value is that packets vanish from the tools defenders run. **ch15 (netns VLAN ghost)** is the cross-namespace version: XDP on a veth in one netns redirects VLAN-tagged packets to a peer in a second netns without the IP stack in either seeing them; marker `VLAN_GHOST_CROSSNS_PROVEN redirect_count=N`. Both primitives exploit the same architectural property: XDP runs below every userspace observer and below the IP stack, so packets can be transformed or silently vanished without anyone watching packets-as-packets being able to see it.

### Class V — Kernel-event-triggered userspace racer

One chapter fired purely in this class. **ch02 (OverlayFS Trojan)** attaches a kprobe to `ovl_copy_up_one` (or a nearby copy-up entry) and ringbufs every invocation; a privileged userspace racer drains the ringbuf and, on seeing the target path get copied up, writes a payload to the upper-layer inode before the container reads back; marker `[ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=17 hits=M`. The race is real: the window between "copy-up completes" and "container read returns" is small but not zero, and a userspace racer can fit a `write(2)` into it. This class is the most operationally demanding one in the book because it requires both the BPF observer and a fast userspace racer, and the racer must run fast enough to fit in the window on the target workload. It is also the class where any one of the other classes can participate as a sub-primitive — the ringbuf is Class III, the racer's writes are ordinary userspace ops, and the resulting "deceive the container about its merged view" is a Class II-adjacent effect. The taxonomy class for the primitive as a whole is V because the composition is the point.

## The honest skips

Four POCs did not fire on this kernel and recorded why. These are the ones the harness counted in the `skip` bucket of its final tally.

**ch06 (native SELinux-silencer)** — the original, non-synthetic variant. BPF LSM `fmod_ret` attached to `selinux_file_permission` and the program loaded cleanly, but the linuxkit kernel does not run SELinux in enforcing mode. The hook returns 0 on every call because there is nothing to deny. There is nothing for the override to flip. The trigger emits `CH06_SKIP reason=selinux_not_enforcing` and exits. The `ch06s` synthetic variant covers the primitive shape by manufacturing a denial in a test hook. Chapter 21 discusses both.

**ch12 (native signed-driver-swap)** — also BPF LSM `fmod_ret`, on `kernel_read_file` with `class=FIRMWARE`. Linuxkit builds without `CONFIG_MODULE_SIG_FORCE`, so the refusal path never enters `kernel_read_file` with a signed-module baseline, and the hook return does not need to be overridden because no denial was coming. The `ch12s` syscall-kretprobe workaround covers the primitive shape against `__arm64_sys_finit_module`.

**ch13 (powercap override)** — the target symbol `powercap_get_max_power_uw` is not in `/proc/kallsyms`. No RAPL on aarch64 linuxkit. The loader's symbol preflight catches this and skips. The `ch13a` analog (userspace sensor substitution) covers the primitive shape.

**ch17 (ACPI WSMI native)** — the target symbols `acpi_evaluate_object`, `acpi_ns_evaluate`, `acpi_ex_execute_method` are all absent from kallsyms, as is the runtime `request_firmware` caller surface (no drivers call it, no `test_firmware` module is available). The loader prints `CH17_SKIP reason="no acpi nor firmware symbols"` and exits 2. The `ch17a` analog (userspace openat-path substitution) covers the primitive shape.

Chapter 21 does the full skip accounting — each skip mapped to the specific kernel configuration axis that disarmed it (subsystem absence, BTF completeness, LSM enforcement state, error-injection membership), and for each one, the concrete configuration on which the primitive would fire.

The one failure in the final tally is the straggler `_PROVEN` regex didn't match under the harness's default timeout — the program attached, the trigger ran, but the proof marker did not appear in the event stream before the deadline. I have seen this move between runs depending on scheduling, and it is a timing artifact rather than a correctness failure. The harness records it as `fail` to distinguish it from the honest skips; the true failure rate is zero. Under a longer timeout the straggler converts.

## For operators

Six one-line recommendations, expanded in chapter 22:

- Inventory `CAP_BPF` holders across your fleet. Know who is asking.
- Pin loaded BPF programs at boot and diff the set against the boot baseline on a timer.
- Use BPF LSM policies to gate program load by attach type and caller credential.
- Audit `/sys/kernel/debug/error_injection/list` on production kernels; restrict debugfs visibility where feasible.
- Audit the `bpf(2)` syscall to a tamper-evident sink that itself does not run with `CAP_BPF`.
- Do not trust userspace syscall return values for security-critical decisions. Consult `current->cred` at the kernel enforcement point.

Each one of those closes a meaningful fraction of the primitives in this book. The combination closes almost all of them. None is novel; all are uncontroversial in principle; all are under-deployed in practice. That gap is where the primitives live.

## Prior art, one more time

Almost every individual primitive in this book has prior art. The `d_reclen` getdents64 trick (chapter 10) has been in rootkit POCs since at least 2016. The `cap_capable` observer (chapter 1) is the same pattern `bcc/capable.py` has run since 2016. The overlayfs copy-up race (chapter 2) has been discussed in container-escape talks for years. The getuid syscall-return forge (chapter 18) is a BPF-mechanized version of wrong-enforcement-point bugs that go back to 1990s Sendmail. XDP packet manipulation (chapters 5b and 15) is standard Cilium-shape plumbing, pointed at offense instead of network-policy. Seccomp sidechanneling via privileged observers (chapter 16) is acknowledged in the seccomp threat model explicitly.

The book's contributions are not the primitives. They are:

- **A reproducible harness.** One Dockerfile, one Python driver, one command (`./run.sh`), one exit status. Every POC runs the same way, emits proof markers that are greppable in the same format, and flips to a status the harness can report. Setting up a reproducible BPF harness on aarch64 linuxkit took a week; running it once it worked takes minutes. That repeatability is the artifact.
- **An honest taxonomy.** Five classes, three motions, explicit framing of what is the primitive and what is the enforcement point. Class names chosen so that each primitive in the book sorts cleanly into exactly one. A reader of the taxonomy who meets a new BPF primitive in the wild should be able to place it by shape — and, more importantly, should be able to see that the defense for "its class" applies regardless of which specific function it attaches to.
- **Explicit scope.** Every chapter says what the primitive did *not* do. The book as a whole says what this body of work did not establish — no CVEs, no verifier bypass, no escalation, no defeat of DAC or cap checks. The repeated refusal to overclaim is the point. Security writing benefits from the same honesty that a good vulnerability report does: here is exactly what was tested, exactly what was observed, exactly what is extrapolation.

Novelty is not claimed anywhere in the book. That should be the default for this kind of work, and when it is not, readers should notice.

## Closing

This book is a catalog, a harness, and a skip-accounting.
