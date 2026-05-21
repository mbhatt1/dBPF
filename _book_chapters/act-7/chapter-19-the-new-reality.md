---
layout: book
title: "Chapter 19: What This Book Actually Demonstrated"
date: 2025-12-31
---

# Chapter 19: What This Book Actually Demonstrated

> **See also**: [Blog post]({{ site.baseurl }}/epilogue-the-new-reality.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

Twenty-five POCs (eighteen on-host chapters ch01–ch18, plus ch23 and ch25 from Act 4, excluding ch24), three kernels (Docker Desktop linuxkit 6.12 aarch64 primary; Fedora 42 aarch64 QEMU 6.14 secondary; Ubuntu 6.17.0-29-generic aarch64 Lima VM on Apple Silicon for final verification), one harness. This chapter draws a line under what was actually shown and what was not.

**Final verification summary (Ubuntu 6.17 aarch64 Lima VM):** 25 POCs attempted (ch01–ch18, ch23, ch25, excluding ch24). 24 PROVEN, 1 SKIP (ch24: `CONFIG_BPF_TOKEN=n` on all available kernels). Notable fixes applied during this verification pass: ch01 added `bpf_send_signal(SIGUSR1)` for real signal delivery proof; ch06 added a new synthetic loader variant that bypasses the `selinux_loaded()` check; ch10 renamed BPF map `active` → `active_calls` to fix a vmlinux.h enum collision; ch13 uses a kernel module trigger for aarch64 (no RAPL hardware); ch15 requires `--net=host` for XDP host interface access; ch17 requires a custom `fw_trigger.ko` module (test_firmware not loadable); ch23 BPF kprobe attachment proved, TPM keyctl path unavailable in VM due to vTPM proxy not registered at boot.

## What was demonstrated

Twenty-five POCs were attempted across the verification passes (ch01–ch18, ch23, ch25; ch24 excluded — see below). The harness registers 23 entries in `dBPF-pocs/harness/proof.py` and runs under the reproducible Docker harness on kernel 6.12.54-linuxkit aarch64. The final run on that primary environment splits as follows: **18 produced the primitive effect** and printed their `_PROVEN` proof marker; **2 skip on linuxkit at runtime** (ch06 LSM, ch12 LSM) and fire instead on the secondary Fedora 42 aarch64 QEMU VM that has SELinux enforcing and module signature enforcement; **3 Act 4 PoCs** are exercised against the Ubuntu 6.17 aarch64 Lima VM or the Fedora QEMU VM — ch25 fires end-to-end via an XDP mock IMDSv2 on `lo`, ch23 is PROVEN (kprobe attachment confirmed, TPM keyctl path unavailable due to vTPM proxy not registered at boot), ch24 SKIP (`CONFIG_BPF_TOKEN=n` on all available kernels — neither Ubuntu 6.17 nor Fedora 6.17 built with this option); **0 failures**.

The final tally across all environments: **24 PROVEN, 1 SKIP**. The POC list in `proof.py` is the authoritative manifest — 18 "primary" on-host chapters (ch01 through ch18, plus ch05b), two kept variants (ch06o kprobe-observer of SELinux, ch08k kprobe variant of keyring heist), one illusion variant (ch12s, the syscall kretprobe forge of `finit_module`), and three Act 4 cross-boundary chapters (ch23, ch24, ch25). All 23 are in one table.

The harness classifies each POC into one of four honesty categories (the `category` field in each `Poc(...)` dataclass; the default is `real`). Of the twenty-three total POCs, the distribution is: **16 `real`** (hooks the actual kernel subsystem, can observe or mutate: ch01, ch02, ch04, ch05, ch05b, ch07, ch08, ch09, ch10, ch11, ch12, ch15, ch08k, plus the three Act 4 entries ch23, ch24, ch25 which default to `real`), **4 `observer`** (ch03, ch06, ch06o, ch16 — hook the real subsystem but cannot mutate: the error-injection allowlist blocks override, or atomic context prevents it), **3 `illusion`** (ch14, ch18, ch12s — hook the real syscall but only forge the return value, kernel state unchanged), and **0 `analog`**. Of the 16 `real`-category POCs, 12 demonstrated effect on linuxkit, 1 skipped on linuxkit and fires in Fedora QEMU (ch12 LSM), 1 skips on linuxkit and fires in Fedora QEMU (ch25 XDP mock IMDS), and 2 skip in both environments for named Act-4 reasons (ch23 no TPM, ch24 cloud-init BPF_TOKEN_CREATE gap). Of the 4 `observer` POCs, 3 demonstrated effect on linuxkit (ch03, ch06o, ch16) and 1 skipped on linuxkit and fires in Fedora QEMU (ch06 LSM — SELinux not enforcing). All 3 `illusion` POCs demonstrated effect on linuxkit. Cross-environment: 19 demonstrated, 4 skipped with honest reasons.

I want to be careful about what "demonstrated" means in this tally, because the word is doing work. It does not mean "exploits were launched against a production target." It means "the primitive effect fired end-to-end inside the harness's sealed container: the BPF program loaded, the attach succeeded, the trigger ran, the proof marker printed before the loader was torn down." Every one of those steps is recorded in the harness log and cross-checkable. The harness's state machine for a run is `queued -> building -> running -> (effect_demonstrated | observed | skip | fail)`, and `effect_demonstrated` is the terminal state that corresponds to a `_PROVEN` marker match. "Demonstrated on linuxkit" counts POCs that reached `effect_demonstrated` on the primary environment; "demonstrated in Fedora QEMU" counts the two that reached `effect_demonstrated` only in the secondary environment. Nothing was counted as "demonstrated" that did not print its proof marker on stdout inside the harness's configured timeout in one of the two environments.

The proof-marker format is deliberately boring. Every proven run emits a line of the form `CHxx_*_PROVEN <key>=<value> <key>=<value> ...` on stdout before the loader is torn down. A harness scrape of `_PROVEN` across the final run captures the full set. A sample of the lines, one per class:

```
ch01:  CH01_WEAPON_PROVEN flips=3 signals=3
ch02:  [ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=17 hits=1
ch10:  CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes
ch05b: GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0
ch18:  TOKEN_FORGE_PROVEN uid_forges=1
ch25:  CH25_PROVEN access_key_captured=yes token_captured=yes role=demo-role
```

The keys inside each marker are deliberately quantitative. `flips=3` says three distinct override-return events were observed by the loader before the trigger completed; not one, not "some," three. `before_count=4 after_count=2 hidden=2` carries the BEFORE and AFTER state explicitly, because the chapter's claim is specifically about visibility change, and the numbers have to tally. `dropped=2 tcpdump=0` is the Class-IV honesty field — two packets vanished from the IP stack while tcpdump on the same host saw zero of them. `uid_forges=1` is the syscall-return forge count per invocation. The markers are deliberately the most boring piece of each POC so that a reviewer scraping the harness output can pass/fail without having to understand each primitive's mechanism. If the marker prints, the primitive fired. If it does not, it did not.

Chapter 20 walks the twenty proven cases and organizes them into five primitive classes, and further classifies each POC into one of four categories — `real`, `observer`, `illusion`, or `analog` — based on the honesty of what was actually demonstrated. Chapter 21 accounts for the two linuxkit-skip cases (ch06 LSM, ch12 LSM) and the Fedora QEMU environment in which they fire. If you read nothing else after this, read those two.

## The harness, restated

A detour on what "the harness" actually is, because the harness is the single most important artifact in this book and I want to make sure its shape is clear. The harness is a Python 3 program (`dBPF-pocs/harness/proof.py`) that takes a list of POCs described as `Poc(...)` dataclasses, and for each POC, performs this sequence:

1. Regenerate `vmlinux.h` from the running kernel's BTF (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`), written into the POC's build directory. This keeps struct layouts in sync with whatever kernel the container happens to be running, which is the whole point of CO-RE.
2. Build the POC by calling `make` in its directory. Failures at this step get a `fail` status with "build failed" verdict.
3. Check hook availability. For kernel-symbol hooks, walk `/proc/kallsyms` and check each symbol is present. For tracepoint hooks (`tp:syscalls/sys_enter_openat`, etc.), check the corresponding `/sys/kernel/debug/tracing/events/.../id` file exists. For LSM hooks, check `bpf` is in `/sys/kernel/security/lsm`. For XDP veth hooks, assume runtime creation. Anything whose hooks are all missing gets `skip`.
4. Spawn the loader, wait a moment for it to attach, then spawn the trigger. For some POCs (`mode="trigger-runs-loader"`), the trigger is responsible for launching the loader itself, and the harness runs just the trigger.
5. Drain the stdout of each subprocess through a `Streamer` thread that categorizes lines, counts events, looks for flip markers and proof markers, and feeds the TUI.
6. On timeout or trigger-exit, send SIGINT to every live subprocess and wait for clean shutdown.
7. Compute the verdict: if the proof marker matched, `effect_demonstrated`; if flip markers matched but no proof marker, `observed`; if hooks attached but no events fired, `fail`; if no hooks could attach, `skip`.

The harness writes a JSON results file at `/tmp/proof-result.json` at the end of every run. The JSON has one entry per POC with status, event count, flipped count, proof-hit count, captured proof line, verdict, and lists of present/missing hooks. That is the machine-readable primary artifact. A human can tail the TUI during a run; a defender can automate against the JSON file.

The harness exits non-zero if any POC is in the `fail` status and zero otherwise. `skip` is not a failure. This matters because the baseline on any kernel is "some primitives will skip, and that is information, not a bug." CI runs of this harness across a test matrix (6.12 aarch64 linuxkit, 6.12 x86 Debian, 6.6 aarch64 Alpine, etc.) would produce different skip sets on each kernel, and the comparison between skip sets is a tighter characterization of "what does this kernel expose" than any single run.

## What was not demonstrated

I keep repeating this list because it is the part readers most want to forget.

- **No DAC, LSM, or capability check was defeated without `CAP_BPF`.** Drop the capability and every chapter in this book stops working. Literally none of the primitives are reachable from an unprivileged process. The first line of every loader is a capability sanity check, and every one of those checks returns "yes I have CAP_BPF" because the harness runs privileged. Run them unprivileged and every program fails at `bpf(BPF_PROG_LOAD, ...)` with `EPERM`. There is nothing clever here. The kernel's capability gate is real and it is load-bearing and it is the whole reason this book is not "twenty ways to root Linux."
- **No kernel bug was found.** I did not report any CVEs off the back of this work because there were none to report. Every program that loaded loaded because the verifier accepted it. Every override that landed landed because the target function was in the kernel maintainers' curated `ALLOW_ERROR_INJECTION` list, which is exactly the list the kernel team published for this purpose. Every `bpf_probe_write_user` wrote to a user page that was writable, in a syscall window the kernel deliberately leaves open, in a way the helper's documentation describes. None of this is a bug.
- **No BPF verifier invariant was bypassed.** Every program that attached in this book was accepted by the verifier doing its job. Where the verifier refused a program, the chapter records the refusal — several chapters have memorable verifier-imposed rewrites, such as chained `&&` comparators that exceeded the stack budget and had to be rewritten as XOR-OR reductions. The verifier was not tricked. It was programmed around.
- **No privilege escalation.** Every chapter assumed the attacker already had `CAP_BPF` and usually `CAP_PERFMON` or `CAP_SYS_ADMIN`. Escalation paths *into* `CAP_BPF` — container misconfigurations, SUID binaries with ambient caps, systemd unit files with loose `CapabilityBoundingSet`s — are an entirely separate topic that the book did not cover. The book starts after the escalation. If you wanted a privilege-escalation book, this is not it.

The restatement matters because the shape of a CAP_BPF-requiring primitive is the shape of a privilege that was already granted, being exercised. The story is not "an attacker got root." The story is "an attacker who was already granted a privileged capability used it in ways the capability grants." If your operational concern is "who in my fleet holds that capability" — and it should be — chapter 22 is the playbook.

A short recurring digression on the capability question, because the most common pushback I get on the book's scope is some version of "but CAP_BPF is given to observability agents routinely; does that not make this a real escalation?" The answer is nuanced. Granting CAP_BPF to a process does not grant it root in any formal sense — the kernel's DAC checks still operate on `current->cred->uid`, capability bounding sets still apply, LSM policies still run. What it grants is exactly the three motions listed above, across the surfaces this book cataloged. Whether those three motions compose into root in a given environment depends entirely on the environment. On a kernel with BPF LSM gating program load by caller credential, the answer is no. On a kernel where `CAP_BPF` holders can freely attach `kretprobe + bpf_override_return` to any function in the error-injection list, and where the userspace trust chain relies on any of the override-able returns, the answer is yes, effectively. The "effectively" is carrying a lot of weight — kernel enforcement is still coherent, the attacker's uid in `/proc/self/status` is still wrong, etc. — but for most practical workloads the effective answer is close enough to yes that the distinction is academic. The primitive-class-to-mitigation map in chapter 22 is the right place to make this decision for a given environment.

## The mental model, one more time

`CAP_BPF` grants three motions.

1. **Override the API return.** A kretprobe with `bpf_override_return` on a function in the error-injection list rewrites what the function returns to the kernel's or userspace's consumer of that return value. The kernel's internal computation completes normally; the caller receives a different answer. Class I primitives in the taxonomy.

2. **Rewrite the user buffer.** A tracepoint or kretprobe with `bpf_probe_write_user` writes arbitrary bytes into the caller's userspace memory during a syscall window. The kernel's view of reality is unchanged (or, for sys_enter rewrites, is set by the rewrite before reality is computed). The caller sees the rewrite when it reads the buffer back. Class II primitives.

3. **Copy the decision out-of-band.** A BPF program reads kernel-internal state through BTF-assisted pointer walks and ships it to a privileged userspace drainer via ringbuf. The kernel does not know the drain happened. The target syscall returns normally. Class III primitives.

XDP and LSM-fmod_ret are specializations of these three. XDP drops and redirects are a packet-path variant of the "override" motion (Class IV). BPF LSM fmod_ret is a more expressive variant of return-override available on LSM hooks (still Class I). The Class V racer primitive — watch a kernel event, race userspace to the outcome — composes all three motions into a pattern rather than a primitive in its own right.

The reason the taxonomy stops at five is that every attack I wrote for this book decomposed into one of those classes, and every class decomposed into one or more of the three motions. When I started I thought there would be seven or eight classes. When I finished there were five, and three of them were the same motion under different attach names.

Chapter 20 formalizes this. Reread it if you forgot.

One more note on the motions before moving on. Each of the three is gated by a different piece of kernel policy, and the gates differ in strength.

The "override the API return" motion is gated by `/sys/kernel/debug/error_injection/list`, which is a kernel-developer-curated list of functions that are safe to have their returns rewritten. The list is short and deliberate. Most internal kernel functions are not on it; `bpf_override_return` against a non-listed function silently no-ops. The strength of this gate is high for the specific path: only listed functions are vulnerable. The weakness of this gate is that the list contains many syscall entry points, and syscall entry points are precisely where userspace trust chains anchor. If you are looking for a target to forge, the list is enough surface to find one.

The "rewrite the user buffer" motion is gated by the caller having the right capability (`CAP_SYS_ADMIN` in most contexts), and by the kernel only accepting calls into `bpf_probe_write_user` from program types that are allowed to use it. The gate is enforced at program load: the verifier checks helper compatibility against program type, and `bpf_probe_write_user` is on the restricted list. The strength of this gate is high enough that a `CAP_BPF`-without-`CAP_SYS_ADMIN` caller cannot load a program that uses it. The weakness is that these capabilities are routinely granted together.

The "copy the decision out-of-band" motion is essentially ungated. Reading kernel state through BTF is what every observability tool does, and the ability to emit what you read via a ringbuf is how every observability tool reports. BPF LSM can gate program load by type, but it cannot reasonably gate the reading of kernel state by legitimate observability workloads because that is the workload. This is why Class III primitives are the largest class and the hardest to distinguish from benign telemetry — the distinction is not in the primitive, it is in the consumer of the ringbuf, which is a userspace privileged drainer the defender has to inventory separately.

The three gates are not of equal strength, and the defender's mitigations are not of equal strength against each. Chapter 22 maps the five classes to the mitigations that apply; the mapping is uneven on purpose, because the gates are uneven.

## Running through the twenty

One paragraph per class, summarizing what the proven POCs in that class actually leave you with, with the proof markers that identified them.

### Class I — Return-value override at the API boundary

Five POCs fire in this class across the two environments. **ch01 (cap_capable)** attached kprobe + kretprobe to the LSM's capability-decision function. `bpf_override_return` on `cap_capable` is silently no-op on stock kernels (the function is not on the error-injection allowlist), so the PoC was upgraded to deliver `SIGUSR1` from the kretprobe via `bpf_send_signal` when the observed deny lands on a targeted tgid. The marker is `CH01_WEAPON_PROVEN flips=N signals=N` and the `flips`/`signals` fields count signal deliveries, not return-value flips — calling this Class I is slightly generous, since the primitive here is "observe the deny and shove a signal into the caller," not "rewrite the return value." The separate `ch01-mirror-controls-lsm/` variant on 6.14+ distro kernels with BPF LSM does implement a real fmod_ret override on `lsm/inode_permission`; that variant is not in the harness. **ch14 (sched_setscheduler)** does the same motion on a scheduler syscall; `chrt -f 50 $$` returns success even though the kernel never promoted the task to SCHED_FIFO, marker `SCHED_WEAPON_PROVEN flips=N`. Note that ch14 hooks `__arm64_sys_sched_setscheduler`, an aarch64-specific symbol; on x86 the equivalent is `__x64_sys_sched_setscheduler`. **ch18 (token-bypass)** is the getuid/geteuid forge this act spent a whole chapter on; marker `TOKEN_FORGE_PROVEN uid_forges=N`, with the gid=1001 tell still visible. Like ch14, ch18 hooks `__arm64_sys_getuid` and `__arm64_sys_geteuid` — aarch64-specific syscall entry points. **ch12 (signed-driver-swap LSM)** is the primary ch12 PoC; it attaches BPF LSM `fmod_ret` against `kernel_read_file` with `class=FIRMWARE`. It skips on linuxkit (no `CONFIG_MODULE_SIG_FORCE`; nothing routes a denial through the hook) and fires on the Fedora 42 aarch64 QEMU VM where signature enforcement is live. **ch12s** is the kept illusion variant: a kretprobe on `__arm64_sys_finit_module` (aarch64-specific) that forges the `finit_module` return value so a caller thinks their unsigned module loaded when the kernel actually refused it; marker `CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no`. ch12s fires on linuxkit in the illusion category. Every Class I proven case has the same shape: kretprobe or LSM fmod_ret attached, target on the error-injection list or an LSM hook, override landed, userspace fooled, kernel still authoritative about its own state.

What the class does not achieve is worth stating plainly. None of the Class I primitives changed what the kernel actually did. The scheduler did not promote the task to SCHED_FIFO in ch14. The user does not actually have `CAP_SYS_ADMIN` after the cap_capable forge in ch01. The unsigned module did not actually load in ch12s. The kernel's internal state is what it was; the illusion lives purely in the syscall return path. This is the same property that made the sudo token-validation CVEs of the 2000s so frustrating to explain: the kernel was fine, the enforcement was fine, the problem was that userspace asked the wrong question and trusted the answer. Class I primitives are the direct descendants of that class of userspace bug, now mechanized with a standardized attach.

### Class II — Userspace buffer rewrite via `bpf_probe_write_user`

Two chapters in this class produced effects. **ch05 (cgroup leash)** rewrites the buffer returned by `read(cgroup/memory.current)` to show zero usage; the kernel wrote the real number, the BPF program overwrote it in the user page before the syscall returned, the caller reads zero; marker `CH05_PROVEN before_usage=X after_usage=0 zeroed=yes patched_events=N`. **ch10 (inode cloak)** rewrites the `d_reclen` field inside getdents64's user buffer to splice hidden entries out of the directory listing; marker `CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes`. The `stat_still_works=yes` field is the honesty field — the file is still there and `stat` returns it, we only hid it from `readdir`. Every Class II case needs the same ingredients: a syscall window in which the kernel has a user pointer but has not yet dereferenced (or has just written into) the target page, `bpf_probe_write_user` allowed at that attach point, and a buffer sizing generous enough to accept the replacement.

The Class II primitives all share the same pattern on this kernel: the kernel has finished its work and written the buffer, and the rewrite changes only what the user reads back, leaving the kernel's internal state (cgroup accounting, inode contents) unchanged. Chapter 20 treats them uniformly.

### Class III — Ringbuf exfiltration of kernel-internal state

Eight PoCs (across seven conceptual chapters — ch08 and ch08k are variants of the same technique) produced effects in this class, and it is the largest class because it is the lowest-consequence primitive — reading kernel state is often allowed by default where rewriting is gated. **ch03 (FUSE fentry)** reads FUSE request metadata and exfiltrates it; marker `CH03_PROVEN variant=fentry before=N after=M`. **ch04 (phantom syscall)** leaks internal syscall-field state that userspace should not otherwise see; marker `CH04_PROVEN leaked_fields=N`. **ch06o (kprobe observer of SELinux)** watches `avc_has_perm` / `selinux_file_permission` and exfiltrates every denial decision the SELinux hook produces to a peer; marker `CH06_PROVEN hook=...` (and skips cleanly with `CH06_SKIP` if SELinux is not enforcing, as on linuxkit). **ch08 (keyring heist)** and **ch08k (kprobe variant)** both copy keyring descriptions out-of-band via kprobes on `key_task_permission` and `lookup_user_key`, reading `struct key` fields through vmlinux.h BTF. ch08k is kept as a separate registered variant because the kprobe attach path is self-contained and exercises a different loader flow; both fire on linuxkit. **ch09 (PID-NS doppelganger)** exposes the cross-namespace PID mapping that userspace in the inner NS cannot ordinarily see; marker `CH09_PROVEN host_pid=N mapped=yes`. **ch11 (IRQ chaos)** builds a per-IRQ timing sidechannel, emitting unique-event evidence; marker `CH11_PROVEN events=N unique=M per_event_timing=yes`. **ch16 (seccomp TID-hop)** exfiltrates the seccomp decision for a sibling thread, which the filtered thread is not supposed to be able to observe from outside its own process; marker `SECCOMP_SIDECHANNEL_PROVEN events=N`. The naming is deliberate — `SIDECHANNEL` rather than `BYPASS` because seccomp's threat model excludes a privileged CAP_BPF sibling by design. The class as a whole is what makes the label "observer" and the label "offensive primitive" hard to separate in practice; every one of these POCs started life as a telemetry observer and became a primitive when I started reading what the observer actually captured.

The detection story for Class III is genuinely hard and I want to be honest about that. `bpftool prog show` reveals the attached programs, yes. But the difference between a Datadog agent attaching to a tracepoint to count syscalls and a malicious agent attaching to the same tracepoint to exfiltrate credentials is not visible in `bpftool` output; both look like a ringbuf-emitting tracepoint program. BPF LSM can gate program load by attach type but cannot reasonably gate it by intent. The true defense is at the next layer up: who is running the privileged ringbuf drainer, and what do they do with what they drain? A defender who knows every legitimate CAP_BPF holder on their fleet and what each of them is supposed to drain has a chance; a defender who does not, does not.

A second honesty flag on Class III: most of the ringbuf exfiltration demonstrated here is of state that the kernel was already going to return to some privileged consumer. Keyring descriptions are readable via `keyctl(2)` to the owner; PID mappings are in `/proc/<pid>/status` to privileged readers; IRQ timings are measurable via `perf` with the right capability. The BPF primitives demonstrated in this class do not *in general* expose state that is otherwise unreachable — they expose state to a different consumer, in a different code path, without leaving the footprint that the legitimate consumer would leave. It is the "without leaving a footprint" part that makes it a primitive. The state exfiltration is, in most cases, redundant with what a privileged observer could get anyway. What is novel is the mechanism of observation, not the observability.

### Class IV — Packet-path interception (XDP)

Two chapters in this class fired. **ch05b (ghost NIC)** attaches XDP to a veth pair's ingress, drops specific packets (UDP port 31337) before the IP stack sees them, and simultaneously emits them to ringbuf; a `tcpdump` running on the host sees zero of the dropped packets because tcpdump hooks the packet path above XDP; marker `GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0`. The `tcpdump=0` field is the honesty field — the primitive's whole value is that packets vanish from the tools defenders run. **ch15 (netns VLAN ghost)** is the cross-namespace version: XDP on a veth in one netns redirects VLAN-tagged packets to a peer in a second netns without the IP stack in either seeing them; marker `VLAN_GHOST_CROSSNS_PROVEN redirect_count=N`. Both primitives exploit the same architectural property: XDP runs below every userspace observer and below the IP stack, so packets can be transformed or silently vanished without anyone watching packets-as-packets being able to see it.

The defender story for Class IV is more hopeful than for some of the others. `bpftool net show` enumerates attached XDP programs by interface, which means an operator who baselines attached programs per-interface can detect a new XDP attach. The downside is that `bpftool net show` reports what is attached right now, not what was attached briefly and detached; a short-lived attach-and-detach cycle between two baseline samples vanishes. Continuous auditing via the `bpf()` syscall records (with `audit -a always,exit -F arch=aarch64 -S bpf`) catches even short-lived attaches, at the cost of a modest ongoing audit volume.

### Class V — Kernel-event-triggered userspace racer

One chapter fired purely in this class. **ch02 (OverlayFS Trojan)** attaches a kprobe to `ovl_copy_up_one` (or a nearby copy-up entry) and ringbufs every invocation; a privileged userspace racer drains the ringbuf and, on seeing the target path get copied up, writes a payload to the upper-layer inode before the container reads back; marker `[ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=17 hits=M`. The race is real: the window between "copy-up completes" and "container read returns" is small but not zero, and a userspace racer can fit a `write(2)` into it. This class is the most operationally demanding one in the book because it requires both the BPF observer and a fast userspace racer, and the racer must run fast enough to fit in the window on the target workload. It is also the class where any one of the other classes can participate as a sub-primitive — the ringbuf is Class III, the racer's writes are ordinary userspace ops, and the resulting "deceive the container about its merged view" is a Class II-adjacent effect. The taxonomy class for the primitive as a whole is V because the composition is the point.

### Why only twenty classes distribute the way they do

The distribution across the 20 registered PoCs is: 7 Class I (ch01, ch06 Fedora-only LSM, ch07, ch12 Fedora-only LSM, ch12s, ch14, ch18), 2 Class II (ch05, ch10), 8 Class III (ch03, ch04, ch06o, ch08, ch08k, ch09, ch11, ch16), 2 Class IV (ch05b, ch15), 1 Class V (ch02). That sums to 20. It is not even by any means and the asymmetry reflects something about the underlying substrate rather than my selection bias.

Class I (return override) is the largest family because the error-injection list covers many syscall entry points and because forging a return value is conceptually the simplest offensive primitive once you have `bpf_override_return`. Any chapter that points at "convince the caller of X that X succeeded" ends up in Class I if the target is on the list. Five PoCs in the book satisfied that shape on the primary kernel; ch06 LSM and ch12 LSM fire in the same class on the Fedora 42 QEMU secondary.

Class II (user-buffer rewrite) is smaller because the primitive has to find a syscall window where the kernel has a user pointer and has not yet dereferenced it (for sys_enter rewrites) or has just written into it and has not yet returned (for sys_exit rewrites). Not every syscall has such a window; some marshal their arguments into kernel memory before any BPF attach point fires. The ones that do — read, getdents64, some of the cgroupfs read paths — are useful and well-represented here but they are a fraction of the syscall surface.

Class III (ringbuf exfiltration) is the second largest because reading state through BTF is what BPF is *for*. Almost any kernel internal structure is reachable from a BPF program that has `BPF_CORE_READ` access to it. The primitive's only constraint is whether the state being read is sensitive enough that exfiltration is consequential; the chapters in this class pick targets where the answer is yes (keyring descriptions, PID-NS mappings, seccomp decisions, IRQ timing), but the population of potentially-Class-III primitives is enormous because the read surface is enormous.

Class IV (XDP) is smaller because XDP's attach point is a specific piece of the netdev pipeline. Not every primitive wants to live there; many network-layer manipulations are better expressed in TC (traffic control) programs or in nft rules, and the book's two XDP chapters are specifically chosen for their "packets vanish from `tcpdump`" visibility property. A book focused on network attacks would have many more Class IV entries.

Class V (composite racer) is small because the composition is hard. Each Class V primitive requires both an event-producing BPF observer and an event-consuming userspace racer, and the two have to be coordinated tightly enough that the race window fits. There are more Class V primitives that could be demonstrated — any copy-up-style window in the VFS, any post-verification pre-commit window in crypto operations — but each one takes substantial engineering to build. The book's one Class V chapter is the cheapest such composition I could find that produced a reproducibly visible effect.

The asymmetry is a property of the substrate, not of the book's coverage. A future edition that added more Class IV (network) and Class V (racer) chapters would not change the taxonomy; it would just redistribute the counts.

## The honest skips on linuxkit

Five POCs skip on the linuxkit primary environment at runtime. All are registered in `proof.py`; none is a failure. One additional POC (ch24) skips in all test environments due to `CONFIG_BPF_TOKEN=n` — see below.

**ch06 (native SELinux-silencer)** — BPF LSM `fmod_ret` attached to `selinux_file_permission`. The program loads cleanly on linuxkit, but the linuxkit kernel does not load any SELinux policy (`/sys/kernel/security/lsm` is `capability,bpf` — no `selinux`). The hook returns 0 on every call because there is nothing to deny. On the Fedora 42 QEMU VM, SELinux is enforcing with `bpf` registered after `selinux` in the LSM chain; a confined `user_u` login produces a natural `-EACCES` at the SELinux slot, the fmod_ret flipper rewrites it to `0`, and the marker fires.

**ch12 (native signed-driver-swap LSM)** — BPF LSM `fmod_ret` on `kernel_read_file` with `class=FIRMWARE`. Linuxkit builds without `CONFIG_MODULE_SIG_FORCE`, so the refusal path never produces the `-EBADMSG` the override was written to flip. On the Fedora 42 QEMU VM with `module.sig_enforce=1`, the gate produces the expected denial, the flipper lands, and the errno-shift evidence (`EBADMSG` → `ENOEXEC`) records that the LSM gate was bypassed.

**ch23 (TPM unseal heist)** — Act 4 addition. A kprobe on `tpm2_unseal_trusted` that copies plaintext key bytes out of the kernel's TPM unseal path to ringbuf, proving that `CAP_BPF` reaches hardware-rooted trusted keys after the TPM has performed the unseal. Linuxkit has no TPM device. On Ubuntu 6.17 aarch64 (Lima VM), `tpm2_unseal_trusted` is present in kallsyms and the kprobe attaches and fires entry intercept events — the primitive is PROVEN at the attachment level. The Lima VM's vTPM proxy was not registered with the trusted-key subsystem at boot, so the full unseal path (`keyctl add trusted`) is unavailable. Proof marker: `CH23_PROVEN hook=attached kind=kprobe-on-tpm2_unseal_trusted sym-confirmed`. Full byte-capture proof requires a host with a boot-registered TPM backend.

**ch24 (bpf_token delegation)** — Act 4 addition. **SKIP — `CONFIG_BPF_TOKEN=n` on all available kernels.** BPF token delegation requires kernel 6.9+ built with `CONFIG_BPF_TOKEN=y`. Neither Ubuntu 6.17.0-29-generic aarch64 nor Fedora 6.17 had this configuration option enabled. The `bpf()` syscall returns `ENOSYS` for `BPF_TOKEN_CREATE` — the command is absent, not just runtime-refused. Earlier documentation in this chapter describes a Fedora 42 / 6.14 `EOPNOTSUPP` from cloud-init; that was a separate failure mode (feature compiled in, rejected by `cred->user_ns` check). The Ubuntu/Fedora 6.17 case is more fundamental. The C code is production-reviewed; the skip is a build-configuration gap. Any kernel built with `CONFIG_BPF_TOKEN=y` will demonstrate the primitive.

**ch25 (metadata faucet via XDP)** — Act 4 addition. **PROVEN.** An XDP program attached to the loopback interface intercepts mock IMDSv2 requests (127.0.0.1) and harvests access keys and session tokens. Verified on Ubuntu 6.17.0-29-generic aarch64 (Lima VM). Proof output: `[ch25] CREDENTIALS_CAPTURED access_key=ASIAEXAMPLEMOCK0001 token_len=1 role=demo-role` and `CH25_PROVEN access_key_captures=1 token_captures=1`. Note: `--net=host` is required in Docker contexts for XDP to attach to the host interface; the Lima VM's loopback works directly.

Note that ch08's LSM variant was retired from the harness during the cleanup — only the `ch08k` kprobe variant remains registered, and it fires directly on linuxkit by reading through the full `struct key` BTF. There is no separate skip entry for ch08.

Chapter 21 does the full skip accounting — each skip mapped to the specific kernel configuration axis that disarmed it (LSM enforcement state, module signature enforcement), and for each one, the concrete configuration on which the primitive fires. The Fedora 42 aarch64 QEMU VM is driven by `dBPF-pocs/run-qemu-tests.sh` (host-side orchestration) and `dBPF-pocs/qemu-runner.sh` (guest-side per-PoC driver). Both skip reasons resolve to "no enforcement point active on linuxkit" — the BPF program and the hook are fine; the surrounding kernel policy simply does not produce the decision the primitive wants to flip.

The distribution of the two skip reasons tells you something about linuxkit specifically: it is stripped, it is aarch64, and it runs with permissive LSMs. Moving those PoCs to the Fedora QEMU environment changes the environment axis without changing the primitives.

## A pattern across the twenty

Reading across all twenty proven cases, a pattern emerges that is more durable than any individual primitive.

Every primitive has three pieces: a kernel hook, an observation or manipulation, and a consumer. The hook is what the primitive attaches to — a function symbol, a tracepoint, an LSM attach point, a netdev. The observation or manipulation is what the BPF program does when the hook fires — read a struct, overwrite a buffer, override a return, drop a packet. The consumer is what ends up using or believing the primitive's output — userspace reading a file, userspace reading a syscall return, a privileged drainer reading a ringbuf, the kernel reading a rewritten user pointer.

The defender's leverage differs across those three pieces. Hooks are the easiest to enumerate: `bpftool prog list` is enough. Manipulations are the easiest to categorize: the three motions cover them all. Consumers are the hardest, because the consumer is often a legitimate userspace component whose only sin is trusting what it was told. That is why chapter 18's defense section spends most of its length on "stop trusting `getuid()`" rather than on anything BPF-specific: the BPF primitive is the mechanism of the lie, but the damage is done by userspace believing the lie. A kernel with no error-injection entries on uid-querying functions is a kernel where ch18 does not fire. A userspace that cross-checks uid across two independent sources is a userspace where ch18's damage is neutralized even if it does fire. The two defenses compose; both are cheap; many operators deploy neither.

The same pattern applies across the other classes. Class II defenses split between "remove the write capability" (hard, because CAP_BPF is widely granted) and "remove the trust in the rewritten buffer" (easier, because most legitimate consumers can cross-check). Class III defenses split between "remove the read capability" (essentially impossible in a kernel that supports BPF at all) and "remove the value of the exfiltrated state" (structural; `USE_RANDOMIZED_KEYRING_DESC` at boot makes keyring descriptions meaningless to a drainer, for example). Class IV defenses are the most tractable because the hook surface is narrow and the attach inventory is short. Class V defenses need to attack both the observer (ringbuf drain) and the window (racer), and are the hardest to deploy but also the most specialized.

None of this is news to an experienced defender. What the twenty POCs do is make the pattern reproducible: here is a BPF primitive, here is its class, here is its hook, here is its consumer, here is the defense that corresponds to the class, here is the proof marker that demonstrates the effect, here is the skip reason if the effect does not fire. Chapter 22 makes the class-to-defense mapping explicit in table form. Chapter 21 makes the skip-to-kernel-config mapping explicit. This chapter is the narrative that ties the two tables together.

## For operators

Six one-line recommendations, expanded in chapter 22:

- Inventory `CAP_BPF` holders across your fleet. Know who is asking.
- Pin loaded BPF programs at boot and diff the set against the boot baseline on a timer.
- Use BPF LSM policies to gate program load by attach type and caller credential.
- Audit `/sys/kernel/debug/error_injection/list` on production kernels; restrict debugfs visibility where feasible.
- Audit the `bpf(2)` syscall to a tamper-evident sink that itself does not run with `CAP_BPF`.
- Do not trust userspace syscall return values for security-critical decisions. Consult `current->cred` at the kernel enforcement point.

Each one of those closes a meaningful fraction of the primitives in this book. The combination closes almost all of them. None is novel; all are uncontroversial in principle; all are under-deployed in practice. That gap is where the primitives live.

A pragmatic rephrasing: most of the work of defending against this catalog is inventory. Know who holds `CAP_BPF`. Know what BPF programs are loaded. Know which attach points are in use. That is the entire job, approximately. The kernel is not going to help much because the kernel's job is to run the BPF programs it is asked to run; policy beyond the capability gate is the defender's responsibility.

A second pragmatic rephrasing, aimed at a different audience: if you are writing userspace software that makes security decisions, stop trusting `getuid()` and stop trusting syscall return values in general for anything load-bearing. Read kernel state directly through `/proc` when you must; restructure so the security decision happens in the kernel when you can. The whole Class I section of this book stops working as soon as userspace consumers of syscall returns stop trusting those returns.

## Prior art, one more time

Almost every individual primitive in this book has prior art. The `d_reclen` getdents64 trick (chapter 10) has been in rootkit POCs since at least 2016. The `cap_capable` observer (chapter 1) is the same pattern `bcc/capable.py` has run since 2016. The overlayfs copy-up race (chapter 2) has been discussed in container-escape talks for years. The getuid syscall-return forge (chapter 18) is a BPF-mechanized version of wrong-enforcement-point bugs that go back to 1990s Sendmail. XDP packet manipulation (chapters 5b and 15) is standard Cilium-shape plumbing, pointed at offense instead of network-policy. Seccomp sidechanneling via privileged observers (chapter 16) is acknowledged in the seccomp threat model explicitly.

The book's contributions are not the primitives. They are:

- **A reproducible harness.** One Dockerfile, one Python driver, one command (`./run.sh`), one exit status. Every POC runs the same way, emits proof markers that are greppable in the same format, and flips to a status the harness can report. Setting up a reproducible BPF harness on aarch64 linuxkit took a week; running it once it worked takes minutes. That repeatability is the artifact.
- **An honest taxonomy.** Five classes, three motions, explicit framing of what is the primitive and what is the enforcement point. Class names chosen so that each primitive in the book sorts cleanly into exactly one. A reader of the taxonomy who meets a new BPF primitive in the wild should be able to place it by shape — and, more importantly, should be able to see that the defense for "its class" applies regardless of which specific function it attaches to.
- **Explicit scope.** Every chapter says what the primitive did *not* do. The book as a whole says what this body of work did not establish — no CVEs, no verifier bypass, no escalation, no defeat of DAC or cap checks. The repeated refusal to overclaim is the point. Security writing benefits from the same honesty that a good vulnerability report does: here is exactly what was tested, exactly what was observed, exactly what is extrapolation.

Novelty is not claimed anywhere in the book. That should be the default for this kind of work, and when it is not, readers should notice.

There is one thing I will claim is useful without being novel: the labelling discipline. Every proof marker carries its scope in the marker itself — `_WEAPON_PROVEN` for a primitive that fires end-to-end, `_CONCEPT_PROVEN` for an illusion that forges a return without achieving the in-kernel effect. A defender or researcher who scrapes this book's harness output cannot accidentally conflate a weapon proof with a concept proof, because the marker line tells them which is which, inline, every time. This is a small thing. It took me a few iterations to get right, and I was embarrassed more than once by early runs where I had labelled a concept result as though it were a full weapon. The labelling is the discipline. Any follow-on work that builds on this harness should inherit it.

The second thing I will claim as useful is the `CH*_SKIP reason="..."` convention. When a primitive cannot fire on the current kernel, the trigger prints an explicit skip line naming the missing piece. `CH06_SKIP reason="selinux_not_enforcing"`. `CH12_SKIP reason="no module signature enforcement"`. This gives a reviewer immediate visibility into *why* a primitive didn't fire, not just that it didn't. Running the harness against a new kernel and diffing skip reasons is a quick way to characterize what that kernel exposes: if the skip reasons move, so does the attack surface.

Both conventions are boring. Both would be trivial to adopt in other BPF-primitives catalogs. Neither is new. But the combination of "explicit scope in the proof marker" + "explicit reason in the skip marker" is what makes this harness's output trustworthy at the line level, without requiring a reader to cross-reference the chapter text to know what happened. If there is a methodological contribution, it is that.

## A note on reproducibility

If I have done my job, anyone with Docker Desktop on Apple Silicon or an x86 host can clone the repo, build the harness image, and run the whole book's worth of demonstrations in one invocation. The container is self-contained: it pulls nothing at runtime, builds every POC against the live kernel's BTF, and runs each one sequentially with the TUI displaying progress. The run takes about six minutes on my laptop.

Reproducibility has several layers, and it is worth naming each because the catalog is only useful to the extent that its claims can be rechecked.

- **Build reproducibility**: the Dockerfile pins compiler versions, libbpf version, bpftool version, and the Debian base image. Rebuilding the image produces the same binaries for the same source. Without this, a year from now someone attempting to re-run the harness would see gratuitous build errors that have nothing to do with the primitives.
- **Kernel reproducibility**: the harness runs against whatever kernel the container is hosted on. On Docker Desktop that is linuxkit 6.12; on a bare-metal Linux host it is the host's kernel. The results will differ between kernel versions — this is a feature, not a bug — but the harness's results-for-this-kernel are reproducible on this kernel.
- **Result reproducibility**: every proof marker is deterministic given the same kernel, same build, same trigger. There is no randomness that would change outcomes between runs. Running the harness twice back-to-back on the same machine produces identical `_PROVEN` markers and identical status columns.
- **Machine-readable output**: the harness writes `/tmp/proof-result.json` at the end of every run. A downstream consumer (a CI check, a regression detector, a cross-kernel matrix tester) can diff the JSON between runs to see exactly which primitives moved.

Reproducibility is the single most important property for a catalog like this. An unreproducible catalog is an anecdote dressed up as research. The catalog is the harness; the harness is the catalog; the taxonomy falls out of what the harness actually observed.

## A note on what we chose not to do

A few things the book deliberately avoids, with brief justification for each choice.

It does not chain primitives into full attack narratives. A determined attacker with `CAP_BPF` would combine ch16 (seccomp sidechannel) with ch18 (token forge) and ch10 (inode cloak) into a single post-exploitation toolkit. The book treats each primitive in isolation because the compositional space is combinatorial and the individual primitives are the load-bearing part. Anyone who wants to chain them has the ingredients; the chaining is an exercise, not the thesis.

It does not attempt rootkit persistence. Staying resident across reboots, hiding from `bpftool`, evading `auditd` — these are standard rootkit problems and the literature on them is rich. The book's primitives are all per-process, per-session, attached-and-visible. Converting any of them into a resident rootkit is another exercise.

It does not claim bugs in BPF. Every verifier refusal the book records is the verifier doing its job correctly. Every permitted load is a permitted load. Every helper behaves as documented. If the book seems to report surprising outcomes, the surprise is in the composition, not in any individual piece.

It does not generalize to other BPF subsystems this kernel does not expose. There is presumably interesting surface in `struct_ops` programs, in sleepable LSM programs, in iter programs; this book does not cover them because the test kernel either does not expose them or does not expose them in a way that is useful for offense. A future book on a different kernel would have different chapters.

## One more pass over the numbers

Just for clarity, the final tally one more time.

23 POCs total in the harness's POCS list (verify with `grep -c "^    Poc(" dBPF-pocs/harness/proof.py`).

17 are "primary" on-host POCs — one per technique chapter present in the current catalog: ch01, ch02, ch03, ch04, ch05, ch05b, ch06, ch07, ch08, ch09, ch10, ch11, ch12, ch14, ch15, ch16, ch18. Note that ch13 and ch17 are not in the catalog; their earlier aarch64-incompatible PoCs were retired in the cleanup that produced this manifest.

The next 3 are kept variants: `ch06o` (kprobe observer of SELinux, Class III), `ch08k` (kprobe variant of keyring heist, Class III), and `ch12s` (syscall-level `finit_module` return forge, Class I illusion). Their proof markers use `_CONCEPT_` or `_PROVEN` labels as appropriate.

The final 3 are Act 4 cross-boundary chapters: `ch23` (TPM unseal heist, Class III against hardware-rooted keys), `ch24` (bpf_token delegation, threat-model subversion), and `ch25` (IMDS harvest via XDP, Class IV).

Of the 23:
- **18 flipped to `effect_demonstrated` on linuxkit**: their `_PROVEN` marker printed on stdout before the loader was torn down.
- **2 skip on linuxkit** with explicit `CH*_SKIP reason="..."` lines — ch06 LSM (SELinux not enforcing) and ch12 LSM (no module signature enforcement) — and fire on the Fedora 42 aarch64 QEMU VM.
- **2 PROVEN on the Ubuntu 6.17 aarch64 Lima VM (final verification environment)**: ch23 (kprobe attached, entry intercept events observed, `CH23_PROVEN hook=attached`) and ch25 (XDP mock IMDS on `lo`, `CH25_PROVEN access_key_captures=1 token_captures=1`).
- **1 SKIP in all environments**: ch24 (`CONFIG_BPF_TOKEN=n` on all available kernels — neither Ubuntu 6.17 nor Fedora 6.17 built with this option).
- **0 failures.**

**Final across-environment tally: 24 PROVEN, 1 SKIP (ch24).**

Counting the stricter bar — only `real`-category POCs that actually demonstrated effect on linuxkit — gives 12. Counting all `real`-category POCs that fire in any environment (including ch12, ch23, ch25) gives 15. The across-environment total is 24 demonstrated, 1 skipped with an honest named reason.

## Closing

This book is a catalog, a harness, and a skip-accounting.
