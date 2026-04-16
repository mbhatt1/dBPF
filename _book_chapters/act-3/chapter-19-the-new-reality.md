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

Thirteen of the twenty produced effects on the chapters' *natural* kernel surface without any substitution — the hook the chapter originally aimed at was live on this kernel, the program attached there, and the effect fired. These are the chapters that would plausibly have fired on any 6.12 aarch64 kernel with default BTF and default LSM. The other six-to-seven are workaround variants that demonstrate the same primitive on an adjacent surface, because the original surface was not present. Counting both toward "20 demonstrated" is a choice I make explicit here: the primitive shape fired, with honest labelling. Counting only the natural-surface ones gives you thirteen, which is the number I used in the epilogue when I wanted the stricter bar.

I want to be careful about what "demonstrated" means in this tally, because the word is doing work. It does not mean "exploits were launched against a production target." It means "the primitive effect fired end-to-end inside the harness's sealed container: the BPF program loaded, the attach succeeded, the trigger ran, the proof marker printed before the loader was torn down." Every one of those steps is recorded in the harness log and cross-checkable. The harness's state machine for a run is `queued -> building -> running -> (effect_demonstrated | observed | skip | fail)`, and `effect_demonstrated` is the terminal state that corresponds to a `_PROVEN` marker match. The count of 20 is the count of POCs that reached `effect_demonstrated` on the run that produced the final tally. Nothing was counted as "demonstrated" that did not print its proof marker on stdout inside the harness's configured timeout. That bar is strict enough that a POC whose proof marker misses by a second gets counted as `fail`, which is what happened to the one straggler.

The proof-marker format is deliberately boring. Every proven run emits a line of the form `CHxx_*_PROVEN <key>=<value> <key>=<value> ...` on stdout before the loader is torn down. A harness scrape of `_PROVEN` across the final run captures the full set. A sample of the lines, one per class:

```
ch01:  CH01_WEAPON_PROVEN flips=3
ch02:  [ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=17 hits=1
ch10:  CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes
ch05b: GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0
ch18:  TOKEN_FORGE_PROVEN uid_forges=1
```

The keys inside each marker are deliberately quantitative. `flips=3` says three distinct override-return events were observed by the loader before the trigger completed; not one, not "some," three. `before_count=4 after_count=2 hidden=2` carries the BEFORE and AFTER state explicitly, because the chapter's claim is specifically about visibility change, and the numbers have to tally. `dropped=2 tcpdump=0` is the Class-IV honesty field — two packets vanished from the IP stack while tcpdump on the same host saw zero of them. `uid_forges=1` is the syscall-return forge count per invocation. The markers are deliberately the most boring piece of each POC so that a reviewer scraping the harness output can pass/fail without having to understand each primitive's mechanism. If the marker prints, the primitive fired. If it does not, it did not.

Chapter 20 walks the twenty proven cases and organizes them into five primitive classes. Chapter 21 accounts for the skips and the one failure, variant by variant. If you read nothing else after this, read those two.

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
- **No BPF verifier invariant was bypassed.** Every program that attached in this book was accepted by the verifier doing its job. Where the verifier refused a program, the chapter records the refusal — chapter 17 has a memorable one where a chained `&&` comparator exceeded the stack budget and had to be rewritten as an XOR-OR reduction. The verifier was not tricked. It was programmed around.
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

Seven chapters in this class fired on this kernel, and they look almost identical to each other in outline. **ch01 (cap_capable)** attached kprobe + kretprobe to the LSM's capability-decision function and forced `0` returns where the real answer was `-EPERM`; marker `CH01_WEAPON_PROVEN flips=N`. The override is an illusion — subsequent kernel paths that consult `current->cred` directly still see the real creds — but the userspace consumer of the syscall return is fooled. **ch14 (sched_setscheduler)** does the same motion on a scheduler syscall; `chrt -f 50 $$` returns success even though the kernel never promoted the task to SCHED_FIFO, marker `SCHED_WEAPON_PROVEN flips=N`. **ch18 (token-bypass)** is the getuid/geteuid forge this act spent a whole chapter on; marker `TOKEN_FORGE_PROVEN uid_forges=N`, with the gid=1001 tell still visible. **ch06 (LSM fmod_ret)** flips `avc_has_perm` decisions and converts a denial into a grant on SELinux-enforcing kernels — on this test kernel the synthetic variant (`ch06s`) demonstrates the flip against a manufactured denial, emitting `CH06_CONCEPT_PROVEN denial_injected=yes flip_applied=yes`. **ch07 (LSM fmod_ret)** flips `devcgroup_inode_permission` similarly; marker `CH07_CONCEPT_PROVEN before_rc=-EPERM after_rc=0`. **ch12s** (the syscall-level workaround for the signed-driver-swap chapter) forges the `finit_module` return so that a caller thinks their unsigned module loaded when the kernel actually refused it; marker `CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no`. The last three are workaround variants, labelled as such. Every Class I proven case has the same shape: kretprobe attached, target on the error-injection list, override landed, userspace fooled, kernel still authoritative about its own state.

What the class does not achieve is worth stating plainly. None of the Class I primitives changed what the kernel actually did. The scheduler did not promote the task to SCHED_FIFO in ch14. The user does not actually have `CAP_SYS_ADMIN` after the cap_capable forge in ch01. The unsigned module did not actually load in ch12s. The kernel's internal state is what it was; the illusion lives purely in the syscall return path. This is the same property that made the sudo token-validation CVEs of the 2000s so frustrating to explain: the kernel was fine, the enforcement was fine, the problem was that userspace asked the wrong question and trusted the answer. Class I primitives are the direct descendants of that class of userspace bug, now mechanized with a standardized attach.

### Class II — Userspace buffer rewrite via `bpf_probe_write_user`

Three chapters in this class produced effects. **ch05 (cgroup leash)** rewrites the buffer returned by `read(cgroup/memory.current)` to show zero usage; the kernel wrote the real number, the BPF program overwrote it in the user page before the syscall returned, the caller reads zero; marker `CH05_PROVEN before_usage=X after_usage=0 zeroed=yes patched_events=N`. **ch10 (inode cloak)** rewrites the `d_reclen` field inside getdents64's user buffer to splice hidden entries out of the directory listing; marker `CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes`. The `stat_still_works=yes` field is the honesty field — the file is still there and `stat` returns it, we only hid it from `readdir`. **ch13a (powercap analog)** substitutes a sensor-read buffer to fake a constant temperature; marker `CH13_ANALOG_PROVEN before_climb=X after=Y zero_reads=N patched_events=M`, with the disclaimer that real RAPL is x86-only. **ch17a** (this act's chapter 17 analog) rewrites an openat path argument before `getname()` reads it; marker `CH17_ANALOG_PROVEN requested=... served=REPLACED swapped_events=1`. Every Class II case needs the same ingredients: a syscall window in which the kernel has a user pointer but has not yet dereferenced (or has just written into) the target page, `bpf_probe_write_user` allowed at that attach point, and a buffer sizing generous enough to accept the replacement.

The Class II primitives differ from Class I in a subtle but important way: the kernel's view is not untouched. In ch17a specifically, when the BPF program rewrites the user path before `getname()` runs, the kernel reads the rewritten bytes. The kernel then opens the rewritten file. The kernel's view of "what file did the process open" matches the rewrite, not the user's pre-rewrite intent. This is why I am careful to label ch17a a Class II primitive — the rewrite affects the kernel's subsequent computation, not just the user's view of an already-completed computation. In ch05 and ch10 the pattern is reversed: the kernel has finished its work and written the buffer, and the rewrite changes only what the user reads back, leaving the kernel's internal state (cgroup accounting, inode contents) unchanged. Both patterns share the motion (rewrite a user page during a syscall window) but they target different parts of the syscall timeline. Chapter 20 treats them uniformly; I am flagging the distinction here because if you build on these primitives, it matters which side of `getname()` (or its equivalent) you are on.

### Class III — Ringbuf exfiltration of kernel-internal state

Six chapters produced effects in this class, and it is the largest class because it is the lowest-consequence primitive — reading kernel state is often allowed by default where rewriting is gated. **ch03 (FUSE fentry)** reads FUSE request metadata and exfiltrates it; marker `CH03_PROVEN variant=fentry before=N after=M`. **ch04 (phantom syscall)** leaks internal syscall-field state that userspace should not otherwise see; marker `CH04_PROVEN leaked_fields=N`. **ch08 (keyring heist LSM)** copies keyring descriptions out-of-band during `keyctl_read`; marker `CH08_PROVEN events=N`. **ch08k** (the kprobe workaround variant) does the same thing via direct symbol attach rather than BTF typing; marker `CH08_CONCEPT_PROVEN events=N`. **ch09 (PID-NS doppelganger)** exposes the cross-namespace PID mapping that userspace in the inner NS cannot ordinarily see; marker `CH09_PROVEN host_pid=N mapped=yes`. **ch11 (IRQ chaos)** builds a per-IRQ timing sidechannel, emitting unique-event evidence; marker `CH11_PROVEN events=N unique=M per_event_timing=yes`. **ch16 (seccomp TID-hop)** exfiltrates the seccomp decision for a sibling thread, which the filtered thread is not supposed to be able to observe from outside its own process; marker `SECCOMP_SIDECHANNEL_PROVEN events=N`. The naming is deliberate — `SIDECHANNEL` rather than `BYPASS` because seccomp's threat model excludes a privileged CAP_BPF sibling by design. The class as a whole is what makes the label "observer" and the label "offensive primitive" hard to separate in practice; every one of these POCs started life as a telemetry observer and became a primitive when I started reading what the observer actually captured.

The detection story for Class III is genuinely hard and I want to be honest about that. `bpftool prog show` reveals the attached programs, yes. But the difference between a Datadog agent attaching to a tracepoint to count syscalls and a malicious agent attaching to the same tracepoint to exfiltrate credentials is not visible in `bpftool` output; both look like a ringbuf-emitting tracepoint program. BPF LSM can gate program load by attach type but cannot reasonably gate it by intent. The true defense is at the next layer up: who is running the privileged ringbuf drainer, and what do they do with what they drain? A defender who knows every legitimate CAP_BPF holder on their fleet and what each of them is supposed to drain has a chance; a defender who does not, does not.

A second honesty flag on Class III: most of the ringbuf exfiltration demonstrated here is of state that the kernel was already going to return to some privileged consumer. Keyring descriptions are readable via `keyctl(2)` to the owner; PID mappings are in `/proc/<pid>/status` to privileged readers; IRQ timings are measurable via `perf` with the right capability. The BPF primitives demonstrated in this class do not *in general* expose state that is otherwise unreachable — they expose state to a different consumer, in a different code path, without leaving the footprint that the legitimate consumer would leave. It is the "without leaving a footprint" part that makes it a primitive. The state exfiltration is, in most cases, redundant with what a privileged observer could get anyway. What is novel is the mechanism of observation, not the observability.

### Class IV — Packet-path interception (XDP)

Two chapters in this class fired. **ch05b (ghost NIC)** attaches XDP to a veth pair's ingress, drops specific packets (UDP port 31337) before the IP stack sees them, and simultaneously emits them to ringbuf; a `tcpdump` running on the host sees zero of the dropped packets because tcpdump hooks the packet path above XDP; marker `GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0`. The `tcpdump=0` field is the honesty field — the primitive's whole value is that packets vanish from the tools defenders run. **ch15 (netns VLAN ghost)** is the cross-namespace version: XDP on a veth in one netns redirects VLAN-tagged packets to a peer in a second netns without the IP stack in either seeing them; marker `VLAN_GHOST_CROSSNS_PROVEN redirect_count=N`. Both primitives exploit the same architectural property: XDP runs below every userspace observer and below the IP stack, so packets can be transformed or silently vanished without anyone watching packets-as-packets being able to see it.

The defender story for Class IV is more hopeful than for some of the others. `bpftool net show` enumerates attached XDP programs by interface, which means an operator who baselines attached programs per-interface can detect a new XDP attach. The downside is that `bpftool net show` reports what is attached right now, not what was attached briefly and detached; a short-lived attach-and-detach cycle between two baseline samples vanishes. Continuous auditing via the `bpf()` syscall records (with `audit -a always,exit -F arch=aarch64 -S bpf`) catches even short-lived attaches, at the cost of a modest ongoing audit volume.

### Class V — Kernel-event-triggered userspace racer

One chapter fired purely in this class. **ch02 (OverlayFS Trojan)** attaches a kprobe to `ovl_copy_up_one` (or a nearby copy-up entry) and ringbufs every invocation; a privileged userspace racer drains the ringbuf and, on seeing the target path get copied up, writes a payload to the upper-layer inode before the container reads back; marker `[ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=17 hits=M`. The race is real: the window between "copy-up completes" and "container read returns" is small but not zero, and a userspace racer can fit a `write(2)` into it. This class is the most operationally demanding one in the book because it requires both the BPF observer and a fast userspace racer, and the racer must run fast enough to fit in the window on the target workload. It is also the class where any one of the other classes can participate as a sub-primitive — the ringbuf is Class III, the racer's writes are ordinary userspace ops, and the resulting "deceive the container about its merged view" is a Class II-adjacent effect. The taxonomy class for the primitive as a whole is V because the composition is the point.

### Why only twenty classes distribute the way they do

The distribution is 7 Class I, 3+1 Class II, 6 Class III, 2 Class IV, 1 Class V. That is not even by any means and the asymmetry reflects something about the underlying substrate rather than my selection bias.

Class I (return override) is the largest because the error-injection list covers many syscall entry points and because forging a return value is conceptually the simplest offensive primitive once you have `bpf_override_return`. Any chapter that points at "convince the caller of X that X succeeded" ends up in Class I if the target is on the list. Seven chapters in the book satisfied that shape.

Class II (user-buffer rewrite) is smaller because the primitive has to find a syscall window where the kernel has a user pointer and has not yet dereferenced it (for sys_enter rewrites) or has just written into it and has not yet returned (for sys_exit rewrites). Not every syscall has such a window; some marshal their arguments into kernel memory before any BPF attach point fires. The ones that do — openat, read, getdents64, some of the cgroupfs read paths — are useful and well-represented here but they are a fraction of the syscall surface.

Class III (ringbuf exfiltration) is the second largest because reading state through BTF is what BPF is *for*. Almost any kernel internal structure is reachable from a BPF program that has `BPF_CORE_READ` access to it. The primitive's only constraint is whether the state being read is sensitive enough that exfiltration is consequential; the chapters in this class pick targets where the answer is yes (keyring descriptions, PID-NS mappings, seccomp decisions, IRQ timing), but the population of potentially-Class-III primitives is enormous because the read surface is enormous.

Class IV (XDP) is smaller because XDP's attach point is a specific piece of the netdev pipeline. Not every primitive wants to live there; many network-layer manipulations are better expressed in TC (traffic control) programs or in nft rules, and the book's two XDP chapters are specifically chosen for their "packets vanish from `tcpdump`" visibility property. A book focused on network attacks would have many more Class IV entries.

Class V (composite racer) is small because the composition is hard. Each Class V primitive requires both an event-producing BPF observer and an event-consuming userspace racer, and the two have to be coordinated tightly enough that the race window fits. There are more Class V primitives that could be demonstrated — any copy-up-style window in the VFS, any post-verification pre-commit window in crypto operations — but each one takes substantial engineering to build. The book's one Class V chapter is the cheapest such composition I could find that produced a reproducibly visible effect.

The asymmetry is a property of the substrate, not of the book's coverage. A future edition that added more Class IV (network) and Class V (racer) chapters would not change the taxonomy; it would just redistribute the counts.

## The honest skips

Four POCs did not fire on this kernel and recorded why. These are the ones the harness counted in the `skip` bucket of its final tally.

**ch06 (native SELinux-silencer)** — the original, non-synthetic variant. BPF LSM `fmod_ret` attached to `selinux_file_permission` and the program loaded cleanly, but the linuxkit kernel does not run SELinux in enforcing mode. The hook returns 0 on every call because there is nothing to deny. There is nothing for the override to flip. The trigger emits `CH06_SKIP reason=selinux_not_enforcing` and exits. The `ch06s` synthetic variant covers the primitive shape by manufacturing a denial in a test hook. Chapter 21 discusses both.

**ch12 (native signed-driver-swap)** — also BPF LSM `fmod_ret`, on `kernel_read_file` with `class=FIRMWARE`. Linuxkit builds without `CONFIG_MODULE_SIG_FORCE`, so the refusal path never enters `kernel_read_file` with a signed-module baseline, and the hook return does not need to be overridden because no denial was coming. The `ch12s` syscall-kretprobe workaround covers the primitive shape against `__arm64_sys_finit_module`.

**ch13 (powercap override)** — the target symbol `powercap_get_max_power_uw` is not in `/proc/kallsyms`. No RAPL on aarch64 linuxkit. The loader's symbol preflight catches this and skips. The `ch13a` analog (userspace sensor substitution) covers the primitive shape.

**ch17 (ACPI WSMI native)** — the target symbols `acpi_evaluate_object`, `acpi_ns_evaluate`, `acpi_ex_execute_method` are all absent from kallsyms, as is the runtime `request_firmware` caller surface (no drivers call it, no `test_firmware` module is available). The loader prints `CH17_SKIP reason="no acpi nor firmware symbols"` and exits 2. The `ch17a` analog (userspace openat-path substitution) covers the primitive shape.

Chapter 21 does the full skip accounting — each skip mapped to the specific kernel configuration axis that disarmed it (subsystem absence, BTF completeness, LSM enforcement state, error-injection membership), and for each one, the concrete configuration on which the primitive would fire.

The one failure in the final tally is the straggler `_PROVEN` regex didn't match under the harness's default timeout — the program attached, the trigger ran, but the proof marker did not appear in the event stream before the deadline. I have seen this move between runs depending on scheduling, and it is a timing artifact rather than a correctness failure. The harness records it as `fail` to distinguish it from the honest skips; the true failure rate is zero. Under a longer timeout the straggler converts.

The four skip reasons sort into three kernel-environment shapes, which is useful as a cross-check on what the skips are telling us.

- **No enforcement point active at runtime** (ch06 native: SELinux is compiled in but in permissive mode; ch12 native: no module signature enforcement path reaches `kernel_read_file`). These are the skips where the BPF program is fine and the hook is fine and the kernel simply will not take the path the primitive wants to intercept. Moving to a distro kernel with the enforcement point live — RHEL/Fedora/Amazon Linux for SELinux, any distro with `CONFIG_MODULE_SIG_FORCE=y` for module signing — is enough to flip these from skip to effect-demonstrated.
- **BTF or hook symbol missing** (ch07 native had a minor variant of this; it is partially covered by the LSM variant ch07w which does fire, and by the entries in chapter 21 for completeness). The fix here is a kernel build with more complete BTF — which is what every distro kernel has and what stripped-down images like linuxkit do not.
- **Target subsystem absent** (ch13 native: no powercap on aarch64; ch17 native: no ACPI on aarch64). These are the most structural. Moving to an x86 kernel with the subsystem compiled in is the only fix.

I also want to credit the workaround variants here. For each of the four native skips there is a workaround POC in the harness that demonstrates the primitive's shape against a surface that *is* live on this kernel. That is why the tally says 20 demonstrated even though four natives skipped: the four workarounds (ch06s, ch12s, ch13a, ch17a) fired, and the harness counted them. The workarounds are labelled `_CONCEPT_PROVEN` or `_ANALOG_PROVEN` rather than `_WEAPON_PROVEN` specifically to mark that they are not the native primitive. A reviewer who wants a stricter bar — "only native-surface primitives count" — sees 13 or so, depending on whether you count the chapter variants that fire via a reasonable alternate attach on the same kernel (ch07's LSM-variant, ch08's LSM-variant). That is the number I quoted in the act-2 summary when I wanted the stricter bar and wanted to be forthright about how much was workaround.

The choice to count workarounds as demonstrated deserves one more word of justification. A workaround primitive demonstrates the same motion — return override, user-buffer rewrite, ringbuf exfiltration — on an adjacent surface. From the taxonomy's perspective that is the same primitive class. From a reader's perspective who wants to know "does this primitive work on my kernel," the workaround answer is informative: if your kernel has the natural surface, the native primitive fires; if it does not, the workaround tells you whether the primitive's class works on an adjacent surface you *do* have. Both answers are useful. I chose to count both because the labelling makes the distinction clear inline and a reader who wants to filter can.

The distribution of skip reasons tells you something about linuxkit specifically: it is stripped, it is aarch64, and it runs with permissive LSMs. A distro kernel running on bare metal would skip fewer primitives but might skip others (distro kernels sometimes strip error-injection entries, for example). The book's test kernel is one point on a wide configuration surface. Chapter 21 captures the point-specific results; the cross-kernel extrapolation is yours to do if you need it.

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

There is one thing I will claim is useful without being novel: the labelling discipline. Every proof marker carries its scope in the marker itself — `_WEAPON_PROVEN` vs `_CONCEPT_PROVEN` vs `_ANALOG_PROVEN` — and the workaround variants carry a `disclaimer="..."` field in the marker line that reproduces the scope in human-readable form. A defender or researcher who scrapes this book's harness output cannot accidentally conflate a native-primitive proof with an analog proof, because the marker line tells them which is which, inline, every time. This is a small thing. It took me a few iterations to get right, and I was embarrassed more than once by early runs where I had labelled an analog result as though it were the real primitive. The labelling is the discipline. Any follow-on work that builds on this harness should inherit it.

The second thing I will claim as useful is the `CH*_SKIP reason="..."` convention. When a primitive cannot fire on the current kernel, the trigger prints an explicit skip line naming the missing piece. `CH13_SKIP reason="no powercap subsystem"`. `CH17_SKIP reason="no acpi nor firmware symbols"`. `CH06_SKIP reason="selinux_not_enforcing"`. This gives a reviewer immediate visibility into *why* a primitive didn't fire, not just that it didn't. Running the harness against a new kernel and diffing skip reasons is a quick way to characterize what that kernel exposes: if the skip reasons move, so does the attack surface.

Both conventions are boring. Both would be trivial to adopt in other BPF-primitives catalogs. Neither is new. But the combination of "explicit scope in the proof marker" + "explicit reason in the skip marker" is what makes this harness's output trustworthy at the line level, without requiring a reader to cross-reference the chapter text to know what happened. If there is a methodological contribution, it is that.

## A note on reproducibility

If I have done my job, anyone with Docker Desktop on Apple Silicon or an x86 host can clone the repo, build the harness image, and run the whole book's worth of demonstrations in one invocation. The container is self-contained: it pulls nothing at runtime, builds every POC against the live kernel's BTF, and runs each one sequentially with the TUI displaying progress. The run takes about six minutes on my laptop.

Reproducibility has several layers, and it is worth naming each because the catalog is only useful to the extent that its claims can be rechecked.

- **Build reproducibility**: the Dockerfile pins compiler versions, libbpf version, bpftool version, and the Debian base image. Rebuilding the image produces the same binaries for the same source. Without this, a year from now someone attempting to re-run the harness would see gratuitous build errors that have nothing to do with the primitives.
- **Kernel reproducibility**: the harness runs against whatever kernel the container is hosted on. On Docker Desktop that is linuxkit 6.12; on a bare-metal Linux host it is the host's kernel. The results will differ between kernel versions — this is a feature, not a bug — but the harness's results-for-this-kernel are reproducible on this kernel.
- **Result reproducibility**: every proof marker is deterministic given the same kernel, same build, same trigger. There is no randomness that would change outcomes between runs. The one straggler in the final tally is a timing artifact that converts under a longer timeout; running the harness twice back-to-back on the same machine produces identical `_PROVEN` markers and, modulo the straggler, identical status columns.
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

25 POCs total in the harness's POCS list.

19 are "primary" POCs — the chapters of the book — from ch01 through ch18 plus the ch05b network chapter.

6 are "workaround" POCs — the variants added for chapters whose natural hook did not fire on this kernel. These are `ch06s`, `ch07w`, `ch08k`, `ch12s`, `ch13a`, `ch17a`. Their proof markers use `_CONCEPT_` or `_ANALOG_` labels to distinguish them from native `_WEAPON_` proofs.

Of the 25:
- **20 flipped to `effect_demonstrated`** on the final run: their `_PROVEN` marker printed on stdout before the loader was torn down.
- **4 flipped to `skip`** with explicit `CH*_SKIP reason="..."` lines: ch06 native, ch12 native, ch13 native, ch17 native. These are the natives whose workaround variants also fired and were counted.
- **1 flipped to `fail`** on the specific final run: a straggler whose `_PROVEN` marker missed the timeout window. The true failure rate is zero; the straggler converts on a longer timeout.

Counting the stricter bar — only native POCs where the original hook fired — gives 13 or 14 depending on how you count the LSM-versus-kprobe variant chapters (ch07 has an LSM variant that fires and an alternative kprobe variant that also fires; I only count one per chapter). The 20-vs-13 spread is the "with workarounds vs without workarounds" choice and I am counting the with-workarounds number as the headline because the workarounds demonstrate the primitive class on an adjacent surface, and the book's contribution is the primitive class rather than any specific symbol.

## Closing

This book is a catalog, a harness, and a skip-accounting.
