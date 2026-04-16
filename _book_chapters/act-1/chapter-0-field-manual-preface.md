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

## A brief history of CAP_BPF

Before kernel 5.8, loading a BPF program meant holding `CAP_SYS_ADMIN`. That was the whole bar. Any observability tool that wanted to attach a kprobe, load an XDP program, or create a perf-event array had to run as root, or had to be granted a capability that effectively amounted to root for anything that lived in `/proc`, `/sys`, or a namespace boundary. The mismatch between what those tools actually needed and what `CAP_SYS_ADMIN` conveyed was large enough to become a maintenance burden.

Commit `2c78ee898d8f` landed in 5.8 and split the BPF surface out of `CAP_SYS_ADMIN` into its own capability. The commit message is specific about the motivation. The new `CAP_BPF` was defined as the permission required to load most BPF program types, create most map types, and perform map lookup and update operations. It did not convey the ability to attach tracing programs; that was carved off into `CAP_PERFMON`. And it did not convey the ability to do the genuinely-administrative things that `CAP_SYS_ADMIN` still protects: module loading, arbitrary namespace operations, `BPF_PROG_TYPE_LIRC_MODE2` and a handful of other program types that were considered too dangerous for the new capability to cover on their own.

The lwn.net coverage at the time walked through the debate. There was a line of concern that splitting `CAP_SYS_ADMIN` created a false sense of least privilege: if the new capability was itself powerful enough to read kernel memory via `bpf_probe_read_kernel`, then granting it to an observability agent was not meaningfully different from granting root. Alexei Starovoitov's position in the patch threads was that the verifier's constraints — type-safety, memory-safety, bounded loops, helper allowlisting — were the actual safety boundary, and the capability split was about aligning the permission surface with what the verifier already enforced.

That argument is worth taking seriously, and it is also the argument this book is designed to stress-test. If the verifier is the actual boundary, then the question becomes: what can a verified program do, given `CAP_BPF` plus `CAP_PERFMON`? The answer turns out to be a lot more than most operators realize when they check the "grant CAP_BPF" box in their DaemonSet manifest.

The split has had downstream consequences in userspace. `libbpf` gained the ability to detect at runtime which capabilities were held and fall back to `CAP_SYS_ADMIN` if `CAP_BPF` was not present. Systemd services picked up `AmbientCapabilities=CAP_BPF CAP_PERFMON` as a common pattern. Kubernetes securityContext examples in the ebpf.io gallery started recommending the pair as the minimum grant for an eBPF workload. Each of those downstream changes widened the footprint of processes holding the capability, which in turn widened the footprint of processes capable of doing everything in this book.

One thing the history does not contain is a major regression tied to the split. In six years of shipping, the `CAP_BPF` boundary has held: no advisory I can find describes a kernel bug where a process with only `CAP_BPF` gained root that a process with `CAP_SYS_ADMIN` would not have gained. The verifier has had bugs. The JIT has had bugs. But the capability model itself has not been the vulnerable piece. That is worth stating up front, because this book is not about breaking the capability model. It is about describing what the capability model intentionally grants.

A second historical note worth recording: the `unprivileged_bpf_disabled` sysctl flipped from `0` to `2` across most distributions in 2021, in the wake of a run of verifier CVEs that were exploitable from unprivileged users (CVE-2021-3490, CVE-2021-31440, and others). That sysctl is orthogonal to `CAP_BPF` — it governs whether an unprivileged process can call `bpf(2)` at all — but the distribution-wide flip set the cultural baseline that BPF program load is a privileged operation. Granting `CAP_BPF` is, in practice, the re-enabling of that privilege for a specific workload. This book's audience is operators who have made that grant.

A third note. The capability split has interacted in interesting ways with user namespaces. A process in a user namespace holding `CAP_BPF` in that namespace does not, by default, get the full `CAP_BPF` surface — the kernel's `ns_capable_noaudit` checks gate several operations on being in the init user namespace. The exact list of ns-restricted operations has shifted across versions; on 6.12, `bpf_probe_read_kernel` from a kprobe attached inside a non-init user namespace still works if the namespace has the capability, but the program load itself will reject if `unprivileged_bpf_disabled=2` is set globally. The upshot is that user-namespace-based sandboxing is not a full mitigation against the techniques in this book; it narrows the attack surface without eliminating it.

## The three capabilities, one at a time

`CAP_BPF` is narrower than most operators think. On kernel 6.12, holding `CAP_BPF` alone gets you:

- Access to the `bpf(2)` syscall.
- The ability to load most program types that do not require `CAP_PERFMON` or `CAP_SYS_ADMIN` — notably `BPF_PROG_TYPE_SOCKET_FILTER`, `BPF_PROG_TYPE_CGROUP_SKB`, `BPF_PROG_TYPE_SK_MSG`, and a few others.
- The ability to create most map types, including `BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_ARRAY`, `BPF_MAP_TYPE_RINGBUF`, and the per-cpu variants.
- Map lookup and update operations on maps the process already has an fd for.

It does not get you tracing programs. It does not get you kprobes. It does not get you most of the things this book describes. For those, you need `CAP_PERFMON`.

`CAP_PERFMON` was introduced in the same 5.8 window as a companion capability. It governs the perf-event subsystem — `perf_event_open(2)`, tracepoint attachment, most kprobe attachment, uprobe attachment — and the BPF program types that hook into that subsystem. On 6.12, the list that specifically requires `CAP_PERFMON` includes `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_TRACEPOINT`, `BPF_PROG_TYPE_PERF_EVENT`, and `BPF_PROG_TYPE_RAW_TRACEPOINT`. This is the capability that makes the techniques in this book possible. Every chapter that uses `SEC("kprobe/...")` or `SEC("tracepoint/...")` is implicitly asking for `CAP_PERFMON` as well as `CAP_BPF`.

`CAP_SYS_ADMIN` is the historical catch-all and remains the superset. Holding `CAP_SYS_ADMIN` gets you everything `CAP_BPF` and `CAP_PERFMON` do, plus the program types that did not get carved out: `BPF_PROG_TYPE_LIRC_MODE2`, `BPF_PROG_TYPE_EXT` (used for `freplace`), and the LSM programs that attach to security hooks. `CONFIG_BPF_LSM=y` changes the story slightly — LSM program attachment still wants `CAP_SYS_ADMIN` on most distributions' default configs, though some kernels have relaxed this to `CAP_MAC_ADMIN` when the LSM is the exclusive owner of the hook.

The observability-stack default grant pattern is `CAP_BPF + CAP_PERFMON`. That is what Cilium's documentation recommends for its agent. It is what Pixie's helm chart sets. It is what Tetragon asks for in its default install. It is also the exact grant required for every technique in chapters 1 through 18 of this book that does not explicitly call out a need for `CAP_SYS_ADMIN`. If your threat model accepts "observability agent holds CAP_BPF + CAP_PERFMON," it has already accepted the starting conditions of this book.

It is worth pausing on what "default" means here. Every observability agent I examined requests `CAP_BPF + CAP_PERFMON` as a minimum and frequently requests `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, and a subset of `CAP_DAC_READ_SEARCH` on top. The vendor documentation rarely walks through the downstream consequences of each capability; the docs treat the grant as a checkbox. When a security team asks "what does this agent actually do with `CAP_BPF`," the honest answer is "anything this book describes, plus whatever the agent's own feature set adds on top." The agent's source code is the authoritative reference; the docs are a summary that tends to undersell the surface area.

```bash
# What a typical observability DaemonSet requests
securityContext:
  capabilities:
    add:
    - CAP_BPF
    - CAP_PERFMON
    - CAP_NET_ADMIN  # for tc-bpf, XDP via netlink
```

```bash
# Verifying a running process holds what you think it does
getpcaps $(pgrep my-agent)
# my-agent: cap_net_admin,cap_perfmon,cap_bpf=ep
```

The program-type-to-capability mapping is enforced in `kernel/bpf/syscall.c` in `bpf_prog_load`. The check is explicit: if the program type is in the perfmon list and the caller does not hold `CAP_PERFMON`, `EPERM`. If the program type is in the sys-admin list and the caller does not hold `CAP_SYS_ADMIN`, `EPERM`. Everything else falls back to `CAP_BPF`. A process holding only `CAP_BPF` that tries to load a kprobe program gets a clear rejection at load time, not a silent failure at attach time. This is one of the places where the capability model's design choices show up in the error surface.

A concrete mapping, for reference. These are the program types this book uses, and the minimum capability grant for each:

- `BPF_PROG_TYPE_KPROBE` — `CAP_BPF + CAP_PERFMON`. Chapters 1, 2, 3, 8, 9, 11, 12, 14.
- `BPF_PROG_TYPE_TRACEPOINT` — `CAP_BPF + CAP_PERFMON`. Chapters 4, 7.
- `BPF_PROG_TYPE_PERF_EVENT` — `CAP_BPF + CAP_PERFMON`. Chapter 6.
- `BPF_PROG_TYPE_TRACING` (fentry/fexit/lsm) — `CAP_BPF + CAP_PERFMON`, and in some configs `CAP_SYS_ADMIN` for the LSM subtype. Chapter 13, and the non-sleepable LSM path in Chapter 1.
- `BPF_PROG_TYPE_XDP` — `CAP_BPF + CAP_NET_ADMIN`. Chapters 5b, 15.
- `BPF_PROG_TYPE_SCHED_CLS` (tc-bpf) — `CAP_BPF + CAP_NET_ADMIN`. Chapter 17.
- `BPF_PROG_TYPE_CGROUP_SKB`, `BPF_PROG_TYPE_CGROUP_SOCK` — `CAP_BPF + CAP_NET_ADMIN`. Chapter 16.

The `CAP_NET_ADMIN` dependency for network-layer programs is frequently forgotten. A process with only `CAP_BPF + CAP_PERFMON` can load a kprobe but cannot attach an XDP program to an interface. The attachment is done via netlink, and the netlink socket binding is gated on `CAP_NET_ADMIN` in the target network namespace. This is why XDP-based techniques are narrower in practice than kprobe-based ones: the capability cost is higher.

There is a tempting shortcut worth warning against. On kernels with `CONFIG_USER_NS=y` and `kernel.unprivileged_userns_clone=1`, a user can enter a new user namespace, gain `CAP_BPF` within it, and attempt to load a program. The program load will usually fail because `unprivileged_bpf_disabled=2` checks the init-namespace capability. This closes the easy path. But a root process that has dropped to `CAP_BPF` and entered a new user namespace retains effective `CAP_BPF` in that namespace and can load programs. This is the path that workload-level capability grants take. The book assumes this starting condition.

## What the verifier actually checks

The verifier is the component that turns "BPF is arbitrary code running in kernel context" into "BPF is constrained code running in kernel context." Everything the capability model permits is gated by the verifier's acceptance. Understanding what the verifier checks is therefore the key to understanding what `CAP_BPF + CAP_PERFMON` actually conveys.

The verifier's responsibilities, in rough order of what trips programs up most often:

- **Type safety.** Every pointer has a type derived from how it was produced. A pointer returned by `bpf_map_lookup_elem` is `PTR_TO_MAP_VALUE_OR_NULL` until the program null-checks it, at which point one branch has `PTR_TO_MAP_VALUE` and the other has `SCALAR_VALUE`. Dereferencing the wrong-branch pointer gets you a rejection with "dereference of modified ctx ptr" or similar.
- **Memory safety.** Reads and writes to a pointer must be within the object's known bounds. If the verifier can prove an access is out of bounds, the program is rejected. If the verifier cannot prove the access is in bounds, the program is rejected. There is no "probably fine" path.
- **Termination.** The verifier must prove the program terminates. Historically this was done by rejecting all backward jumps, which is why BPF programs were unrolled loops up through 5.2. Bounded-loop support landed in 5.3 and lets the verifier accept loops with a compile-time-bounded trip count. Unbounded loops are still rejected.
- **Helper function access control.** Each helper is tagged with which program types can call it and what arguments it expects. `bpf_probe_read_kernel` is available from tracing programs but not from socket filters. `bpf_override_return` is available from kprobe programs but only when the target function is in the error-injection list. The verifier checks both the program type and the argument types at each helper call site.
- **BTF requirements.** Programs that attach to a specific kernel function by BTF ID — LSM programs, fentry/fexit, tracing programs that use `SEC("fentry/...")` — need the kernel to have BTF compiled in (`CONFIG_DEBUG_INFO_BTF=y`). The verifier refuses to attach the program if the BTF ID does not resolve.
- **Stack depth.** BPF programs have a fixed 512-byte stack. The verifier tracks worst-case stack usage across the call graph and rejects programs whose stack would exceed the budget. Tail calls consume an additional stack frame; the verifier tracks tail-call depth and caps it at 33.
- **Instruction budget.** Pre-5.2 kernels capped BPF programs at 4096 instructions. Post-5.2 kernels with `CAP_BPF` raised the cap to one million instructions. The verifier enforces this cap and also bounds the total verification time — a program whose verification walks too many states is rejected with `BPF program is too large. Processed N insn`.

The checkpoint for most of these checks lives in `kernel/bpf/verifier.c`. The function-call-checking logic sits around the `check_attach_btf_id` area for BTF-based attach points and in `check_helper_call` for helper invocations. Line numbers drift between kernels, so rather than pin specific lines, the pattern worth learning is: `do_check` walks the instruction stream, `check_helper_call` validates each helper invocation against the program-type allowlist, and `check_attach_btf_id` validates that the program's attach target is compatible with the program type.

A worked example. The following program tries to dereference a pointer without a null check:

```c
SEC("kprobe/do_unlinkat")
int bad(struct pt_regs *ctx) {
    u32 key = 0;
    struct value *v = bpf_map_lookup_elem(&my_map, &key);
    return v->count; // verifier rejects: v may be NULL
}
```

The rejection message is specific: `R1 type=map_value_or_null expected=map_value`. The verifier has proven that `v` can be `NULL` at this point because the lookup helper's return type is `PTR_TO_MAP_VALUE_OR_NULL`, and the dereference is unconditional. Adding `if (!v) return 0;` before the dereference narrows `v` to `PTR_TO_MAP_VALUE` on the passing branch, and the program loads.

Another worked example. The following program passes `pid_tgid` as a scalar through a map lookup:

```c
SEC("kprobe/cap_capable")
int good(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    int *cap = bpf_map_lookup_elem(&in_flight, &id);
    if (!cap) return 0;
    bpf_printk("cap=%d\n", *cap);
    return 0;
}
```

The verifier accepts this. The key is a scalar, the map lookup returns a typed pointer, the null check narrows the type, and the dereference is on the narrowed pointer. This is the shape every probe in this book uses.

The verifier's job is not to decide whether a program is malicious. It is to decide whether the program is memory-safe and terminates. A program that silently exfiltrates every capability check to a ringbuf is, as far as the verifier is concerned, well-typed. The boundary between "verified" and "safe" is the gap this book lives in.

A third worked example, showing the bounded-loop path. On kernels before 5.3, a program that wanted to iterate over a fixed-size array had to be fully unrolled:

```c
SEC("kprobe/do_something")
int unrolled(struct pt_regs *ctx) {
    u32 i;
    int total = 0;
    // pre-5.3: manually unrolled, verifier rejects real loops
    #pragma unroll
    for (i = 0; i < 8; i++) {
        int *v = bpf_map_lookup_elem(&arr, &i);
        if (v) total += *v;
    }
    return total;
}
```

On 5.3 and later the same program loads without `#pragma unroll` because the verifier can prove the loop's trip count is bounded at compile time. The verifier still rejects unbounded loops — any loop whose termination depends on runtime state — because it cannot prove termination in polynomial time. The `bpf_loop` helper, added in 5.17, provides an escape hatch: the helper takes a callback and a count, and the verifier trusts the callback's bounded invocation count without walking the loop body symbolically.

A fourth worked example, showing the BTF-ID requirement. An LSM program attaches to a hook by BTF ID, not by function name:

```c
SEC("lsm/file_permission")
int BPF_PROG(check_read, struct file *file, int mask) {
    // verifier needs CONFIG_DEBUG_INFO_BTF=y on the running kernel
    // to resolve "file_permission" to a BTF ID at attach time
    return 0;
}
```

On a kernel without BTF, the attach fails with `ENOENT` at `BPF_RAW_TRACEPOINT_OPEN` or the LSM equivalent. On a kernel with BTF but without `CONFIG_BPF_LSM=y`, the hook does not exist and the attach fails for a different reason. The verifier's check and the attach-time check are separate — the program may verify fine and still refuse to attach.

The verifier has grown considerably since 5.8. The 6.12 verifier is roughly 20,000 lines of C; the 5.8 verifier was under 10,000. The growth reflects the program-type surface, not a fundamental rearchitecture: each new program type, each new helper, each new map type has its own verification path, and the path is additive. This is relevant for defenders because the verifier's complexity is also the attack surface for verifier CVEs. None of the techniques in this book depend on verifier bugs, but a defender planning long-term should expect more verifier CVEs over time simply because the component keeps growing.

## What ALLOW_ERROR_INJECTION is for

`ALLOW_ERROR_INJECTION` is a macro defined in `include/asm-generic/error-injection.h`. A kernel function annotated with it is recorded at build time into a special section, and the resulting list is exposed to userspace at `/sys/kernel/debug/error_injection/list`. The original purpose of the annotation was fuzz-testing: if you wanted to test how the rest of the kernel handled errors from a specific function, you could mark that function as injectable and have a test harness flip its return value to various error codes.

The list is curated per-kernel. The kernel maintainers decide, function by function, whether an annotation is appropriate. The criteria are not formally published, but the pattern is clear from the annotated set: syscall entry points and filesystem operations get annotated frequently; core security decision functions do not.

```bash
# On a linuxkit 6.12 VM
cat /sys/kernel/debug/error_injection/list | head
# do_unlinkat EI_ETYPE_NULL
# do_mkdirat EI_ETYPE_NULL
# do_renameat2 EI_ETYPE_NULL
# do_symlinkat EI_ETYPE_NULL
# ...
```

The relevance to this book is that `bpf_override_return` — the helper that lets a kretprobe change the return value of the function it attaches to — only lands on functions in that list. The verifier accepts the program regardless; the override-check happens at runtime when the kretprobe fires. If the target function is not in the allowlist, the helper returns without modifying the return register, and the kernel logs nothing. This is the failure mode I hit against `cap_capable` in Chapter 1.

The annotated set is skewed toward syscall entries. `do_unlinkat`, `do_mkdirat`, `do_renameat2` — these are all annotated because they are places where error injection makes sense as a test primitive. The filesystem will cope with an `-ENOMEM` from `do_unlinkat` because that is a return value the caller already has to handle. Annotating a function where failure is not a supported path would cause test infrastructure to produce spurious bug reports.

The set is equally notable for what is missing. `cap_capable` is not annotated. `security_file_permission` is not annotated. `avc_has_perm` is not annotated. Every decision function — every function whose return value expresses the kernel's security policy — is deliberately excluded. The exclusion is the kernel maintainers telling you that error-injection is for testing error paths, not for policy override.

The BPF subsystem inherited the error-injection list as the allowlist for `bpf_override_return`. This inheritance is not automatic; it is a design decision, documented in the `kprobe_override` commit logs. The argument is that if a function is safe for test infrastructure to corrupt, it is also safe for a privileged BPF program to corrupt. The converse — if a function is too sensitive for test corruption, it is too sensitive for BPF override — has the same force.

Kernel 6.12 has roughly 60 functions in the list on a standard linuxkit build. The exact count varies by config. Checking the list against a target function before writing the POC saves a lot of time. The workflow is: pick a target, check `/sys/kernel/debug/error_injection/list`, and if it is not there, rewrite the technique around observation rather than override. Chapter 1 is the long form of that workflow.

```c
// A representative entry from fs/namei.c, annotated for error injection.
// Both the annotation and the kretprobe-override path land here.
long do_unlinkat(int dfd, struct filename *name)
{
    // ...
    return retval;
}
ALLOW_ERROR_INJECTION(do_unlinkat, ERRNO);
```

The `ERRNO` in `ALLOW_ERROR_INJECTION(do_unlinkat, ERRNO)` declares the injection category: the return value can be overridden to any negative errno. Other categories exist — `TRUE`, `FALSE`, `NULL` — but `ERRNO` is what the filesystem entries use, and it is what `bpf_override_return` targets. A kretprobe can override the return to any value the verifier can produce as an integer, with no further runtime check once the allowlist lookup succeeds.

The runtime dispatch lives in `kernel/trace/trace_kprobe.c` and `arch/*/kernel/kprobes.c`. On aarch64, the kretprobe fire path checks a per-kprobe flag set at attach time by the BPF program-load path; if the flag is set and the target's error-injection entry is present, the helper's stored override value replaces the return register. If the flag is not set, or if the target was not in the allowlist at attach time, the helper runs but its effect is discarded. No message is emitted in either case; the silence is the key failure mode.

A second workflow consequence. If you want to find *all* the functions you could override from BPF on a specific kernel, `cat /sys/kernel/debug/error_injection/list` is the authoritative source. Cross-referencing the list with `/proc/kallsyms` gives you the subset that is also currently loaded (some annotated functions are in modules that may not be loaded). The intersection is typically 40-50 functions on a running 6.12 system. That is the override primitive's full surface for any given kernel.

The list is append-only in practice. Once a function is annotated, removing the annotation is a breaking change for test infrastructure and happens rarely. This means that the set of override-eligible functions grows slowly over kernel releases, and that a technique that depends on a specific allowlisted function will keep working across upgrades. Chapter 11's override of `do_unlinkat`, for instance, has been stable since 5.4.

## The taxonomy, foreshadowed

Chapter 20 formalizes the five-class taxonomy of primitives that actually fired on this kernel. Each class has a characteristic shape and a characteristic failure mode. Knowing the shape is useful for knowing which chapters to read together.

**Class 1: Return override.** A kretprobe on a function in `ALLOW_ERROR_INJECTION` uses `bpf_override_return` to change the function's return value. The primitive is narrow — the function has to be in the allowlist — and the failure mode is silent when the allowlist check fails. Chapters 11 and 12 fire this against filesystem entry points.

**Class 2: Buffer rewrite.** A fentry or LSM program with sleepable context rewrites a buffer in the caller's address space before the caller reads it. The primitive is broad in principle and narrow in practice, because the verifier is strict about which buffers are writable from which attach points. Chapter 13 fires this against `vfs_read` output.

**Class 3: Out-of-band copy.** A probe on any decision function captures the decision's inputs and outputs and streams them to a ringbuf for a userspace consumer. No override required; pure observation. This is the shape Chapter 1 and most of Act 2 use.

**Class 4: XDP.** An XDP program attached to an interface observes, rewrites, or exfiltrates packets before they reach the kernel's network stack. The primitive is independent of the capability stack most of this book uses, because XDP attaches at a lower layer. Chapters 5b and 15 fire this.

**Class 5: Ringbuf-as-trigger.** A userspace consumer reads events from a BPF ringbuf and reacts — spawning a process, writing a file, making a network call. The BPF program is the sensor; the reaction is in userspace. This is how every chapter turns a kernel-side observation into an actual effect. Chapter 3 is the archetype.

The primitive classes are not mutually exclusive within a chapter. A chapter that observes a syscall and then has a userspace reaction is using Class 3 and Class 5 together. A chapter that overrides a return and also streams observations to userspace is using Class 1 and Class 5 together. The taxonomy is over primary primitives; a chapter's secondary primitives are called out in the chapter's header.

A primitive's class is also a rough predictor of its detection difficulty. Class 1 (return override) is the easiest to detect: the target function is in a short allowlist, and a defender watching for kretprobe attachments to that allowlist will catch it. Class 3 (out-of-band copy) is harder: any decision function is a valid target, and the attachment looks like legitimate observability tooling. Class 4 (XDP) is the hardest on an interface-by-interface basis, because XDP attachment is a normal operation for network tooling and the defender cannot tell by attachment alone what the XDP program is doing. The detection-difficulty gradient drives Chapter 22's recommendation priority.

Each chapter is tagged with which class its primary primitive belongs to. The failure-mode chapters (21) are tagged by which class failed.

The taxonomy is not a partition of all possible BPF techniques. It is a partition of the techniques that fired on this specific kernel in this specific configuration. Other classes exist — cgroup-based filtering, socket-reuseport load balancing, BPF-based tracing for performance — and they are not represented here because they did not produce a primitive that a capability-holding attacker would use for a meaningful effect. Chapter 20 discusses the boundary between "in the taxonomy" and "out of the taxonomy" in more detail. For now, the five classes are sufficient as a reading guide.

A practical consequence of the taxonomy is that the chapters within a class share code. The two override chapters (11, 12) use nearly identical BPF skeletons, differing only in which syscall entry they attach to and what override value they produce. The XDP chapters (5b, 15) share the same tc/XDP plumbing. The ringbuf-as-trigger chapters share a common userspace consumer shape. Readers can skim within a class once they have read one chapter in that class carefully.

The other practical consequence is that the defender's job is class-shaped. Detecting a Class 3 primitive (out-of-band copy) means watching for kprobe attachments to decision functions; the specific target function is secondary. Detecting a Class 1 primitive (return override) means watching for kretprobe attachments to functions on `/sys/kernel/debug/error_injection/list`; again, the specific target is secondary. Chapter 22's defender playbook is organized by class for this reason.

## Non-claims

- **Not novel research.** The `d_reclen` swallow trick for hiding directory entries (chapter 10) has prior art in rootkit POCs going back to at least 2016. XDP as a covert exfil channel (chapter 5b, chapter 15) is a well-trodden path. PID-namespace sidechannels (chapter 9) have appeared in prior container-escape work. The contribution here is a reproducible harness on current kernels, an honest taxonomy, and explicit scope — not novelty. Where a technique has a clear prior-art reference, it is cited in the chapter's footer. Where I could not find a prior-art reference, the chapter says so and does not claim novelty on that basis alone.
- **Not an escalation path.** Remove `CAP_BPF` from the threat model and every chapter stops working. There is no "but what if the attacker does not have the capability" section, because the answer is: they cannot do any of this. The book is explicit about this because the opposite assumption is how threat-model discussions go sideways. If your deployment does not grant `CAP_BPF` to untrusted code, this book is a description of what you are protecting against, not a toolkit against you.
- **Not a verifier bug catalog.** Every program that attached in this book was accepted by the verifier doing its job. Where the verifier refused a program, the chapter records the refusal and moves on. If you came here for a verifier exploit, you are in the wrong manual. The verifier has had CVEs; none of them are used here.
- **Not a zero-day drop.** Everything in this book uses documented helpers, documented attach points, and documented program types. The techniques work because the capability was granted and the kernel behaved as designed. A kernel update does not close any of these primitives unless it changes the design.
- **Not a hardening guide in isolation.** Chapter 22 sketches detection and prevention options, but the book's center of mass is the attacker's side of the capability boundary. A defender reading only Chapter 22 will miss the texture of what they are defending against.

## How to read this book

Start with the chapter you are worried about. The chapters are independent enough that the taxonomy in Chapter 20 is the navigation aid if you want one, and Chapter 21 is the honest-failures list if you want the other.

**If you are an operator** deciding whether to grant `CAP_BPF` to a workload: read Chapter 0 (this one), skip to Chapter 22 for the defender playbook, then walk Chapters 1 through 18 in order. The operator reading order prioritizes detection and baseline-diff recipes over attack detail. By the time you finish Chapter 22, you should have a concrete list of `bpftool`, `auditd`, and `/sys/kernel/debug/` signatures that your monitoring stack needs to cover.

**If you are a researcher** extending the taxonomy: read Chapter 0, then Chapter 20 for the five-class framing, then Chapters 1 through 18 in whatever order the taxonomy suggests, then Chapter 21 for the failure catalog. The researcher reading order treats the chapters as data points in a classification and prioritizes the framing over the individual techniques.

**If you are on a red team** with an engagement in flight: pick the chapter whose primitive matches your goal, check Chapter 21 to see if that primitive's failure-mode applies to your target kernel, then read the chapter. The red-team order is the only one that treats the book as a reference manual rather than a narrative.

**If you are a kernel developer** reading to verify the claims: the harness at `dBPF-pocs/harness/proof.py` runs every chapter's trigger on a clean VM and records the BEFORE/AFTER output. Every claim is machine-grep-able. Where a claim turns out to be wrong, I want to know. The repository issue tracker is the right venue.

The chapters are roughly linear in the original writing order. That is an artifact, not a recommendation. Linear reading is fine; topical reading is also fine. The only chapter I would read first regardless of goal is this one, because it sets the scope that everything else depends on.

## The target environment

Every claim in this book was tested against a specific environment. Writing the environment down here, once, lets every subsequent chapter omit the boilerplate and keep the chapter-level focus on the technique.

The kernel is 6.12.54-linuxkit, aarch64. This is the kernel shipped by Docker Desktop on Apple Silicon as of late 2024; the exact version drifts with Docker Desktop updates, but the `6.12.*` line is stable. Linuxkit's kernel config is close to a minimal `defconfig` with the BPF and tracing subsystems enabled. Specifically, the following config entries are set:

- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_BPF_JIT=y`
- `CONFIG_BPF_EVENTS=y`
- `CONFIG_BPF_LSM=y`
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_KPROBES=y`
- `CONFIG_KPROBE_EVENTS=y`
- `CONFIG_BPF_KPROBE_OVERRIDE=y`
- `CONFIG_FUNCTION_ERROR_INJECTION=y`
- `CONFIG_UPROBES=y`

`CONFIG_BPF_KPROBE_OVERRIDE=y` is worth calling out. On kernels where this config is not set, `bpf_override_return` is not even exposed to programs at verification time; the verifier rejects any use of the helper. The linuxkit default enables it, which is why Chapter 1 can get as far as "the override loads and silently no-ops" rather than "the override is rejected at load time." A hardened production kernel might disable this config and close the primitive entirely.

The userspace toolchain is `libbpf` from `libbpf/libbpf` at a tag close to 1.4, `clang`/`llvm` 17 for BPF CO-RE compilation, and `bpftool` from the same kernel tree as the running kernel. The harness scripts are Python 3.11 using `psutil` for process introspection and `subprocess` for test orchestration. No external dependencies beyond what a standard development container provides.

The threat model is a process running inside a container with `CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN` ambient, the container's filesystem mounted read-write, `/sys/kernel/debug` bind-mounted read-write, `/sys/fs/bpf` bind-mounted read-write, and network egress permitted. This is close to the grant an observability DaemonSet with broad permissions receives in a real cluster. A stricter grant (no `/sys/kernel/debug`, no `/sys/fs/bpf`) narrows the attack surface but does not eliminate it; Chapter 21 discusses which techniques fail under each restriction.

The harness at `dBPF-pocs/harness/proof.py` orchestrates the test matrix. For each chapter, it builds the POC, loads it into a Docker container, runs the trigger, collects the BEFORE/AFTER output, and writes the result to `dBPF-pocs/results/ch<nn>.json`. The result file includes the exact kernel version, the exact libbpf version, the BPF program bytecode hash, and the BEFORE/AFTER markers. Reproducing the book's claims means running the harness and diffing against the shipped results.

## What this book is not going to cover

There are directions the reader might expect this book to go that it deliberately does not.

**Kernel exploitation beyond the verifier boundary.** If a verifier CVE is what makes a technique work, the technique is out of scope. The book's entire premise is that the capability grant, not the bug, is what enables the primitives. Documenting verifier CVEs would undermine that premise by conflating "things a capability-holder can do" with "things an attacker exploiting a kernel bug can do."

**Userspace exploitation after a capability is gained.** Chapters stop once the BPF-side primitive produces its effect. The userspace consumer of a ringbuf is described only to the extent needed to demonstrate the primitive fires. How an attacker with a ringbuf feed of capability checks then escalates to persistence, lateral movement, or data exfiltration is documented in many other places and is not a BPF-specific topic.

**Windows, macOS, or BSD equivalents.** Windows has eBPF via the `ebpf-for-windows` project; macOS has limited tracing facilities via DTrace and the Endpoint Security framework; FreeBSD has its own tracing stack. None of these are covered. The book is Linux-specific on purpose: the threat model, the capability grants, and the verifier behavior are all Linux artifacts.

**Pre-5.8 kernels.** The capability split is the book's assumption. Techniques against kernels old enough to lack the split are out of scope because their threat model is different (`CAP_SYS_ADMIN` or nothing). Some techniques would work on older kernels with straightforward adjustments; the book does not document them because the audience of this book is operating modern kernels.

**Production incident response.** The book describes what an attacker holding `CAP_BPF` can do. It does not walk through how a defender responds to an active intrusion where those capabilities are in use. Incident response is a discipline with its own literature, tooling, and workflows. The defender-oriented material in Chapter 22 is a starting point for monitoring design, not a runbook for triage.

## Notation conventions

A few conventions used throughout the book, collected here for reference.

- **Kernel line numbers** are given relative to the 6.12 source tree as shipped by linuxkit. Line numbers drift between kernel versions; where precision is possible, the book names a function or a code region rather than a line.
- **BTF type names** are quoted as they appear in the kernel's BTF, typically the same as the C struct name (`struct task_struct`, `struct cred`). Where the BPF program uses CO-RE relocations, the book says so explicitly.
- **Capability names** are written `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` in uppercase. The kernel's internal representation uses lowercase constants (`CAP_NET_ADMIN` → value 12); the book uses whichever form is clearer in context.
- **Helper names** are written with the `bpf_` prefix (`bpf_override_return`, `bpf_probe_read_kernel`) as they appear in C code. Userspace-facing helpers use their libbpf names.
- **Command examples** assume a bash shell inside the harness container. `#` denotes a root-in-container prompt; `$` denotes an unprivileged prompt where relevant. The book does not show prompts that are not load-bearing for the example.
- **BEFORE/AFTER** markers denote the state captured by the harness at trigger time. `BEFORE` is the state immediately before the BPF program is loaded or triggered; `AFTER` is the state immediately after. A technique "fires" when BEFORE differs from AFTER in the expected direction.
- **`CH<nn>_WEAPON_PROVEN`** and similar markers are machine-grep-able strings the harness writes on success. The exact marker for each chapter is listed in that chapter's footer.
- **"Stock kernel"** means the linuxkit 6.12 kernel with the config given above. "Hardened kernel" refers to a hypothetical kernel with `CONFIG_BPF_KPROBE_OVERRIDE=n` and `unprivileged_bpf_disabled=2`.

## A note on responsible disclosure

Nothing in this book constitutes a vulnerability report. Every technique uses documented, intentional kernel interfaces; every capability grant is one the operator made on purpose; every primitive is the kernel behaving as the maintainers designed. There is no vendor to notify because there is no bug.

There is, however, an ongoing conversation in the kernel-security community about whether the capability split's guarantees are strong enough. I have tried to reflect that conversation honestly. Where a technique feels like it should be forbidden but is not, the chapter says so and explains why the kernel maintainers have chosen not to forbid it. Where a technique is genuinely bounded by the verifier or by an allowlist, the chapter says that too.

If a reader believes a specific claim in this book is wrong — a technique does not actually fire, a kernel version detail is inaccurate, a capability dependency is mis-stated — the book's repository is the right place to file an issue. Reproducible disagreement is how the record improves.

## What to expect in the individual chapters

Every chapter follows roughly the same shape. The shape is not enforced rigidly; some chapters truncate a section because the technique does not warrant it, and some chapters expand a section because the technique has an unusual quirk. But the rough shape is:

1. **Opening** — a few paragraphs of the investigative voice: what I was trying to do, what I found out, what surprised me.
2. **Target** — what kernel function, syscall, or subsystem the technique attaches to.
3. **The probe** — the BPF C source, usually with per-line commentary on the non-obvious parts.
4. **Loader** — the userspace side, typically a short C or Python program that loads the BPF object, attaches it, and consumes the ringbuf.
5. **Trigger** — how the technique is provoked. For override chapters this is the syscall being intercepted; for observation chapters this is a test workload that exercises the decision function.
6. **BEFORE/AFTER** — the captured harness output, verbatim, showing the state change.
7. **Detection** — what signatures a defender running `bpftool`, `auditd`, `/sys/kernel/debug/`, or a behavior-based EDR would produce.
8. **Variations** — other kernel functions the same technique applies to, other attach points, other output shapes.
9. **Closing** — what this chapter actually gives you, in one or two paragraphs.

Chapters 20, 21, and 22 deviate from this shape because they are cross-cutting: 20 is the taxonomy, 21 is the failure catalog, 22 is the defender playbook. All three reference the chapter-specific material rather than introducing new techniques.

The book's chapters are numbered for reference, not for ordering. If chapter 5b appears between chapter 5 and chapter 6, that is because chapter 5b was written later and shares a theme with chapter 5 (XDP-based exfil) but treats a distinct primitive. The "b" suffix is a Knuth-style insertion; the numbering makes it convenient to reference chapters without reshuffling.

## A representative failure mode

To set expectations for the honesty this book attempts, here is a representative failure mode that recurs through the manuscript.

A technique looks like it should work. The verifier accepts the program. The kernel attaches the probe. The trigger fires. `bpftool prog show` confirms the program is loaded. The ringbuf produces events. And yet the side effect the technique was supposed to produce does not occur.

This is the shape of the `cap_capable` override in Chapter 1. It is also the shape of the `security_*` overrides I tried and deleted before they became their own chapters. It is the shape of the `sys_call_table` rewrite path that has been closed in 5.x-era kernels. Each of these failures has a specific cause, and the specific causes are what Chapter 21 catalogs.

The honest form of this book's claim is therefore narrower than "CAP_BPF grants enormous power." The honest form is: CAP_BPF grants the exact power listed in the five-class taxonomy, subject to the failure modes listed in Chapter 21. Some techniques that sound powerful are silently no-ops. Some techniques that sound restricted are fully operational. The distinction is not obvious from the docs; the distinction is why the harness exists.

A defender's operational takeaway is: do not assume a technique does or does not work based on its description. Run it in a staging environment that matches your production kernel and check the harness output. The techniques are reproducible; the failures are also reproducible. Both are useful information.

An attacker's operational takeaway is symmetric: do not assume a technique does or does not work based on its description. The harness results are specific to this kernel; your target kernel may have different config, different BTF, different error-injection allowlist. The book's value is the methodology, not the pre-cooked exploits.

## The scope of "modern kernel"

The book uses "modern kernel" to mean 6.x. The specific version targeted is 6.12, but most techniques work on 6.x kernels going back to 6.1 (the LTS release), and several work on 5.15 or earlier. Where a technique requires a specific kernel feature, the chapter notes the minimum version.

The LTS versions currently in play as of writing are 5.15, 6.1, 6.6, and 6.12. Distributions typically ship one of these. Ubuntu 22.04 LTS ships 5.15 with backports of specific BPF features. Ubuntu 24.04 LTS ships 6.8. Debian 12 ships 6.1. RHEL 9 ships 5.14-based with significant backports. Amazon Linux 2023 ships 6.1. None of these are exotic; all of them support the vast majority of this book.

"Modern" is therefore a floor, not a single version. A technique that works on 6.12 usually works on 6.1. A technique that works on 6.1 often works on 5.15 with caveats. Where a technique does not work on an older kernel, the limitation is typically the verifier (bounded loops, for example) or the allowlist (error-injection entries added in a specific release). The chapter calls out the floor explicitly.

## Reading this book with a live kernel

The most productive way to read the chapters is alongside a running kernel you can attach to. The harness container is designed for this: `docker compose up -d` starts a linuxkit 6.12 VM with the book's expected config, and `docker exec -it dbpf-harness bash` drops you into a shell inside the VM with `bpftool`, `libbpf`, `clang`, and the book's POCs pre-built. Running a chapter's trigger takes seconds; the BEFORE/AFTER output lands in the terminal and in the results file.

Reading without the kernel is also possible. Every chapter's critical output is reproduced inline, verbatim, with the markers the harness emits. A careful reader can follow the argument without running anything. But the book's value is largely in the reproducibility: if you are not at least occasionally running the harness to check a claim, you are reading a description of the techniques rather than learning the techniques.

## One last note before the techniques

The techniques are described from the attacker's point of view because that is the clearest way to convey what the primitive does. This framing is not an endorsement of the attacks. It is the lens that makes the primitives legible. A defender reading a Class 3 chapter gets the best mental model of what they are defending against by thinking like the attacker did while writing it.

The blog posts this book distills were originally written as an honest record of failed attempts. The book tightens the writing and adds connective tissue, but it does not hide the failures. Chapters that describe techniques that silently no-op are as important as chapters that describe techniques that fire. The failure catalog in Chapter 21 is not an appendix; it is a central artifact.

With that, the individual chapters.

## Appendix to the preface: vocabulary

One small appendix before the techniques. The BPF subsystem has accumulated a vocabulary that is easy to confuse, and the book uses several terms precisely. A short glossary:

- **Program.** A compiled BPF bytecode blob, loaded via `BPF_PROG_LOAD`. Has a program type (`BPF_PROG_TYPE_KPROBE`, etc.), an attach type in some cases, and a BTF ID if the kernel resolved one.
- **Attach.** The binding of a loaded program to a specific kernel event source — a kprobe, a tracepoint, an XDP interface, an LSM hook. `BPF_PROG_LOAD` creates the program; `BPF_RAW_TRACEPOINT_OPEN` or the equivalent for the program type attaches it.
- **Map.** A kernel-side data structure accessible by BPF programs and by userspace via the `bpf(2)` syscall. `BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_ARRAY`, `BPF_MAP_TYPE_RINGBUF`, etc.
- **Helper.** A kernel function callable from a BPF program. `bpf_map_lookup_elem`, `bpf_probe_read_kernel`, `bpf_override_return`. Each helper is tagged with which program types may call it.
- **Kfunc.** A kernel function exposed to BPF programs by name rather than by helper ID. Newer, more flexible than helpers; used for BPF-LSM interactions and for some kernel-structure accessors.
- **BTF.** BPF Type Format. A compact debuginfo format that describes kernel types, used for CO-RE and for LSM attach resolution.
- **CO-RE.** Compile Once, Run Everywhere. The libbpf mechanism that rewrites BPF programs at load time to match the running kernel's BTF, making a single program binary portable across kernel versions.
- **Ringbuf.** `BPF_MAP_TYPE_RINGBUF`. A lock-free single-producer-single-consumer ring buffer that replaces the older `BPF_MAP_TYPE_PERF_EVENT_ARRAY` for streaming events to userspace. The book prefers ringbuf for all streaming cases.
- **Sleepable.** A BPF program context that allows helpers that may sleep (`bpf_d_path`, `bpf_copy_from_user`). Only specific program subtypes — `lsm.s/`, fentry with sleepable annotations — are sleepable. Chapter 1 documents the non-sleepable path in detail.

The book uses these terms as defined here. Where a term's usage is ambiguous in the broader ecosystem (the word "probe" is used to mean both a kprobe and any attach point), the book picks one meaning and sticks to it.

With the glossary settled, the book moves to the first technique.

## Appendix: on the choice of linuxkit as the target

A short note on why the target environment is a linuxkit 6.12 VM rather than a physical host or a generic Ubuntu image.

Linuxkit is minimal. The kernel config is readable and the attack surface is small enough that every claim can be checked against the actual binary. A technique that works on linuxkit and not on a stock Ubuntu image usually works on Ubuntu too — the difference is almost always a default-enabled security module or a distribution-specific patch that closes a specific gap. By starting from the minimal environment, the book documents the technique's bare-metal behavior; downstream, a reader can check whether their specific distribution closes the gap.

Linuxkit is aarch64 on Apple Silicon because that is the machine I have on my desk. The techniques translate to x86_64 with two caveats: the register ABI for `PT_REGS_PARM*` macros is different, and the kprobe fire path has slightly different JIT characteristics. Neither caveat changes the conceptual content of any chapter. Where a chapter's code would need adjustment for x86_64, the chapter calls it out; most chapters do not need adjustment because the BPF C compiles to the same bytecode on both architectures.

Linuxkit boots in seconds, which matters for the harness. The full test matrix (22 chapters, each with BEFORE/AFTER capture) runs in under a minute on a clean linuxkit VM. The same matrix on a full Ubuntu VM would take several minutes; on bare metal it would require physical access. The harness's ergonomics were a deciding factor in picking the test environment.

One downside of linuxkit: it is not a production environment. A technique that works on linuxkit is not automatically applicable to a production host, because production hosts run additional tooling — security modules, auditd rules, EDR agents — that may interfere. The book's position is that linuxkit's output is the *upper bound* on what an attacker holding the stated capabilities can do; production deployments close some of the gaps, and Chapter 22's defender playbook describes which ones and how.

## Appendix: versioning and drift

Kernel versions change. This book's claims are specific to 6.12.54-linuxkit aarch64 as of the writing. When a claim diverges on a future kernel, the book's repository is the canonical record; the issue tracker is the place to report divergence.

The most likely sources of drift:

- **Error-injection allowlist changes.** Functions get added and, rarely, removed. A chapter whose override depends on `do_unlinkat` being in the list would notice immediately if the annotation were removed.
- **Verifier behavior changes.** The verifier's acceptance surface expands over time. A program that fails verification on 6.12 may verify on 6.15. The book's claims are lower bounds.
- **LSM hook sleepability changes.** A non-sleepable hook becoming sleepable (or vice versa) changes which program types can attach. The book's specific `SEC("lsm/...")` choices are correct for 6.12 and may need adjustment elsewhere.
- **Helper additions.** New helpers get added in nearly every kernel release. The book does not use a helper that was not available in 6.1 LTS; techniques that use newer helpers would extend the book rather than replace it.

A reader who runs the harness on a different kernel version and notices a divergence has found something worth documenting. Divergence is not a bug; it is data. The book's taxonomy accommodates divergence by describing the class of primitive rather than the specific kernel-version-dependent mechanism.

With the preface complete, the first technique is the kprobe on `cap_capable`.