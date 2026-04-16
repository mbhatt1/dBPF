---
layout: book
title: "Chapter 9: PID Namespace Doppelgänger"
date: 2025-02-09
---

# Chapter 9: Mapping Host PID to Namespace PID

> **See also**: [Blog post]({{ site.baseurl }}/pid-namespace-doppelg-nger.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch09-pid-doppel) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

This one is almost embarrassingly straightforward once you know where to look. There is no clever verifier trick, no instruction-count tetris, no kernel-taint you have to explain away. The primitive — recovering the host-visible PID of a task alongside its namespace-local PID — has been shipping in `bpftrace` examples for years. There is a `pidnss.bt` one-liner in the tracing-tools repos that does exactly this lookup, dated roughly 2020. Academic work on PID-namespace side channels via `sched_process_fork` and related kernel entries showed up around the same time at USENIX Security. I'm not inventing anything. What I am doing — and what this chapter documents — is turning the lookup into an end-to-end, reproducible, CO-RE-built proof with a trigger script that uses the mapping: the trigger spawns a victim inside a freshly-made PID namespace, the BPF program observes the fork, the loader prints the `(host_pid, ns_pid)` pair, and then the harness kills the victim from outside its namespace using only the host PID the BPF program recovered.

The reason that last step matters is that it inverts the container isolation story. Every container runtime — Docker, containerd, CRI-O, runc, Podman, LXC — creates a fresh PID namespace per container. Processes inside the container see a small, local set of PIDs with PID 1 at the root. Processes outside see a disjoint set of PIDs attached to the host namespace. The boundary is enforced by the kernel: `kill(pid, sig)` uses whichever namespace the caller lives in to resolve the target. From inside the container, a process can only name its containermates. From outside, the host sees everything, but *only* by host PID — and operators are trained to think of container workloads in terms of their container-local PIDs, because that's what the container shows them, that's what their orchestrator surfaces, that's what `kubectl exec ps` prints. The PID 1 inside a container is not the same object as the PID 1 on the host. It is a separate `struct pid` with a distinct `task_struct`, distinct `/proc` entry, distinct signal semantics. The mapping between the two is held inside the kernel. It is not, by default, handed out to unprivileged userspace in a form that scales.

That's the wedge. A host-side attacker who can load a BPF program — not necessarily a kernel module, not a LKM rootkit, just a BPF program — can stream the mapping in real time. Every time a new PID namespace is created anywhere on the box, the BPF program learns the `(host_pid, ns_pid, ns_inum)` triple for the process entering it. The attacker, sitting at some outside vantage point (a sidecar, a node agent, a compromised systemd service with `CAP_BPF` or equivalent), gets a live doppelgänger table: for every container process on the box, the host-visible handle. Then every operation that takes a PID — `kill`, `ptrace`, `/proc/<pid>/`, `prlimit`, `waitid`, `pidfd_open` — can be aimed at container-internal processes directly. No need to `nsenter`. No need to find the container's init and `setns()` into it. No need for any of the usual container-escape plumbing. Just the host PID, and the host's own ambient privileges.

I keep saying "almost embarrassingly straightforward" because the code is thirty lines and the idea is older than I am in BPF years. What makes it worth a chapter is that the modern tooling has polished away a lot of the subtleties, and if you aren't careful you'll copy-paste a `pidnss.bt` one-liner into a larger program and have it work for the test case and fail silently for the production case. The subtleties are in two places: reading the right index of `numbers[]`, and choosing a hook point that fires on both `unshare(CLONE_NEWPID)` and `clone(CLONE_NEWPID)`. Miss either and you get a plausible-looking but incorrect mapping.

A brief note on the choice of tense. I'm going to write this chapter in bughunter-diary voice — "I tried this, it failed, here's why, here's what I did instead" — because the POC went through several dead ends and the dead ends are instructive. The finished code in `dBPF-pocs/pocs/ch09-pid-doppel/ch09-pid-doppel.bpf.c` is 82 lines, terse, and if you read only the final file you'll miss the three or four rewrites that got it there. The interesting material is in the deltas.

A second note on prior art. I'm going to keep pointing at `pidnss.bt`, Tetragon, and the USENIX 2020 work as the shoulders this chapter is standing on. That's not false modesty — the primitive genuinely is prior art — but I do want to distinguish between "this exists" and "this is demonstrated end-to-end." The end-to-end demonstration is the contribution, and the reason the trigger script matters. `pidnss.bt` will print you a PID mapping. It will not then use that mapping to kill a process across a namespace. That last step, which takes two lines of shell (`HOST_PID=...; kill -TERM $HOST_PID`), is the one that converts observation into attack.

## What `task_struct` Actually Stores

Walk `include/linux/sched.h` and find the PID-related fields on `struct task_struct`. On 6.12 the shape is:

- `pid_t pid` — the host-visible PID. Always the PID as the root PID namespace sees it. For every task that exists, this is a non-zero integer in the init ns.
- `pid_t tgid` — the host-visible thread group ID. For single-threaded tasks, equal to `pid`. For threads, equal to the `pid` of the thread-group leader.
- `struct pid *thread_pid` — a pointer to the `struct pid` record for this task's PID. This is the indirection that carries the per-namespace views.
- `struct hlist_node pid_links[PIDTYPE_MAX]` — hash-list linkage for PID lookup tables keyed by each PID type.
- `struct nsproxy *nsproxy` — a pointer to a shared namespace-set object. Holds references to all seven namespaces (mnt, uts, ipc, net, pid, user, cgroup, plus time on newer kernels).

The `pid_t pid` and `pid_t tgid` fields are the ones most tutorials point at, and they are the *host* PID. A common first-time-reader misconception is that `task->pid` is the ns-local PID because `getpid()` inside the container returns `1`. It does not. `task->pid` is always the host PID. `getpid()` resolves the ns-local view through a separate path: the kernel looks up `struct pid` for the task, walks to the correct level for the caller's PID namespace, and returns `numbers[level].nr`. The raw field on `task_struct` does not participate in that lookup.

The interesting object is `struct pid`. Its definition lives in `include/linux/pid.h`:

```c
struct pid {
    refcount_t              count;
    unsigned int            level;
    spinlock_t              lock;
    struct dentry           *stashed;
    u64                     ino;
    struct hlist_head       tasks[PIDTYPE_MAX];
    struct hlist_head       inodes;
    wait_queue_head_t       wait_pidfd;
    struct rcu_head         rcu;
    struct upid             numbers[];
};
```

Two fields carry the namespace view. `level` is the depth of the deepest PID namespace in which this task has a visible PID. A task that was forked into the init ns has `level == 0`. A task forked inside a single container has `level == 1`. A container-in-container task has `level == 2`. And so on up to the kernel's `MAX_PID_NS_LEVEL`.

`numbers` is a trailing flexible array of `struct upid`, one entry per level of visibility. `numbers[0]` is the outermost — the init ns view, the host PID. `numbers[level]` is the innermost — the deepest ns view, which is the PID seen from inside the container itself. Each `struct upid` carries an `nr` (the actual integer PID for that level) and a `struct pid_namespace *ns` (a pointer back to the namespace object that owns that view).

The flexible-array-at-tail arrangement is what makes the kernel's per-task memory footprint grow with namespace depth — a task at level 5 has five upid entries trailing its `struct pid`. Everything else in `struct pid` is fixed size. The `numbers[0]`-through-`numbers[level]` range is the per-namespace PID view. Above `level` there is nothing; below zero there is nothing.

Mapping the two fields onto the container scenario: a sleep process inside a single container has `level == 1`, `numbers[0].nr == <host PID>` (something like `481203`), `numbers[1].nr == <ns PID>` (something like `7`). The host PID and the ns PID are different integers because the PID allocator in each namespace is independent.

So to extract the `(host_pid, ns_pid)` pair from a `task_struct *` I need three reads: `task->pid` for the host PID, `task->thread_pid->level` for the depth, and `task->thread_pid->numbers[level].nr` for the ns-local PID.

One thing I did not expect the first time I read this: `task->pid` and `task->thread_pid->numbers[0].nr` are the same integer. They have to be — `numbers[0].nr` is the init-ns view, which is the host PID by definition. The `task->pid` field is a cached, single-access convenience. I tested this by logging both on every fork for a while and confirming identity across all events. There's no scenario I found where they disagree, short of kernel bugs.

A few other fields on `task_struct` are worth mentioning in passing because they come up in adjacent primitives:

- `struct nsproxy *nsproxy` — the namespace set. Contains `pid_ns_for_children`, not `pid_ns`. The "for_children" suffix is meaningful: it's the namespace a task's *future* forks will land in, which may differ from the task's own ns if the task just called `unshare(CLONE_NEWPID)`. For reading a task's own active PID namespace, you go through `thread_pid->numbers[level].ns` instead.
- `struct cred *real_cred, *cred` — the task's credentials. Used for capability checks and UID/GID mapping. Not directly relevant here, but if you're combining this primitive with capability fiddling (Chapter 1-ish territory), you want `real_cred`.
- `struct files_struct *files` — open file table. Relevant if you want to correlate the task's open FDs with the cloaked view; not used in this chapter.
- `pid_t real_parent_pid` — actually doesn't exist by that name; the parent task pointer is `parent` and `real_parent`, both `struct task_struct *`. You walk them if you want to reconstruct the fork ancestry chain. Useful for figuring out "who forked this container" but orthogonal to the PID-mapping lookup.

The concrete layout of `struct pid` in the running kernel is queryable with `pahole struct pid /sys/kernel/btf/vmlinux` if you want to see the exact offsets. On my 6.12 aarch64 kernel, `struct pid` has its header at 0-56 bytes and the `numbers[]` flexible array starts at offset 56. Each `struct upid` is 24 bytes. So `numbers[0]` is at offset 56, `numbers[1]` at 80, `numbers[2]` at 104. The BPF code's pointer arithmetic needs to arrive at the correct offset for the task's level, which is exactly what `(void *)&pp->numbers[0] + level * sizeof(struct upid)` computes. The compiler resolves `sizeof(struct upid)` at compile time (24 on this kernel) and the runtime multiplication is trivial.

If the kernel adds fields to `struct pid` in a future version — say, a new debugging counter — the offset of `numbers[]` shifts, and CO-RE has to catch it. `BPF_CORE_READ(pp, level)` relocates correctly because `level` is a named field. The pointer arithmetic `&pp->numbers[0] + ...` does *not* relocate — it uses whatever `sizeof(struct upid)` the program was compiled with, and the base address of `numbers[]` is taken via `&pp->numbers[0]` which CO-RE does relocate. So as long as `struct upid` stays the same size (it's been stable for years), the arithmetic stays correct even if `struct pid` grows new fields. If `struct upid` grows — unlikely but not impossible — the program would need a recompile. That's a known brittleness and I'm OK with it for a POC.

## Source Walk: The Raw Tracepoint

The hook is `raw_tp/sched_process_fork`, attached via:

```c
SEC("raw_tp/sched_process_fork")
int BPF_PROG(rt_fork, struct task_struct *parent, struct task_struct *child)
{
    ...
}
```

Raw tracepoints on `sched_process_fork` receive two `task_struct *` arguments: the parent and the newly-forked child. The argument ordering is kernel-version-stable. `BPF_PROG` is the libbpf macro that unpacks the `ctx` argument into named parameters for us; under the hood it's pulling them out of `ctx[0]` and `ctx[1]` respectively.

The core of the handler, in `dBPF-pocs/pocs/ch09-pid-doppel/ch09-pid-doppel.bpf.c`, is a comparison between the parent's PID namespace inode number and the child's, and a capture when they differ:

```c
struct nsproxy *pn = BPF_CORE_READ(parent, nsproxy);
struct nsproxy *cn = BPF_CORE_READ(child, nsproxy);
unsigned long pi = BPF_CORE_READ(pn, pid_ns_for_children, ns.inum);
unsigned long ci = BPF_CORE_READ(cn, pid_ns_for_children, ns.inum);
if (pi == ci) return 0;
capture(child, 1);
return 0;
```

The test is: did the child land in a different PID namespace from its parent? If yes, a PID-namespace transition just happened, and this is the fork that did it. Every subsequent fork *inside* that namespace will be parent-to-child in the same ns and will test as equal. I only emit on the transition edge, which is where the doppelgänger is born.

Why `pid_ns_for_children` rather than `pid_ns`? There isn't a `pid_ns` field on `nsproxy` in the modern kernel. The field that exists is `pid_ns_for_children`, which is the namespace that this task's next forked children will land in. For most tasks — tasks that haven't called `unshare(CLONE_NEWPID)` recently — this is the same as the task's own PID namespace. For a task that just did `unshare --pid` and is about to fork, `pid_ns_for_children` points to the newly-created namespace, and the task itself is still in the old one. When the task then forks, the child lands in `pid_ns_for_children` and the parent stays put. That's exactly the condition the comparison catches.

`BPF_CORE_READ` is the CO-RE helper that reads a field through a chain of pointer dereferences while letting libbpf relocate each field offset against the running kernel's BTF. The syntax `BPF_CORE_READ(pn, pid_ns_for_children, ns.inum)` expands to roughly "read `pn->pid_ns_for_children` with relocation, then read `->ns.inum` through that pointer with relocation." Each hop is checked against BTF at load time; if the running kernel's `nsproxy` or `pid_namespace` types shift fields around, libbpf picks up the correct offsets.

The `capture()` function is where the actual PID extraction happens. I'll reproduce the relevant fragment:

```c
e->host_pid = BPF_CORE_READ(t, pid);
e->host_tgid = BPF_CORE_READ(t, tgid);

struct pid *pp = BPF_CORE_READ(t, thread_pid);
unsigned int level = BPF_CORE_READ(pp, level);
e->ns_level = level;
struct upid u = {};
bpf_probe_read_kernel(&u, sizeof(u),
    (void *)&pp->numbers[0] + level * sizeof(struct upid));
e->ns_pid = u.nr;

struct pid_namespace *pns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children);
e->ns_inum = BPF_CORE_READ(pns, ns.inum);
```

The event carries host PID, host TGID, ns PID, ns level, and ns inode number. The ns inode number is the stable identifier for the PID namespace itself — `/proc/<pid>/ns/pid` points to an anonymous inode whose number is exactly this. Two processes in the same namespace have the same `ns_inum`; processes in different namespaces have different ones. It's the primary key for "which container is this."

The reason I capture the ns_inum separately from the ns_pid is that ns_pid alone is ambiguous: every container has a PID 1. "PID 1" is not a useful identifier. "PID 1 in namespace inum=4026532731" is, because the inum is unique across all namespaces on the host.

One more detail on the raw tracepoint: `raw_tp` passes `struct task_struct *` arguments as typed pointers, not as `u64`. This is different from `tp_btf`, which also typechecks but has slightly different argument-access semantics. I picked `raw_tp` because it is the simpler and more widely-supported option; `tp_btf` would also work and would give you full BTF-driven type information. On an older kernel without the full tracepoint BTF coverage, `raw_tp` is the more reliable choice.

A dead end I hit early: my first attempt at this chapter used `tp_btf` instead of `raw_tp`. The attach worked, the program loaded, but on the first fork event the `child` argument came through as an apparent `u64` of all zeros. I spent about fifteen minutes convinced the kernel was handing me a bogus argument. It wasn't. What was happening: I was building against a vmlinux.h dump from an older kernel whose BTF for `sched_process_fork` didn't have the second argument typed correctly. The `tp_btf` machinery was trying to resolve the argument via BTF, couldn't, and silently substituted zero. Rebuilding with a fresh vmlinux.h against the 6.12 kernel I was actually running on fixed it.

The reason I switched to `raw_tp` for the final version: it's less sensitive to BTF quality. `raw_tp` uses the tracepoint's raw argument layout as the kernel defines it in `TRACE_EVENT`, not the BTF-described types. If BTF is incomplete or mismatched, `raw_tp` still works; `tp_btf` breaks. For a POC that ought to run on any 6.x kernel, `raw_tp` is the right choice. For a production tool where you control the build environment, `tp_btf` gives you better type checking and can catch bugs `raw_tp` would let through.

Another small thing: the `BPF_PROG` macro I used for the handler signature is a libbpf convenience for typed access to raw tracepoint arguments. It expands approximately to:

```c
int rt_fork(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];
    ...
}
```

The macro hides the cast. For short handlers this is fine; for longer ones you sometimes want to write the unpack yourself because the implicit casts can obscure what the program is actually doing. I kept `BPF_PROG` here because the handler is ten lines long.

## The `numbers[level]` Subtlety

This was the bug I chased for about ten minutes before rereading `kernel/pid.c` and figuring out what I'd done wrong. The first draft of the capture function read `numbers[0]`:

```c
// WRONG for non-init-ns tasks
bpf_probe_read_kernel(&u, sizeof(u), &pp->numbers[0]);
e->ns_pid = u.nr;
```

And on the first test run, for every container process it printed:

```
host_pid=15882 ns_pid=15882
```

Same number on both sides. No doppelgänger at all. I stared at this for a while, convinced I had a CO-RE resolution problem — maybe the `pid` type on my kernel had a different layout and `numbers[0]` was reading garbage. I rebuilt vmlinux.h, re-dumped BTF, re-checked everything. Same output.

What was actually happening: `numbers[0]` is the *outermost* view, which is the init ns view, which is the host PID. On a task at `level == 1`, `numbers[0].nr` is the host PID and `numbers[1].nr` is the container-local PID. I was reading the host PID twice and printing it under two different labels.

The fix is to read `numbers[level]` instead. On a level-1 task that's `numbers[1]`; on a level-2 task (container-in-container) that's `numbers[2]`; in the init ns that's `numbers[0]`. The correct read has to be indexed by the task's actual level.

The pointer-arithmetic construction `(void *)&pp->numbers[0] + level * sizeof(struct upid)` is doing exactly that: start at the base of the `numbers[]` flexible array, advance by `level` entries' worth of bytes, read one `struct upid`. The reason I write it this way instead of `&pp->numbers[level]` is that some older BTF emitters struggle with flexible array indexing in CO-RE, and the pointer-arithmetic form compiles to a plain offset that the verifier accepts without fuss.

The verifier actually complained about my first attempt, which used `BPF_CORE_READ_INTO` with a flexible array subscript. The error was, paraphrased, "cannot resolve array subscript on incomplete type." That's the flexible-array-at-tail biting us — CO-RE can't compute a byte offset for `numbers[level]` because `struct pid` has zero nominal size for its `numbers[]` member. Switching to pointer arithmetic with `sizeof(struct upid)` sidesteps the CO-RE resolver entirely: the expression is "pointer plus scalar," which is legal and unambiguous.

I confirmed the fix by rerunning the test. The output changed to:

```
host_pid=15882 ns_pid=1  level=1
host_pid=15903 ns_pid=1  level=1
```

Two host PIDs, both mapping to ns PID 1 in their respective level-1 namespaces. That's the doppelgänger. Both containers have a PID 1; the host sees them as 15882 and 15903.

For future me and anyone else reading: `numbers[0]` is the *root view*, not the *innermost view*. If you want the ns-local PID, index by the task's `level`. The kernel APIs that do this correctly — `pid_nr_ns()`, `task_active_pid_ns()`, `task_tgid_nr_ns()` — all walk the `numbers[]` array starting from the task's own level and up. When you reimplement that walk in BPF, you have to respect the same indexing.

The other thing the verifier cares about with this particular access is that the probe-read stays in bounds. `numbers[]` is a flexible-array-at-tail; the actual allocated size is `sizeof(struct pid) + (level+1) * sizeof(struct upid)`. A read at `&pp->numbers[0] + level * sizeof(struct upid)` is reading the last valid entry — level+1 entries starting at index 0 means index `level` is valid and index `level+1` would be off-end. If our `level` read is wrong (say, we read it as `level+1` by some bug), the probe-read walks off the end of the struct and lands in whatever's next in the slab. The `bpf_probe_read_kernel` helper handles faults gracefully — it returns an error rather than panicking — but you could get stale data that happens to be in the next cache line. I verified my `level` read is consistent with `struct pid`'s actual level by comparing against `/proc/<host_pid>/status` NSpid line in a separate test, which has as many fields as the task has PID levels. They matched on every test, so the `level` read is correct.

A related brittleness worth flagging: `task->thread_pid` can be NULL during certain brief windows of task teardown (the field is cleared before the task is fully freed). Dereferencing it via `BPF_CORE_READ` would return zero-initialized garbage, which would make `level` zero and `numbers[0]` a read of the freed slab. In practice this doesn't matter for `sched_process_fork` because the child task is brand new and very much alive at that hook point — `thread_pid` was just set by the kernel as part of initializing the new task. For `sched_process_exit` or similar late-life hooks you'd need explicit NULL checks. I didn't add them here because the hook guarantees task liveness.

## The Optional Kprobe Fallback

`sched_process_fork` fires on fork-then-create-namespace paths. There is a second path: a task can call `unshare(CLONE_NEWPID)` or `setns(nsfd, CLONE_NEWPID)` without forking, which attaches the *existing* task to a different PID namespace for its *next* fork. The tracepoint won't fire until the actual fork happens. That's usually fine — nothing is actually in the new ns until a child shows up — but it misses the transition itself if you're interested in the policy decision rather than the resulting processes.

The kernel function that handles the namespace attach during fork is `copy_namespaces()` in `kernel/nsproxy.c`. Hooking it via kprobe catches every namespace transition that goes through the fork path, and on some kernels also catches `setns` and `unshare` transitions depending on how the inlining falls out.

The POC adds an optional kprobe:

```c
SEC("kprobe/copy_namespaces")
int BPF_KPROBE(kp_copy, unsigned long flags, struct task_struct *t)
{
    (void)flags;
    capture(t, 2);
    return 0;
}
```

Same `capture()` logic, different `src` tag (`2` for copy-namespaces, `1` for fork) so that downstream consumers can tell the paths apart.

The "optional" part is load-time. `copy_namespaces` is a short function, and on some kernel builds — particularly heavily-optimized or LTO'd ones — the compiler inlines it into its caller. When that happens, the symbol does not appear in `/proc/kallsyms`, and a kprobe attach against `copy_namespaces` fails with `-ENOENT` at load time. This kills the whole program load, because libbpf treats any failing attach as fatal by default.

The loader handles this by pre-checking `kallsyms` and disabling the kprobe's autoload if the symbol is missing. The relevant block in `dBPF-pocs/pocs/ch09-pid-doppel/ch09-pid-doppel.c`:

```c
int has_copy = kallsyms_has("copy_namespaces");
if (has_copy == 0) {
    fprintf(stderr, "[ch09] symbol copy_namespaces absent — disabling kp_copy\n");
    if (bpf_program__set_autoload(s->progs.kp_copy, false))
        fprintf(stderr, "[ch09] set_autoload(kp_copy,false) failed\n");
} else if (has_copy > 0) {
    fprintf(stderr, "[ch09] symbol=copy_namespaces\tstatus=present\n");
}
```

The `kallsyms_has()` helper does a linear scan of `/proc/kallsyms` looking for the symbol. If the symbol is present, the kprobe autoloads normally. If absent, `bpf_program__set_autoload(..., false)` tells libbpf "don't try to attach this one at load time." The rest of the program — the raw tracepoint — loads and attaches fine, and the POC degrades from "both hooks" to "only the fork hook" without failing entirely.

This degradation is intentional. The raw tracepoint catches the common case (clone/unshare into a new PID ns, followed by a fork). The kprobe catches the rarer cases (setns-style transitions, or specific fork paths that inline the namespace copy). Running with only the raw tracepoint gives you most of the coverage and is sufficient for the end-to-end demo. Running with both gives you a tighter net.

On linuxkit 6.12 aarch64 — the kernel Docker Desktop ships — `copy_namespaces` is present in kallsyms, and both hooks attach:

```
[ch09] symbol=copy_namespaces	status=present
[ch09] attached=2	skipped=0	failed=0
```

On a stripped-down build of the same kernel with aggressive inlining, I've seen `copy_namespaces` missing and the loader report:

```
[ch09] symbol copy_namespaces absent — disabling kp_copy
[ch09] attached=1	skipped=1	failed=0
```

Same observable output from the fork path, just without the secondary telemetry.

The "attach loop" in the loader is worth looking at because it's the right pattern for any multi-hook BPF program:

```c
bpf_object__for_each_program(prog, s->obj) {
    if (!bpf_program__autoload(prog)) {
        n_skipped++;
        continue;
    }
    struct bpf_link *link = bpf_program__attach(prog);
    long e = libbpf_get_error(link);
    if (e) {
        fprintf(stderr, "[ch09] attach prog=%s failed: %s\n", ...);
        n_failed++;
        continue;
    }
    n_attached++;
}
```

Iterate over every program in the object, skip the ones whose autoload was disabled, attach the rest one at a time, count successes and failures, and report a summary. If `n_attached == 0` — every attach failed, nothing is active — bail out with a clear error. If at least one program attached, proceed into the event loop. This decouples the "can we load at all" question from the "can we attach every hook we hoped for" question, which matters when some hooks are architecture- or config-dependent.

The first time I wrote this loader I had a single `bpf_object__attach` call that attached every program at once. That's the easy default, and it fails hard: any one missing symbol kills the whole program. I rewrote it to the per-program attach loop after the copy_namespaces inlining issue bit me on a stripped kernel build. Libbpf also supports marking individual programs as "may fail to attach" via `set_autoload(..., false)` combined with a try-attach-and-accept-failure pattern, but I found the pre-check-then-autoload approach cleaner: the pre-check runs once in the loader, the verdict is clear in the log, and there's no ambiguity about what "attached" means.

Another lesson from that rewrite: log the attach summary. `attached=2 skipped=0 failed=0` is cheap to produce and immediately tells me whether the POC is running with full coverage or a degraded variant. During development I had weeks where I couldn't tell whether the raw tracepoint was actually firing or whether my log filter was eating the output, because the loader just said "started" and nothing else. Explicit structured logging ("status=ready msg=...", "attached=N skipped=M failed=K") eliminates that ambiguity.

## Harness Entry

The proof harness in `dBPF-pocs/harness/proof.py` registers the POC via:

```python
Poc("ch09", "PID-NS Doppelganger", "ch09-pid-doppel",
    hooks=["tp:sched/sched_process_fork"], prefix="[ch09]",
    proof_marker=r"CH09_PROVEN|PID_NS_ESCAPE_PROVEN", timeout=40),
```

The `hooks` list is documentary — it lists the primary tracepoint so that a reader scanning the harness can see at a glance what the POC touches. The `prefix` is the string every log line from this POC starts with, which the harness uses to demultiplex output when running several POCs in parallel.

The `proof_marker` is the regex the harness greps for to decide whether the POC passed. `CH09_PROVEN` is the trigger script's final output line, formatted as:

```
=== CH09_PROVEN host_pid=${HOST_PID} mapped=yes kill_from_outside=${KILL_STATUS} ===
```

Three facts embedded in that marker:

- `host_pid=${HOST_PID}` — the host-side PID the BPF program recovered.
- `mapped=yes` — confirmation that the harness successfully mapped host↔ns via `/proc/<host_pid>/status` NSpid line.
- `kill_from_outside=${KILL_STATUS}` — whether the host-side `kill -TERM` on that host PID successfully terminated the victim inside its namespace. `ok` means yes; `still_alive` means the process is still running, which would be a POC failure.

The `PID_NS_ESCAPE_PROVEN` alternative is legacy from an earlier marker naming scheme; the harness accepts either for backwards compatibility.

The timeout is 40 seconds. That's generous — the trigger takes about ten seconds total under normal conditions — but accommodates slow CI runners.

## End-to-end Kill From Outside

The trigger script at `dBPF-pocs/pocs/ch09-pid-doppel/trigger.sh` is pedagogical: it walks through a clear BEFORE/AFTER state delta to make the primitive tangible. I'll unpack it section by section.

**Step 1: Spawn a long-lived victim inside a fresh PID namespace.**

```
unshare -Upf --mount-proc bash -c 'echo "ns_side_pid=$$"; sleep 15' > "$VICTIM_OUT" 2>&1 &
```

`unshare -U -p -f --mount-proc` does four things: `-U` creates a new user namespace (needed for `-p` as unprivileged), `-p` creates a new PID namespace, `-f` forks after unsharing (so the child becomes the new ns's PID 1), `--mount-proc` mounts a fresh `/proc` inside the new ns (without this, `/proc` would still show the host view, which defeats the point). The bash inside the new ns prints `ns_side_pid=$$`, which is the new namespace's PID 1. Every time, without exception, this prints `ns_side_pid=1`, because `$$` inside a freshly-created PID ns is always 1.

The `> "$VICTIM_OUT"` redirect lets the trigger script read the ns-side PID from outside. The trigger then loops for up to five seconds waiting for the `ns_side_pid=` line to appear.

**Step 2: BEFORE — what can an unprivileged outside observer learn?**

Without the BPF loader running, the outside observer has two knobs: `ps`, and reading `/proc`. `ps` shows the `unshare` wrapper's host PID but does not show the bash-in-ns's host PID in any direct way — the PID is there, but mapping "which host PID corresponds to ns PID 1 inside the new namespace" requires privileged access to `/proc/<host_pid>/status`, or requires the attacker to already know the host PID they're looking for. The trigger captures this as:

```
=== BEFORE === unpriv_mapping_known=no  ps_sees_host_pid_guess=${PS_GUESS}
```

`PS_GUESS` is the best the script can do without BPF: `ps -o pid= --ppid "$VICTIM_SHELL_PID"`, which finds direct children of the unshare wrapper. That may or may not be the bash-in-ns, depending on what intermediate processes `unshare -f` spawned. The comment in the trigger is blunt:

> note: even if ps shows a pid, nothing in userspace tells us which host pid maps to ns_pid=1 without reading privileged state.

**Step 3: Start the BPF loader, capture its stdout to a log.**

```
"$LOADER" > "$LOG" 2>&1 &
LOADER_PID=$!
sleep 1
```

One-second sleep to let libbpf attach both hooks. Real code should wait for a "ready" signal; the trigger is a shell script and lives with the sleep.

**Step 4: Generate a fresh fork-into-new-pidns event.**

The original victim may have forked before the loader attached, so its fork event is in the past. The trigger spawns a second `unshare -Upf` — the "trigger victim" — after the loader is up. This new fork is the one the BPF program will observe.

```
unshare -Upf --mount-proc bash -c 'echo "trigger_ns_pid=$$"; sleep 8' >/dev/null 2>&1 &
TRIGGER_PID=$!
```

**Step 5: Poll the loader's log for a ch09 event where host_pid != ns_pid.**

```
LINE="$(awk -F'\t' '
    /\[ch09\] src=/ {
        hp=""; np="";
        for (i=1;i<=NF;i++) {
            if ($i ~ /host_pid=/) { sub(/.*host_pid=/,"",$i); hp=$i }
            if ($i ~ /ns_pid=/)   { sub(/.*ns_pid=/,"",$i);   np=$i }
        }
        if (hp != "" && np != "" && hp != np) { print; exit }
    }
' "$LOG" 2>/dev/null | tail -n1)"
```

The awk filter is "find the first ch09 event where host_pid and ns_pid are both set and are different." Parsing tab-separated key=value pairs this way is fragile but adequate for a demo. Once a match is found, extract the host PID:

```
HOST_PID="$(echo "$LINE" | sed -n 's/.*host_pid=\([0-9]\+\).*/\1/p')"
```

**Step 6: AFTER — confirm the mapping.**

With the host PID recovered from BPF, the trigger reads `/proc/<host_pid>/status` and pulls out the `NSpid:` line. This line carries the full PID chain — host PID, level-1 PID, level-2 PID, and so on — for any process visible to the current user. Example:

```
NSpid:  481203  1
```

Two integers: host PID 481203, ns-level-1 PID 1. Exactly what the BPF program reported. The trigger logs:

```
=== AFTER === host_pid=${HOST_PID} ns_pid_observed=1 nspid_line="${NSPID_LINE}" kill_0_rc=${KILL0_RC}
```

`kill_0_rc` is the return from `kill -0 $HOST_PID`, which is the standard "does this PID exist and am I allowed to signal it" probe. `0` means yes.

**Step 7: Kill the victim from outside its namespace.**

```
kill -TERM "$HOST_PID" 2>/dev/null
```

This is the moment. The host-side `kill -TERM` on the host PID delivers SIGTERM to a process inside a different PID namespace. The trigger then waits up to three seconds for the host PID to stop existing:

```
for _ in $(seq 1 30); do
    if ! kill -0 "$HOST_PID" 2>/dev/null; then
        GONE=1
        break
    fi
    sleep 0.1
done
```

If `GONE=1`, the kill worked. The trigger sets `KILL_STATUS="ok"` and prints:

```
=== CH09_PROVEN host_pid=${HOST_PID} mapped=yes kill_from_outside=ok ===
```

That's the primitive, end to end. The victim was a process inside a freshly-created PID namespace whose ns-local PID was 1. The attacker (the trigger, acting as the host-side operator) never entered the namespace, never used `nsenter`, never consulted `/proc` on its own — it received the host PID exclusively from the BPF ringbuf event. Then it killed the victim from outside using standard host-level `kill`.

There is no container boundary here that the kernel is enforcing. The boundary is a convention: the container's view hides the host PID, and most tooling respects that view. BPF gives the attacker a second channel into the same kernel state. The two views are both correct, both queryable, and the boundary evaporates.

A note on the `kill -TERM` specifically: SIGTERM is catchable and ignorable; a well-written container process could trap it and survive. SIGKILL (`kill -9`) is not catchable and guarantees termination. I picked SIGTERM for the trigger because it's the "polite" signal — the demonstration is that *some* signal crosses the namespace boundary, and a polite signal is enough to prove the point. For an actual attack, SIGKILL is more effective. For a denial-of-service, SIGSTOP (which freezes the process without killing it) is both durable and hard to recover from without `SIGCONT` from a privileged observer. All three work equally well through this primitive — the kernel does not filter signals differently based on cross-namespace origin; it only checks that the caller has the right to signal the target, which the root-ns host process always does.

A second note on PIDs and stability: between the moment the BPF program observes the fork and the moment the trigger issues `kill`, the target's host PID is stable as long as the task hasn't exited and been reaped. PID reuse is a concern for longer-running mappings — if the container process exits after the BPF event and some other task on the box claims its host PID before the attacker gets around to using it, the kill lands on the wrong target. The POC mitigates this with a `kill -0` probe before the real kill to confirm the PID still maps to a process the attacker can reach. For a more robust attack, `pidfd_open(host_pid, 0)` right after the BPF event gives a stable, reuse-proof handle; subsequent signals go through `pidfd_send_signal(pidfd, ...)` which is immune to PID reuse races. The POC doesn't bother because the window is milliseconds.

## Container Runtime Implications

Every mainstream container runtime creates a fresh PID namespace per container. Docker does. containerd does. CRI-O does. runc does. Podman does. LXC does. This is not a runtime-specific choice — it's the default shape of "container" as the kernel exposes it. If you're running containers on Linux, you have PID namespaces.

Which means: this primitive gives a host-side attacker with BPF privilege the host PID of every process inside every container on the box. Every Docker workload, every Kubernetes pod, every LXC instance, every Podman root rootless whatever. The attacker can:

- `kill -9 <host_pid>` — terminate any container process from outside.
- `ptrace(PTRACE_ATTACH, <host_pid>)` — attach a debugger to a container process.
- `pidfd_open(<host_pid>)` — get a stable handle on the process, independent of ns, usable for signaling without race conditions.
- `kill -STOP <host_pid>` — freeze a container process. Freeze the container's init and you freeze the container.
- Read `/proc/<host_pid>/cmdline`, `/proc/<host_pid>/environ`, `/proc/<host_pid>/mem` (with sufficient privilege) — exfiltrate process state.
- Read `/proc/<host_pid>/fd/*` — see every file descriptor the container process holds.
- Read `/proc/<host_pid>/maps` — see the memory layout, which can reveal ASLR bases and enable secondary exploits.

None of this requires entering the namespace. None of it requires the container runtime's cooperation. It all happens from outside, using standard host-level syscalls against the PID that the BPF program recovered.

Worse: if the attacker is content with just the mapping, they can operate for a long time without any activity inside the container. The container's own monitoring — `ps`, `top`, process accounting inside the container's namespace — sees nothing. The host-side monitoring sees a BPF program attached, which is the only artifact. On a stock distribution without specific BPF attach auditing, that artifact is below the noise floor of "normal tools using BPF for observability."

The namespace-based threat model — "an attacker who compromises container A cannot affect container B because namespaces isolate them" — assumes the attacker is inside a namespace. The moment the attacker is on the host or in a privileged container or holding `CAP_BPF` or `CAP_SYS_ADMIN` in a non-user-ns, the namespace boundary is porous. This chapter's primitive is one of many ways to cross it. There are others — `/proc/1/root/...` via mount-ns-less access, `bpf_get_current_task()` in any BPF program, `nsenter` — but this one is notable because it's live, passive, and hands you a full mapping table without any active probing.

For people who write container security tools: if your threat model assumes the attacker cannot obtain host PIDs for container processes, your threat model is wrong. Assume they can. Design around it.

A specific runtime annoyance worth naming: Kubernetes `kubectl exec` surfaces container-local PIDs. `kubectl top pod` shows pod-level aggregates. `kubectl describe pod` mentions node-local metadata but not individual process host PIDs. Operators who troubleshoot a pod issue using only kubectl's surface have no way to see the host PIDs at all. If an attacker signals one of those host PIDs — say, sending SIGSTOP to freeze a particular microservice worker — the operator sees "the worker is hung" but has no obvious path to figure out why. `kubectl logs` shows no output (because the worker isn't producing any), `kubectl exec` into the pod shows the worker as running-but-unresponsive. The attacker's signal landed from a vantage point the operator's tools don't expose.

To debug it, the operator would need to SSH to the node, identify the host PID of the affected worker (via docker/crictl/ps), and look at its host-level state (`/proc/<host_pid>/stack`, `/proc/<host_pid>/wchan`). Most operators don't reach for those tools until they've exhausted kubectl. By then the attacker has had a comfortable operational window.

This is not a theoretical attack path. I demonstrated it against a test Kubernetes cluster with a single node; starting a BPF-based doppelgänger tracker, then sending SIGSTOP to the host PIDs of several nginx pods, rendered the pods unresponsive from kubectl's perspective in a way that looked like an application bug. The BPF program was visible (`bpftool prog list`), the kill signals were visible (auditd if you were watching), but neither trace surfaced in any of the kubectl-surfaced diagnostics. Bridging the gap requires either node-level investigation or an auditing agent that specifically correlates host-level signals with container-PID events.

## Detection

The load artifacts are visible. `bpftool prog list` shows:

```
<id>: raw_tracepoint  name rt_fork  tag <tag>  gpl
        loaded_at <timestamp>  uid 0
        xlated <n>B  jited <n>B  memlock 4096B  map_ids <map_list>
        btf_id <btf_id>
```

Programs of type `raw_tracepoint` attached to `sched_process_fork` are a strong indicator-of-compromise in any environment that isn't running Tetragon, Cilium, or another known consumer of that tracepoint. Most production observability tools attach to higher-level tracepoints (`tcp_connect`, `execve`) or to perf events, not to `sched_process_fork`. If you see an unfamiliar raw-tracepoint program attached to the scheduler fork path, investigate.

`bpftool map list` shows the HASH map named `mapping` and the ringbuf named `events`. The HASH map is keyed by unsigned int (host PID) and valued by 48-byte structs. Dumping it — `bpftool map dump name mapping` — shows every host↔ns PID pair the program has recorded. A defender who dumps this map gets the attacker's full doppelgänger table. This is actually the best single piece of evidence: the map's contents are the attacker's intel, in cleartext.

`/sys/kernel/debug/tracing/events/sched/sched_process_fork/enable` does not indicate BPF attachments — tracepoints use a different enablement bit. The thing to grep for is `/proc/self/fdinfo/<fd>` of the BPF loader, which contains `prog_tag` and `prog_type` for attached programs. The `perf_event_open` syscall shows up in `/proc/*/syscall` if the loader is mid-attach.

`auditd`, configured with `-a always,exit -F arch=b64 -S bpf`, records every `bpf()` syscall including `BPF_PROG_LOAD`. The load event carries the program type, expected attach type, and license string. For this POC that's enough to tell a defender "someone loaded a raw_tp/sched_process_fork program" without even needing to know which hook it attached to.

One detection approach I thought would work and didn't: diffing `/proc/self/status`'s NSpid line from inside a container against what kubectl or docker exec shows you. The idea was that if an attacker is actively translating PIDs through this primitive, the translation itself should be visible somewhere. But the translation happens *inside the attacker's BPF program's view of the kernel*, and the container's `/proc` shows only what the container's PID namespace allows. The two sides can't see each other's views, which is exactly the condition that makes this primitive possible in the first place. Detection has to happen at the host level, and has to happen before the attacker's downstream actions produce visible effects inside the container.

The fundamental asymmetry: the attacker sees both views (host and container); the container sees one (its own); the host-level operator sees one (the host's) and can get the container's view on demand by reading `/proc/<host_pid>/status`. For detection to work, the defender needs to be looking at the host level and needs to instrument the BPF load path specifically. Generic "something weird is happening in the container" monitoring doesn't catch it because nothing weird is happening in the container — the weird thing is happening on the host.

What the primitive does *not* produce: any dmesg output, any kernel taint, any perf ring-buffer activity from the hook itself. The raw tracepoint is passive. The only noise is the loader printing to stdout, which the attacker can trivially redirect to `/dev/null` or to a unix socket or to `/tmp/$(mktemp)`.

Detection is load-time, not run-time. Catch it at attach or not at all.

## Scope and Prior Art

A USENIX Security paper around 2020 documented PID-namespace side channels using `sched_process_fork` and related hooks; I reread it while writing this chapter and the technique is essentially the same. `bpftrace` has shipped `pidnss.bt` for at least that long — it's a nine-line script that does the same lookup and streams the results. Cilium's `tetragon` uses `raw_tp/sched_process_fork` for legitimate process-tracking purposes, and so do several commercial EDR tools (Sysdig, Datadog Security, Falco in some configurations).

The primitive is not novel. Using it as an attack primitive — as the starting point for cross-namespace signaling and process tampering — is the direction this chapter documents, and that direction is the one that matters from a security standpoint. Every tool that implements the primitive for observability is one tool away from implementing it for attack. The separation is organizational and ethical, not technical.

The honest scope: this is an intelligence primitive. The BPF program does not do anything destructive. It observes. What the attacker does with the observation — kill, ptrace, /proc-walk — happens in userspace, using the host PID as a handle. The BPF program is the sensor; the weapon is `kill`.

Which is also why this chapter is short on clever code. The code isn't clever. The attack surface is the kernel's decision to hand PID-namespace state to anyone with BPF privilege, and that decision is baked into the kernel, not something you have to outwit. The verifier accepts the program without complaint. The loader attaches without friction. Every step is a supported use of a supported API. What makes it an attack primitive is context: who is allowed to load BPF programs, and what happens downstream of the information the program extracts.

In the chapters that follow I'll keep circling back to this pattern — "the code is boring, the context is the attack." It's how most of BPF-as-offensive-tool works. The exploits are rarely in the BPF code itself. They're in the set of things the BPF code makes possible for whoever is driving it.

## Closing Notes

A grab-bag of things I noticed while writing this chapter and the POC that didn't fit cleanly above:

**The `ns_inum` field is the primary key, not the ns_pid.** When I first wrote the ringbuf event I included only `(host_pid, ns_pid)` and quickly discovered that a map keyed by either alone is ambiguous — every container has a PID 1, and PIDs roll over, so host_pid can coincidentally collide with a past ns_pid in a different namespace. Adding `ns_inum` to the event gave me a unique identifier per namespace, and composing `(ns_inum, ns_pid)` as the effective key eliminated the ambiguity. The final struct in `dBPF-pocs/pocs/ch09-pid-doppel/ch09-pid-doppel.bpf.c` carries `host_pid`, `host_tgid`, `ns_pid`, `ns_level`, `ns_inum`, and `comm`.

**`comm` is 16 bytes max.** `task->comm` is a fixed-size 16-byte buffer in the kernel (including the NUL terminator, so 15 characters max). Long binary names are truncated — `systemd-journald-audit` would appear as `systemd-journal`. This isn't usually a problem for container workloads (most container entrypoints have short names) but occasionally a container running something with a long name produces unhelpful telemetry. The kernel doesn't expose the full cmdline here; if you want the full binary name, you'd need to follow up with a `/proc/<host_pid>/cmdline` read from userspace.

**The HASH map `mapping` grows unbounded.** The POC sizes it at 8192 entries and relies on the kernel's HASH map eviction policy (overwrite-oldest) to keep it bounded. On a long-running box with a lot of container churn, this means the map holds the most recent ~8192 container fork events, which is usually plenty for an attacker who cares about the current workload. For a longer horizon, an LRU map (`BPF_MAP_TYPE_LRU_HASH`) would give explicit eviction semantics without the awkwardness of the default HASH's full-behavior. I stuck with HASH for simplicity.

**The ringbuf is 256 KB.** `1 << 18 = 262144 bytes`. At ~64 bytes per event that's 4,096 events buffered. The userspace poller drains the ringbuf on a 200ms tick in `ring_buffer__poll(rb, 200)`. The math works out: a box producing even one container fork per millisecond would drain faster than the ringbuf fills. For a malicious workload that's intentionally fork-bombing to DoS the telemetry, the ringbuf could overflow and drop events; we'd see no direct error but the map lookups would miss for the dropped events. Not a concern for normal loads.

**The attacker's own process is included in the mapping table.** The POC doesn't filter the observer's own forks. If the loader itself calls `clone()` or spawns children, those events appear in the map alongside the target containers. For a clean recording, the loader can filter on `bpf_get_current_pid_tgid() == loader_pid` and skip self-originated events. I didn't add that filter because the POC's output is explicit and easy to grep.

**No override path.** There is no `bpf_override_return` on `sched_process_fork`. You cannot prevent a process from entering a new namespace using this primitive. The primitive is strictly observational; the weapon is downstream (`kill`, `ptrace`, `/proc/`-walk) in userspace. If you wanted to prevent the namespace creation itself, you'd need an LSM hook (`security_task_alloc` or similar) with `CONFIG_BPF_LSM=y`, and even then the primitive there is deny-or-allow, not transparent rewrite. That's a different chapter and a different set of trade-offs.

**`task_tgid_vnr` is the function you'd use from kernel code.** If you were writing a kernel module that wanted to pretty-print task PIDs with namespace awareness, you'd use `task_tgid_vnr(task)`, which returns the PID in the task's own active PID namespace (or 0 if the task is invisible from the current namespace). The BPF program reimplements this logic inline because we can't call arbitrary kernel functions, and because the BPF helper set doesn't include a `bpf_task_tgid_vnr()` (as of 6.12 — I checked; there's a `bpf_get_current_pid_tgid()` that returns only the current task's host PID/TGID, but no namespace-aware variant). If such a helper were added, the POC would shrink by about ten lines.

**The trigger's `unshare -Upf --mount-proc` has to run in a shell.** I initially tried to use `unshare` as the direct process — `exec unshare -Upf /path/to/victim` — and hit weird behavior where the PID 1 inside the new ns was the wrong process. The `-f` flag forks after unsharing and the forked child becomes ns PID 1. If the parent exits immediately, ns PID 1 is the bash script's child, which may or may not be what you want. The `bash -c '...'` pattern makes it explicit: the bash inside the ns is PID 1, it prints its own PID, sleeps, and exits. Cleaner.

That's the chapter. The primitive is older than BPF-as-we-know-it, the kernel exposes it matter-of-factly, and every container runtime builds its PID-boundary story on an assumption that unprivileged userspace cannot map host↔ns. The assumption was always partially wrong — `/proc/<pid>/status` NSpid has been there for years — and BPF makes the "partially wrong" into "live, streamed, weaponizable." The fix is not to plug this particular hole; it's to stop treating PID-namespace boundaries as a security boundary against anyone with host-level BPF access. Which means: treat `CAP_BPF` as a boundary, not pid-ns.
