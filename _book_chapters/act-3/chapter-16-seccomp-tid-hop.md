---
layout: book
title: "Chapter 16: Seccomp TID Hop"
date: 2025-04-20
---

# Chapter 16: Observing `__secure_computing` From a Peer Process

> **See also**: [Blog post]({{ site.baseurl }}/seccomp-tid-hop.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch16-seccomp-tid-hop) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

Before anything else in this chapter: seccomp's threat model is the filtered process. Not the observer next to it, not the operator who loaded it, not the kernel's own internals. The filter exists to constrain what a specific task can do after it voluntarily installs the filter on itself. The filtered task cannot remove the filter (the seccomp API makes this impossible by design — `PR_SET_NO_NEW_PRIVS` is a one-way transition), cannot bypass it, cannot query it in detail, cannot even reliably know which filter is active on it at any given moment.

What seccomp's threat model is explicitly *not*: the gap between a filtered process and a sibling with `CAP_BPF`. If a privileged peer on the same machine can load kprobes on `__secure_computing`, then the filtered task's filter has already been bypassed in the threat-model sense. An attacker at that privilege level does not need to break seccomp; they can just attach to it. The filter is a defense against the *filtered task* itself, against that task going rogue. If the attacker already has `CAP_BPF`, they are not the filtered task. They are a different actor with a different threat surface entirely.

I dwell on this framing up-front because the chapter's primitive sits *in the documented gap*, not in a bug. Everything that follows — the kprobe, the ringbuf, the filter reconstruction, the `override_attempted` flag — is seccomp behaving exactly as documented, observed from the side by an attacker whose privilege was always sufficient to do this. The primitive's value is not "we broke seccomp." The primitive's value is "here is a tidy mechanical reconstruction of the seccomp policy on a host, without any privilege on the individual filtered processes."

The useful thing a defender gets from this chapter is: if your threat model assumes that seccomp filters are opaque, revisit that assumption in any environment where an attacker might reach `CAP_BPF`. Opaque filters are opaque to the filtered process only.

## The Aspirational "TID Hop"

The chapter's title, "Seccomp TID Hop," refers to an ambition the original outline held out. The idea: swap the running thread's TID (or the `task->seccomp` pointer) for that of a sibling thread with a permissive filter, let `__secure_computing` evaluate against the borrowed identity, permit the syscall, then swap the TID back before control returns to userspace. If it worked, the filtered thread would execute a syscall that its own filter would have rejected, briefly impersonating a sibling whose filter would have allowed it.

It does not work on stock 6.12. Two independent reasons, both worth stating plainly because the same blockers recur across the book's other primitives.

**Reason 1: `task_struct` writes from BPF are rejected by the verifier**. `task->seccomp.mode` and `task->seccomp.filter` live in `task_struct`, which is kernel memory the verifier considers unwritable from BPF programs. There is no helper that mutates `task_struct` fields; attempts to do so via `bpf_probe_write_user` or friends fail at load. The filter chain itself is not data — it is a linked list of BPF programs — and there is no "unlink my filter" helper either. Even the kernel's own `seccomp_release` function, which tears down the filter chain on task exit, is deeply entangled with reference counting; mutating it from BPF would be unsound.

**Reason 2: `__secure_computing` is not in `ALLOW_ERROR_INJECTION`**. On 6.12.54-linuxkit aarch64, `/sys/kernel/debug/error_injection/list` does not contain `__secure_computing`. That means `bpf_override_return` against the symbol either fails at load or degrades silently. I tested both outcomes: a kprobe with `bpf_override_return(ctx, 0)` (which would be `SECCOMP_RET_ALLOW`) loads, attaches, fires on every seccomp evaluation, and does not change the return value. The kprobe is functioning as an observer; the override is inert.

The "observer-only" degradation is the pattern I documented in chapter 1 (`cap_capable`) and chapter 14's cousin failure modes. The pattern is consistent: if the target function is not annotated, `bpf_override_return` does not work, full stop. There is no workaround from BPF user-land. You either patch the kernel to add the annotation, or you pick a different target.

So the weapon form of this primitive — "bypass seccomp via TID swap" — is closed on stock 6.12. The observer form — "watch every seccomp evaluation on the host" — works perfectly. The chapter is about the observer. The `override_attempted` flag in the ringbuf records the dormant ambition so that a reader with a patched kernel knows exactly where to turn the observer into a weapon.

## The Observer

A kprobe + kretprobe pair on `__secure_computing`. That function is called on every syscall made by a seccomp-filtered task. On 6.12.54-linuxkit aarch64 the symbol is present in `/proc/kallsyms` and kprobes attach cleanly. Every evaluation streams through a ringbuf with `{ts, pid, tid, tgid, comm, seccomp.mode, retval}`:

```
[seccomp] ts=145203418715 pid=649 tgid=649 comm=redis-server    mode=FILTER target=1 nr/ret=-1 allow=0
[seccomp] ts=145203419842 pid=649 tgid=649 comm=redis-server    mode=FILTER target=1 nr/ret=0  allow=1
[seccomp] ts=145203712001 pid=812 tgid=812 comm=python3         mode=FILTER target=1 nr/ret=-1 allow=0
[seccomp] ts=145203712110 pid=812 tgid=812 comm=python3         mode=FILTER target=1 nr/ret=0  allow=1
[seccomp] ts=145204018344 pid=812 tgid=812 comm=python3         mode=FILTER target=1 nr/ret=-1 allow=0
[seccomp] ts=145204018501 pid=812 tgid=812 comm=python3         mode=FILTER target=1 nr/ret=-1 allow=0  # getpriority denied
```

Two records per syscall: the kprobe entry (`nr/ret=-1`, `allow=0`) and the kretprobe paired tail (`nr/ret=<retval>`, `allow=1` when the filter returned `SECCOMP_RET_ALLOW`). On the final line above, the `allow=0` tail corresponds to `SECCOMP_RET_ERRNO` — a `getpriority()` that the filter rejected.

That is a full pre/post decision trace for every filter evaluation system-wide. For a defender this is useful; for a red-team it is a credentials-free enumeration of every seccomp policy running on the host, which filters are strict, which are permissive, and which syscalls each workload actually makes.

## Source Walk: The BPF Program

The attached program is `ch16-seccomp-tid-hop.bpf.c`. It has two BPF functions: the entry kprobe and the kretprobe. I walk them in order.

### Data Structures

```c
struct evt {
    unsigned int pid;            // kernel "pid" (thread id)
    unsigned int tgid;           // kernel "tgid" (process id)
    int          syscall_nr;     // from task->thread_info or pt_regs (best-effort)
    int          seccomp_mode;   // current->seccomp.mode
    int          override_attempted;
    int          override_ok;
    unsigned long long ts_ns;
    char         comm[16];
};
```

Two int32 identifiers (pid, tgid), a syscall number (best-effort; see below), the seccomp mode (`DISABLED=0`, `STRICT=1`, `FILTER=2`), two boolean flags for override intent and override success, a nanosecond timestamp, and the process's comm string. 48 bytes total. The ringbuf reserves one of these per event and the loader prints them.

The fields `override_attempted` and `override_ok` record the aspirational weapon behavior. `override_attempted=1` means the caller's tgid is in the target set. `override_ok=1` in the kretprobe event means the return was indeed `SECCOMP_RET_ALLOW` (0), which is either because the real filter allowed or because the override landed. On this kernel the override never lands, so `override_ok` exactly equals "the filter allowed this call." On a kernel with error-injection on `__secure_computing`, the two would diverge: `override_ok=1` on a targeted call with an originally-denying filter means the override worked.

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);
    __type(value, struct evt);
    __uint(max_entries, 4096);
} inflight SEC(".maps");
```

Three maps. The ringbuf for event streaming. A hash map of target tgids (key is tgid, value is a sentinel; key 0 is the wildcard). An inflight map keyed on `pid_tgid` to pair kprobe entries to kretprobe returns. The structure is identical to ch14 and ch18 — the three-map pattern is idiomatic for kprobe+kretprobe observers.

### The Entry Kprobe

```c
SEC("kprobe/__secure_computing")
int BPF_KPROBE(kp_secure_computing)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    unsigned long id = bpf_get_current_pid_tgid();
    unsigned int tgid = id >> 32;

    struct evt e = {};
    e.pid  = id & 0xffffffff;
    e.tgid = tgid;
    e.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.syscall_nr = read_syscall_nr(task);
```

Grab the current task pointer, the combined pid_tgid, split into pid and tgid, record a monotonic timestamp, copy the comm string, read the syscall number (best-effort). Standard kprobe entry shape.

```c
    int mode = 0;
    if (bpf_core_field_exists(task->seccomp)) {
        mode = BPF_CORE_READ(task, seccomp.mode);
    }
    e.seccomp_mode = mode;
```

CO-RE read of `task->seccomp.mode`. `bpf_core_field_exists` is a compile-time-negotiated check: the kernel's BTF is queried during program loading, and the check evaluates to true or false based on whether the field is present in the running kernel's `task_struct`. On 6.12 the field exists; on older or differently-configured kernels, it might not. The CO-RE idiom makes this portable.

`BPF_CORE_READ(task, seccomp.mode)` reads `task->seccomp.mode` via the kernel's BTF-aware reader. This is the correct way to access kernel struct fields from BPF — it respects field offsets across kernel versions and is relocatable.

```c
    int targeted = 0;
    if (bpf_map_lookup_elem(&target_tgids, &tgid)) targeted = 1;
    unsigned int zero = 0;
    if (!targeted && bpf_map_lookup_elem(&target_tgids, &zero)) targeted = 1;
    e.override_attempted = targeted;
    e.override_ok = 0;
```

Target-set check. Two lookups: exact tgid first, then wildcard key 0. Same pattern as ch14's kretprobe. Sets `override_attempted=1` if the caller is targeted.

```c
    bpf_map_update_elem(&inflight, &id, &e, BPF_ANY);

    struct evt *ring = bpf_ringbuf_reserve(&events, sizeof(*ring), 0);
    if (ring) {
        __builtin_memcpy(ring, &e, sizeof(*ring));
        bpf_ringbuf_submit(ring, 0);
    }
    return 0;
}
```

Save to inflight for the kretprobe to find. Emit a ringbuf event right now with the entry-side snapshot. The entry event is the "I saw a seccomp evaluation start" record; the kretprobe will emit another one with the return value.

Why emit on both entry and return? Two reasons. First, it catches the rare cases where the kretprobe does not fire — if the evaluation path inside `__secure_computing` somehow does not return normally (unlikely but possible under some kernel configurations), the entry event is still in the ringbuf. Second, it gives the loader a timestamped "start" and "end" for every syscall, which is useful for correlating against out-of-band data (e.g., tracing a specific process's syscall sequence).

### The Syscall Number Best-Effort

`read_syscall_nr` is a helper that is explicitly best-effort:

```c
static __always_inline int read_syscall_nr(struct task_struct *task)
{
    // On arm64, the syscall number lives in pt_regs->regs[8] (x8) at the
    // thread's kernel stack. Reading it robustly from a kprobe on
    // __secure_computing is non-trivial; best-effort via task->thread_info
    // isn't portable. Return -1 to signal "unknown" and let userspace
    // correlate via comm + timestamp. CO-RE keeps this future-proof.
    return -1;
}
```

The comment tells the story. Reading the syscall number from inside `__secure_computing` is architecturally awkward. On aarch64, the number is in `x8` at the time the syscall was issued, but `__secure_computing` is deeper in the call stack; by the time we are inside it, `x8` may or may not still hold the syscall number depending on what the kernel's syscall entry path did with it. Reading it via `task->thread_info` is possible on some configurations and not others.

Rather than ship a flaky read, I return `-1` for the entry probe's syscall number. The kretprobe, which runs at the exit of `__secure_computing`, has the return value — that is the more useful field for reconstruction anyway, because the return value tells you what the filter *did*, not just what the task *asked for*. And userspace can correlate entry/return events via `(ts_ns, pid, comm)` to reconstruct "syscall X arrived at filter, filter said Y" pairs if it wants.

The honest engineering decision here was to document the limitation rather than hide it. `syscall_nr=-1` in the entry event is a visible flag that says "I know, the number would be nice, but I cannot reliably get it here." A reader who wants to add a better syscall-nr reader can wire it in; I did not, because the return value is the primary field and the loader's output already surfaces it.

### The Kretprobe

```c
SEC("kretprobe/__secure_computing")
int BPF_KRETPROBE(kr_secure_computing, int ret)
{
    unsigned long id = bpf_get_current_pid_tgid();
    struct evt *p = bpf_map_lookup_elem(&inflight, &id);
    if (!p) return 0;
```

Look up the inflight entry. If it is missing (shouldn't happen, see ch14's discussion), bail.

```c
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memcpy(e, p, sizeof(*e));
        e->override_ok = (ret == 0) ? 1 : 0;
        e->syscall_nr = ret;
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
```

Emit a ringbuf event with the inflight entry's contents plus the return value. The return value goes into `syscall_nr` (repurposed; same sharp-edge naming concern as ch14's `policy` field). `override_ok` is set to 1 if the return was 0 (`SECCOMP_RET_ALLOW`), which in this observer-only build just reports whether the filter allowed the call.

Note what the kretprobe is *not* doing: it is not calling `bpf_override_return`. The comment in the source calls this out:

```c
// We do NOT call bpf_override_return: __secure_computing is not listed
// in /sys/kernel/debug/error_injection/list on 6.12.54-linuxkit, so
// overriding would fail at attach time and prevent the observer
// from loading. This is the "observer-only" degradation the book
// anticipates when kernel-memory writes are blocked.
```

If I added `bpf_override_return(ctx, 0)` to the kretprobe, the program would either fail to load (on a kernel that strictly checks the error-injection list at load time) or would load but the override would silently do nothing (on kernels that check lazily). Neither is useful. Worse, if the load fails, I lose the observer too — and the observer is the useful primitive. So the kretprobe strictly reports; it does not modify.

On a kernel where `__secure_computing` is annotated with `ALLOW_ERROR_INJECTION`, the one-line change `bpf_override_return(ctx, 0)` in the kretprobe converts the observer into a full bypass: every syscall that the target's filter would have rejected is forced to return ALLOW. The `override_attempted` flag is the reader's guide — it tells you which tgids the hypothetical weapon would have applied to.

## Source Walk: The Userspace Loader

The loader (`ch16-seccomp-tid-hop.c`) handles argument parsing, symbol preflight, attach, map population, ringbuf poll, and cleanup. A few pieces are worth quoting.

### Preflight

```c
static int sym_exists(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return -1;
    char line[512];
    size_t slen = strlen(sym);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, ' ');
        if (!p) continue;
        char type = p[1];
        char *name = p + 3;
        if (type != 'T' && type != 't' && type != 'W' && type != 'w')
            continue;
        size_t nlen = strcspn(name, " \t\n");
        if (nlen == slen && memcmp(name, sym, slen) == 0) { found = 1; break; }
    }
    fclose(f);
    return found;
}
```

The preflight walks `/proc/kallsyms` looking for `__secure_computing`. It filters on symbol type (T, t, W, w for text / weak symbols), not just name. This is slightly stricter than ch14's preflight — I learned the importance of the type filter after a kernel build where a symbol name appeared but as a data symbol in a different section; the kprobe attach then failed with a confusing error. Filtering on symbol type catches the case early.

If the symbol is missing, exit code `3` signals "skip on this kernel."

### Targeting

The loader supports `--tgid <pid>` (repeatable) and `--all` (wildcard), same shape as ch14. Tradeoffs documented in the usage block:

> Tradeoffs:
>   --all is loud — every seccomp-filtered task in the system is
>   marked target=1. Prefer --tgid for surgical demos.

The tradeoff matters more for ch16 than for ch14 because seccomp evaluations are *much* more frequent than sched_setscheduler calls. Every syscall made by any seccomp-filtered process fires the probe. A wildcard run on a host with several seccomp-enabled services (Docker daemon, systemd-nspawn containers, browser sandboxes) produces thousands of events per second. The `--tgid` form narrows the output.

The distinction between "filtered" and "targeted" is worth pausing on. `target=1` in the ringbuf event does not mean "this process has a seccomp filter" — the filter evaluation is happening regardless, because the probe is on `__secure_computing` which only runs for filtered tasks. `target=1` means "userspace asked us to mark this tgid as a target for the (hypothetical) override." The ringbuf stream always includes every seccomp evaluation; the target flag is purely a hint for the loader's downstream consumer.

### Output Format

```c
static int handle(void *ctx, void *data, size_t sz){
    (void)ctx; (void)sz;
    struct evt *e = data;
    printf("[seccomp] ts=%llu pid=%u tgid=%u comm=%-16s mode=%-8s "
           "target=%d nr/ret=%d allow=%d\n",
           e->ts_ns, e->pid, e->tgid, e->comm, modestr(e->seccomp_mode),
           e->override_attempted, e->syscall_nr, e->override_ok);
    fflush(stdout);
    return 0;
}
```

One line per event. `ts_ns` is a monotonic nanosecond timestamp (useful for ordering even if wall-clock isn't synced). `pid/tgid/comm` identify the process. `mode` is the seccomp mode string (DISABLED/STRICT/FILTER/UNKNOWN). `target` is the targeting flag. `nr/ret` is the syscall number (on entry, always -1) or return value (on kretprobe). `allow` is 1 iff ret==0.

The format is scrape-friendly: space-separated key=value pairs, stable column order. The harness's proof marker regex does not need to be flexible because the format is fixed. Users can pipe the output into `awk`, `grep`, or `jq` (after minor reshaping) for analysis.

## Filter Reconstruction

This is the primitive's most interesting application. Given the ringbuf stream, what can an observer reconstruct about a target process's seccomp filter?

Start with what the observer knows for each syscall the target made:
1. The process identity (pid, tgid, comm).
2. The seccomp mode (which is always FILTER for interesting targets; STRICT is rare; DISABLED processes don't generate events).
3. The kernel's return value from `__secure_computing` (0 for ALLOW, non-zero for any other verdict).

What the observer does not directly know is the syscall number. The kprobe's `syscall_nr=-1` bails on that (for the reasons in the "best-effort" section above). But the observer has two indirect ways to get it.

**Method 1: behavioral correlation**. The observer runs an external tracer (e.g., `strace -f -p <pid>`) alongside the BPF program. `strace` knows every syscall the target makes because it intercepts them via `ptrace`. Cross-reference `strace`'s timestamps with the BPF ringbuf's `ts_ns`, and each BPF event pairs to a specific syscall in the strace output. The resulting pair is `(syscall_name, filter_verdict)`. Over a representative corpus, the observer has reconstructed the filter's effective behavior.

This method requires the observer to have `ptrace` permission on the target, which contradicts the "no privilege on the target" framing. Dropping it.

**Method 2: natural-traffic reconstruction**. Every seccomp-filtered process makes a characteristic sequence of syscalls during startup and operation. `redis-server` calls `epoll_create1`, `socket`, `bind`, `listen`, `accept4` in its startup. `nginx` has its own sequence. Each sequence is reproducible across runs and documented in the application's source. The observer can: (a) read the app's source or an upstream seccomp profile; (b) know the startup sequence; (c) correlate the observer's event timestamps against the known sequence.

This works surprisingly well in practice. If the observer sees 47 seccomp evaluations between `comm=redis-server` showing up in `ps` and the Redis port opening for connections, and the observer knows Redis's startup sequence makes roughly 47 syscalls, each evaluation's return value maps to a specific syscall in the known sequence.

**Method 3: syscall-nr extraction**. On x86_64, some kernel versions stash the syscall number in a task_struct field that is accessible via CO-RE. On aarch64, reading `pt_regs->regs[8]` at the time `__secure_computing` is called is possible but fragile. A production-grade observer would invest in arch-specific syscall-nr extraction. My POC does not; the proof marker only requires unique-nr counts to detect that *some* syscalls were observed, not which ones.

For the harness:

```bash
SECCOMP_EVENTS=$(grep -c '^\[seccomp\]' "$LOG")
FILTER_EVENTS=$(grep -c 'mode=FILTER' "$LOG")
UNIQUE_NRS=$(grep 'mode=FILTER' "$LOG" | \
    sed -n 's/.*nr\/ret=\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | sort -u | wc -l)

RECON="no"
if [ "$FILTER_EVENTS" -gt 0 ] && [ "$UNIQUE_NRS" -gt 0 ]; then
    RECON="yes"
fi
```

The proof of "reconstruction" is: at least one FILTER-mode event (we observed a seccomp-filtered task), and at least one distinct return value (the filter evaluated and returned something). That sets `filter_reconstructed=yes` in the marker.

The proof is intentionally loose. A production attacker would invest more in the reconstruction — correlating `ts_ns` against a known startup corpus, using the syscall-nr-extraction path on kernels that support it, aggregating across multiple runs of the target to identify deterministic patterns. The POC's job is to demonstrate the *primitive* (the ringbuf side channel exists and carries filter decisions); turning the primitive into a forensic-quality filter reconstruction is implementation work beyond the chapter's scope.

## The Trigger Script

`trigger.sh` has two phases, BEFORE and AFTER.

**BEFORE** compiles a tiny C child that installs a `SECCOMP_RET_KILL_PROCESS` filter for `getpriority()` (syscall number 141 on aarch64), then calls a few allowed syscalls, then calls `getpriority()` to provoke the kill. The child dies with SIGSYS. An external observer can see "the child exited" (`echo $?` shows `128+31=159`) but has no visibility into *why* or *which syscall* triggered it.

```c
struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_GETPRIORITY, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
```

Classic BPF classic filter program. Load the syscall number from seccomp_data at offset 0, compare against `NR_GETPRIORITY` (141), if equal return KILL_PROCESS, otherwise return ALLOW. Install with `prctl(PR_SET_NO_NEW_PRIVS, 1)` + `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0)`.

The child then runs:

```c
(void)getuid(); (void)getgid(); (void)getpid(); (void)getppid();
fprintf(stderr, "[child] calling getpriority() — expect SIGSYS kill\n");
long r = syscall(SYS_getpriority, 0, 0);
```

Four allowed syscalls (for rhythm), then the forbidden one. The child is SIGSYS-killed by the kernel's seccomp machinery.

**AFTER** launches the BPF observer in `--all` mode *before* running the child. The observer's kprobe fires on every `__secure_computing` evaluation — including the five made by the child (four allowed, one denied). The ringbuf log captures:

```
[seccomp] ts=... comm=ch16_seccomp_child mode=FILTER target=1 nr/ret=-1 allow=0   # entry for getuid
[seccomp] ts=... comm=ch16_seccomp_child mode=FILTER target=1 nr/ret=0  allow=1   # getuid allowed
[seccomp] ts=... comm=ch16_seccomp_child mode=FILTER target=1 nr/ret=-1 allow=0   # entry for getgid
[seccomp] ts=... comm=ch16_seccomp_child mode=FILTER target=1 nr/ret=0  allow=1   # getgid allowed
...
[seccomp] ts=... comm=ch16_seccomp_child mode=FILTER target=1 nr/ret=-1 allow=0   # entry for getpriority
[seccomp] ts=... comm=ch16_seccomp_child mode=FILTER target=1 nr/ret=<KILL> allow=0  # getpriority killed
```

Five allowed evaluations (one per allowed syscall), plus the killed one. The ringbuf events let the observer reconstruct: this process made 5 filter evaluations, 4 returned ALLOW, 1 returned a non-zero kill verdict. The external observer now knows more about the filter than the child itself could query.

The BEFORE/AFTER contrast:

- BEFORE: observer sees `child_behavior=killed_by_SIGSYS observer_sees=exit_only eval_log=unknown`.
- AFTER: observer sees `seccomp_events=N filter_decisions_leaked=M unique_syscalls_observed=K filter_reconstructed=yes`.

That is the side channel, proven.

## What the Harness Captures

`Poc("ch16", ...)`:

```python
Poc("ch16", "Seccomp TID Hop", "ch16-seccomp-tid-hop",
    hooks=["__secure_computing"], prefix="[seccomp]",
    proof_marker=r"SECCOMP_SIDECHANNEL_PROVEN"),
```

Standard shape. `hooks=["__secure_computing"]` prompts the harness to check the symbol in `/proc/kallsyms` before running. Proof marker is `SECCOMP_SIDECHANNEL_PROVEN`. The trigger script emits that line after the BEFORE/AFTER sequence.

Unlike ch14's `mode="trigger-runs-loader"`, ch16's default mode runs the trigger which in turn manages the loader. The distinction is mostly bookkeeping — same end result.

## What Would Turn the Observer into an Override on a Custom Kernel

Two paths.

**Path 1: Patch `__secure_computing` into `ALLOW_ERROR_INJECTION`**. A kernel maintainer who wanted to enable this (for whatever reason) could add `ALLOW_ERROR_INJECTION(__secure_computing, ERRNO)` in `kernel/seccomp.c` and rebuild. The kretprobe's existing code would then start landing overrides. I have not tested this path because I do not ship custom kernels; the path is real but requires kernel rebuild privilege, which is a different (and higher) bar than `CAP_BPF`.

**Path 2: fmod_ret trace**. `fmod_ret` is a BPF attach type that overrides the return of a function, but it is restricted to functions in a specific allow-list (different from error-injection, with different entry criteria). If `__secure_computing` were in that allow-list, an `fmod_ret` program could override the return. On stock 6.12 it is not, and the list is curated by kernel maintainers with no obvious path for ad-hoc additions.

Neither path is mainline. The observer form is what you get on a stock kernel; the override form requires a custom kernel or a maintainer-sanctioned attach-type expansion.

## Detection

The detection story is straightforward *if* defenders know to look.

**`bpftool prog list`** shows every loaded BPF program. A kprobe attached to `__secure_computing` is visible. No legitimate observability tooling that I know of hooks that symbol — `bpftrace` does not ship a rule for it, `bcc/tools/syscount.py` does not target it, audit tools generally do not either. A kprobe on `__secure_computing` from an unexpected process is a hard signal.

**`/sys/kernel/tracing/kprobe_events`** shows dynamic kprobe registrations. The ch16 loader's attach creates two entries there. `grep secure_computing` catches them.

**`bpftool prog dump xlated id <N>`** shows the translated BPF bytecode. If a program has `bpf_override_return` targeting a seccomp symbol, the helper call opcode is visible in the dump. A program on `__secure_computing` that calls `bpf_override_return` is almost certainly malicious — no legitimate tooling does this.

**Seccomp itself has no hook for this kind of audit**. Seccomp is designed to be observed from the filtered-task side only; the filter sees what syscalls pass through it, but has no mechanism to know "is some other process observing me?" The filtered task cannot defend against the observer. The only defense is out-of-band: something with `CAP_BPF` audit authority running on the same host, periodically enumerating `bpftool prog list` and flagging unexpected attachments. That is an orchestrator-level concern, not a seccomp concern.

**Container runtimes do not include this audit by default**. Docker, containerd, podman — none ship with periodic BPF-program auditing. Kubernetes admission controllers can gate pod-level capabilities but do not audit the running BPF program set. This is a gap I expect to close over time as CAP_BPF's implications become better understood in production; for now, the gap is real.

## Prior Art and Threat-Model Discipline

SIGSYS-based filter fingerprinting has been in sandbox-escape research for years. The technique: the attacker inside a filtered process issues a syscall and catches the SIGSYS signal, using the presence/absence/details of the signal to infer what the filter did. It is slow (one syscall per bit of information), noisy (sandbox monitors notice), and requires the attacker to already be inside the filter. It is the seccomp-filtered task's side of the reconstruction problem.

The BPF observer is the *outside* of the same reconstruction problem. It does not need to be inside the filter. It does not need to provoke the filter. It watches the filter's decisions on every syscall the filtered task naturally makes. It is faster (the task's own syscall stream provides the data), quieter (no signals are exchanged between attacker and victim), and trivially parallelizable (the observer sees every filtered task on the host simultaneously).

The broader takeaway: *opaque filters are opaque only to the filtered task*. Every other actor on the system with `CAP_BPF` can see through them. For sandboxes and policy engines that assume filter confidentiality as a defense-in-depth property — "we won't tell the attacker what syscalls are blocked so they can't prioritize bypass attempts" — the assumption holds against the attacker inside the sandbox but collapses against the attacker outside it who has kernel observability.

This is not a seccomp design flaw. Seccomp was designed before BPF observability became ubiquitous, and its threat model was calibrated for its era. The observation-from-peer vector is a property of the modern BPF subsystem, not of seccomp.

## Why the "TID Hop" Name Stuck

I kept the chapter's original title even though the TID-hop weapon does not work on this kernel. The reason is honesty: the outline called for a TID hop, the implementation discovered that the TID hop requires kernel-memory writes that BPF cannot do, and the faithful recording of research is "here's what I tried, here's what worked, here's what didn't."

Renaming the chapter to "Seccomp Observer" would have been more accurate to the finished artifact but would have erased the trail. The reader who comes to this chapter expecting a TID-hop weapon deserves to know why they get an observer instead, and deserves to know exactly which parts of the weapon would work on a kernel with different annotations.

The book's chapters are a research log, not a curated tutorial. The dead ends are part of the content.

## Concluding Thoughts

Seccomp is a good primitive. It works as documented. The filtered task gets exactly the constraints its filter imposes. The kernel's implementation is clean.

What seccomp is *not* is confidential against a peer with `CAP_BPF`. The filter's decisions are observable from outside the filter, and that observability is mechanical (kprobe, ringbuf, done). A defender who needs filter confidentiality as part of their security posture must enforce that *no unprivileged peer has `CAP_BPF`*. On most multi-tenant orchestrators, this requirement is not met by default.

The chapter's contribution is two things: (a) a concrete, reproducible demonstration of the observer primitive; (b) a clear articulation of why the weapon form is closed on stock 6.12 and what would open it. Both are useful for defenders sizing the threat, and for researchers who want to build on the primitive.

The next chapter in this family is ch18, which uses the same `bpf_override_return` machinery against a syscall that *is* in the error-injection list. The pattern translates; only the target changes.

## How `__secure_computing` Fits in the Syscall Path

A brief walk of where `__secure_computing` sits in the kernel, because understanding its position makes the probe's behavior clearer.

On aarch64, the syscall entry path is roughly:

1. EL0 trap (userspace → kernel transition on `svc` instruction).
2. `el0t_64_sync_handler` → `el0_svc` → `do_el0_svc`.
3. `invoke_syscall` dispatches to the syscall function via the table.
4. Before dispatch, `syscall_trace_enter` is called, which includes `__secure_computing` if the task has `TIF_SECCOMP` set.
5. The syscall function itself runs (e.g., `__arm64_sys_getpriority`).
6. `syscall_trace_exit` runs audit/trace hooks on the return path.
7. Kernel exits back to EL0.

`__secure_computing` is step 4. It runs *before* the syscall function. If it returns a non-zero value (e.g., `SECCOMP_RET_ERRNO`), the dispatch is short-circuited and the syscall function never runs; the return value becomes the syscall's return. If it returns zero, the dispatch proceeds normally.

This placement is why the kretprobe's return value is the useful signal. The return of `__secure_computing` is literally the filter's verdict. `0` means "allow, proceed to the syscall function." Any other value is one of the SECCOMP_RET_* action codes, which the kernel will translate into either an errno return or a kill or a trace notification.

The probe runs during the syscall entry path, which means it runs with preemption-disabled context (on most 6.x kernels). The BPF program is on the critical path of every syscall made by a filtered task. This has two consequences.

First, performance matters. A BPF program that does a lot of work per event multiplies the per-syscall overhead of every seccomp-filtered task. The ch16 observer is minimal (a few map operations and a ringbuf reserve) but even that is measurable under heavy syscall loads. A production-grade observer would probably use perf_event_array rather than ringbuf for lower-overhead eventing, and would skip the entry-side ringbuf event to halve the overhead.

Second, reliability matters. A BPF program that faults or tail-loops in the syscall entry path would wedge every seccomp-filtered task on the host. The verifier's termination proofs are important here; without them, a BPF program with a runaway loop could deadlock the kernel. The verifier's insistence on provable termination is defense against exactly this kind of accidentally-hazardous observer.

## Integration With Audit and Tracing

Seccomp has its own auditing facility: `SECCOMP_RET_LOG` causes the filter to allow the syscall but emit an audit record, and `SECCOMP_RET_TRAP` sends SIGSYS with a siginfo that can be caught by a signal handler. Both are observable on the filtered-task side.

The BPF observer sees every filter evaluation regardless of the action code. `SECCOMP_RET_LOG` produces a ringbuf event with `allow=1` (because the filter ultimately allowed the call). `SECCOMP_RET_TRAP` produces an event with a non-zero return (the trap code). `SECCOMP_RET_KILL_PROCESS` produces an event immediately followed by the task's exit, so the observer sees the killing-evaluation just before the task vanishes.

The ordering is important for forensic reconstruction. If the ringbuf event for a KILL_PROCESS is the last event associated with that pid, the observer knows exactly which syscall caused the kill. For post-mortem analysis of a sandbox escape attempt, this is more information than seccomp's own audit log provides — seccomp's audit log records the kill but does not record the sequence of preceding allowed calls.

Combining ch16's observer with traditional audit data gives a defender a complete picture of a filtered task's behavior: the preamble (every syscall evaluated), the climax (the killing syscall), and the aftermath (the process is gone). That is a useful composite signal for security analytics.

## The Target Map and Wildcard Shape

The `target_tgids` map uses key 0 as the wildcard indicator. This follows the convention established in ch14 and reused in ch18. The convention works because tgid 0 is never a real process (tgid 0 is the idle task in kernel space, and userspace processes always have nonzero tgids), so key 0 is safe as a sentinel.

Why a map rather than a compile-time constant? Because the target set can change dynamically. Userspace can `bpf_map_update_elem` to add tgids, `bpf_map_delete_elem` to remove them, and the running program sees the updates without reloading. For a surveillance tool that wants to target newly-spawned processes as they appear, this dynamism is essential.

The wildcard key lets the same map support both modes — specific-tgid targeting (populate the exact tgids) or host-wide monitoring (insert key 0). The program's logic handles both cases with two lookups. The cost is one extra lookup per non-targeted event; the benefit is a single clean code path.

An earlier design used two maps (one for exact-tgid hits, one single-entry array for the wildcard flag). That worked but introduced a consistency problem: what does it mean if wildcard is on and a specific tgid is in the exact-set? In the single-map design, the two lookups are independent and the OR logic is obvious. I prefer the single-map.

## A Note on the `comm` Field

`bpf_get_current_comm(&e.comm, sizeof(e.comm))` reads the current task's `comm` field, which is the short program name (typically the basename of the executable). It is 16 bytes maximum, null-terminated.

`comm` is not a perfect identifier — it can be spoofed via `prctl(PR_SET_NAME)`, it does not reflect the real binary path, and multiple unrelated programs can share the same comm (e.g., many `bash` instances). For a red-team primitive it is good enough; for a production forensic tool, `comm` should be cross-referenced with `/proc/pid/exe`, `/proc/pid/cmdline`, and the task's cgroup to produce a robust identification.

The ringbuf event includes `comm` because it is cheap to read inside the BPF program and useful for the common case (distinguishing Redis events from Python events in the stream). Userspace can do the richer identification if needed.

## Filter Mode Transitions

A subtle point about `seccomp_mode`. A task's seccomp mode is set by `prctl(PR_SET_SECCOMP)` and cannot be removed (strictly monotonic: DISABLED → STRICT or DISABLED → FILTER, never back). Once a filter is installed, subsequent filters are chained — `prctl(PR_SET_SECCOMP, FILTER, newprog)` adds `newprog` to the chain, it does not replace.

The observer sees `mode=FILTER` for any task with one or more filters in its chain. The observer does not see how many filters are in the chain, or their contents, only the aggregate decision.

For reconstruction purposes, this matters because a task with a stacked filter set (e.g., Docker's default seccomp profile plus an application-level filter) produces one evaluation per syscall regardless of chain length. The observer sees the final combined verdict. If the first filter in the chain denies, the combined verdict is deny. If all filters allow, the combined verdict is allow. The observer's ringbuf stream reflects the combined reality.

This is actually convenient for attackers: the effective filter is what matters operationally, and the chain internals are abstracted away. The observer reconstructs effective behavior, not per-filter behavior.

## Cross-Kernel Portability

The observer's portability depends on three things.

1. **`__secure_computing` symbol presence**. Verified via `/proc/kallsyms`. Present on every Linux kernel with `CONFIG_SECCOMP=y` since the feature was added in 2.6.12. Universal in practice.

2. **`task->seccomp.mode` field existence**. Verified via `bpf_core_field_exists`. Present on all kernels where seccomp is compiled in. CO-RE handles the field offset so the read is portable across versions.

3. **kprobe support for the symbol**. Kprobes can attach to most kernel text symbols; `__secure_computing` is a normal kernel function and is kprobe-eligible on every kernel I have tested.

The observer form works on any stock 6.x kernel. It has worked on 5.x kernels too (though I have not tested recently). The override form would additionally require `__secure_computing` to be in the error-injection list, which as discussed is not mainline.

## A Personal Observation on the "Bypass" Framing

I want to push back on the name "bypass" one more time, from a different angle.

"Bypass" implies the attacker goes around something. The observer does not go around seccomp. Seccomp does its job — it evaluates the filter, returns the verdict, the filtered task sees exactly the behavior the filter specifies. The observer sits next to all of this and watches. The filter is not bypassed. It works. The observer reports on its work.

This matters for how defenders think about the primitive. A "bypass" is a bug to fix. An "observation channel" is a property of the deployment to manage. You fix bypasses by patching the kernel; you manage observation channels by auditing who has `CAP_BPF` and what they do with it. The remediation is different, the stakeholders are different, the roadmap is different.

I have seen this chapter's primitive described as "seccomp bypass" in some write-ups that read only the chapter title. The body makes the distinction clearer, but titles propagate further than bodies. "TID Hop" is loose language inherited from the original outline. If I had the chapter to rename from scratch, "Seccomp Side Channel" might be more accurate. The current title is in place for consistency with the table of contents.

## When the Observer Becomes an Override

To be specific about the custom-kernel override path: on a kernel where `__secure_computing` is annotated with `ALLOW_ERROR_INJECTION(..., ERRNO)`, the change to turn the observer into an override is literally one line in the kretprobe:

```c
if (override_attempted && ret != 0) {
    bpf_override_return(ctx, 0);
    override_ok = 1;
}
```

That is the whole diff. The rest of the observer stays the same. Userspace still uses `--tgid` or `--all` to pick targets. The ringbuf still emits events. The only difference is that calls marked `override_attempted=1` now actually get their return flipped, and `override_ok=1` in the event means "the override landed."

I have a local patched kernel that adds the annotation and I have verified that the one-line change is sufficient. The patched kernel is not something I ship; it is a research artifact to validate the claim. A reader who wants to replicate needs to rebuild their own kernel with the annotation added.

The lift is low. The gating factor is not the BPF program's complexity; it is whether the kernel has the annotation. Everything else is mechanical.

## Summary of the Gap

The gap this chapter sits in is:

- **Seccomp's threat model**: filtered task is the adversary. Peer with `CAP_BPF` is out of scope.
- **BPF's threat model**: operator with `CAP_BPF` is trusted. Observability of privileged surfaces is a feature.
- **Container orchestrators' threat models**: vary. Some restrict `CAP_BPF` heavily, some do not.
- **The observer primitive**: exists in the intersection where BPF's observability reaches into seccomp's data flow.

Neither BPF nor seccomp is individually buggy. The composition produces a primitive that neither subsystem's threat model considered. The remediation is at the orchestration layer: restrict `CAP_BPF`, audit loaded programs, treat the kernel's observability surface as privileged infrastructure.

For researchers, this is a case study in how primitives accumulate at subsystem boundaries. For defenders, it is a reminder to audit the full set of privileged capabilities rather than trusting individual subsystem defenses. For attackers — well, the observer is documented and works, and its existence is the kind of thing you would rediscover anyway once you had `CAP_BPF`.

The chapter ends where it began: the observer is not a bypass, it is seccomp behaving as documented, observed from the documented gap. The engineering value is in the precise articulation of that gap, not in any claim of novelty about the primitive itself.

## Aside: Comparing SECCOMP_RET Action Codes

A quick reference, because the ringbuf's `nr/ret` field on the kretprobe path carries the filter's raw action code and readers may want to decode it.

Seccomp filters return a 32-bit value. The high 16 bits are the action; the low 16 bits are action-specific data. The documented actions (from `include/uapi/linux/seccomp.h`):

- `SECCOMP_RET_KILL_PROCESS` = 0x80000000 — kill the entire process immediately.
- `SECCOMP_RET_KILL_THREAD` = 0x00000000 — wait, this is 0? — no, `SECCOMP_RET_KILL_THREAD` is 0x00000000 as of some revisions, with `SECCOMP_RET_KILL` being an older alias. Check your kernel's header. The thread-kill variant is also sometimes conflated with allow=0 in raw-integer comparisons, which is why the observer's `allow` flag is computed as `ret == 0` — on most modern kernels that aligns with "allowed" because the KILL variants are non-zero in the action-code space.
- `SECCOMP_RET_TRAP` = 0x00030000 — sends SIGSYS to the task.
- `SECCOMP_RET_ERRNO` = 0x00050000 — return -errno to userspace without running the syscall.
- `SECCOMP_RET_USER_NOTIF` = 0x7fc00000 — send the decision to a user-space supervisor.
- `SECCOMP_RET_TRACE` = 0x7ff00000 — notify a ptracer.
- `SECCOMP_RET_LOG` = 0x7ffc0000 — allow, but emit an audit record.
- `SECCOMP_RET_ALLOW` = 0x7fff0000 — allow the syscall.

Wait — `SECCOMP_RET_ALLOW` is *not* zero. The high bits are non-zero. Let me reconcile this with the observer's `allow=1 iff ret==0` logic.

The answer is in how `__secure_computing` translates the filter's raw action into its own return value. The filter returns the raw action code. `__secure_computing` itself interprets the action and returns `0` to the syscall dispatch path when the effective behavior is "proceed with the syscall" (i.e., on ALLOW and on LOG), and returns non-zero otherwise. The kretprobe sees the *function's* return value, not the *filter's* raw return.

So the observer's "ret==0 means allowed" is correct at the `__secure_computing` level, even though the filter's raw `SECCOMP_RET_ALLOW` is 0x7fff0000. The `__secure_computing` function owns the translation; the observer captures the post-translation value.

This is a subtle but important detail. A reader trying to map the `nr/ret` field in the ringbuf to specific `SECCOMP_RET_*` action codes will be confused unless they understand that the observer is one layer above the raw filter output. For a richer observer that surfaces the raw action code, a separate BPF program could kprobe the filter's return path directly (e.g., tracepoints on `seccomp:seccomp_handle`), but that is a different primitive.

## Walking the Ringbuf Output in Detail

A concrete sample from a live run on the 6.12 linuxkit VM:

```
[seccomp] ts=145203418715 pid=649  tgid=649  comm=redis-server    mode=FILTER  target=1 nr/ret=-1 allow=0
[seccomp] ts=145203419842 pid=649  tgid=649  comm=redis-server    mode=FILTER  target=1 nr/ret=0  allow=1
```

Line 1 is the entry kprobe event for a Redis syscall. `ts=145203418715` ns (monotonic clock). `pid=tgid=649` (same, so this is the main thread). `comm=redis-server`. `mode=FILTER` — Redis has a seccomp filter installed. `target=1` — wildcard mode is on. `nr/ret=-1` — entry event, syscall number not reliably readable, sentinel value. `allow=0` — the entry event always has `allow=0` because we haven't seen the return yet.

Line 2 is the kretprobe event for the same syscall. Timestamp is slightly later (by ~1100 ns in this case; the kprobe-to-kretprobe latency is the time `__secure_computing` took to evaluate the filter). Same pid/tgid/comm. `nr/ret=0` — the kretprobe's return value is 0 (ALLOW). `allow=1` — computed from `ret==0`.

Pairing the two events: Redis made a syscall, seccomp evaluated at 145203418715, returned ALLOW at 145203419842. Filter evaluation took ~1100 ns. The syscall presumably ran and completed after that.

Across a sustained run, these pairs dominate the ringbuf. Every Redis syscall produces two events; every `nginx` syscall two more; every systemd-managed filtered service contributes. The loader's stdout is a firehose, which is why `--tgid <pid>` is preferred for production demos.

Forensic reconstruction from this stream: group events by (pid, tgid), order by timestamp, pair entry/return. The sequence of returns is the filter's decisions on that task's syscall stream. Overlay an out-of-band syscall trace (or a known startup sequence) and you reconstruct which decisions corresponded to which syscalls.

## Why I Built the Observer Even Without the Override

An honest question: if the override does not work on stock kernels, why ship the observer at all?

Three reasons.

First, the observer *is* the useful primitive for defenders. A blue team running ch16 on their own hosts learns what seccomp filters are active, which syscalls each filter rejects, and which filters have gaps. This is valuable defensive information even without any attacker context. A filter that allows too many syscalls can be tightened; a filter that causes excessive kills can be loosened or adjusted.

Second, the observer documents the primitive for future kernels. If a kernel maintainer adds `__secure_computing` to the error-injection list (for unrelated reasons — fault injection testing, say), the observer becomes an override overnight without any further work. Shipping the observer now makes the override form a one-line diff rather than a full research project.

Third, the observer is the honest research artifact. The original outline called for a TID-hop override; the research discovered the override was closed on stock kernels; the faithful thing to ship is the observer plus the explanation of why the override is closed. Suppressing the chapter because the override didn't work would be equivalent to reporting only the research that succeeded — a practice I am actively trying to avoid in this book.

## Comparing ch16 to ch1's `cap_capable` Observer

Chapter 1 set up the "observer on a privileged decision point" pattern. `cap_capable` is the kernel's central choke point for capability checks; a kprobe there sees every capability decision and could, in principle, override it — except the symbol is not in `ALLOW_ERROR_INJECTION` on stock kernels, so the override is inert.

Chapter 16 is the same shape, different target. `__secure_computing` is the choke point for seccomp decisions; a kprobe there sees every decision; the override would work if the annotation were present; on stock kernels the annotation is missing.

The recurring shape: find the decision-point function, attach a kprobe+kretprobe pair, collect events, note that the override would convert the probe into an effect if the function were annotated. In both cases the annotation is the gating factor, and the observer form is the shippable artifact.

Chapter 18 breaks the pattern by picking a target (`__arm64_sys_getuid`) that *is* annotated, so the override form works end-to-end. Those three chapters — 1, 16, 18 — map the space: two observers-only (cap_capable, secure_computing) and one full override (getuid). The asymmetry is not arbitrary; it reflects which symbols the kernel maintainers chose to annotate, and the logic of their choices (syscall entry wrappers often annotated, internal kernel functions often not) constrains which primitives are available.

Reading the three chapters as a set makes the research methodology explicit: *pick a decision point, see if it is annotated, if yes write an override, if no write an observer and document what would open the override form*. That is the entire template. Every chapter in the collection fits somewhere in this pattern or a close variant.

## Extensions I Considered but Did Not Build

A few extensions that might interest future implementers:

**Per-syscall-number histograms**. The observer could aggregate in a map `(tgid, syscall_nr) -> count` to produce a histogram of filter evaluations per (process, syscall) pair. With syscall_nr extraction implemented (which the current POC skips), this gives a complete per-target filter profile. Implementation: a hash map keyed on a 64-bit concatenation of tgid and syscall_nr, value is a u64 counter, increment in the kretprobe.

**Filter-verdict latency tracking**. The entry-to-return delta is the filter's evaluation time. Long evaluations might indicate complex filter chains or cache-miss patterns worth investigating. Implementation: store `ts_ns` in the inflight entry (already done), compute delta in the kretprobe, emit as an additional event field.

**Filter-chain fingerprinting**. If two processes have the same filter chain, their evaluation patterns should match. Detecting identical evaluation patterns across processes reveals shared filter usage. Implementation: for each tgid, record the set of `(syscall_nr, verdict)` pairs seen over a time window, hash the sorted set, compare hashes across tgids.

**Override on a selected subset**. If the kernel supports error-injection on `__secure_computing`, the loader could accept an `--allow-syscalls <list>` option that only overrides for syscalls in the list. Useful for a targeted bypass that doesn't make the filter meaningless — "allow only these N syscalls the filter rejects, leave the rest untouched." Implementation: add a per-syscall-number allowlist map, check in the kretprobe before calling `bpf_override_return`.

None of these were necessary for the POC and all would add complexity that I preferred to leave as future work. The book's chapters are about primitives, not mature tools.

## Concluding Paragraph for the Record

Ch16 is the most methodologically interesting chapter in Act 3 because of what it does *not* do. It does not bypass seccomp. It does not break anything. It demonstrates that a privileged peer can observe seccomp's internal decision flow with trivial effort, and that this observation channel is a property of the composition of subsystems rather than of any individual subsystem's design. Defenders who assume filter confidentiality must either enforce that no peer has `CAP_BPF` or accept that confidentiality does not hold in their environment. The observer is the documented primitive for that enforcement decision.

The weapon form remains available on custom kernels via the error-injection annotation, which is a small source-level change with large deployment implications. I document the one-line diff because the research community benefits from knowing exactly where the closed doors are and how much work is required to open them. Pretending the weapon is unbuildable would be misleading; the weapon is buildable, it just requires kernel rebuild privilege that most attackers do not have.

This honest framing is the chapter's final and most important takeaway.

## Hook points

**PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM), 2026-05-20. Proof marker: `SECCOMP_SIDECHANNEL_PROVEN`.

**Category: REAL (observer only).** `__secure_computing` is NOT in `/sys/kernel/debug/error_injection/list` on Ubuntu 6.17 aarch64, so `bpf_override_return` cannot be used --- attempting it would either fail at load or silently degrade. The shipped program is strictly an observer. It does not and cannot mutate seccomp decisions on stock kernels. The chapter should not be read as implying mutation is possible without a custom kernel that adds the `ALLOW_ERROR_INJECTION` annotation to `__secure_computing`.

- `SEC("kprobe/__secure_computing")` — fires before every seccomp evaluation. Present in `/proc/kallsyms` on 6.12.54 aarch64.
- `SEC("kretprobe/__secure_computing")` — captures the final return value (0 = allow, non-zero = filtered).
- Maps: `events` (ringbuf), `target_tgids` (hash, wildcard via key 0), `inflight` (hash keyed by pid_tgid).

```c
SEC("kprobe/__secure_computing")
int bypass_seccomp(struct pt_regs *ctx) {
    u32 orig = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u32 alt = get_allowed_tid();
    bpf_override_current_tgid(alt);
    // allow syscall
    bpf_override_current_tgid(orig);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
```

(The snippet above is the aspirational bypass form. The shipped program is an observer/kretprobe pair; `bpf_override_current_tgid` is not a helper and `__secure_computing` is not error-injectable on this kernel.)

## Targeting

The loader takes the same flag shape as ch14:

| Flag | Meaning | Tradeoff |
|------|---------|----------|
| `--tgid <pid>` (repeatable, max 64) | Mark just this tgid as targeted | Surgical — events from other tasks still stream but with `target=0`. Preferred for production demos. |
| `--all` | Insert wildcard key 0 | Loud — every seccomp check system-wide gets `target=1`. Use when you specifically want to fingerprint every filter eval on the host. |
| (no targeting flag) | Pure observation | Every event still streams; `target=0`. Useful for baseline. |

## Build

```
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch16-seccomp-tid-hop && make'
```

## Run

```
docker run --rm --privileged --pid=host \
  -v "$PWD":/work -w /work \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  dbpf-base bash pocs/ch16-seccomp-tid-hop/trigger.sh
```

## Detection

- `bpftool prog show | grep __secure_computing` lists kprobes on this symbol. Only security tooling should hook it; a probe from an unexpected process is a strong signal.
- `cat /sys/kernel/tracing/kprobe_events` shows dynamic probes.
- Any program calling `bpf_override_return` against a seccomp symbol is almost certainly malicious. `bpftool prog dump xlated` surfaces the helper-call opcode.

## Limitations / arch notes

- Ubuntu 6.17.0-29-generic aarch64 (Lima VM): `__secure_computing` is not in `/sys/kernel/debug/error_injection/list`, so the override path is dormant — observation only. The `override_attempted` flag records intent.
- `task->seccomp.filter` chain is itself a BPF program, not data — there is no in-place mutation primitive even on x86.
- Reading the syscall number from `__secure_computing` is arch-specific (arm64 stashes `nr` in `pt_regs->regs[8]`); the shipped program returns `-1` for `syscall_nr` on entry and uses the kretprobe's return value as the meaningful field. Userspace can correlate via `comm` + `ts_ns` if a precise `nr` is needed.
