# BPF Audit Pass 2 — ch06/ch07/ch08/ch09

Defensive audit of seven `.bpf.c` programs against the 12 criteria
(unbounded loops, unbounded reads, pointer-arithmetic bounds, stack
size, helper availability, CO-RE correctness, GPL marker, SEC()
validity, ringbuf lifecycle, implicit returns, pointer-null-check
ordering, map type/key/value consistency).

Scope:
- `/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch06-silence-selinux/ch06-silence-selinux.bpf.c`
- `/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch06-silence-selinux-lsm/ch06-silence-selinux-lsm.bpf.c`
- `/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch07-devcgroup-houdini/ch07-devcgroup-houdini.bpf.c`
- `/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch08-keyring-heist/ch08-keyring-heist.bpf.c`
- `/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch08-keyring-heist-kprobe/ch08-keyring-heist-kprobe.bpf.c`
- `/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch08-keyring-heist-lsm/ch08-keyring-heist-lsm.bpf.c`
- `/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch09-pid-doppel/ch09-pid-doppel.bpf.c`

No code changes made. Findings are ranked High / Medium / Low.

---

## ch06-silence-selinux (observer kprobes)

Clean on 9/12 criteria. Ringbuf reserve/submit pairs are balanced on
every branch (early returns happen before reserve). GPL marker, SEC()
strings, map type/key/value, stack usage (`struct evt` ~48B) all OK.

**Medium — `avc_has_perm_noaudit` heuristic pointer test (lines
81–91).** The program tries to autodetect whether the first kprobe
argument is `struct selinux_state *` versus a scalar `ssid` using
`if (a0 > 0xffff000000000000ULL)`. On aarch64 with 52-bit VA / KASLR
disabled, kernel pointers may sit below that sentinel (e.g.
`0xffff8000…`); the test is correct for that range but will classify
any 32-bit SID with its high word non-zero the same way. Since `ssid`
is a `u32` the upper 32 bits are zero, so in practice the heuristic
works — but note this in the chapter text, because the function
signature changed upstream and the heuristic will go stale.

**Low — argument-count mismatch in BPF_KPROBE macro (line 71–73).**
`kp_avc_has_perm_noaudit` declares four args but the upstream prototype
took five (`state, ssid, tsid, tclass, requested`) prior to kernel
~5.18 and four after. BPF_KPROBE copes with reading more args than the
register bank can supply (unread regs are just garbage), but the comment
should flag that `a3` is undefined on the 5-arg variant when arg0 is the
state pointer. No verifier impact — arg access from `pt_regs` is always
valid even if semantically wrong.

---

## ch06-silence-selinux-lsm (fmod_ret mutation)

**Medium — fmod_ret return convention.** For `lsm/*` fmod_ret programs
the verifier enforces that returned errors be drawn from the hook's
allowlist; returning 0 (allow) is always permitted, and the program
only ever returns either the original `ret` or 0, so this is safe.
Worth calling out: returning an arbitrary negative value would be
rejected by the verifier for some hooks. The code is correct, but a
one-line comment asserting "we never synthesize a new error" would
help readers.

**Low — STAGE_* machine referenced in the audit brief is absent.** The
audit brief asked to verify `STAGE_DENY / STAGE_FLIP` consistency in a
`ctrl_map`. That construct does not exist in this tree — the current
LSM variant uses `target_tgids` (hash map, wildcard key 0) plus three
compile-time hook IDs `H_FILE_PERMISSION=1`, `H_INODE_PERMISSION=2`,
`H_BPRM_CHECK_SECURITY=3`. Those three constants DO match the
userspace `hook_name()` switch in
`ch06-silence-selinux-lsm.c` (`case 1/2/3`). No inconsistency.

Stack usage per program (~40B for `struct evt` plus locals) is well
under 512B. Ringbuf reserve/submit pairing is balanced.

---

## ch07-devcgroup-houdini (kprobe + kretprobe + bpf_send_signal)

**High — `bpf_send_signal` from kretprobe is policy-gated.**
`bpf_send_signal()` is allowed from kprobe, kretprobe, tracepoint,
perf_event, and raw_tp programs on modern kernels. Linux 6.12 accepts
it from kretprobe (see `kernel/trace/bpf_trace.c:bpf_send_signal_proto`
gated on `prog->type == BPF_PROG_TYPE_KPROBE` which covers both
variants). This is safe.

However, there is a **real semantic hazard**: `bpf_send_signal()`
targets `current`. At kretprobe entry, `current` is the task whose
`devcgroup_check_permission()` just returned — i.e. the process that
attempted the device op. Good. But if the kernel ever inlines the
permission check into a worker thread (it does not today for this
symbol), `current` would be the worker, not the requester. Worth a
one-line comment asserting "non-worker context expected".

**High — inflight map race across nested fork.** The `inflight` hash
keyed on `bpf_get_current_pid_tgid()` drops entries if a process
nests another kprobe entry before the kretprobe returns
(stack-recursion / NMI / softirq reentry). This is not a verifier bug,
just a lost-event risk; ringbuf submission from kretprobe reads the
stashed `p`, so a lost entry yields no event. Acceptable for a PoC.

**Medium — `signal_count` rate limit is racy.** Read-modify-write on
the per-tgid counter without an atomic (`__sync_fetch_and_add`) can
under-count; the cap `MAX_SIGNALS=32` is only a soft ceiling. Not a
verifier issue, but note it.

**Low — `struct evt e = {}` on stack is 72 bytes**, well within limits.
Map value type `struct evt` matches consumer reads in the kretprobe
path; ringbuf event layout is identical to the hash-map value. Good.

No unbounded loops; no CO-RE reads (all args come direct from
`pt_regs`). SEC strings valid; GPL marker present; ringbuf
reserve/submit pairs balanced.

---

## ch08-keyring-heist (observer kprobe w/ payload exfil)

**High — `payload.data[0]` assumption is fragile.** `struct key`'s
`payload` is a union; `data[0]` is only the "user" type's slot. For
other key types (`keyring`, `asymmetric`, `encrypted`, `trusted`,
`logon`) the slot has different semantics (pointer to a keyring,
to a `public_key`, etc.). The code reads it unconditionally whenever
`datalen > 0`, so on a non-user key it will `bpf_probe_read_kernel`
from whatever happens to sit there. `bpf_probe_read_kernel` is
fault-tolerant (returns `-EFAULT` on bad addr), but for a keyring
pointer the dereference WILL succeed and yield garbage bytes into
`payload[]`. The `s->type` field is filled before this, so userspace
MUST gate payload interpretation on `strcmp(type, "user") == 0`. Flag
this in the chapter — the BPF does not itself filter by type.

**High — hardcoded `+16 +2` offset for `struct user_key_payload`.**
Line 84 computes `void *secret = data_ptr + 16 + 2;` assuming
`sizeof(struct rcu_head) == 16` and `sizeof(unsigned short) == 2`.
This is true on arm64/x86_64 for Linux 6.12 but is NOT CO-RE — a
kernel with lockdep or RCU tracing enabled can grow `rcu_head`. The
correct form is `bpf_core_field_offset(struct user_key_payload, data)`.
The fallback path on line 91 (read directly from `data_ptr`) papers
over the issue only if the first `dlen` bytes happen to look right.
This is the most brittle piece in the whole batch.

**Medium — `dlen & (PAYLOAD_CAP - 1)` masks payload length.** Because
`PAYLOAD_CAP == 128` (power of two) the mask produces `dlen mod 128`,
which is fine for feeding the verifier a proven bound ≤128. But when
`datalen == 128` itself the mask yields 0, silently reading zero bytes
— so the exfil fails precisely at capacity. Fix would be an explicit
`min(dlen, PAYLOAD_CAP)` conditional. Not a verifier rejection, just a
silent corner case.

**Medium — `struct evt` is `PAYLOAD_CAP + ~100 = ~240 bytes`.** Too
large for direct stack use; the program correctly routes through a
`BPF_MAP_TYPE_PERCPU_ARRAY` scratch slot. Good. Verifier will accept.
`__builtin_memcpy(e, s, sizeof(*e))` into ringbuf-reserved memory is
fine — reserved region is `sizeof(struct evt)` bytes.

**Low — `__builtin_memcpy(s->type, "lookup", 7)` writes a NUL past a
16-byte field.** "lookup" plus NUL is 7 bytes into a `char[16]`; OK.

Null checks: `k`, `kt`, `tname`, `desc`, `data_ptr` are all checked
before dereference. GPL, SEC("kprobe/…"), map types all OK.

---

## ch08-keyring-heist-kprobe (observer, CO-RE, no payload)

Cleanest program of the batch. Uses `PT_REGS_PARM1(ctx)` directly to
avoid the `key_ref_t` BTF forward-declaration trap on 6.12 (see the
LSM variant below). Masks the low 2 possession bits off `key_ref` to
obtain `struct key *`, which is correct (see
`include/linux/key.h:key_ref_to_ptr`).

No unbounded loops; no pointer arithmetic; null checks before every
deref; stack usage trivial (`struct evt` ~104B). CO-RE reads via
`BPF_CORE_READ` through `struct key` and `struct key_type` resolve
against vmlinux.h's full definitions — independent of the LSM hook's
BTF FWD type for the same struct.

**Low — `__builtin_memcpy(e->type_name, "lookup", 7)` writes "lookup\0"
into a 16-byte field.** Same as the sibling; fine.

No verifier concerns. No CO-RE concerns.

---

## ch08-keyring-heist-lsm (fmod_ret mutation)

**High (resolved in-file) — `key_ref_t` BTF FWD.** The program's
opening comment documents that `security_key_permission`'s first
argument has BTF kind `FWD` on linuxkit 6.12, and standard
`BPF_PROG(lsm_key_permission, key_ref_t kref, …)` fails
verification at arg0. The workaround — declare the program as
`int lsm_key_permission(unsigned long long *ctx)` and index args
manually — is the correct pattern. `ctx[2]` (need_perm) and
`ctx[3]` (ret) are the hook's 3rd and 4th positional args, where
the 4th is the fmod_ret synthetic tail. That matches the BPF_PROG
macro expansion on functional kernels. Good.

**Medium — no CO-RE read of `serial`/`type_name`.** Because the
program cannot touch `ctx[0]` safely on FWD-typed kernels, it zeroes
`serial` and `type_name` and relies on the kprobe variant for those
fields. This is called out in the comment. Acceptable for a PoC that
deliberately ships as a sibling pair.

**Low — ringbuf reserve happens inside `if (e)` guard**, submit
balanced, return value `new_ret` passed through unchanged on
non-target tgids. Stack usage minimal.

---

## ch09-pid-doppel

**High — `numbers[level]` flex-array access is bounds-checked.** The
audit brief flagged `BPF_CORE_READ(task, thread_pid, numbers[level], nr)`
as potentially unchecked. The actual code (lines 62–69) is:

```
struct pid *pp = BPF_CORE_READ(t, thread_pid);
unsigned int level = BPF_CORE_READ(pp, level);
...
bpf_probe_read_kernel(&u, sizeof(u),
    (void *)&pp->numbers[0] + level * sizeof(struct upid));
```

There is NO explicit upper bound on `level`. `struct pid::level` is a
`unsigned int`; if it were arbitrarily large, the pointer expression
`&pp->numbers[0] + level*sizeof(upid)` would compute out-of-bounds.
The read is routed through `bpf_probe_read_kernel`, which catches
page faults and returns `-EFAULT`, so it cannot crash the kernel —
but a corrupted or hostile `pp` could cause misleading `ns_pid`
values. Recommendation: clamp `level` to `MAX_PID_NS_LEVEL` (32) or
similar before indexing. Flag in chapter text. Not a verifier
rejection (pointer arithmetic on stack-typed `void *` plus scalar is
allowed for `bpf_probe_read_kernel`'s third arg).

**High — `bpf_send_signal()` from `raw_tp/sched_process_fork` targets
the parent, not the child.** The in-code comment acknowledges this
(lines 83–88). The chapter claim — "target a process in a child
namespace at the moment it's created" — is only satisfied on the
`kprobe/copy_namespaces` path, which runs in the child's execution
context. The fork raw_tp path signals the parent. Either the claim
needs softening or the program should drop the fork-path signal to
avoid the misleading effect. Not a verifier issue, just a semantic
one.

**Medium — `bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), BPF_CORE_READ(t, comm))`.**
`comm` is a `char[16]` inline array inside `task_struct`, not a
pointer. `BPF_CORE_READ(t, comm)` yields an lvalue-of-array, which
decays to a pointer to the first element — which then works, but it's
idiomatically clearer to use
`bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), &t->comm)` via a
direct address (or just `bpf_get_current_comm()` when `t == current`).
The existing form compiles and verifies; note it.

**Medium — mapping-table copy double-emits.** Lines 92–94 copy `*e`
into a local `copy`, stash `copy` into the `mapping` hash, then submit
`e` into ringbuf. Two users of the same struct is fine, but if the
ringbuf submit ever gets moved before the hash update, the userspace
consumer could observe the event before the map entry is queryable.
Ordering today is correct.

**Low — null checks.** `pp`, `pns` are read via `BPF_CORE_READ` which
silently produces zero on failure; dereferences via
`BPF_CORE_READ(pp, level)` and `BPF_CORE_READ(pns, ns.inum)` would
return zero rather than fault, but a subsequent
`&pp->numbers[0] + …` on a NULL `pp` with nonzero `level` produces a
small kernel address (e.g. `0x8`), handed to
`bpf_probe_read_kernel`, which returns `-EFAULT`. Safe; emits
garbage. Acceptable for a PoC but worth a defensive `if (!pp) return;`.

SEC strings valid, GPL marker present, ringbuf reserve/submit
balanced, no unbounded loops, map type/key/value consistent (key=`u32`
host pid, value=`struct evt`), cfg map is correct `ARRAY(1)`.

---

## Summary table

| POC | High | Medium | Low |
|---|---|---|---|
| ch06-silence-selinux        | 0 | 1 | 1 |
| ch06-silence-selinux-lsm    | 0 | 1 | 1 |
| ch07-devcgroup-houdini      | 2 | 1 | 1 |
| ch08-keyring-heist          | 2 | 2 | 1 |
| ch08-keyring-heist-kprobe   | 0 | 0 | 1 |
| ch08-keyring-heist-lsm      | 0 | 1 | 1 |
| ch09-pid-doppel             | 2 | 2 | 1 |

## Highest-priority fixes (defensive, no code yet)

1. **ch08-keyring-heist**: filter payload read by key type (`s->type`)
   in BPF or clearly document the requirement in userspace; replace
   hardcoded `+16 +2` with `bpf_core_field_offset(struct user_key_payload, data)`.
2. **ch09-pid-doppel**: clamp `level` before indexing `numbers[]`, and
   either drop the fork-path `bpf_send_signal` or rewrite the claim to
   match (signal targets the parent, not the child).
3. **ch07-devcgroup-houdini**: use `__sync_fetch_and_add` for the
   signal rate counter; document that `current` at kretprobe is the
   caller, not a worker.

No verifier rejections are expected on any of these programs on
Linux 6.12 aarch64 as written; the issues above are correctness and
brittleness concerns, not load-time failures.
