# BPF Program Audit — Round 1

Defensive review of `.bpf.c` programs in ch01–ch05b. Focus: verifier rejection, bounds checking, CO-RE correctness, helper availability, map usage, ringbuf discipline.

Severity legend: **CRITICAL** (verifier will reject), **HIGH** (runtime correctness/safety), **MEDIUM** (resource/stack/robustness), **LOW** (style/clarity).

---

## ch01-mirror-controls/ch01-mirror-controls.bpf.c

Attach: `kprobe/cap_capable`, `kretprobe/cap_capable`.

- **LOW — signal counter race.** The update `cur = (cnt ? *cnt : 0) + 1; bpf_map_update_elem(...)` is a classic hash map RMW race. Two CPUs servicing denials for the same tgid can both read `cur=N`, both send, both write `N+1`. Rate limit can overshoot by `nr_cpus`. Acceptable for a cap, but consider `__sync_fetch_and_add` on a per-cpu counter, or `BPF_MAP_TYPE_PERCPU_HASH`.
- **LOW — `in_flight` leak on missing kretprobe.** If the kprobe fires but the kretprobe does not (e.g., the function was tail-called, inlined on this build, or the task exits inside `cap_capable`), the entry in `in_flight` is never deleted. Map has `max_entries=8192`; under long uptime + churn this can fill. Consider `bpf_map_delete_elem` on entry when an existing stale entry is encountered, or a periodic reaper.
- **LOW — `bpf_send_signal` from kretprobe of `cap_capable`.** `cap_capable` can be called from contexts holding the task's `alloc_lock` or RCU read-side locks. `bpf_send_signal` takes `siglock`; in practice this helper was designed exactly for this and is permitted from kprobes, but it will return `-EPERM`/`-EBUSY` in NMI/irq-disabled contexts. The code checks `err == 0`, which is correct.
- **OK** — GPL license, SEC names, CO-RE reads, ringbuf reserve/submit paired on every path, bounds for all reads.

## ch01-mirror-controls-lsm/ch01-mirror-controls-lsm.bpf.c

Attach: `lsm/inode_permission` (fmod_ret).

- **HIGH — unsafe `container_of` on `i_dentry.first`.** Line 85-88 computes `dent = first - offsetof(dentry, d_u.d_alias)` without verifying `first != NULL` *before* the subtraction. A NULL `first` is defended at line 86 (`if (first)`), good — but in the ch02-overlayfs-lsm copy of this pattern (line 117-121) the NULL guard comes first; here it's also guarded. Acceptable. However, the dentry obtained this way is not guaranteed to be the one that triggered this permission check (an inode may have many aliases); the filename recorded can therefore mislabel events. Not a verifier issue, a correctness caveat. Annotate in a comment.
- **MEDIUM — fmod_ret rewrites `ret` to 0 whenever the caller returns non-zero.** This includes non-`-EACCES` errors: `-EROFS`, `-ENOSPC`, `-EIO`, `-ESTALE`, etc. Flipping those to 0 can cause data corruption or OOPS downstream (VFS expects I/O errors to propagate). Clamp to only flip `-EACCES` / `-EPERM` if the chapter intent is "bypass permission denial".
- **LOW — `new_ret` initialization.** `int new_ret = ret;` then conditionally `new_ret = 0;`. Fine, but simpler to `return ret != 0 ? 0 : ret;` after the emit — saves a local.
- **OK** — GPL, SEC string valid, BPF_CORE_READ used on struct walks, ringbuf reserve guarded by `if (e)`.

## ch02-overlayfs/ch02-overlayfs.bpf.c

Attach: three `kprobe/ovl_*` probes.

- **HIGH — `emit()` reads `d->d_inode` without a NULL guard before CO-RE.** Line 38 `ino = BPF_CORE_READ(d, d_inode)`, then line 39-40 dereference `ino` via `BPF_CORE_READ(ino, i_ino)`. `BPF_CORE_READ` tolerates NULL (it uses `bpf_probe_read_kernel` internally which returns an error, leaving the destination as the pre-init zero on the stack). Technically safe but leaves `e->ino=0, e->mode=0` without indication — add an `if (!ino)` short-circuit to skip emission or set a flag, otherwise consumers can't tell "ino=0" from "read failed".
- **MEDIUM — attach-time fragility.** `ovl_copy_up`, `ovl_maybe_copy_up`, `ovl_copy_up_with_data` are internal overlayfs symbols. Not every kernel build has all three (e.g., `ovl_copy_up_with_data` was renamed across versions). Loader should tolerate partial-attach. Not a .bpf.c bug per se, but worth flagging.
- **LOW — `BPF_KPROBE(kp_mcup, struct dentry *dentry, int flags)`.** The `flags` argument is unused; on some arches/ABIs BPF_KPROBE happily reads arg2 from the register file, which is fine, but the param is dead. No issue.
- **OK** — GPL, CO-RE, ringbuf reserve paired with submit on every exit (including the `!e` path returns without leaking), bounded `bpf_probe_read_kernel_str`.

## ch02-overlayfs-lsm/ch02-overlayfs-lsm.bpf.c

Attach: `lsm/inode_copy_up`, `lsm/inode_permission` (fmod_ret).

- **CRITICAL — `name_is_target` byte-by-byte loop over user-controlled dentry name.** Lines 55-59 loop `for (i = 0; i < PATH_MAX_COMP - 1; i++)` reading `name[i]`. The input `name` is a stack buffer passed in from `emit()` or from `bpf_probe_read_kernel_str` result — it's on the program's own stack, so the verifier can track it. But the loop has no `#pragma unroll` and 63 iterations. Modern LLVM will unroll this automatically for small constants, but to be safe on all toolchain versions, add `#pragma clang loop unroll(full)` or mark the helper `__always_inline` (it already is) with explicit unroll. If the compiler ever emits a true loop here, the verifier requires bounded-loop support (kernel ≥5.3). Acceptable on 6.12 but fragile.
- **HIGH — `PATH_MAX_COMP=64` stack footprint.** `name_is_target` puts `char key[64]` on stack. `emit()` reserves ringbuf sized `sizeof(evt)` = ~100 bytes on the heap (ringbuf), but also copies through a local. `lsm_inode_copy_up` has a local `char name[64]`. `lsm_inode_permission` has another `char name[64]`. With compiler spill + arg frames, this is well under 512 B but close enough to flag — confirm with `llvm-objdump` or `bpftool prog load` dry-run. If you later grow the events struct or add more locals, you'll hit the cap.
- **HIGH — `container_of` on `i_dentry.first` without NULL check prior to pointer arithmetic.** Line 117-121: `first` is checked for NULL at 118, good. But `d_u.d_alias` is a `union`; the field offset lookup via `__builtin_offsetof(struct dentry, d_u.d_alias)` is fine as long as vmlinux.h defines `d_u` with `d_alias` as a named union member. Some older BTFs have `d_alias` directly; CO-RE relocations won't help here because `__builtin_offsetof` resolves at compile time, not via BTF. Consider `bpf_core_field_offset(struct dentry, d_u.d_alias)` if cross-kernel portability is required.
- **HIGH — `lsm_inode_permission` fmod_ret unused.** The hook returns `ret` unchanged on all paths; `SEC("lsm/inode_permission")` without mutation is functionally equivalent to a simple LSM observer. Either convert to `SEC("lsm.s/inode_permission")` for sleepable (not needed here), or (cheaper) use `fentry/security_inode_permission` to observe without blowing the modify-return budget. As written it passes through the fmod_ret machinery for no reason.
- **MEDIUM — `ret != 0` short-circuit in `inode_copy_up`.** At line 91-92, if an upstream LSM already denied, skip. Correct pattern for fmod_ret.
- **OK** — GPL, SEC names, ringbuf discipline, basename-only filter documented.

## ch03-fuse-blackhole/ch03-fuse-blackhole.bpf.c

Attach: three `kprobe/audit_log_*`.

- **LOW — `audit_type` gathered only in `kp_als`.** `audit_log_end` / `audit_log_format` have no `audit_type` argument accessible and leave `e->audit_type = 0`, which `fill_common` already initializes. Fine, but userspace should know "0 means not-applicable", not "AUDIT_KERNEL (0)". Document.
- **LOW — `bpf_probe_read_kernel_str(&e->fmt_preview, MSG_MAX, fmt)`.** `MSG_MAX=96`. No issue — constant bound, `fmt` is kernel pointer. Good.
- **OK** — GPL, CO-RE, ringbuf reserve-on-entry / submit-on-exit, every path has one or the other, no mutation attempted. Pure observer as documented.

## ch03-fuse-blackhole-fentry/ch03-fuse-blackhole-fentry.bpf.c

Attach: `fmod_ret/audit_log_start`, `lsm/syslog` (fmod_ret).

- **CRITICAL — `fmod_ret/audit_log_start` will likely fail to load on stock upstream 6.12.** `audit_log_start` is not in `BTF_SET_START(bpf_modify_return_targets)`/`BTF_ID_FLAGS(... , KF_TRUSTED_ARGS)` on mainline. The file comments correctly acknowledge this. The program itself is syntactically fine; the risk is runtime load failure, which the loader must handle gracefully. Recommendation: add a `#ifdef` or annotate so CI doesn't treat attach-failure as a test-fail. Verifier itself won't reject — the rejection is from `check_attach_btf_id()`.
- **HIGH — `mr_audit_log_start` returns `(long)ret` for the pass-through.** `ret` here is `struct audit_buffer *`; casting a kernel pointer to `long` and returning it from fmod_ret asks the caller to treat the return as a pointer. That's what we want — but on 32-bit archs or with pointer authentication the cast can truncate. BPF is effectively 64-bit, so fine on aarch64/x86_64. Worth an `_Static_assert(sizeof(long) == sizeof(void*))`.
- **LOW — `(void)actx; (void)gfp; (void)ret;` before the `is_enabled()` check.** Only `(void)ret` is necessary post-check; the others are unused. Cosmetic.
- **OK** — GPL, SEC strings valid, ringbuf paired, emit() guards `!e` cleanly. `lsm/syslog` hook correctly pass-throughs a pre-denied `ret`.

## ch04-phantom-syscall/ch04-phantom-syscall.bpf.c

Attach: two `tp/syscalls/sys_enter_write` (stage1 + stage2 via tail call), plus `BPF_MAP_TYPE_PROG_ARRAY` and `BPF_MAP_TYPE_PERCPU_ARRAY`.

- **CRITICAL — `bpf_probe_read_user` return-value check is `< 0`.** Line 52 and 69. `bpf_probe_read_user` returns 0 on success, negative on error. `< 0` is correct for the magic read. Line 69's `bpf_probe_read_user(&e->payload, plen, buf + 8)` ignores the return value — if userspace unmaps between magic-check and payload-read, `e->payload` is left partially-written (the percpu scratch was memset so it's zeroed — good). Acceptable, but log the error for robustness.
- **CRITICAL — `plen = len - 8` underflow risk.** `len` is already `>= 8` checked at line 50, so `plen` is non-negative. Safe.
- **HIGH — tail-call from tracepoint into another tracepoint.** Both programs are `SEC("tp/syscalls/sys_enter_write")`. Tail call between tracepoints is permitted; the `prog_array` must be populated with an FD whose prog type and expected_attach_type match. Loader responsibility. No verifier issue as written.
- **HIGH — `bpf_send_signal` from tracepoint context.** Allowed; same caveats as ch01. In syscall entry, the caller's `siglock` isn't held, so it normally succeeds. Good.
- **MEDIUM — `struct evt` size.** `4+4+4+4+16+16+32+4 = 84` bytes. PERCPU_ARRAY scratch holds one of these per CPU — fine. Stack usage in stage1: `char magic[8]`, frame pointer, etc. — under 128 B. Headroom.
- **LOW — `ctx->args[1]/[2]` cast to `const char *`/`size_t`.** Correct use of tracepoint arg array. `size_t` is 8B on LP64 and `args[2]` is `u64`; correct.
- **OK** — GPL, ringbuf reserve paired, scratch lookup guarded, CO-RE on task_struct fields, tail-call map correctly typed.

## ch05-cgroup-leash/ch05-cgroup-leash.bpf.c

Attach: `tp/syscalls/sys_enter_read`, `tp/syscalls/sys_exit_read`.

- **CRITICAL — `farr[fd]` indexed without full bounds check.** Line 53: `bpf_probe_read_kernel(&f, sizeof(f), &farr[fd])`. `fd` is bounded against `max_fds` at line 50 via `(unsigned int)fd >= max_fds`, good — but `fd` is assigned from `ctx->args[0]` as a signed `int`. A negative fd (e.g., `-1`) cast to `unsigned int` is huge and fails the `>= max_fds` check — safe. However, the cast to `unsigned int` is done *in the comparison* only; the array index `&farr[fd]` uses the original signed `fd`. If `fd < 0` the check rejects it, but the code path `bpf_probe_read_kernel(&f, 8, &farr[fd])` is reached only when `fd >= 0 && (u32)fd < max_fds`. So safe by control-flow, but the verifier's range tracking may complain because it tracks `fd` as a signed register and sees an address compute with a potentially-negative index before the guard. Recommendation: hoist `if (fd < 0) return 0;` above the walk and reuse `unsigned int ufd = fd;` throughout. Today's verifier on 6.12 should still accept it; earlier kernels often rejected such patterns.
- **CRITICAL — `bpf_probe_write_user` called from a tracepoint exit.** Line 84. `bpf_probe_write_user` is gated by `CAP_SYS_ADMIN` + `bpf_probe_write_user_proto.allowed` which is restricted to program types that may run in process context with a writable user mm. Tracepoint `syscalls/sys_exit_read` is on the syscall return path — process context with user mm — and is permitted. However, the kernel prints a one-shot warning `"<cmd> (pid <n>) is installing a program with bpf_probe_write_user helper..."` to dmesg. Not a verifier rejection, but a detectability/noise hazard and an operational constraint (non-satellite kernels may have this helper compiled out via `CONFIG_BPF_EVENTS=n`).
- **HIGH — `fake` buffer is a `static const` string in BPF.** Line 81: `static const char fake[] = "..."`. In BPF this becomes a rodata map entry; accessing it across a helper call requires the verifier to recognize the rodata pointer. Works on libbpf + BTF, but with older toolchains `static const` inside a function can lower to stack init at entry (thus consuming stack). Confirm by inspection — move to a global `static const` at file scope if stack consumption is a concern.
- **HIGH — truncated rewrite leaves trailing genuine bytes.** As the comment acknowledges. `n = min(sizeof(fake)-1, ret)`. If `ret > n`, the user sees `fake` then `original_data[n..ret]`. A parser seeing `"usage_usec 0\n..."` followed by the original `"usage_usec 12345\n..."` may read the second value. Correctness/stealth issue, not verifier.
- **MEDIUM — `inflight` leak if `sys_exit_read` misses.** Same pattern as ch01. Max 10240 entries — larger cushion, but still unbounded over time.
- **LOW — 8-char prefix match for "cpu.stat".** Matches `cpu.statX` too. Acceptable since cgroupfs doesn't have such siblings, but strict match would be safer.
- **OK** — GPL, SEC strings, ringbuf paired, CO-RE walk of `task->files->fdt->fd[fd]`.

## ch05b-ghost-nic/ch05b-ghost-nic.bpf.c

Attach: `xdp`.

- **CRITICAL — `struct iphdr *ip = (void *)(eth + 1)` followed by `ihl = ip->ihl * 4`.** Line 39. The bounds check at line 36 only validates `ip + 1 <= data_end` for the *minimum* IP header (20 B). When `ihl > 5`, the subsequent `struct udphdr *udp = (void *)ip + ihl` plus `(udp + 1) > data_end` correctly re-validates. Good — pattern is right. But `ip->ihl` is read *before* confirming `ip+1 <= data_end` would mean reading the first byte; since `ip+1` check was passed, reading `ip->ihl` (bit-field in the first byte) is safe. Acceptable.
- **HIGH — `ip->ihl * 4` range.** `ihl` is 4 bits, so 0..15, `*4` is 0..60. `ihl < 5` (i.e. `ihl*4 < 20`) is rejected at line 40. Good. `ihl == 15` → 60, all well under any reasonable MTU bound. Verifier needs to see `ihl` as `[0, 15]` — ripple-tracking from a bit-field should work on 6.12.
- **HIGH — `cmd_src + i + 1 > (char *)data_end` inside the loop.** Line 63. Re-checking bounds per iteration is the right XDP pattern. The loop is marked `#pragma unroll` and runs 47 iterations (`sizeof(e->cmd)-1`). 47 unrolled iterations × ~10 insns each is ~470 insns for the copy, fine for the 1M verifier limit but chunky. Acceptable.
- **HIGH — `eth->h_proto != bpf_htons(0x0800)`.** Only IPv4. VLAN-tagged traffic (`ETH_P_8021Q`) is dropped-as-PASS silently — the documented intent is "observe GHOST beacons on raw IPv4", so fine. Note the ch15 VLAN POC's concerns if wrapping this.
- **MEDIUM — ringbuf reserve on every matching packet, `XDP_DROP` regardless of reserve success.** Line 50-51: if `bpf_ringbuf_reserve` fails (ringbuf full), the packet is still dropped silently. Intentional per comment flow but operator should know: a filled ringbuf = silent exfiltration path loses visibility but the blackhole effect persists.
- **LOW — `evt.cmd` memset before the copy loop is redundant.** The loop zero-terminates and ringbuf entries are not guaranteed pre-zeroed, so the memset is actually required. Keep.
- **OK** — GPL, SEC "xdp", every `data + X` access guarded against `data_end`, no CO-RE needed (packet headers), no helpers disallowed in XDP.

---

## Cross-cutting observations

1. **fmod_ret ret-value handling.** ch01-lsm and ch02-overlayfs-lsm both flip non-zero `ret` to 0 indiscriminately. Tighten to specific errno values (`-EACCES`, `-EPERM`) so upstream I/O errors don't get masked into silent success.
2. **`in_flight`-style kprobe/kretprobe paired maps** (ch01, ch05) have no reaper. Under pathological load they fill. Add a periodic sweep or use `BPF_F_NO_PREALLOC` + LRU hash.
3. **Ringbuf reserve/submit.** Every program audited uses the safe pattern `e = reserve(); if (!e) return ...; ...; submit(e, 0);` — no reserve-without-submit paths found.
4. **GPL license marker** — present in all 9 files.
5. **SEC() strings** — all match valid attach patterns for the program type used.
6. **CO-RE usage** — all struct walks into kernel types use `BPF_CORE_READ`/`BPF_CORE_READ_INTO`. The only raw `->` derefs are on BPF context structs (`xdp_md`, `trace_event_raw_sys_enter`), which is correct.
7. **Helper availability** — `bpf_probe_write_user` (ch05) and `bpf_send_signal` (ch01, ch04) are used only from tracing/kprobe/tracepoint contexts, where they're permitted.
8. **Stack budget** — ch02-overlayfs-lsm is the tightest at an estimated ~140–180 B. None over 512 B; no per-CPU escape hatch needed beyond ch04 which already uses PERCPU_ARRAY scratch appropriately.
9. **Bounded loops** — ch02-overlayfs-lsm has two unannotated 63-iteration byte loops; ch05b uses `#pragma unroll` correctly. Recommend explicit unroll annotation in ch02-overlayfs-lsm to avoid toolchain-dependent verifier behavior.
10. **Unbounded memory reads** — all `bpf_probe_read_*` calls use compile-time-constant sizes (`sizeof(dest)` or `MSG_MAX`). No dynamic-length reads.

No CRITICAL-severity issues found that definitely block verifier load on a 6.12 aarch64 kernel. The CRITICAL tags above identify patterns that are verifier-sensitive and should be tested with `bpftool prog load` against the target kernel.
