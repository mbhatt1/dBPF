# BPF Audit 4 — ch18, ch23, ch24, ch25

Defensive review against the 12-criteria rubric: (1) LICENSE, (2) map
definitions, (3) context-type correctness, (4) helper availability/signature,
(5) pointer-bounds/data_end guards, (6) CO-RE read correctness,
(7) ringbuf reserve+submit lifecycle, (8) loop/termination/stack bounds,
(9) probe-type vs. argument model (kprobe/kretprobe/tracepoint/xdp),
(10) symbol/arch portability, (11) error-injection / `bpf_override_return`
preconditions, (12) information-leak hygiene on captured memory.

No code changes. Scope: four `.bpf.c` files only; user-space loaders inspected
only where they bear on verifier behavior or preconditions.

## ch18 — token-bypass (kretprobes on `__arm64_sys_{get,gete}uid`)

**File:** `dBPF-pocs/pocs/ch18-token-bypass/ch18-token-bypass.bpf.c` (80 lines)

1. LICENSE: `"GPL"` present. OK.
2. Maps: `events` ringbuf (256 KiB) and `target_tgids` hash (key=u32 tgid,
   value=u32, 1024 entries). Both correctly declared. `target_tgids` is used
   by `is_target()` and a tgid==0 wildcard entry, which is consistent.
3. Context type: `BPF_KRETPROBE` macro — correct for `SEC("kretprobe/…")`.
4. Helpers: `bpf_get_current_pid_tgid`, `bpf_get_current_comm`,
   `bpf_ringbuf_reserve/submit`, `bpf_map_lookup_elem`, `bpf_override_return`.
   All available on 6.12. `bpf_override_return` requires
   `CONFIG_BPF_KPROBE_OVERRIDE=y` and the target function must be on the
   error-injection allowlist (`/sys/kernel/debug/error_injection/list`).
5. Pointer bounds: only ringbuf-reserved pointer is dereferenced; NULL-check
   after `bpf_ringbuf_reserve` is present. OK.
6. CO-RE: none required (no kernel struct field reads). OK.
7. Ringbuf lifecycle: `emit()` reserves then always submits on the success
   path; early `return` on reserve-fail. No double-submit, no leaked reserve.
   OK.
8. Loops/stack: no loops. `struct evt` is ~32 bytes — trivial. OK.
9. Probe vs. args: kretprobe only sees the return value — `BPF_KRETPROBE(..,
   long ret)` is used correctly; no attempt to read entry args.
10. Symbol/arch portability: **arch-specific symbol hardcoded.** Only
    `__arm64_sys_getuid`/`__arm64_sys_geteuid` are present in the BPF object.
    On x86_64 the symbols are `__x64_sys_getuid`/`__x64_sys_geteuid`. The
    source comment says the loader should select at runtime, but the C
    program only does kallsyms preflight for the arm64 names (lines 175–176
    of the loader). On x86_64 hosts this PoC will silently report skip or
    fail to attach. Not a verifier risk, but a portability gap worth
    flagging. **Recommendation (doc-level):** ship a second SEC variant or
    attach by address via `bpf_program__set_attach_target` from the loader.
11. **Error-injection requirement:** `__arm64_sys_getuid` and
    `__arm64_sys_geteuid` must appear in `/sys/kernel/debug/error_injection/
    list`. In mainline 6.12, `sys_getuid`/`sys_geteuid` in `kernel/sys.c` are
    tagged with `ALLOW_ERROR_INJECTION(..., ERRNO)`; the arch wrappers
    inherit via the syscall stub machinery. The README and source comment
    both acknowledge this. On kernels built without
    `CONFIG_FUNCTION_ERROR_INJECTION=y` or `CONFIG_BPF_KPROBE_OVERRIDE=y`,
    the program will load but `bpf_override_return` will be rejected at
    attach. This is the correct external precondition; no BPF-side change
    needed.
12. Leak hygiene: `emit()` writes every field of `struct evt` before
    `submit`. `comm[16]` is filled by `bpf_get_current_comm`, which is
    documented to zero-pad. No uninitialized-byte leak into ringbuf. OK.

**Verdict:** verifier-clean and CO-RE-clean. Only concern is the hardcoded
arm64 symbol name; behavior on x86_64 is a preflight skip, not a miscompile.

## ch23 — tpm-unseal-heist (kprobe+kretprobe on `tpm2_unseal_trusted`)

**File:** `dBPF-pocs/pocs/ch23-tpm-unseal-heist/ch23-tpm-unseal-heist.bpf.c`
(103 lines)

1. LICENSE: `"GPL"`. OK.
2. Maps: `events` ringbuf (256 KiB) and `inflight` hash (u64→u64, 4096
   entries) for pid_tgid → `struct trusted_key_payload *` stashing. Correct.
3. Context type: `BPF_KPROBE` + `BPF_KRETPROBE`. OK.
4. Helpers: `bpf_probe_read_kernel`, `BPF_CORE_READ_INTO`,
   `bpf_map_{update,lookup,delete}_elem`, ringbuf, `bpf_get_current_*`.
   All 6.12-available.
5. Pointer bounds: the stashed kernel pointer `p` is NULL-checked
   (`if (!p) return 0;`) before use. All struct reads go through CO-RE or
   `bpf_probe_read_kernel`, which are the correct safe accessors for
   arbitrary kernel addresses.
6. **CO-RE correctness:** `BPF_CORE_READ_INTO(&key_len, p, key_len)` and
   same for `blob_len`. Field names match `struct trusted_key_payload` in
   `include/keys/trusted-type.h` (unsigned int `key_len`, unsigned int
   `blob_len`). The trailing flex-array `key[]` is read with
   `bpf_probe_read_kernel(&e->key_bytes, n, &p->key[0])`; the inline comment
   correctly notes that `BPF_CORE_READ` cannot express a flex-array member
   read. **Caveat:** `&p->key[0]` here is an address computed by the BPF
   compiler against the vmlinux layout, not via CO-RE relocation. If
   `trusted_key_payload` reorders its fields between kernels, the offset of
   `key[0]` shifts and this PoC reads the wrong bytes. For a defensive PoC
   that's acceptable; noting it for completeness.
7. Ringbuf lifecycle: reserve → NULL-check → field writes → `submit`. The
   two early-return paths before `bpf_ringbuf_reserve` (inflight miss,
   `ret != 0`, NULL `p`) occur *before* reserve, so no leaked reservation.
   OK.
8. Loops/stack: no loops. `struct evt` ≈ 100 bytes — fine.
9. **Probe vs. args (flagged item):** The kretprobe does NOT attempt to
   read entry args. It reads `int ret` via `BPF_KRETPROBE(.., int ret)` —
   correct — and recovers the struct pointer from the `inflight` map, which
   was populated by the paired kprobe on function entry. This is the
   idiomatic kprobe-entry-stash + kretprobe-consume pattern and is exactly
   how you must handle "return-site needs entry args" on Linux BPF. Clean.
10. Symbol portability: `tpm2_unseal_trusted` is a C function, not a
    syscall wrapper, so the arch-prefix problem (ch18) does not apply.
    Subject to config (`CONFIG_TRUSTED_KEYS`, `CONFIG_TCG_TPM2`); the
    loader performs a kallsyms preflight.
11. Error-injection: N/A — no `bpf_override_return`.
12. **Leak hygiene (flagged item — CRITICAL REVIEW):**
    - Order of operations: `n = key_len; if (n > MAX_KEY_CAPTURE) n =
      MAX_KEY_CAPTURE; e->captured = n;` then
      `__builtin_memset(e->key_bytes, 0, sizeof(e->key_bytes));` then
      `if (n > 0) bpf_probe_read_kernel(&e->key_bytes, n, &p->key[0]);`.
      The clamp (`n > MAX_KEY_CAPTURE ? MAX_KEY_CAPTURE : n`) precedes the
      probe read, so `n` is provably in `[0, 64]` at the helper call.
    - Verifier range tracking: `n` is derived from a scalar register
      clamped immediately prior; the verifier tracks `n` as `0..=64` at the
      call. `bpf_probe_read_kernel`'s size argument must be a known scalar
      ≤ the destination buffer size, and `sizeof(e->key_bytes) == 64`. The
      pattern matches the canonical "mask, then read" idiom the verifier
      accepts.
    - Tail zeroing: `__builtin_memset(e->key_bytes, 0, 64)` covers the full
      buffer, so any bytes past `captured` are zero (prevents leaking stale
      stack/ringbuf memory past the real key length).
    - Minor nit: `e->key_bytes` is 64 bytes of sensitive plaintext being
      written to a ringbuf — but this PoC's *purpose* is to exfiltrate
      that, so the "leak" is intentional. Hygiene as it pertains to BPF
      (no uninitialized reads) is correct.

**Verdict:** verifier-clean, CO-RE-clean, probe-arg-model clean. The clamp
precedes the helper call (as required), the kretprobe uses an inflight map
to access entry args (as required), and the zeroing-then-partial-read
pattern is correct.

## ch24 — bpf-token-delegation (tracepoint on `sys_enter_getuid`)

**File:** `dBPF-pocs/pocs/ch24-bpf-token-delegation/
ch24-bpf-token-delegation.bpf.c` (40 lines)

1. LICENSE: `"GPL"`. OK.
2. Maps: single ringbuf (64 KiB). OK.
3. Context type: `SEC("tp/syscalls/sys_enter_getuid")`, `void *ctx` — the
   PoC does not read tracepoint args, so the untyped ctx is fine. (A
   stricter form would use the generated `struct trace_event_raw_sys_enter`,
   but it's not needed here.)
4. Helpers: all core and 6.12-available.
5. Pointer bounds: only the ringbuf-reserved pointer is dereferenced, with
   NULL-check. OK.
6. CO-RE: none used. OK.
7. Ringbuf lifecycle: reserve → NULL-check → field writes → submit. Clean.
8. Loops/stack: none. `struct evt` = 32 bytes.
9. Probe vs. args: tracepoint. Correct program type. OK.
10. Symbol portability: tracepoint names are stable across arches
    (`syscalls/sys_enter_getuid`). No `__arm64_` prefix problem. OK.
11. No override_return. N/A.
12. All four fields (`ts`, `pid`, `uid`, `comm`) written before submit. OK.

**Verdict:** minimal and clean, as intended — this is a delegation smoke
test, not a primitive. No unusual complexity to flag.

## ch25 — imds-harvest (XDP full L2/L3/L4 parse)

**File:** `dBPF-pocs/pocs/ch25-imds-harvest/ch25-imds-harvest.bpf.c` (131
lines)

1. LICENSE: `"GPL"`. OK.
2. Maps: `events` ringbuf (1 MiB) and `cfg` array (1 u32 entry) for mock
   mode. Correct.
3. Context type: `struct xdp_md *ctx`. OK.
4. Helpers: `bpf_ringbuf_reserve/submit`, `bpf_map_lookup_elem`,
   `bpf_probe_read_kernel`, `bpf_htons`/`bpf_ntohs`. All fine.
5. **Pointer bounds / data_end guards (flagged item — CRITICAL REVIEW):**
    - `eth`: `(void *)(eth + 1) > data_end` before any eth field read.
    - Eth proto check: reads `eth->h_proto` only after the bound check
      above. OK.
    - `ip = (void *)(eth + 1)`; `(void *)(ip + 1) > data_end` check before
      any IP field read. OK — this covers the fixed 20-byte IP header.
    - `ihl = ip->ihl & 0x0f; if (ihl < 5) return XDP_PASS;` — masks to
      0..15 and rejects <5. This ensures `ihl*4 ≥ 20`.
    - `tcp = (void *)ip + ihl*4;` then `(void *)(tcp + 1) > data_end`. The
      verifier accepts this: `ihl` is a bounded scalar (0..15 after mask),
      so `tcp` is within `[ip, ip+60]`, and the `tcp+1` bound re-checks
      against `data_end`. OK.
    - Note: the check `ihl < 5` rejects malformed packets but does NOT
      skip the ihl=5 fast path. Options headers (ihl>5) are tolerated
      because `tcp = ip + ihl*4` correctly advances past them.
    - `doff = tcp->doff & 0x0f; if (doff < 5) return XDP_PASS;` — same
      pattern for TCP header length. OK.
    - **Payload pointer bound (flagged item):** `payload = (u8*)tcp +
      doff*4; if ((void*)payload >= data_end) return XDP_PASS;`. This is
      the critical check. `doff` is in `[5, 15]` after the mask+reject, so
      `doff*4` is in `[20, 60]`. The verifier must prove `payload ≤
      data_end` before the `bpf_probe_read_kernel`. The `>=` check
      establishes `payload < data_end`, and `payload_len = data_end -
      payload` is then a valid bounded scalar. OK.
    - `payload_len` clamped to `MAX_PAYLOAD` (512) before the helper call.
      `to_copy ≤ MAX_PAYLOAD == sizeof(e->payload)`. The redundant
      `if (to_copy > 0 && to_copy <= MAX_PAYLOAD)` around the helper is
      belt-and-suspenders but satisfies the verifier's range tracking
      unambiguously.
6. CO-RE: not used (XDP parses raw on-wire bytes, CO-RE doesn't apply).
7. **Ringbuf lifecycle under early-return (flagged item):** the ringbuf
   reserve happens *after* all validation and the direction check. Every
   path before `bpf_ringbuf_reserve` returns `XDP_PASS` without reserving.
   Every path after reserve either (a) NULL-check returns `XDP_PASS` (no
   reservation to leak) or (b) falls through to `bpf_ringbuf_submit`.
   There is no `bpf_ringbuf_discard` — the only reason to discard would be
   a post-reserve validation failure, and none exists here. Clean.
8. Loops/stack: no loops. `struct evt` with 512-byte payload = ~528 bytes,
   but lives in the ringbuf reservation, not on the BPF stack. OK. Stack
   usage is minimal (a few scalars).
9. Program type: XDP. OK.
10. VLAN handling (flagged item): no VLAN tag parsing. The program checks
    `eth->h_proto == htons(ETH_P_IP)` directly and skips anything else.
    A VLAN-tagged packet presents `h_proto == htons(ETH_P_8021Q)` and is
    correctly dropped from consideration (returns `XDP_PASS` without
    capture). No stack corruption risk — this is a design limit, not a
    bug, and matches the documented scope ("IPv4 only").
11. Override_return: N/A.
12. Leak hygiene: `__builtin_memset(e->payload, 0, 512)` clears the buffer
    before the partial `bpf_probe_read_kernel`, so bytes past `to_copy`
    are zero. Fixed fields (saddr/daddr/sport/dport/payload_len/direction/
    _pad) all written before submit. OK.

**XDP-specific flagged items:**
- `XDP_PASS` always returned (never `XDP_DROP`). Every failure-path return
  is `XDP_PASS`, and the success path ends with `return XDP_PASS;` after
  submit. Tap semantics confirmed — this is a capture, not a filter. Good.
- Ringbuf reserve+submit under early-return paths: correct (see 7 above).

**Verdict:** verifier-clean for direct-packet access. All four header
stages (eth / ip / tcp-fixed / tcp-payload) have the correct `data_end`
guard, and the `ihl`/`doff` masks plus minimum checks establish the
scalar ranges the verifier needs for the variable-stride advances.

## Cross-cutting observations

- All four programs use `char LICENSE[] SEC("license") = "GPL";` — required
  for helpers like `bpf_probe_read_kernel` and `bpf_override_return`.
- No program uses `bpf_loop` or bounded loops; all iteration is unrolled or
  absent. No loop-termination risk.
- None write to LLM/userspace without going through the ringbuf, so there's
  no shared-buffer race.
- ch18 and ch23 both depend on external preconditions (error-injection
  allowlist; CONFIG_TRUSTED_KEYS + TPM hardware) that are correctly gated
  by kallsyms preflights in the loaders; no BPF-side change needed.

No verifier-rejection or CO-RE-correctness findings that would block load
on the documented target kernels. The only portability nit is ch18's
hardcoded `__arm64_` symbol name, which is a loader-selection concern
rather than a BPF-side issue.
