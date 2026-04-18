# Loader Audit 3 — ch18, ch23, ch24, ch25

Targets:
- `dBPF-pocs/pocs/ch18-token-bypass/ch18-token-bypass.c` (274 lines)
- `dBPF-pocs/pocs/ch23-tpm-unseal-heist/ch23-tpm-unseal-heist.c` (134 lines)
- `dBPF-pocs/pocs/ch24-bpf-token-delegation/ch24-bpf-token-delegation.c` (874 lines — deep dive)
- `dBPF-pocs/pocs/ch25-imds-harvest/ch25-imds-harvest.c` (230 lines)

Same 14 criteria as prior loader audits: arg parsing, libbpf error handling, skel lifecycle, map/prog fd lifetime, ringbuf polling, signal discipline, resource cleanup on error paths, kallsyms preflight correctness, XDP/perf attach semantics, SCM_RIGHTS, BPF token / opts, userspace reassembly, string/format safety, zero-unwrap/expect discipline (N/A C).

---

## ch24 — BPF_TOKEN delegation (deep dive)

### C24-1. `server_send_token` does not close the local copy of `token_fd` after send
File: `ch24-bpf-token-delegation.c:224-257`, `server_state::token_fd` kept until `server_cleanup`.

SCM_RIGHTS dups the fd into the peer — the kernel installs a new fd in the receiving process without consuming the sender's. The sender must `close(token_fd)` after the peer has read the cmsg to release the local reference. The server here deliberately keeps `st.token_fd` open across the accept loop so it can re-send to flaky clients (line 418 closes only `cfd`, not the token). That's intentional reuse, **but** it means:

- Every reconnect leaks one kernel-side fd-table slot in the receiver if clients connect more than once in a run (the server re-sends the same `token_fd`; each send dups). Not the server's problem directly — it is the receiver's (client) leak if it never closes old token fds across reconnects. The client here only receives once, so operationally benign.
- Real concern: if `g_running` flips to 0 **after** `sendmsg` queues the message but **before** the kernel actually installs the fd in the peer's receive queue, `server_cleanup` closes `st.token_fd` — this is fine because SCM_RIGHTS delivery is atomic at `sendmsg` return. OK.

**Verdict:** not a bug, but note the file-descriptor accounting for documentation. Criterion 3 satisfied.

### C24-2. Ready-file is written **before** `accept` starts; SIGTERM race before send
File: `ch24-bpf-token-delegation.c:373-419` (run_server).

Sequence: mount bpffs → mint token → bind → listen → write ready-file → accept loop. If the harness reads the ready file and launches the client the instant `fputs("ready\n")` flushes, the client may `connect()` before the next iteration of the `select`-wrapped accept loop begins. `connect()` on a `listen()`ing socket succeeds because the kernel queues up to `backlog=4` connections. No race.

**But**: if SIGTERM arrives between `listen()` and the first `select()` call, `g_running=0` and the server exits without serving a single `sendmsg`, yet the ready file is already on disk. The harness will see "ready" and the client will race to `connect()` — it succeeds into the closed listen socket (or fails with ECONNREFUSED after server_cleanup unlinks). Client retries 50× over 5s, so most cases recover, but the marker file lies. Criterion 9.

**Recommend:** write ready-file **after** `listen()` succeeds and install the sigaction before `listen()` so the sighandler sets `g_running=0` atomically (already the order — install_sig_handlers is at line 277 before mount). OK as written; false alarm.

### C24-3. `patch_map_fds` iteration — `i += 2` via loop-incremented `i++` after internal `i++`
File: `ch24-bpf-token-delegation.c:565-583`.

Correct for LD_IMM64 which occupies two 8-byte slots. The loop does:
```
for (i = 0; i + 1 < cnt; i++) {
    ...
    if (match) { patched++; }
    i++;   // skip paired slot (THIS IS UNCONDITIONAL)
}
```
The `i++` at line 580 runs on **every iteration**, not just when a match is found. So non-LD_IMM64 instructions advance `i` by 2 as well, potentially skipping one-slot instructions. A single-slot insn at offset N whose `code != (BPF_LD|BPF_DW|BPF_IMM)` is examined; then `i++` bumps past N+1 too, so the instruction at N+1 is never examined. **This means LD_IMM64 placeholders at odd offsets after a single-slot instruction get skipped.** For a compiler-emitted program where LD_IMM64 instructions are generally on even offsets, it works; for hand-crafted insn streams it silently misses placeholders.

**Impact:** the chapter's test BPF object has exactly one ringbuf map reference; the libbpf compiler emits LD_IMM64 at offsets where this happens to work. Fragile. If the program were ever rebuilt with different optimizations, patched count could drop silently. The `fprintf` that reports `patched=%d` would reveal the mismatch, but the subsequent `bpf_prog_load` would fail with a verifier error pointing at "map_fd not set". Criterion 5.

**Bound check `i + 1 < cnt`:** correct — ensures the paired slot read via `insns[i+1].imm = 0` is in range. OK.

### C24-4. `log_userns_state` readlink truncation
File: `ch24-bpf-token-delegation.c:178-188`.

`readlink("/proc/self/ns/user", self_ns, sizeof(self_ns)-1)` with `self_ns[64]`. The target is `user:[4026531837]` (20 chars). 63 bytes easily fits. `readlink` does not NUL-terminate; the code does `self_ns[r] = '\0'` on `r > 0` — correct. If `readlink` returns -1, the buffer stays all-zero from `= {0}` initialization, so `strcmp` on an empty string prints `match=no`, which is misleading but not a crash. Criterion 8.

### C24-5. `client_recv_token` — buffer too small for server's iovec
File: `ch24-bpf-token-delegation.c:487-488` vs. server at line 226.

Server sends `iov.iov_base = &dummy, iov.iov_len = 1` (a single 'T' byte). Client receives into `char buf[4]`. `recvmsg` returns `n=1`; client ignores `n` and checks only `msg_flags`. `buf` is larger than needed — no overflow, no leak. OK.

Ctrun mitigation: `MSG_CMSG_CLOEXEC` is passed — the received fd gets `O_CLOEXEC`. Good.

`MSG_CTRUNC` is checked (line 511) — good. Criterion 2.

### C24-6. Cmsg iteration validates level/type/len — correct
File: `ch24-bpf-token-delegation.c:516-523`.

`CMSG_FIRSTHDR` + `CMSG_NXTHDR` loop with `cmsg_level == SOL_SOCKET && cmsg_type == SCM_RIGHTS && cmsg_len == CMSG_LEN(sizeof(int))`. Exact-match on `cmsg_len` is slightly over-strict — kernel may pad, but `CMSG_LEN` is the canonical "data length" form (excludes trailing pad). `recvmsg` writes exactly this. Safe.

**Minor:** if the server ever passed more than one fd (e.g., future version), the client accepts only the first SOL_SOCKET/SCM_RIGHTS matching cmsg and **leaks** subsequent fds (they land in the client's fd table, never closed). Out of scope today. Criterion 2.

### C24-7. `BPF_TOKEN_CREATE` — attr fully zeroed, fields set
File: `ch24-bpf-token-delegation.c:199-204`.

```
union bpf_attr attr;
memset(&attr, 0, sizeof(attr));
attr.token_create.bpffs_fd = dir_fd;
attr.token_create.flags    = 0;
syscall(SYS_bpf, BPF_TOKEN_CREATE, &attr, sizeof(attr));
```

Correct. `memset` zeroes the full union including all sibling cmd fields. `sizeof(attr)` passed as size — kernel uses `CHECK_ATTR` to validate; 6.9+ accepts full size. Criterion 1.

### C24-8. `LIBBPF_OPTS` for map_create and prog_load
File: `ch24-bpf-token-delegation.c:653, 704-706`.

`LIBBPF_OPTS` macro zeroes the opts struct and sets `sz` automatically. Both call sites use the macro — `.token_fd = token_fd` and `.expected_attach_type = 0` are set. Correct. Criterion 6.

### C24-9. perf_event_open + SET_BPF + ENABLE sequence — all error-checked
File: `ch24-bpf-token-delegation.c:743-771`.

Three operations, each checked:
- `open_perf_tracepoint` returns -1 on failure, caller checks `< 0` at 744.
- `ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd)` → `!= 0` check at 752 with cleanup of all prior fds. Good.
- `ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0)` → `!= 0` check at 762 with identical cleanup. Good.

Teardown at line 803 calls `PERF_EVENT_IOC_DISABLE` before `close(perf_fd)` — correct ordering so no last-sample lands after `ring_buffer__free`. Criterion 7.

### C24-10. `open_perf_tracepoint` — missing `read_format`, `sample_type` defaults
File: `ch24-bpf-token-delegation.c:542-559`.

`perf_event_attr` zeroed, `type=TRACEPOINT`, `size=sizeof(pe)`, `config=tp_id`, `sample_period=1`, `wakeup_events=1`. For a raw tracepoint that feeds a BPF program via SET_BPF, this is sufficient — sample_type is only needed if the program itself reads perf sample data via `BPF_FUNC_perf_prog_read_value`, which this program doesn't. OK.

No `cpu=-1`/`pid=0` subtlety issue: `syscall(SYS_perf_event_open, &pe, -1 /* pid */, 0 /* cpu */, -1 /* group */, ...)`. Comment in header says args are `(attr, pid, cpu, group, flags)`. `pid=-1, cpu=0` means "all tasks on CPU 0". That only captures getuid calls executed on CPU 0; a multi-CPU system with the trigger pinned elsewhere would miss events. On a VM with 1 CPU (dBPF harness default), fine. On multi-CPU hosts, this will under-count.

**Recommend:** open one perf_event per CPU, or use `pid=0, cpu=-1` (profile calling task on any CPU) for a single-threaded trigger. Not a correctness bug on the target harness, but a silent under-counting footgun. Criterion 9.

### C24-11. Client shutdown — polls exit cleanly; rb freed; perf disabled before close
File: `ch24-bpf-token-delegation.c:788-808`.

- `for (int i = 0; i < 50 && g_running; i++)` — SIGINT flips `g_running`, loop exits. Good.
- `ring_buffer__poll` returning `-EINTR` handled. Non-EINTR errors break. Good.
- Teardown order: `ring_buffer__free(rb)` → `PERF_EVENT_IOC_DISABLE` → `close(perf_fd)` → `close(prog_fd)` → `close(map_fd)` → `bpf_object__close(obj)` → `close(token_fd)`. This is the correct order. Criterion 10.

### C24-12. `bpf_object__open_file` error handling — double-free risk
File: `ch24-bpf-token-delegation.c:620-627`.

```c
struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, NULL);
if (!obj || libbpf_get_error(obj)) {
    long err = libbpf_get_error(obj);   // if obj is NULL, returns 0 — strerror(0) = "Success"
    fprintf(stderr, "...: %ld (%s)\n", err, strerror(err ? (int)-err : errno));
```

`libbpf_get_error(NULL)` returns 0 per libbpf semantics, so `err = 0`. Then `strerror(err ? ... : errno)` uses `errno` — which may be stale from a previous failing call. Message may lie. Minor.

Worse: on `obj != NULL && libbpf_get_error(obj) != 0`, the code logs and returns **without calling `bpf_object__close(obj)`**. In modern libbpf (0.7+), `__open_file` returning an error-encoded pointer (ERR_PTR) must not be closed; but if it returns a real pointer with an internal error, that pointer leaks. Practically libbpf uses ERR_PTR here, so `!obj || libbpf_get_error(obj)` handles both cases and close-skip is correct. Verified via libbpf source convention. OK.

### C24-13. `mount()` tries three option strings; only the **last** `mount_errno` is reported
File: `ch24-bpf-token-delegation.c:299-314`.

Variable `mount_errno` is overwritten each iteration. If attempt 1 fails with EINVAL (bad option) and attempt 3 fails with EPERM (not privileged), the error message reports only EPERM — misleading. Low impact for CH24_SKIP reason but makes debugging harder.

### C24-14. `server_cleanup` unconditionally `unlink`s ready_path and sock_path
File: `ch24-bpf-token-delegation.c:165-167`.

If a stale ready file exists from a previous run and the new server exits before writing its own, cleanup removes it — correct but creates a window where harness reads the old file between old-cleanup and new-write. Addressed at line 336 (`unlink(sock_path)` before bind) but no equivalent for ready_path. Low.

### C24-15. `server_cleanup` closes `token_fd` only after `unlink` of sock
File: `ch24-bpf-token-delegation.c:156-176`.

Order: close listen_fd, close token_fd, unlink sock_path, unlink ready_path, umount, rmdir. Correct: close token before umount so the token's reference to the superblock is released, allowing umount to succeed (otherwise EBUSY). Good.

### C24-16. `libbpf_get_error` vs ERR_PTR on `bpf_object__open_file`
Already covered in C24-12. Criterion met.

### C24-17. Signal-safety of ready-file write
File: `ch24-bpf-token-delegation.c:373-383`.

`fopen`, `fputs`, `fclose`, `chmod` — none async-signal-safe. But these run in the main thread before the accept loop; sigaction is already installed but no signal handler executes during fopen (SIGINT would just set `g_running=0` and return). The subsequent accept loop checks `g_running` — if SIGINT arrived during fopen, we continue through to the accept loop and exit cleanly on first select iteration. OK.

### C24-18. `read_cap_eff` — format string and bounds
File: `ch24-bpf-token-delegation.c:128-143`.

`fgets` into 256-byte buf; `strncmp("CapEff:", 7)` then `strtoull(line+7, NULL, 16)`. If `/proc/self/status` changes format (kernel has shipped "CapEff:" since forever), OK. `strtoull` tolerates leading whitespace. Good.

### C24-19. Opts zero-init and `sz`
File: `ch24-bpf-token-delegation.c:653, 704`.

`LIBBPF_OPTS(bpf_map_create_opts, mopts, .token_fd = token_fd);` — the macro expands to `struct bpf_map_create_opts mopts = { .sz = sizeof(mopts), .token_fd = token_fd };` with trailing fields zeroed. Compiler ensures `sz` is first. Correct. Criterion 6.

---

## ch18 — token bypass (getuid/geteuid kretprobe)

### C18-1. `kallsyms_has` skips line type column — may match data symbols
File: `ch18-token-bypass.c:74-101`.

Parser: find first space (after addr), find second space (after type char), then `name = third_token`. Works for `/proc/kallsyms`'s 3-column format `ADDR TYPE NAME [MODULE]`. Does **not** filter by type — a data symbol named `__arm64_sys_getuid` (implausible but not rejected) would match. ch23's version (line 32) correctly filters on `T/t/W/w`. Inconsistent. Low. Criterion 8.

### C18-2. `--tgid 0` rejected; but wildcard key is also `0`
File: `ch18-token-bypass.c:133` rejects `v == 0` as invalid. Wildcard mode uses key `0` (line 223 `z=0`). So a legitimate kernel-thread tgid=0 (swapper) would be unreachable via `--tgid 0` but is implicitly matched by `--all`. Not a bug — swapper doesn't run getuid anyway. OK.

### C18-3. `bpf_map__update_elem` on `target_tgids` map — assumes specific map type
The loader calls `BPF_ANY` updates with key=`unsigned int`, value=`unsigned int`. If the map is `BPF_MAP_TYPE_HASH` the key `0` is just a regular entry. If it's `BPF_MAP_TYPE_ARRAY`, `0` is the first slot. Either works. Good.

### C18-4. Attach loop ignores per-program failures
File: `ch18-token-bypass.c:207-215`.

Attach errors log and `continue`. If zero programs attach, the code at 217 detects and aborts. Good. If one of two attaches succeeds, the PoC runs partial — acceptable.

### C18-5. Ring buffer `handle` — checks `sz < sizeof(struct evt)`
File: `ch18-token-bypass.c:43-50`. Good; no under-read.

### C18-6. Signal handler — only sets `stop`, no I/O
File: `ch18-token-bypass.c:33-38`. Async-signal-safe. Good.

### C18-7. Cleanup path — `rb` freed before skel destroyed
File: `ch18-token-bypass.c:268-273`. Correct order: ringbuf references the map fd owned by the skel; free it first. Good.

### C18-8. No `.unwrap()`/`.expect()` — this is C; criterion 14 trivially satisfied.

No critical issues in ch18. Clean.

---

## ch23 — TPM unseal heist

### C23-1. Only ONE kallsyms check; chapter claims kprobe+kretprobe pair
File: `ch23-tpm-unseal-heist.c:77` checks `tpm2_unseal_trusted` (single symbol). Uses `ch23_tpm_unseal_heist_bpf__attach` (line 103) — the libbpf auto-attach. The BPF object is expected to declare both a `kprobe/tpm2_unseal_trusted` (entry, to stash `struct trusted_key_payload *p` into an inflight map keyed by `bpf_get_current_pid_tgid()`) and a `kretprobe/tpm2_unseal_trusted` (exit, to fetch the stashed pointer and read `p->key[0..key_len]` which has been filled by the kernel).

Auto-attach will attach both SEC("kprobe/...") and SEC("kretprobe/...") automatically if they use the standard section name. The loader is correct **iff** the `.bpf.c` declares both sections with that naming. Cannot verify from loader alone. Assuming the BPF object is correct, loader satisfies the "attach both" criterion.

**Note:** there is no explicit iteration over programs and no per-program status log — a silent half-attach (e.g., kretprobe fails because symbol is a different arch alias) would not surface here. Only the aggregate `attach failed` message appears. Recommend iterating `bpf_object__for_each_program` and logging each attach status (as ch18 does).

### C23-2. Inflight map capacity — not verified in loader
The loader does not inspect `max_entries` of the inflight map nor log it. If the `.bpf.c` declares `max_entries=1024` and a stress test unseals >1024 keys in parallel (highly unlikely — TPM serializes), entries would be evicted. Out of scope for loader; loader is silent.

### C23-3. `kallsyms_has` — stricter type filtering
File: `ch23-tpm-unseal-heist.c:30-40`.

`sscanf(line, "%*s %c %255s", &t, sym)` — skips addr, reads 1-char type, reads 255-char symbol. Filters `T/t/W/w`. Correct. Note that `%255s` stops at whitespace and prevents overflow. Good.

**Edge case:** kallsyms lines may include trailing `\t[module]` — not captured, not matched against. OK.

### C23-4. `handle` ringbuf callback — no size check
File: `ch23-tpm-unseal-heist.c:58-71`.

`const struct evt *e = data;` used without validating `sz >= sizeof(struct evt)`. If the BPF side submits a short event (shouldn't happen — `bpf_ringbuf_reserve` is fixed-size), we read past the ringbuf record into adjacent memory. Minor robustness gap. ch18 checks this; ch23 does not. Criterion 5.

### C23-5. Captures counter is a global — fine for single-thread polling
`g_captures` incremented in the handle callback. `ring_buffer__poll` is single-threaded so no race. Good.

### C23-6. Signal-driven shutdown
`running=0` in `on_sig`; main loop checks. Clean. ringbuf freed, skel destroyed in order. Good.

### C23-7. Return code on skip is `2`; on success `0`. Harness-compatible. Good.

**ch23 verdict:** usable. Recommend (a) adding ringbuf size check in `handle`, (b) iterating programs for per-attach logging, (c) documenting that the `.bpf.c` must declare both `SEC("kprobe/tpm2_unseal_trusted")` and `SEC("kretprobe/tpm2_unseal_trusted")` — loader is oblivious to which.

---

## ch25 — IMDS harvest

### C25-1. XDP attach fallback order is wrong
File: `ch25-imds-harvest.c:190-194`.

```c
unsigned int flags_try[] = { 0, XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE };
```

`flags=0` means "kernel default mode" — which is **native (DRV)** if supported, falling back to generic. So the first attempt already covers DRV. The second attempt `XDP_FLAGS_DRV_MODE` is redundant at best; on an interface that rejects DRV, the first `flags=0` attempt would have done the generic fallback automatically on newer kernels (≥5.0), or failed on older ones.

**Missing:** `XDP_FLAGS_HW_MODE` (offload, for supported NICs like Netronome/Mellanox). Not required for the PoC target (loopback/veth), but docs claim "fallback across native/generic/skb" — which is what the code attempts. The order is conceptually fine for 6.x kernels; the redundancy is cosmetic. Criterion 9.

### C25-2. `conn_for` — eviction policy is "always overwrite slot 0"
File: `ch25-imds-harvest.c:52-67`.

```c
if (free_idx < 0) free_idx = 0;
memset(&conns[free_idx], 0, ...);
```

When all 64 slots are active, new connections evict slot 0 **every time**. Two consequences:

- **UAF-adjacent:** not strictly UAF since memory isn't freed, but reassembly state for the long-lived connection in slot 0 gets clobbered the moment a new connection comes in with all slots full. The half-captured buffer is silently discarded; `scan_reassembled` on the next call sees a reset buffer and starts over.
- **Livelock under stress:** slot 0 is repeatedly reset while slots 1..63 persist until they go idle. No LRU. For the PoC (single IMDS flow), irrelevant; under adversarial traffic, the IMDS flow ending up in slot 0 is evicted on contention.

**Not a correctness crash; it is a silent data-loss eviction.** Criterion 11.

### C25-3. `find_json_str` bounds check — off-by-one
File: `ch25-imds-harvest.c:69-89`.

```c
for (unsigned int i = 0; i + klen + 4 < len; i++) {
    if (buf[i] != '"') continue;                     // buf[i] OK
    if (memcmp(buf + i + 1, key, klen) != 0) ...;    // buf[i+1 .. i+klen] (klen bytes)
    if (buf[i + 1 + klen] != '"') continue;          // buf[i+1+klen] OK
    unsigned int j = i + 2 + klen;
    while (j < len && (buf[j] == ' ' || buf[j] == ':' || buf[j] == '\t')) j++;
    if (j >= len || buf[j] != '"') continue;
    unsigned int start = j + 1;
    unsigned int end = start;
    while (end < len && buf[end] != '"') end++;
```

Outer guard `i + klen + 4 < len` guarantees `i + klen + 3 < len`, so access up to `buf[i + klen + 2]` is safe. The code accesses `buf[i + 1 + klen]` (= `buf[i + klen + 1]`) which is ≤ `buf[i + klen + 2]`. Inner loop advances `j` through `i + 2 + klen` to ≤ `len-1` with explicit `j < len` guard. `end < len` guard correct. No OOB.

**Subtle issue:** `strlen(key)` on a caller-supplied string is fine (caller passes literal). If a key longer than `len` is passed, `klen + 4` could underflow `len` → loop skipped. `unsigned int` subtraction via `i + klen + 4 < len` — no overflow for realistic `len ≤ 8192`, `klen < 256`. Safe. Criterion 11.

### C25-4. `scan_reassembled` — `active=0` drop after capture, but slot still occupies
File: `ch25-imds-harvest.c:109-110`.

Sets `c->active = 0` after printing credentials. Next `conn_for` call will reuse the slot. Good — this is the intended repeated-capture counter path. No UAF because `conns[]` is a static array, not heap.

### C25-5. `scrape_role` — needle match on boundaries
File: `ch25-imds-harvest.c:113-132`.

`needle = "iam/security-credentials/"`. Scans buffer for needle, extracts role name delimited by `' '`, `'\r'`, `'/'`, `'?'`, `'\n'`. Bounds: `i + nlen < c->len` ensures `memcmp(c->buf + i, needle, nlen)` is safe. `end` loop bounded by `c->len`. `rl < sizeof(g_last_role) - 1` prevents overflow. Good.

**Minor:** `g_last_role` is updated on every HTTP request containing the needle — if two role requests interleave (unlikely but possible with TTL rotation), the most recent wins. Chapter semantics match.

### C25-6. `handle` does NOT check ringbuf record size
File: `ch25-imds-harvest.c:134-151`.

`const struct evt *e = data;` — no `sz < sizeof(struct evt)` check. If a short record sneaks through, `e->payload_len` is garbage. The subsequent `min(payload_len, room)` could memcpy up to 8192 bytes of stale ringbuf data into the reassembly buffer. **Exploitability low** since BPF side reserves exact size, but a defensive `if (sz < sizeof(struct evt)) return 0;` is standard practice (ch18 does it). Criterion 5.

**Also:** `e->payload_len` is `unsigned short` (≤ 65535) and `room = REASM_SIZE - c->len` (≤ 8192). `unsigned int n = payload_len < room ? payload_len : room` narrows correctly. Safe.

### C25-7. `bpf_xdp_detach` error ignored
File: `ch25-imds-harvest.c:227`. On shutdown the detach result is not checked. If the interface disappeared (unlikely during the run), the program stays attached until the next reboot. Minor.

### C25-8. Signal handler sets `running=0`; poll loop exits cleanly; rb freed before detach before destroy. Good.

---

## Cross-cutting / Criterion Summary

| # | Criterion | ch18 | ch23 | ch24 | ch25 |
|---|-----------|------|------|------|------|
| 1 | arg parsing | OK | N/A | OK | minimal but OK |
| 2 | libbpf error handling | OK | OK | OK | OK |
| 3 | skel lifecycle | OK | OK | OK (manual) | OK |
| 4 | map/prog fd lifetime | OK | OK | OK | OK |
| 5 | ringbuf handler validates size | **OK** | **MISS** | OK | **MISS** |
| 6 | signal discipline | OK | OK | OK | OK |
| 7 | cleanup on error paths | OK | OK | OK | OK (ignores detach err) |
| 8 | kallsyms preflight | **weak type filter** | OK | N/A | N/A |
| 9 | attach fallback / logging | OK | **no per-prog log** | OK (CPU=0 only) | **redundant fallback** |
| 10 | shutdown ordering | OK | OK | OK | OK |
| 11 | userspace reassembly | N/A | N/A | N/A | **slot-0 eviction** |
| 12 | string/format safety | OK | OK | OK | OK |
| 13 | SCM_RIGHTS correctness | N/A | N/A | **OK** | N/A |
| 14 | no unwrap/expect | N/A (C) | N/A | N/A | N/A |

## Top issues to fix (priority order)

1. **ch24 C24-3** — `patch_map_fds` unconditional `i++` after loop body skips odd-offset LD_IMM64. Rewrite as `while (i + 1 < cnt) { ... ; if (match) {...}; i += 2; }` only when the current insn is a two-slot LD; otherwise `i += 1`. Code comment says "skip the paired second slot" but does so unconditionally.
2. **ch24 C24-10** — `perf_event_open` uses `cpu=0` — add per-CPU open or switch to `pid=-1, cpu=0` loop over nprocs. Under-counts on multi-CPU hosts.
3. **ch25 C25-2** — `conn_for` evicts slot 0 under full table. Implement simple LRU (track `last_update_ts`, evict least-recent).
4. **ch23 C23-4 / ch25 C25-6** — add `sz < sizeof(struct evt)` guard in ringbuf callbacks.
5. **ch23 C23-1** — iterate programs in attach path, log each program's attach status, for diagnostic visibility on the kprobe+kretprobe pair.
6. **ch18 C18-1** — tighten `kallsyms_has` to filter type column (`T/t/W/w`) like ch23's version.
7. **ch24 C24-13** — preserve first-failure `mount_errno` rather than last.

No segfaults found. No direct memory corruption. The most impactful latent bug is ch24 C24-3 (patch_map_fds) — it currently works by luck of libbpf's insn layout; a rebuild against a newer libbpf could silently emit a program with unpatched map_fd placeholders and trigger a verifier rejection whose message points at the BPF program, not the loader.
