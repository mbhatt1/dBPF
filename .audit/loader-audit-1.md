# Userspace BPF Loader Audit (defensive review)

Scope: the 11 non-BPF `.c` loaders listed in the task. Categorised by the
14 audit criteria; each finding cites an absolute path and line number.

Legend: **[BUG]** likely real defect · **[SMELL]** suspicious but not
proven wrong · **[NIT]** stylistic / low-priority.

---

## 1. File-descriptor leaks

### [BUG] ch01-mirror-controls-lsm — double/triple `fopen()` with no close, no NULL check
`/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch01-mirror-controls-lsm/ch01-mirror-controls-lsm.c:60-66`

```c
if (!fopen("/sys/kernel/security/lsm", "r") ||
    !strstr(({ static char buf[256]; FILE *f = fopen(...); if (f) {...; fclose(f);} buf; }),
            "bpf")) { ... }
```

Three distinct problems on these six lines:

1. The first `fopen()` is leaked unconditionally — the return value is only
   tested for NULL; no `fclose()`. Opens a `FILE *` every run.
2. The nested statement-expression opens a *second* `FILE *` (correctly
   closed inside) — so work is duplicated.
3. If the first `fopen()` fails, the `||` short-circuits: the skip marker
   is printed, but `buf` is uninitialised on the *next* invocation path
   because it's `static` and only written by the inner `fopen()`. The
   control-flow is fine because short-circuit prevents the `strstr()`, but
   the code is needlessly fragile and actively leaks one FD on success.

### [BUG] ch05b-ghost-nic — XDP detach skipped if `goto out` fires *before* `attached=1`
`/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch05b-ghost-nic/ch05b-ghost-nic.c:168-189`

The current code is correct for the documented failure modes, but note:
`bpf_xdp_attach()` can partially succeed-then-rollback internally; there
is no symmetric "detach if unsure" path. Not a concrete bug — flagged as
**[SMELL]** for defence-in-depth; a belt-and-braces `bpf_xdp_detach(..,
XDP_FLAGS_REPLACE,..)` before first attach would make double-run safe.

### [BUG] ch03-fuse-blackhole-fentry — `bpf_link` objects leaked on normal exit
`/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch03-fuse-blackhole-fentry/ch03-fuse-blackhole-fentry.c:131,144`

```c
struct bpf_link *l = bpf_program__attach(s->progs.mr_audit_log_start);
if (l) { ...; used_mr = 1; }
```

`l` is never stored, never freed. `ch03_fuse_blackhole_fentry_bpf__destroy(s)`
at shutdown does *not* know about these manually-attached links, so they
leak for the life of the process. Same issue at line 144 for `lsm_syslog`.
They're cleaned up by kernel on process exit so not catastrophic, but
functionally this is a resource leak in a loader explicitly meant to be
long-running.

### [NIT] ch06-silence-selinux — per-program `bpf_link *` return from attach is discarded
`/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch06-silence-selinux/ch06-silence-selinux.c:249`

Same pattern as ch03-fentry: `bpf_program__attach()` return not stored,
relying on skeleton `__destroy()` to tear down. Since these programs were
**not** attached via the skeleton's `__attach()` helper, `__destroy()`
may not detach them — verify libbpf behavior. Same issue in
`ch01-mirror-controls.c:189` and `ch02-overlayfs.c:238`.

### [NIT] ch04-phantom-syscall — no libbpf_set_print to silence debug
`/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/pocs/ch04-phantom-syscall/ch04-phantom-syscall.c:45`

Minor stdout/stderr hygiene: lacks the silencer every other loader has.

---

## 2. Missing libbpf return-value checks

### [BUG] ch01-lsm — map updates unchecked
`ch01-mirror-controls-lsm.c:79,84`

```c
bpf_map__update_elem(s->maps.target_tgids, &z, sizeof(z), &one, sizeof(one), BPF_ANY);
```

No error check, no message. If the wildcard or per-tgid update fails,
user sees nothing; the BPF program sees an empty target set and the whole
PoC silently observes-only.

### [BUG] ch04-phantom-syscall — critical tail-call setup unchecked
`ch04-phantom-syscall.c:59`

```c
bpf_map__update_elem(s->maps.jumps, &k, sizeof(k), &stage2_fd, sizeof(stage2_fd), BPF_ANY);
```

This is the tail-call install; if it fails, stage-2 never runs and the
PoC trivially reports "no events". Must be error-checked.

### [BUG] ch03-fuse-blackhole — ctrl map update unchecked
`ch03-fuse-blackhole.c:107`

```c
bpf_map__update_elem(s->maps.ctrl, &z, sizeof(z), &v, sizeof(v), BPF_ANY);
```

Pretend-drop mode silently no-ops on failure.

### [BUG] ch03-fuse-blackhole-fentry — `enabled` map update unchecked
`ch03-fuse-blackhole-fentry.c:162`

Same pattern; failure means suppression never engages but loader still
prints "active — audit suppression engaged" → false-positive PROVEN.

### [BUG] ch02-overlayfs-lsm — signal handler registration unchecked
`ch02-overlayfs-lsm.c:113`

```c
signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
```

`signal()` return is `SIG_ERR` on failure; never checked. Also using
`signal()` rather than `sigaction()` yields unspecified `SA_RESTART`
semantics across libc versions — inconsistent with every other loader.

### [BUG] ch01-mirror-controls — `bpf_program__fd(...) < 0` never checked
`ch01-mirror-controls.c:228`  (also **ch04** line 68)

`bpf_map__fd(s->maps.events)` is called; on failure returns negative and
the subsequent `ring_buffer__new()` returns NULL which *is* checked — so
not catastrophic, but the specific fd error is lost.

### [NIT] `libbpf_get_error(link)` pattern — modern libbpf deprecation
All loaders that use `libbpf_get_error()` (ch01, ch02, ch06) are using the
older libbpf 0.x idiom. Since libbpf 1.0, `bpf_program__attach()` returns
NULL on failure and `errno` carries the error. The current dual check is
redundant but harmless.

---

## 3. `errno` stomping

### [BUG] ch01-lsm — `strerror(errno)` after two `fopen()` calls and one `fclose()`
`ch01-mirror-controls-lsm.c:71-75`

```c
struct ch01_..._bpf *s = ..._open_and_load();
if (!s) {
    fprintf(stderr, "... reason=\"load: %s\"\n", strerror(errno));
```

Between a load failure and the `strerror(errno)` call, the statement-
expression LSM check above (line 60-66) has already run: one or two
`fopen()`s, a `fgets()`, a `fclose()`, and a `strstr()`. By the time we
reach the failure-print, `errno` almost certainly reflects `ENOENT` from
the `/sys/kernel/security/lsm` open, not the actual load error. **This
prints a nonsense reason to the harness.**

Correct idiom: libbpf returns a *negative errno* from `__load()`. Use
`strerror(-err)` or capture errno immediately.

### [BUG] ch02-overlayfs-lsm — same pattern
`ch02-overlayfs-lsm.c:79-84`

`ch02_overlayfs_lsm_bpf__open_and_load()` failure prints
`strerror(errno)` — but `check_lsm_bpf_enabled()` just executed
`fopen/fgets/fclose/strstr` and overwrote errno.

### [BUG] ch03-fuse-blackhole — same
`ch03-fuse-blackhole.c:93-100`

After `open_and_load()` fails, prints `strerror(errno)`. Before that
call, no intervening work is done *in main*, so OK; but for the `attach`
branch at line 97-100, the failed `open_and_load` error has already been
clobbered by the subsequent `attach` call itself — which returns an
int-errno, not via errno. The printed errno here is unreliable (libbpf
sets errno internally but not consistently documented). Prefer
`strerror(-err)` where an integer return is available.

### [BUG] ch03-fuse-blackhole-fentry — `strerror(errno)` after signalling path
`ch03-fuse-blackhole-fentry.c:90-92, 121, 137-138, 149-150`

After `ch03_..._bpf__open()` fails → prints `strerror(errno)`. **BUT**
the `btf_has_func()` call below the open does `btf__load_vmlinux_btf()`
and `btf__free()`; between `__open` and the print of the error message
at line 91 there are no intervening calls — that one is OK.
However line 137-138 (`fmod_ret attach failed`) and 149-150
(`lsm attach failed`) both print `strerror(errno)` after
`bpf_program__attach()` → libbpf sets errno on NULL return, so this is
technically correct but fragile.

### [BUG] ch06-silence-selinux-lsm — same open_and_load pattern
`ch06-silence-selinux-lsm.c:115-118`

`check_lsm_bpf_enabled()` runs `fopen/fgets/fclose/strstr` just before
the `__open_and_load()` call. On load failure, the errno printed is
usually the residue from the preceding file work, not from bpf.

### [BUG] ch01-mirror-controls — `ring_buffer__new` errno race
`ch01-mirror-controls.c:228-230`

`ring_buffer__new(bpf_map__fd(...), ...)` — `bpf_map__fd()` internal
plumbing may touch errno. The documented contract for `ring_buffer__new`
is that it returns NULL on error and libbpf sets errno. Modern libbpf is
consistent here, but the same pattern in earlier versions would be
suspect.

---

## 4. Signal-handler safety

All 11 loaders use `volatile sig_atomic_t stop/running` flag pattern and
handlers call only `(void)sig; stop = 1;`. That is async-signal-safe and
correct. **No finding.**

Exception: none of the handlers call `write()`/`printf()`/`malloc()`.

### [NIT] `sig_atomic_t flips` (ch01-lsm:20)
`static unsigned long long flips;` at file scope — read by `fprintf` in
the handler-flag-checked shutdown path, but incremented in the **ringbuf
callback**, which runs from poll context (signal safe). The value printed
at shutdown is *not* accessed from the handler itself, so this is fine.

---

## 5. Race between signal and normal flow

All loaders use the canonical `volatile sig_atomic_t stop` pattern. The
read in `while (!stop)` is OK. **No finding.**

### [NIT] SA_RESTART flag
- ch01, ch02, ch02-lsm, ch03, ch03-lsm use `struct sigaction sa = { .sa_handler = on_signal };
  sigemptyset(&sa.sa_mask);` — `sa_flags` is zero-initialised by the
  designated initialiser, so `SA_RESTART` is off → `ring_buffer__poll`
  returns `-EINTR` promptly. Correct.
- ch02-lsm and ch03 (non-fentry) use the legacy `signal()` call — behavior
  of `SA_RESTART` is implementation-defined. Minor inconsistency.
- ch05b explicitly sets `sa.sa_flags = 0` with a comment — good.

### [BUG] ch06-silence-selinux-lsm — `struct sigaction sa = {0};` without explicit SA_RESTART=0
`ch06-silence-selinux-lsm.c:159-161`

Zero-init gives `sa_flags = 0`, so this is correct — flagged only
because `{0}` warns on stricter C standards (pre-C23); the other loaders
use the designated-initializer form for clarity.

---

## 6. Ring-buffer drain

All loops follow the shape:

```c
while (!stop) {
    int n = ring_buffer__poll(rb, ms);
    if (n < 0 && n != -EINTR) break;
}
```

This is correct for the three cases of interest (0, positive, -EINTR).

### [BUG] ch01-lsm, ch02-lsm, ch03, ch03-fentry, ch06-lsm — `n < 0` not logged
e.g. `ch01-mirror-controls-lsm.c:107`
`if (n < 0 && n != -EINTR) break;`

On non-EINTR error the loop silently breaks with **no** diagnostic. The
surviving loaders (ch01, ch02, ch04, ch05, ch05b, ch06) print
`strerror(-n)` — recommend normalising.

### [BUG] ch05b-ghost-nic — subtle loop-exit semantics
`ch05b-ghost-nic.c:199-207`

```c
while (!stop) {
    int n = ring_buffer__poll(rb, 200);
    if (n < 0) {
        if (n == -EINTR) break;
```

`break` on EINTR is **correct here** because the signal handler already
set `stop=1`; but if `SA_RESTART=0` and EINTR fires with `stop` still 0
(race: signal delivered but flag write not yet visible), this short-
circuits before the next iteration can exit normally. In practice the
`stop=1` write is ordered before signal return by the kernel, so this
works — but it's a subtle enough invariant to warrant a comment.

### [NIT] Event rate limiting
None of the loaders rate-limit ringbuf → stdout. Under adversarial load
(e.g. a fork-bomb inside the targeted tgid) the loader will buffer
megabytes of text in stdout. Not a bug, but a robustness gap for
long-running satellite deployment.

---

## 7. Kallsyms preflight

### [BUG] ch01-mirror-controls / ch02-overlayfs — no symbol-type filter
`ch01-mirror-controls.c:70-100, ch02-overlayfs.c:127-154`

Neither parser filters on the single-character **type** field. A symbol
can appear as `D/d/B/b` (data/bss) — accepting such a match for a kprobe
target is wrong: kprobes need `T/t/W/w` (text / weak text). In practice
this is nearly always benign because `cap_capable`, `ovl_copy_up` etc.
are textual, but a future rename that collides with a BSS symbol of the
same name would silently pass preflight.

**Contrast:** `ch06-silence-selinux.c:97-119` (`sym_exists`) does this
correctly — explicit `type` extraction and `T/t/W/w` whitelist. That
function is the right pattern; ch01 and ch02 should adopt it.

### [BUG] ch01/ch02 kallsyms parser — misparses symbols with trailing tab
`ch01-mirror-controls.c:86-92`

The parser strips trailing whitespace, then looks for a `\t` module
suffix. But `/proc/kallsyms` separates the module in `[mod]` form with a
preceding space, not tab:

```
ffffffff81xxxxxx T symbol_name\t[module_name]
```

(older kernels use `\t`; newer use space). The tab-stripping happens
*before* the module-strip, so on kernels that emit space-separated
modules, the module stays glued to the name and the `strcmp` fails
against the bare symbol. ch06's `strcspn(name, " \t\n")` handles both.

### [BUG] ch01/ch02 — address of symbol zero/NULL not filtered
If kallsyms restrictions are active (`/proc/sys/kernel/kptr_restrict=2`
without CAP_SYSLOG), all addresses read as `0000000000000000`. The
current parser doesn't distinguish; it will happily match a name but
that match is meaningless. Consider checking the address is nonzero
before trusting the type byte.

### [SMELL] kallsyms_has returns 0 (absent) vs -1 (I/O err)
`ch02-overlayfs.c:209-223`

The handling treats `-1` as "proceed optimistically", which is the right
call — but `0` (definitively absent) unconditionally disables the probe.
Good. No finding for ch02/ch01.

---

## 8. `bpf_program__set_autoload(false)` selectivity

### [BUG] ch03-fuse-blackhole-fentry — can disable *both* programs
`ch03-fuse-blackhole-fentry.c:107-110`

```c
if (!have_mr)  bpf_program__set_autoload(s->progs.mr_audit_log_start, false);
if (!have_lsm) bpf_program__set_autoload(s->progs.lsm_syslog, false);
```

If both `have_mr == 0` and `have_lsm == 0`, both programs are disabled.
Then the guard at line 112-118 correctly emits CH03_FE_SKIP and exits.
That's correct — **not** a bug. Flag kept as **[NIT]**: the order of
"disable then check empty" is slightly surprising; easier to reason
about would be "check empty first, then disable losers".

### [BUG] ch01/ch02/ch06 — selective disable works, no finding
Verified each loader only disables the programs whose kallsyms target
is absent, and the `n_attached==0` guard catches the "all disabled"
case.

---

## 9. Map-update race with BPF side

### [BUG] ch01, ch02-lsm, ch06-lsm — attach happens *before* map population
Universal pattern:

```c
skel__attach(s);              // BPF side now live
// … later …
bpf_map__update_elem(target_tgids, …);
```

Example: `ch02-overlayfs-lsm.c:86-92` attaches the fmod_ret programs
immediately, then `ch02-overlayfs-lsm.c:94-105` fills `target_paths`.
Between attach and population there is a window where the BPF side sees
an empty target set and under-enforces. For `copy-up` that means the
very first event after attach can escape the DENY.

**Same issue:** `ch06-silence-selinux-lsm.c:121-149` (attach at 121,
map populate at 129-149); `ch01-mirror-controls-lsm.c:77-92`.

Fix is trivial: populate `target_tgids` / `target_paths` *before*
calling `__attach`. ch01 non-LSM loader gets this right (it populates at
`ch01-mirror-controls.c:204-226`, which is *after* per-program
`bpf_program__attach` loop — same bug there).

### [BUG] ch01-mirror-controls — non-LSM version has the same ordering bug
`ch01-mirror-controls.c:184-226`

Attach loop at 184-197 completes, then targets populated at 204-226.
Window exposed.

### [NIT] ch04 — tail-call map populated *before* attach
`ch04-phantom-syscall.c:56-61` — jumps map populated at 59 *before*
attach at 61. Correct.

---

## 10. Argv parsing

### [BUG] ch01-lsm — `atoi()` on untrusted tgid
`ch01-mirror-controls-lsm.c:53`
```c
if (ntargets < 1024) targets[ntargets++] = atoi(optarg);
```
No overflow check; no validity check; `atoi("abc")` returns 0 silently.
ch01 non-LSM uses `strtoul` with bounds-checking at line 122-126 — same
loader family, inconsistent quality.

### [BUG] ch06-lsm — same `atoi()` issue
`ch06-silence-selinux-lsm.c:94`
```c
tgid_args[n_tgid++] = (unsigned int)atoi(optarg);
```
No range check; negatives silently wrap.

### [BUG] ch02-lsm — `strncpy` without explicit NUL guarantee (but buf is zeroed so OK)
`ch02-overlayfs-lsm.c:95-96`
```c
char key[PATH_MAX_COMP] = {0};
strncpy(key, targets[i], PATH_MAX_COMP - 1);
```
Zero-init guarantees NUL termination. **No finding.** Good pattern.

### [NIT] Option return mismatch — ch01-lsm:56, ch02-lsm:63
`default: return c == 'h' ? 0 : 2;`  — but `case 'h'` is folded into
`default`, so `c` at this point could also be `?` (unknown). Returns 2
for unknown, 0 for `-h`. Works but subtle.

### [BUG] ch02-overlayfs — weapon-mode triad
`ch02-overlayfs.c:181-185`
```c
int weapon = (g_race_upperdir && g_race_target && g_race_payload);
if ((g_race_upperdir || g_race_target || g_race_payload) && !weapon) { error }
```
Correct — rejects any partial set. **No finding.**

### [BUG] ch02-overlayfs — payload via argv has no length cap
`ch02-overlayfs.c:77-78`
```c
size_t n = strlen(g_race_payload);
ssize_t w = write(fd, g_race_payload, n);
```
If `-w` argument is multi-megabyte, the handler blocks in `write()`
inside the ringbuf callback, stalling the poll loop. Not a crash, but a
DOS surface. Cap to e.g. 4 KiB or write in a loop with `usleep`.

---

## 11. Stdout vs stderr discipline

The harness convention per README: `CHNN_PROVEN`/`CHNN_SKIP` → stdout;
diagnostic → stderr.

### [BUG] ch01-mirror-controls — SKIP markers go to stderr
`ch01-mirror-controls.c:154, 176`:
```c
fprintf(stderr, "[ch01] CH01_SKIP reason=\"...\"\n", ...);
```
Same in **ch02** (lines 197, 227), **ch02-lsm** (67, 73, 81, 88),
**ch03** (93, 98), **ch03-fentry** (90, 114, 121, 155), **ch05** (103,
110), **ch05b** (157), **ch06-lsm** (107, 116, 123).

Only **ch06-silence-selinux** (non-LSM) emits SKIP correctly to stdout
(lines 192, 234, 241). **If the harness scrapes stdout for `CH*_SKIP`,
every other loader is producing false negatives.**

### [BUG] ch06-silence-selinux — CH06_PROVEN mixed with diagnostic events
`ch06-silence-selinux.c:63, 70`
PROVEN goes to stdout (correct). General event stream also to stdout
(line 70). Ambiguity: first PROVEN line *is* an event, so harness
regex must tolerate both. Likely intentional; flagged only.

### [BUG] ch01-lsm, ch04, ch05, ch05b, ch06-lsm — event stream on stdout
All correct. But the SKIP markers above go to stderr, which is the
real issue.

### [BUG] ch04-phantom-syscall — PROVEN marker on stdout good; SKIP on stderr bad
`ch04-phantom-syscall.c:92-95` prints `CH04_PROVEN`/`EXFIL_COMPLETE` to
stdout — correct. But SKIP at `51, 63` goes to stderr. Inconsistent
within the same loader.

---

## 12. Marker format correctness

### [BUG] Inconsistent marker prefix
- ch01: `[ch01]` and `[ch01-lsm]`
- ch02: `[ch02]` and `[ch02-lsm]`
- ch03 non-fentry: `[ch03]` for SKIP but `[audit]` for events (line 75,
  79, 82, 125) — the harness regex `\[chNN\]` will miss event lines.
- ch03-fentry: `[ch03-fe]` everywhere — consistent.
- ch04: `[ch04]` for SKIP and PROVEN, but `[phantom]` for events (line
  36) — same mismatch as ch03.
- ch05: `[ch05]` everywhere — consistent.
- ch05b: `[ghost]` everywhere — **never** uses `[ch05b]`. Harness
  regex `\[ch05b\]` will never match. **Real bug.**
- ch06-lsm: `[ch06]` everywhere — consistent.

### [BUG] `CHNN_SKIP` always includes `reason=` — verified
Spot-checked all 11 loaders: every SKIP marker has a `reason="..."`
suffix. **No finding.** Good.

### [BUG] ch02-overlayfs-lsm — SKIP marker is `CH02_LSM_SKIP`, not `CH02_SKIP`
`ch02-overlayfs-lsm.c:73, 81, 88`

Same in ch03-fentry (`CH03_FE_SKIP`) and ch06-lsm (`CH06_LSM_SKIP`).
If the harness regex is literal `CH02_SKIP`, these variants are
invisible. Recommend either normalising to `CHNN_SKIP` with a `variant=`
tag, or documenting the two-form regex.

---

## 13. Skeleton lifecycle

All 11 loaders observe `open -> [tweak] -> load -> attach -> poll ->
destroy`. No use-after-destroy found.

### [BUG] ch03-fuse-blackhole-fentry — `__attach()` not called, manual attach only
`ch03-fuse-blackhole-fentry.c:131, 144`

Uses `bpf_program__attach()` per program rather than
`ch03_..._bpf__attach(s)`. The skeleton's `__destroy()` may not know
about the manually-attached links (see §1). libbpf's documented
behavior: `bpf_link` objects attached via `bpf_program__attach` are
**not** tracked by the skeleton and **must** be freed by the caller via
`bpf_link__destroy()`. The current loader leaks them (process exit
cleans up via kernel, but the loader API contract is violated).

Same in ch01-mirror-controls.c:189, ch02-overlayfs.c:238,
ch06-silence-selinux.c:249.

### [NIT] ch01-lsm, ch02-lsm, ch03-fe, ch06-lsm — early-return paths
On early failure (`attach` returns err), some paths do
`skel__destroy(s); return 1;` — this is correct. But they do *not* free
the ringbuf — since ringbuf is created *after* these early returns, no
leak. Verified.

---

## 14. PID recyclability in target maps

### [BUG] Universal — loader accepts `-t <tgid>` and assumes it is stable
All loaders that accept `-t` (ch01, ch01-lsm, ch06-lsm) insert a TGID
into `target_tgids` at startup. On Linux, TGIDs *can* be recycled after
the original process exits. If the target exits and its TGID is re-used
by an unrelated process while the loader is still running, the loader
continues to coerce the new process with the old policy.

Mitigation would be: insert `(tgid, starttime_ns)` tuples and have the
BPF side verify via `bpf_get_current_task_btf()` → `start_time`. None of
the loaders do this. Not a correctness bug in the isolated-PoC sense,
but a footgun if re-deployed as tooling. **Document as limitation** or
fix.

### [BUG] ch02-overlayfs weaponize uses basename, not tgid — not affected
ch02 matches by basename, no PID tracking. **No finding.**

---

## Cross-cutting summary

| # | Finding | Severity | Files |
|---|---|---|---|
| 1 | SKIP markers on stderr not stdout | High (may break harness) | ch01, ch02, ch02-lsm, ch03, ch03-fe, ch05, ch05b, ch06-lsm, ch04 |
| 2 | Inconsistent `[chNN]` prefix (ch05b uses `[ghost]`, ch03 uses `[audit]`, ch04 uses `[phantom]`) | High | ch03, ch04, ch05b |
| 3 | `errno` stomped by intervening FILE I/O between error and `strerror(errno)` | High | ch01-lsm, ch02-lsm, ch03, ch03-fe, ch06-lsm |
| 4 | Map populated *after* attach — window of under-enforcement | Med | ch01, ch01-lsm, ch02-lsm, ch06-lsm |
| 5 | Unchecked `bpf_map__update_elem` return | Med | ch01-lsm, ch03, ch03-fe, ch04 |
| 6 | `atoi()` instead of `strtoul` with bounds check | Med | ch01-lsm, ch06-lsm |
| 7 | kallsyms parser missing type-field filter & address-zero check | Med | ch01, ch02 |
| 8 | `bpf_link` from manual `bpf_program__attach` never freed | Low | ch01, ch02, ch03-fe, ch06 |
| 9 | `fopen()` result leaked on first check | Low | ch01-lsm |
|10 | TGID recyclability | Low (doc) | ch01, ch01-lsm, ch06-lsm |
|11 | SKIP marker variant `CHNN_LSM_SKIP` may miss regex | Med | ch02-lsm, ch03-fe, ch06-lsm |
|12 | ringbuf callback may block in `write()` during weapon mode | Low | ch02 |
|13 | `signal()` instead of `sigaction()` | Low | ch02-lsm, ch03, ch03-fe, ch06-lsm |
|14 | Event-stream rate limiting absent | Low | all |

**Highest-leverage fixes**: #1 (SKIP to stdout), #2 (prefix), #3 (errno
capture immediately), and #4 (populate maps before attach) would
eliminate the most severe harness-observable and correctness bugs.
