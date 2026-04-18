# Integration Surface Audit — harness ↔ PoCs ↔ QEMU ↔ triggers ↔ chapters

Scope: cross-component drift only. This audit does not re-cover the intra-file bugs
already documented in `.audit/harness-audit.md` or `.audit/chapter-xref-audit.md`;
it focuses on mismatches that only surface at the seams between components.

Overall verdict: **minor-drift**. All 23 registered PoCs have valid on-disk directories,
matching Makefile `APP` variables, trigger-emitted markers that satisfy their
`proof_marker` regex, and realistic timeouts. The drift lives almost entirely in
the published site (`index.md`, `book/index.md`, `README.md` top matter,
two `_posts/` files) and a handful of chapter-body cross-references to
**PoC directories that were deleted in the 0.3.0 synthetic/analog cleanup** but
whose links were not updated.

---

## CRITICAL

### CR1. `_book_chapters/act-2/chapter-7-device-cgroup-houdini.md:9` and `:210` reference a deleted PoC directory

Chapter 7 still points readers at `dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm/` as the
"surviving workaround variant":

```
_book_chapters/act-2/chapter-7-device-cgroup-houdini.md:9
   and the surviving workaround variant at
   [dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm/]
   (https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs).

_book_chapters/act-2/chapter-7-device-cgroup-houdini.md:210
   The fix, which is the approach now baked into the POC at
   `dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm/ch07-devcgroup-houdini-lsm.c` ...
```

CHANGELOG.md:65 explicitly records that `ch07-devcgroup-houdini-lsm` was deleted as an
analog in release 0.3.0. There is no such directory on disk and no Makefile targets it.
Chapter 7 thus documents behavior ("the approach now baked into the POC at …") that
no longer exists.

What it should reference:
- The only surviving ch07 variant is `dBPF-pocs/pocs/ch07-devcgroup-houdini/`
  (kprobe observer + `bpf_send_signal(SIGUSR2)`, already registered in proof.py:99).

Proposed fix: rewrite both mentions to point at `ch07-devcgroup-houdini/` and
rephrase the paragraph at `:210` to describe the kretprobe-driven signal design
actually shipping, *not* a non-existent LSM fmod_ret variant. Also update
`dBPF-pocs/pocs/ch07-devcgroup-houdini/README.md:14` which makes the same
dangling reference ("see `ch07-devcgroup-houdini-lsm/`").

### CR2. `index.md` and `book/index.md` still advertise retired chapters 13 and 17

CHANGELOG.md:67–70 records that chapters 13 (Powercap Override) and 17 (ACPI WSMI Ping)
were retired along with their analog PoCs. On disk:
- `_book_chapters/act-2/chapter-13-*` — absent
- `_book_chapters/act-3/chapter-17-*` — absent
- `dBPF-pocs/pocs/ch13-*` — absent
- `dBPF-pocs/pocs/ch17-*` — absent

But the published table of contents still links them:

```
index.md:34
   13. [Chapter 13: Powercap Override]({{ site.baseurl }}/book/act-2/chapter-13-powercap-override.html) — ...
index.md:41
   17. [Chapter 17: ACPI WSMI Ping]({{ site.baseurl }}/book/act-3/chapter-17-acpi-wsmi-ping.html) — ...
book/index.md:47 (row 13 in Act II table)
book/index.md:58 (row 17 in Act III table)
book/index.md:78 (skips-explained row)
book/index.md:79 (skips-explained row)
```

Clicking either link on the rendered site produces a 404 (the Jekyll build has no
corresponding source file to render). The skips-explained list in `book/index.md:74–79`
also mis-counts: it claims six skips but the retirement of 13 and 17 leaves at most four
Act I–III skips on linuxkit. `README.md:3` already updated to the new count ("4 honest
skips documented"); the site index didn't.

Proposed fix: delete the 13 and 17 rows from `index.md` and `book/index.md`. Remove the
two now-orphaned posts `_posts/2025-03-10-powercap-override.md` and
`_posts/2025-05-07-acpi-wsmi-ping.md`, or rewrite them as "retired — here is why" stubs
that do not link to non-existent book chapters or PoC directories.

### CR3. `index.md` and `book/index.md` route every chapter 19–22 link to `act-3/` but the files live in `act-7/`

Every navigation link on the front page pointing to the synthesis chapters is broken:

```
index.md:43  Chapter 19 → /book/act-3/chapter-19-the-new-reality.html
index.md:47  Chapter 20 → /book/act-3/chapter-20-the-autopsy-what-we-proved.html
index.md:48  Chapter 21 → /book/act-3/chapter-21-the-autopsy-what-refused-to-die.html
index.md:49  Chapter 22 → /book/act-3/chapter-22-the-defender-playbook.html
book/index.md:60–63  same four chapters, same wrong directory
book/index.md:81  Chapter 21 "Full accounting" link — same wrong directory
```

On disk these four chapters live in `_book_chapters/act-7/`, which `_book_chapters/README.md`
correctly documents ("Act VII — Conclusion"). The in-chapter navigation footers inside each
Act VII chapter already use `act-7/` (e.g. `_book_chapters/act-7/chapter-20-the-autopsy-what-we-proved.md:11`),
so the drift is isolated to the two top-level index pages.

Proposed fix: replace `act-3` with `act-7` for chapters 19, 20, 21, 22 in both
`index.md` (4 lines) and `book/index.md` (5 lines). Also update `book/index.md`'s
act-header on line 51 ("Act III — Total Control") and the table around line 60
which lumps synthesis into Act III.

### CR4. `README.md` repository layout panel claims Act III houses chapters 19–22

```
README.md:14   act-1/  Foundations, chapters 1–5b, plus chapter 0 preface.
README.md:15   act-2/  Mid-complexity primitives, chapters 7–13.
README.md:16   act-3/  Synthesis and taxonomy, chapters 19–22.
README.md:17   act-4/  Cross-boundary primitives, chapters 23–25.
```

Three problems in four lines:
- Line 15 says Act II contains chapter 13 — retired (see CR2).
- Line 16 says Act III is "Synthesis, chapters 19–22" — wrong directory (19–22 live
  in act-7, per CR3) and Act III actually holds the primitive chapters 14, 15, 16, 18.
- Line 17 is correct.
- Act VII (where the synthesis chapters actually live) is not mentioned at all.

Proposed fix: align the layout panel with `_book_chapters/README.md`'s Act arc
(lines 19–27), i.e. rewrite as:

```
act-1/  Foundations, chapters 0–6 (5b included).
act-2/  Kernel intrusion, chapters 7–12.
act-3/  Total control, chapters 14–18 (13, 17 retired).
act-4/  Cross-boundary, chapters 23–25.
act-7/  Conclusion / synthesis, chapters 19–22.
```

---

## HIGH

### H1. `_posts/2025-02-07-device-cgroup-houdini.md` front-matter names a deleted PoC directory

```
_posts/2025-02-07-device-cgroup-houdini.md:5
   poc_dir: dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm
_posts/2025-02-07-device-cgroup-houdini.md:10
   [Workaround variant](...master/dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm)
_posts/2025-02-07-device-cgroup-houdini.md:66
   - Workaround POC: [dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm/]
```

Same deletion as CR1. Whatever Jekyll include/layout consumes `page.poc_dir` will emit
a broken GitHub link when this post is rendered.

Proposed fix: set `poc_dir: dBPF-pocs/pocs/ch07-devcgroup-houdini` and delete the
"Workaround variant" link, or rewrite this post as a retired-chapter stub.

### H2. proof.py does **not** register five PoC directories that exist on disk

Directories on disk but not referenced by any `Poc(...)` entry in proof.py:

| Directory                             | Status                                                                                     |
|---------------------------------------|--------------------------------------------------------------------------------------------|
| `ch01-mirror-controls-lsm`            | Built and run by `run-qemu-tests.sh:7` and `qemu-runner.sh:114`; chapter 1 treats it as the canonical variant. Proof.py registers only the kprobe sidebar variant. |
| `ch02-overlayfs-lsm`                  | Built by `run-qemu-tests.sh:25`; emits `CH02_LSM_PROVEN`; no proof.py entry.               |
| `ch03-fuse-blackhole-fentry`          | Built by `run-qemu-tests.sh:32`; emits `CH03_FE_PROVEN`; no proof.py entry.                |
| `ch08-keyring-heist-lsm`              | Built by `qemu-runner.sh:167`; emits `CH08_PROVEN flipped=N`; no proof.py entry.           |
| `ch12-signed-driver-swap` (kprobe)    | Built on disk; emits `CH12_PROVEN hook=…` from the loader. proof.py registers the `-lsm` and `-syscall` variants but not the bare kprobe directory. |

The net effect: the primary Docker harness in `harness/proof.py` does not exercise
these five directories at all, and the secondary QEMU harness exercises four of them
(`ch12-signed-driver-swap` base dir is exercised by neither). This is the source of the
"23 registered / 28 on disk" gap and is the mirror image of CR1: the linuxkit harness's
PoC list has diverged from the QEMU runner's list without a single source of truth.

Proposed fix: either
(a) register the QEMU-only PoCs in proof.py with explicit `skip_reason="requires Fedora 42 QEMU VM (no bpf-lsm on linuxkit)"` so every disk directory appears in `/tmp/proof-result.json`, or
(b) declare `ch01-mirror-controls-lsm`/`ch02-overlayfs-lsm`/`ch03-fuse-blackhole-fentry`/`ch08-keyring-heist-lsm` as sidebar / reference directories and delete the bare `ch12-signed-driver-swap` kprobe directory to match the three-variant `-lsm`/`-syscall` registration that `_book_chapters/README.md:53` already documents.

### H3. `ch24` `proof_marker` requires both `uid_events=` **and** `token_delegated=yes`; trigger can print a `CH24_PROVEN` line with only `token_delegated=yes`

proof.py:175:
```
proof_marker=r"CH24_PROVEN\s+uid_events=\d+\s+token_delegated=yes|CH24_SKIP\s+reason="
```

But `ch24-bpf-token-delegation/trigger.sh:225`:
```
echo "=== CH24_PROVEN uid_events=$UID_EVENTS token_delegated=yes ==="
```

`UID_EVENTS` is derived with `sed` from the client log (`trigger.sh:223`). If the
client printed a `CH24_PROVEN` line but the `uid_events=` field was empty or
missing (e.g. mid-refactor client output), `UID_EVENTS` would be empty, and the
echo would produce `CH24_PROVEN uid_events= token_delegated=yes` — which the
regex refuses (`\d+` needs at least one digit) but also does not hit `CH24_SKIP`.
The final-marker fallback at `trigger.sh:236` does emit `CH24_SKIP`, but only
when `PROVEN_LINE` was empty, not when it was non-empty-but-malformed.

The harness verdict would then fall through to `fail` (no proof, no skip, no events).
This is a corner case but worth tightening. Proposed fix:
```
-  proof_marker=r"CH24_PROVEN\s+uid_events=\d+\s+token_delegated=yes|CH24_SKIP\s+reason="
+  proof_marker=r"CH24_PROVEN\s+uid_events=\d*\s+token_delegated=yes|CH24_SKIP"
```
or guard in `trigger.sh:223` by substituting `UID_EVENTS=${UID_EVENTS:-0}`.

### H4. `ch07` `proof_marker` matches `SIGUSR2_SENT` but trigger only prints the literal string inside a `flip_marker`

proof.py:103:
```
flip_marker=r"SIGUSR2_SENT|FLIP\s+hook=",
proof_marker=r"CH07_PROVEN|CH07_WEAPON_PROVEN|CH07_CONCEPT_PROVEN|SIGUSR2_SENT"),
```

`ch07-devcgroup-houdini/trigger.sh` only prints the literal string `signals=$SIGNALS`
and `CH07_WEAPON_PROVEN` / `CH07_PROVEN`; no bare `SIGUSR2_SENT` token. The loader
`ch07-devcgroup-houdini.c:201` prints `CH07_WEAPON_PROVEN signals=N denies=N`. The
dangling `SIGUSR2_SENT` alternative in the regex is dead code — not a bug, but
slightly misleading because it implies a marker the PoC does not actually emit.

Proposed fix: drop `SIGUSR2_SENT` from the `proof_marker` (it is still useful in
`flip_marker` for event-stream recognition if a future version emits it).
Similar dead alternatives exist in ch05's `proof_marker=r"CH05_PROVEN|LEASH_SUCCESS"`
(only `CH05_PROVEN` is ever emitted) and ch04's `EXFIL_COMPLETE|SIGUSR1_SENT`
alternatives, which the loader does print but the trigger never does; these are
not harness bugs, just noise.

---

## MEDIUM

### M1. ch09's registered hook name is a tracepoint, but the BPF program attaches as a raw tracepoint

proof.py:109: `hooks=["tp:sched/sched_process_fork"]`.
But `ch09-pid-doppel.bpf.c:97` uses `SEC("raw_tp/sched_process_fork")`.

`kallsyms_has` converts the `tp:` prefix to a path under
`/sys/kernel/debug/tracing/events/sched/sched_process_fork/id`. That path exists
whenever the kernel has a tracepoint for `sched/sched_process_fork`, which is the
same tracepoint the raw_tp program attaches to, so the presence check works.
But it is a semantic mismatch that would confuse a reader of proof.py who
expects the hook string to describe the program's actual SEC.

Proposed fix: add a `rawtp:` prefix to `kallsyms_has` that checks the same file
path, and change ch09's entry to `rawtp:sched/sched_process_fork`. Low priority.

### M2. `qemu-runner.sh` and `run-qemu-tests.sh` have overlapping but non-identical PoC lists

- `run-qemu-tests.sh` runs: ch01-lsm, ch02-lsm, ch03-fentry, ch12-lsm, ch23, ch24, ch25.
- `qemu-runner.sh` runs: ch06, ch06-lsm, ch01-lsm, ch02-lsm, ch03-fentry, ch08-lsm, ch12-lsm, ch23, ch24, ch25.
- `act4-runner.sh` runs: ch23, ch24, ch25.

The overlap is deliberate (act4-runner is the focused Act-4 driver; qemu-runner is
the full secondary harness), but there is no single script that maps 1:1 to the
proof.py registered set. A PoC added to proof.py but not to any of these three
scripts will silently go un-run on the secondary harness. A reviewer cannot tell
from the scripts alone which PoCs are intended to fire on QEMU.

Proposed fix: add a comment to each script indicating which proof.py entries it
covers and which it deliberately omits, or extract the list into a shared
`qemu-poc-list.txt` that both scripts source.

### M3. ch25 trigger emits `=== CH25_PROVEN access_key_captured=yes token_captured=yes role=$ROLE ===` but proof_marker requires `access_key_captured=yes`

proof.py:180:
```
proof_marker=r"CH25_PROVEN\s+access_key_captured=yes|CH25_SKIP"
```

trigger.sh:108: `echo "=== CH25_PROVEN access_key_captured=yes token_captured=yes role=$ROLE ==="`.

These match. But the loader `ch25-imds-harvest.c:221` prints a slightly different
variant: `CH25_PROVEN access_key_captures=%llu token_captures=%llu role=%s`
(plural `captures`, not `captured=yes`). That line is **not** matched by the
regex. Both streams feed the Streamer thread, so the trigger's line is the
one that matters — OK in practice — but the loader line could be mistaken
for a valid proof by a defender reading log output who did not know the
harness only blesses the trigger's shape.

Proposed fix: either align the loader's printf to `access_key_captured=yes`
format or update the regex to cover both spellings.

### M4. `ch05b` and `ch15` register `hooks=["veth"]` which `kallsyms_has` short-circuits to `True`

proof.py:200–201:
```
if name.startswith("veth"):
    return True  # runtime-created
```

Any hook string starting with `veth` returns True unconditionally — the harness
does not actually verify that a veth interface will exist when the PoC runs.
If `ch05b-ghost-nic/trigger.sh` fails to create its veth (e.g. `CONFIG_VETH=n`
or user-namespace limits in the container), `check_hooks` records `veth` as
present anyway and the PoC goes all the way to `fail` instead of `skip`. Both
triggers have their own `CH??_SKIP` fallback if setup fails, but the harness's
hook-presence signal is stubbed.

Proposed fix: have `kallsyms_has("veth")` probe `/proc/modules` or
`/sys/class/net` for actual veth readiness, or rename the hook to
`runtime:veth` to make the stubbing explicit.

### M5. ch09 `timeout=40` is tight for worst-case path inside the harness

Trigger's worst-case wait sums to ≈ 17 seconds (5s for `ns_side_pid`, 1s for
loader warm-up, 8s polling for the host/ns translation event, ≈ 3s kill wait).
proof.py gives 40s. The finally block adds up to 3s per subprocess on SIGINT
retirement. Under Docker Desktop load the 15-second background `sleep` in the
unshare wrapper can contribute to slowness. Not currently broken; margin
shrinks to ~15 seconds if multiple unshare calls queue up.

Proposed fix: leave at 40s but watch for flake under load; consider 60s if
CI latency permits.

---

## LOW

### L1. Every Makefile's APP variable matches its dir name — clean

Verified via grep: 28 Makefiles, 28 APP assignments, all matching their parent
directory basename. No drift here.

### L2. README.md top-level PoC count (23) and category counts (16/4/3) are correct

Direct count of `Poc(` entries in proof.py: 23. Categorized:
- `real` (default): 16 (ch01, ch02, ch04, ch05, ch05b, ch07, ch08, ch09, ch10, ch11, ch12, ch15, ch08k, ch23, ch24, ch25)
- `observer`: 4 (ch03, ch06, ch06o, ch16)
- `illusion`: 3 (ch14, ch18, ch12s)
- `analog`: 0

All match README.md:84–88. Clean.

### L3. `_book_chapters/README.md` is the canonical and correct mapping

Its table correctly points chapters 19–22 at `act-7/` and omits chapters 13 and
17. The drift is entirely in the Jekyll front-end (`index.md`, `book/index.md`,
`README.md`), not in the manuscript source-of-truth document.

### L4. Prior `.audit/` reports are largely current

- `.audit/harness-audit.md` covers in-process bugs; does not overlap with seam
  bugs here.
- `.audit/chapter-xref-audit.md` (13,481 bytes) reviewed; still relevant.
- `.audit/c-style-audit.md` orthogonal.
- `.audit/commit-message-audit.md` orthogonal.

---

## Cross-component summary

| Plane                                      | State                                                                                                      |
|--------------------------------------------|------------------------------------------------------------------------------------------------------------|
| proof.py Poc entries ↔ on-disk directories | 23 registered, 23 directories exist (of 28). 5 directories orphaned — see H2.                             |
| Trigger markers ↔ proof_marker regexes     | All 23 match. Four have dead-code alternatives (H4, M3). No PoC has a *missing* marker path.              |
| Makefile APP ↔ directory name              | 28/28 match. Clean.                                                                                        |
| QEMU scripts ↔ proof.py                    | Three scripts (`run-qemu-tests.sh`, `qemu-runner.sh`, `act4-runner.sh`) partially overlap. See M2.        |
| Chapter body ↔ PoC directory               | One broken reference: `ch07-devcgroup-houdini-lsm` (CR1), mirrored in README and post front-matter (H1). |
| index.md / book/index.md ↔ disk files      | Two retired chapters still linked (CR2); four synthesis chapters linked under wrong act path (CR3).       |
| README.md layout claim ↔ disk structure    | Layout panel out of date (CR4).                                                                            |

## Severity-ranked finding list

| ID  | Severity | File:line                                                              | Summary                                                         |
|-----|----------|------------------------------------------------------------------------|-----------------------------------------------------------------|
| CR1 | CRITICAL | `_book_chapters/act-2/chapter-7-device-cgroup-houdini.md:9,210`        | References deleted `ch07-devcgroup-houdini-lsm/` directory.     |
| CR2 | CRITICAL | `index.md:34,41` · `book/index.md:47,58,78,79`                          | Chapters 13 and 17 retired but still linked.                    |
| CR3 | CRITICAL | `index.md:43,47,48,49` · `book/index.md:60–63,81`                      | Chapters 19–22 linked under `act-3/`; they live in `act-7/`.    |
| CR4 | CRITICAL | `README.md:14–17`                                                      | Repo layout panel misreports act→chapter mapping.               |
| H1  | HIGH     | `_posts/2025-02-07-device-cgroup-houdini.md:5,10,66`                   | Post front-matter and body reference deleted PoC dir.           |
| H2  | HIGH     | `dBPF-pocs/pocs/ch01-lsm` (× 5)                                        | Five disk PoC directories not registered in proof.py.           |
| H3  | HIGH     | `proof.py:175` ↔ `ch24/trigger.sh:225`                                 | Regex brittle to empty `uid_events=` value.                     |
| H4  | HIGH     | `proof.py:103,82,80`                                                    | Dead proof_marker alternatives (SIGUSR2_SENT, LEASH_SUCCESS, etc.). |
| M1  | MEDIUM   | `proof.py:109`                                                         | `tp:` hook name vs. `raw_tp/` SEC attribute — semantic mismatch.|
| M2  | MEDIUM   | `qemu-runner.sh`, `run-qemu-tests.sh`, `act4-runner.sh`                | Overlapping PoC lists, no shared source of truth.               |
| M3  | MEDIUM   | `ch25-imds-harvest.c:221`                                              | Loader marker spelled `access_key_captures=N`, regex wants `access_key_captured=yes`. |
| M4  | MEDIUM   | `proof.py:200–201`                                                     | `veth*` hook check short-circuited to True.                     |
| M5  | MEDIUM   | `proof.py:110`                                                         | ch09 timeout=40s has <15s slack under load.                     |
| L1  | LOW      | all Makefiles                                                          | APP ↔ dir clean.                                                |
| L2  | LOW      | `README.md:3,84–88`                                                    | PoC count and categories correct.                               |
| L3  | LOW      | `_book_chapters/README.md`                                             | Canonical map is correct.                                       |
| L4  | LOW      | `.audit/*.md`                                                          | Prior reports not stale.                                        |

## Overall verdict

**minor-drift.** The harness-to-PoC integration (proof.py ↔ trigger ↔ kernel) is
consistent: every registered `Poc()` has a real directory, a real Makefile, a
real trigger, and a marker that satisfies the regex. The drift is confined to
published documentation that still carries pre-0.3.0 state: four
top-of-repo files (`README.md`, `index.md`, `book/index.md`,
`_posts/2025-02-07-device-cgroup-houdini.md`) and one chapter body
(`chapter-7-device-cgroup-houdini.md`). Fixing CR1–CR4 and H1 brings the
surface back to clean without any code changes; H2 is a design choice about
whether to mirror the QEMU-only PoCs into proof.py as skip-registered entries.
