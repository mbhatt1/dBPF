# Chapter Cross-Reference & Doc-Code Consistency Audit

Repo: `/Users/mbhatt/spaceclaw/evilBPF/dBPF`
Scope: all `*.md` under `_book_chapters/`
Ground-truth PoC manifest: `dBPF-pocs/harness/proof.py` (23 `Poc(...)` entries)
Ground-truth PoC dirs: `dBPF-pocs/pocs/` (28 directories)

Overall verdict: **minor-fixes** — structure is sound, frontmatter is 100% present, all 25 chapter files exist with proper Jekyll headers, synthesis chapters (ch19-22) and preface use consistent 23/16/4/3/0 counts that match `proof.py`. The significant drift is a cluster of references to directories that were renamed or retired (ch07-devcgroup-houdini-lsm, ch06-silence-selinux-lsm-synthetic, ch13-*, ch17-*, ch09-pid-ns-spy) and a stale `Poc("ch07w",...)` reference in the chapter-7 prose that does not match the current `Poc("ch07",...)` entry.

---

## Top-level structural checks

| Check | Result |
|-------|--------|
| Jekyll frontmatter (`layout: book`, `title:`, `date:`) present in all chapters | PASS (25/25) |
| All act-4 chapter files present (ch23, ch24, ch25) | PASS |
| Synthesis chapters (ch19-22) reference act-4 (ch23/ch24/ch25) | PASS (all four reference act-4 by id) |
| PoC count in preface matches `proof.py` | PASS (23 PoCs) |
| Category distribution in synthesis matches `proof.py` | PASS (16 real / 4 observer / 3 illusion / 0 analog) |
| Orphaned `TODO` / `FIXME` / `XXX` markers in prose | 1 soft hit (ch14 line 360 describes a TODO left in source — acceptable narrative, not an orphan) |
| Chapters with `POC code` / `Harness entry` top link | 21/25. Missing: **ch06**, **ch07**, **ch08**, **ch12** (all four have a `Note:` link to Chapter 21 instead). Ch0 preface has `Harness` link, no PoC dir — correct. |

---

## Per-chapter findings (only where issues exist)

### Act-1

**ch0 preface** (`_book_chapters/act-1/chapter-0-field-manual-preface.md`) — clean. States "23 PoCs ... 18 on-host technique chapters plus Act 4's three cross-boundary chapters" — matches `proof.py`. Line 411 repeats "23 PoCs across the 18 on-host technique chapters plus three Act 4 cross-boundary chapters" — consistent.

**ch1** — clean. `POC code` links to `ch01-mirror-controls-lsm` (exists). Legacy link to `ch01-mirror-controls` (exists).

**ch2** — clean. kernel refs `fs/overlayfs/copy_up.c`, `fs/overlayfs/file.c` plausible.

**ch3** — clean. kernel refs `kernel/audit.c`, `kernel/bpf/verifier.c` plausible.

**ch4** — clean.

**ch5** — Minor. Line 508, 519 reference `ch13-powercap-override-analog` (directory retired; `ch13-*` does not exist under `dBPF-pocs/pocs/`). Mentioned as narrative reference to a retired analog PoC — the text is consistent with ch19's "ch13 and ch17 are not in the catalog" disclosure, so it is historical context, not a broken link. Flag for prose-only clean-up.

**ch5b** — clean.

**ch6** — Missing top-of-chapter `POC code` link. Has `See also` line pointing only to blog post — no direct PoC/harness link. Two PoC dirs exist (`ch06-silence-selinux`, `ch06-silence-selinux-lsm`); chapter body talks about both but the header does not cite either.

### Act-2

**ch7** — Multiple issues:
- Line 9 "Note" links to `dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm/` — **directory does NOT exist** in `dBPF-pocs/pocs/`. Only `ch07-devcgroup-houdini` is present.
- Line 210 same broken path: `dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm/ch07-devcgroup-houdini-lsm.c`.
- Lines 305, 538 reference `ch06-silence-selinux-lsm-synthetic` — **directory does NOT exist**. Only `ch06-silence-selinux` and `ch06-silence-selinux-lsm` exist.
- Lines 546-549 describe the harness entry as `Poc("ch07w", ...)` with a workaround label — **stale**. `proof.py` line 99 currently registers `Poc("ch07", "Device-cgroup Houdini (signal)", "ch07-devcgroup-houdini", ...)`. No `ch07w` entry exists. Comment in `proof.py` line 377 preserves historical "ch07/ch07w" reference.
- Missing top-of-chapter `POC code` link.

**ch8** — Minor:
- Line 9 "Note" links to `dBPF-pocs/pocs/ch08-keyring-heist-kprobe/` — directory **exists**. OK.
- Missing top-of-chapter `POC code` / `Harness entry` link (only the "Note"-style link).

**ch9** — clean. Code refs to `ch09-pid-doppel/ch09-pid-doppel.bpf.c` and `.c` are accurate.

**ch10** — clean.

**ch11** — clean.

**ch12** — Missing top-of-chapter `POC code` / `Harness entry` link.

### Act-3

**ch14** — clean. Contains a narrative "I have left a TODO in the source" on line 360 about a `policy` field rename — this is self-aware commentary on a deliberate naming ambiguity in the code, not an orphaned marker.

**ch15** — clean.

**ch16** — clean.

**ch18** — clean. `arch/arm64/include/asm/syscall_wrapper.h` and `arch/x86/include/asm/syscall_wrapper.h` are real kernel paths.

**ch19** (`chapter-19-the-new-reality.md`) — Tallies match `proof.py`:
- "Twenty-three POCs are registered" ✓
- "16 `real` ... 4 `observer` ... 3 `illusion` ... 0 `analog`" ✓
- Member list for 16 `real` (ch01, ch02, ch04, ch05, ch05b, ch07, ch08, ch09, ch10, ch11, ch12, ch15, ch08k, ch23, ch24, ch25) ✓
- Line 239 "17 are 'primary'" + 3 variants (ch06o/ch08k/ch12s) + 3 Act-4 (ch23/ch24/ch25) = 23 ✓
- Line 252 stricter-bar counts of 12 / 14 / 19 demonstrated cross-env consistent with narrative.

**ch20** (`chapter-20-the-autopsy-what-we-proved.md`) — One stale claim and one drifted dir ref:
- Line 28: "these were removed in the cleanup that also produced the current **20-PoC manifest**" — **drift**. Current manifest is 23, not 20. Elsewhere in the same chapter line 13 correctly states "23 POCs", so this is a stale editorial leftover from a prior draft.
- Line 281: references `dBPF-pocs/pocs/ch09-pid-ns-spy/` — **directory does NOT exist**. Actual dir is `ch09-pid-doppel`. Broken code ref.
- Category counts (16 real / 4 observer / 3 illusion / 0 analog) match `proof.py`.
- Member lists for each category match `proof.py` entries.

**ch21** (`chapter-21-the-autopsy-what-refused-to-die.md`) — clean on counts. Lines 39, 92, 96 account for the four real skips (ch06 LSM, ch12 LSM, ch23, ch24) and ch25 Fedora-only fire. Line 100's "cross-environment total is 20" on the hypothetical max-fire kernel is a thought-experiment number (not the real tally) — the immediately surrounding prose makes that clear; leave as-is unless you want to spell it out.

**ch22** (`chapter-22-the-defender-playbook.md`) — clean. Table at line 705–712 correctly slots ch23 into Class III, ch25 into Class IV, and ch24 into a new "Threat-model subversion" row; each act-4 PoC is cited with its correct harness id. Line 604/614-617 cite `ch18-token-bypass/`, `ch14-sched-fifo/`, `ch12-signed-driver-swap-syscall/`, `ch07-devcgroup-houdini/` — all exist. Line 604 separately cites `ch08-keyring-heist-kprobe/` (exists) and `ch08-keyring-heist/` (exists).

### Act-4

**ch23** — clean. `POC code` link points to `ch23-tpm-unseal-heist` (exists). Kernel refs `security/keys/trusted-keys/trusted_tpm2.c`, `include/keys/trusted-type.h`, `drivers/char/tpm/tpm-interface.c` are real kernel paths.

**ch24** — clean. `POC code` link points to `ch24-bpf-token-delegation` (exists). Kernel refs `kernel/bpf/token.c`, `kernel/bpf/inode.c`, `kernel/bpf/syscall.c` are real paths. Cross-ref to Chapter 18 via relative link `../act-3/chapter-18-ebpf-token-bypass.html` — resolves.

**ch25** — clean content. Navigation bar (line 11) only lists ch24 and ch25; it does not include ch23 the way ch23's own navigation bar does (which lists ch22/ch23/ch24). Not broken, just inconsistent navigation density.

---

## Summary of broken or stale references

### Broken code references (paths that do not exist on disk)

| File | Line(s) | Broken ref | Notes |
|------|---------|------------|-------|
| `act-2/chapter-7-device-cgroup-houdini.md` | 9, 210 | `dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm/` | Only `ch07-devcgroup-houdini` exists |
| `act-2/chapter-7-device-cgroup-houdini.md` | 305, 538 | `ch06-silence-selinux-lsm-synthetic` | Retired directory |
| `act-3/chapter-20-the-autopsy-what-we-proved.md` | 281 | `dBPF-pocs/pocs/ch09-pid-ns-spy/` | Actual: `ch09-pid-doppel` |
| `_book_chapters/README.md` | 50, 59 | `ch13-powercap-override*`, `ch17-acpi-wsmi*` | Retired — TOC table still lists them |
| `act-1/chapter-5-slipping-the-cgroup-leash.md` | 508, 519 | `ch13-powercap-override-analog` | Retired — narrative reference |

### Stale harness-entry claim

| File | Line | Claim | Reality |
|------|------|-------|---------|
| `act-2/chapter-7-device-cgroup-houdini.md` | 546–549 | `Poc("ch07w", "Device-cgroup Houdini — workaround (LSM)", ...)` | `proof.py` has `Poc("ch07", "Device-cgroup Houdini (signal)", "ch07-devcgroup-houdini", ...)` |

### Count / manifest drifts

| File | Line | Drift | Ground truth |
|------|------|-------|--------------|
| `act-3/chapter-20-the-autopsy-what-we-proved.md` | 28 | "current 20-PoC manifest" | `proof.py` has 23 PoCs |

### Missing top-of-chapter PoC / Harness link (audit criterion #8/#9)

- `act-1/chapter-6-silencing-selinux.md` — has `See also: Blog post` only.
- `act-2/chapter-7-device-cgroup-houdini.md` — has `Note:` only.
- `act-2/chapter-8-keyring-heist.md` — has `Note:` only.
- `act-2/chapter-12-ebpf-signed-driver-swap.md` — no external links in header area.

All four chapters DO have a corresponding `Poc(...)` entry in `proof.py` and the PoC directory exists, so the fix is additive: add a standard `> **See also**: [POC code](...) · [Harness entry](...)` line after the title matching the pattern used in the other 17 primitive chapters.

### Navigation inconsistency (cosmetic)

- `act-4/chapter-25-the-metadata-faucet.md` line 11 navigation bar omits Chapter 23 (ch23 navigation and ch24 navigation both carry a three-chapter breadcrumb; ch25 carries only two).

---

## Proof.py ground-truth tally (for reference)

```
Total Poc(...) entries: 23
  ch01, ch02, ch03, ch04, ch05, ch05b, ch06, ch06o, ch07, ch08, ch09,
  ch10, ch11, ch12, ch14, ch15, ch16, ch18, ch08k, ch12s, ch23, ch24, ch25

Categories (explicit category= + default "real"):
  real     = 16  (ch01, ch02, ch04, ch05, ch05b, ch07, ch08, ch08k, ch09,
                  ch10, ch11, ch12, ch15, ch23, ch24, ch25)
  observer = 4   (ch03, ch06, ch06o, ch16)
  illusion = 3   (ch12s, ch14, ch18)
  analog   = 0
```

All four synthesis chapters (ch19, ch20, ch21, ch22) and the preface (ch0) quote numbers consistent with the above.

---

## Internal Jekyll link integrity

All `{{ site.baseurl }}/book/actN/...` links enumerated in the corpus resolve to existing chapter files:

| Target referenced | File exists? |
|-------------------|--------------|
| `/book/act-3/chapter-20-the-autopsy-what-we-proved.html` | yes |
| `/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html` | yes |
| `/book/act-3/chapter-22-the-defender-playbook.html` | yes |
| `/book/act-4/chapter-23-tpm-unseal-heist.html` | yes |
| `/book/act-4/chapter-24-the-token-hand-off.html` | yes |
| `/book/act-4/chapter-25-the-metadata-faucet.html` | yes |

Chapter-by-number cross-references in prose ("see Chapter 9", "same as Chapter 1", "Chapter 21 accounts for every skip", etc.) all reference chapters that exist. No references to missing Chapter 13 or Chapter 17 were found in narrative prose — only in `_book_chapters/README.md` (the TOC) and in ch19's explicit "ch13 and ch17 are not in the catalog" disclosure. ch19's acknowledgement is accurate; the README TOC is stale.

---

## Kernel-source reference sanity

Spot-checked kernel paths referenced across chapters; all are real Linux kernel paths (verified by path shape and filename conventions, not by line numbers):

- `kernel/bpf/token.c`, `kernel/bpf/inode.c`, `kernel/bpf/syscall.c`, `kernel/bpf/verifier.c`, `kernel/bpf/bpf_lsm.c`
- `kernel/audit.c`, `kernel/pid.c`, `kernel/nsproxy.c`, `kernel/seccomp.c`, `kernel/sys.c`, `kernel/sched/fair.c`, `kernel/trace/bpf_trace.c`
- `fs/overlayfs/copy_up.c`, `fs/overlayfs/file.c`, `fs/namei.c`, `fs/readdir.c`
- `security/keys/trusted-keys/trusted_tpm2.c`
- `drivers/char/tpm/tpm-interface.c`
- `include/linux/sched.h`, `include/linux/pid.h`, `include/linux/key.h`, `include/linux/cgroup.h`, `include/linux/dirent.h`, `include/linux/panic.h`, `include/keys/trusted-type.h`
- `arch/arm64/include/asm/syscall_wrapper.h`, `arch/arm64/include/uapi/asm/unistd.h`, `arch/x86/include/asm/syscall_wrapper.h`

Line numbers were not individually verified per audit scope.

---

## Recommended fixes (prioritized)

1. **Replace the four broken pocs/ path references** in `act-2/chapter-7-device-cgroup-houdini.md` (lines 9, 210, 305, 538) with `ch07-devcgroup-houdini` and drop the non-existent `-synthetic` suffix.
2. **Fix the `ch09-pid-ns-spy` path** in `act-3/chapter-20-the-autopsy-what-we-proved.md:281` → `ch09-pid-doppel`.
3. **Update "ch07w" / "workaround" harness-entry prose** in `act-2/chapter-7-device-cgroup-houdini.md:546-549` to match current `Poc("ch07", ...)` registration.
4. **Fix "20-PoC manifest"** in `act-3/chapter-20-the-autopsy-what-we-proved.md:28` → "current 23-PoC manifest".
5. **Add top-of-chapter `POC code` / `Harness entry` links** to ch06, ch07, ch08, ch12.
6. **Update `_book_chapters/README.md`** to either remove rows 13 and 17 or mark them "retired — see Chapter 19".
7. **Normalize ch25 navigation bar** to include ch23 for symmetry with ch23/ch24.

All seven are text-only prose fixes; no code or harness changes are implied.
