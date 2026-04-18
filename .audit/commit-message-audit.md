# Commit Message Audit — dBPF

Audited against kernel-community ("Linus review") standards:
<= 72-char imperative subject, no trailing period, blank line before body,
body wrapped at 72 cols explaining *why*, and a trailer (`Signed-off-by:`
or `Co-Authored-By:`).

Scope: `git log --no-merges` on `master`, 34 commits total.

---

## 1. Summary

| Metric | Value |
|---|---|
| Total non-merge commits | 34 |
| Subjects <= 72 chars | 32 / 34 |
| Subjects > 72 chars | 2 (see list) |
| Subjects in imperative mood | 34 / 34 (all start with a verb) |
| Subjects ending with a period | 0 |
| Commits with empty body | 20 / 34 |
| Commits with `Signed-off-by:` | 0 |
| Commits with `Co-Authored-By:` | 4 |
| Commits with neither trailer | 30 / 34 |
| Trailing whitespace in message | None observed |

Subjects over 72 chars:

- `4c3b939` — `Add Act 4: TPM unseal, bpf_token delegation, IMDS harvest (3 chapters + PoCs)` (77)
- `19aa859` — `Sync posts to code; register book_chapters as a Jekyll collection; add crosslinks` (80)

Both are close to the limit and are compound subjects that would be
better rewritten than truncated.

No subject ends with a period. Imperative mood is consistent ("Add",
"Fix", "Ground", "Production-harden", "Switch", "Trigger", "Extend",
"Remove", "Complete", "Sync"). The sole outlier form is `WIP: upgrade
PoCs ...` — imperative, but the `WIP:` prefix is a smell of its own.

---

## 2. Problematic Commits

### A. Placeholder / meaningless subjects

These violate the single most important rule: a subject must summarize
the change. They also all have empty bodies, which makes them
effectively undocumented.

| SHA | Subject | Reason |
|---|---|---|
| `1dc9dc8` | `Fix qemu ones` | Placeholder; 9 consecutive commits share this exact subject |
| `ee00f0c` | `Fix qemu ones` | Placeholder; duplicate |
| `e7039e1` | `Fix qemu ones` | Placeholder; duplicate |
| `119169a` | `Fix qemu ones` | Placeholder; duplicate |
| `28cb1e3` | `Fix qemu ones` | Placeholder; duplicate |
| `296c6c7` | `Fix qemu ones` | Placeholder; duplicate |
| `740e3aa` | `Fix qemu ones` | Placeholder; duplicate |
| `7ce1c24` | `Fix qemu ones` | Placeholder; duplicate |
| `420a3b9` | `Fix qemu ones` | Placeholder; duplicate |
| `a4e3576` | `WIP: upgrade PoCs to have real effects + fix triggers` | `WIP:` prefix — transient state, empty body, reads like a stash |
| `10b03db` | `Add poc` | Placeholder; which PoC? empty body |
| `2d7d657` | `Add poc` | Placeholder; duplicate |
| `c6469d0` | `Add poc` | Placeholder; duplicate |
| `6374f2e` | `Add poc` | Placeholder; duplicate |
| `f9550be` | `Add poc` | Placeholder; duplicate |
| `7010f7f` | `Add poc` | Placeholder; duplicate |
| `c92948c` | `Add poc` | Placeholder; duplicate |
| `137c913` | `Add poc` | Placeholder; duplicate |
| `6fd89a1` | `Add poc` | Placeholder; duplicate |
| `e160fd9` | `Add poc` | Placeholder; duplicate |
| `1860a67` | `Add poc` | Placeholder; duplicate |

That is **21 of 34 commits (62%)** that a kernel maintainer would
reject at the subject line without reading the diff. None of them
says which chapter, which PoC, which bug, or why.

### B. Subjects over 72 characters

| SHA | Len | Subject |
|---|---|---|
| `4c3b939` | 77 | `Add Act 4: TPM unseal, bpf_token delegation, IMDS harvest (3 chapters + PoCs)` |
| `19aa859` | 80 | `Sync posts to code; register book_chapters as a Jekyll collection; add crosslinks` |

### C. Transient-state / throwaway language

| SHA | Subject | Problem |
|---|---|---|
| `a4e3576` | `WIP: upgrade PoCs ...` | `WIP:` means "don't merge me"; commit is on `master` anyway |
| `6654167` | `Trigger Pages deploy (environment now exists)` | "now exists" dates the message to the moment it was written; reads like an ops action, not a change |

### D. Empty body where context is needed

All 21 placeholder commits above also have empty bodies. The body
should answer "why was this needed, and what was wrong before?" —
especially for a bug-fix series that re-ran 7 QEMU iterations.

Commits with empty body that are otherwise reasonable (borderline
— could keep, but a one-line body would help):

- `6654167` Trigger Pages deploy (environment now exists) — empty
- `5a9573d` Switch Pages workflow to actions/deploy-pages@v4 — body OK (3 lines, explains why)

### E. Missing trailers

Zero commits have `Signed-off-by:`. The project does not appear to use
DCO, so this may be intentional, but for a "kernel-level review"
posture the absence is notable. Only 4 of the 34 commits carry the
`Co-Authored-By: Claude ...` trailer that appears to be this
repository's convention for AI-assisted commits
(`4c3b939`, `ffda4fe`, `412ed64`, `69bc4d4`).

If the AI-assistance convention is meant to be applied to every
AI-authored commit, the 30 that lack it are inconsistent with that
policy. If the convention is "only when the AI wrote substantial
prose", that should be documented somewhere; right now it is
applied unevenly.

### F. Well-formed commits (keep as-is)

Good examples, should be preserved through any rewrite:

- `4c3b939` (subject is 5 chars too long, but body is exemplary:
  structured, cites kernel sources, enumerates iterations, lists
  outcomes per chapter, states test results) — fix the subject only
- `ffda4fe` Fix 16 remaining factual errors + 14 harness bugs
- `412ed64` Ground all chapter claims in Linux 6.12 kernel source
- `69bc4d4` Production-harden all POCs, harness, and align chapters to code
- `39a843c` Final expansion: ch4, ch5, ch20 at 30-page target via Sonnet agents
- `d230c37` Extend ch4, ch5, ch20 manually (policy filter blocked agent pass)
- `f77c7a9` 30-page expansion wave: every chapter POC-grounded
- `50ed6b8` Remove blog/posts from navigation; book-only sidebar and indexes
- `43af998` Complete blog/book integration: post per chapter + consistency cleanup
- `e3d0336` Fix crosslink URLs to match /:title.html permalink scheme
- `19aa859` Sync posts ... (subject too long, body is clean)
- `437adfb` dBPF — a modern-kernel eBPF primitive book with reproducible harness

These 12 are production-quality. The bodies describe *why*, wrap
around 72 cols, and are scannable.

---

## 3. Recommended Squash Plan

The bad news: 21 of 34 commits are placeholders. The good news: they
fall into two obvious groups and can be squashed into two (or three)
atomic commits. **Do not rewrite history yourself.** This is the
proposal to present for human approval.

### Group 1 — "Add poc" chain (11 commits)

SHAs, oldest-first:
`1860a67`, `e160fd9`, `6fd89a1`, `137c913`, `c92948c`, `7010f7f`,
`f9550be`, `6374f2e`, `c6469d0`, `2d7d657`, `10b03db`

These sit between `437adfb` (initial book drop) and `43af998` /
`39a843c` (major integration/expansion work). They look like
per-PoC additions with no prose.

Proposed atomic squash:

    Add PoC sources for chapters 1-18

    Each chapter gets a reproducible PoC under poc/chNN/ with:
      - BEFORE/AFTER trigger script
      - loader (C) + BPF object (if applicable)
      - machine-grep-able proof marker consumed by proof.py

    PoC layout and marker convention are described in ch0 and
    enforced by the harness (proof.py registrations).

Alternative if PoCs were added in thematic waves: split into Act 1 /
Act 2 / Act 3 PoC batches. The current 11-commit split has no
visible thematic structure from the messages alone, so one atomic
commit per wave (or one total) is fine.

### Group 2 — "Fix qemu ones" chain (9 commits)

SHAs, oldest-first:
`420a3b9`, `7ce1c24`, `740e3aa`, `296c6c7`, `28cb1e3`, `119169a`,
`e7039e1`, `ee00f0c`, `1dc9dc8`

These all sit directly on top of `4c3b939` (Add Act 4). The Act 4
commit body explicitly mentions 7 QEMU iterations with CH23_SKIP /
CH24_SKIP fragility classes, so these 9 are almost certainly the
iteration fixups.

Proposed atomic squash:

    Fix QEMU harness for Act 4 chapters (ch23, ch24, ch25)

    Iterative fixes from 7 VM boots on Fedora 42 aarch64 6.14:
      - ch23 (TPM unseal): loader preflights when no TPM present,
        emits CH23_SKIP cleanly instead of hanging on tpm2_unseal
      - ch24 (bpf_token delegation): correct bpffs delegate_*
        grammar, caller CAP_SYS_ADMIN check, BPF_TOKEN_CREATE
        EOPNOTSUPP handled as CH24_SKIP under cloud-init
      - ch25 (IMDS harvest): XDP attach path, mock IMDSv2 Python
        server lifecycle, proof marker extraction
      - run-qemu-tests.sh / qemu-runner.sh / act4-runner.sh:
        cidata.iso cloud-init runcmd, swtpm attempt, tu24
        unprivileged-user setup

    Result: ch25 CH25_PROVEN; ch23 and ch24 skip cleanly with
    accurate markers; no regressions on Acts 1-3.

If the 9 commits each touched disjoint files, a two-way split is
also fine (harness vs PoCs). A 9-way split is not.

### Group 3 — WIP commit (1 commit)

`a4e3576 WIP: upgrade PoCs to have real effects + fix triggers`

Fold into whichever chapter-expansion or PoC commit it logically
precedes (likely `69bc4d4 Production-harden all POCs`), or keep
standalone with a proper subject:

    Upgrade PoCs to demonstrate real effect and fix trigger scripts

    ... (body describing which PoCs gained real effect, which
    triggers were broken, and what the new pass/skip matrix is)

### Net result

34 commits → roughly 15 atomic commits. Every remaining subject
would be self-explanatory; every commit would bisect cleanly.

---

## 4. Other Notes

- **Em dash in subject.** `437adfb` uses `—` (U+2014). Harmless, but
  some tooling (`git log --oneline` on minimal terminals, mail-based
  review) prefers ASCII. Consider `:` or `-`.
- **Semicolon-chained subjects.** `50ed6b8`, `19aa859`, `43af998` use
  `;` to pack two ideas into one subject. Kernel style prefers one
  verb per commit. If the change is truly indivisible, keep it; if
  not, split.
- **Consistency of AI trailer.** Pick one policy — always or never —
  and apply it uniformly. The current 4/34 ratio is the worst of
  both worlds.

---

## 5. Overall Grade

**needs-rework**

Rationale:

- 21 of 34 commits (62%) have placeholder subjects with empty
  bodies. A Linus-style review would stop at commit #2 (`Fix qemu
  ones`) and bounce the whole series.
- However, the 12 well-formed commits are genuinely excellent —
  structured bodies, kernel-source citations, explicit per-chapter
  outcomes. The author clearly knows the standard; two distinct
  habits are being mixed.
- Two subjects exceed 72 chars but are trivially fixable.
- No periods, no trailing whitespace, imperative mood throughout —
  the mechanical hygiene is fine. The failure mode is discipline,
  not skill.

After the two squash groups above land (21 commits → 2-3 atomic
commits with proper bodies), the tree would move to
**production-ready** without any further work. The underlying work
is high-quality; the history presentation hides it.
