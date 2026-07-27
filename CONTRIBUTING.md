# Contributing to dBPF

Thank you for considering a contribution. This repository is a defensive-security
field manual plus a reproducible harness. Every prose claim must be backed by a
PoC that runs under the harness and produces a machine-parseable marker.

## Developer Certificate of Origin

Every commit must be signed off using the Developer Certificate of Origin
(DCO) version 1.1. Add a `Signed-off-by` trailer to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` appends this automatically. By signing off, you certify the
terms at <https://developercertificate.org/>.

Commits authored with AI assistance should additionally carry a
`Co-Authored-By:` trailer identifying the assistant model. The existing
repository uses `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`
as the convention.

## Commit messages

Follow Linux kernel commit-message style:

1. Subject line **≤ 72 characters**, imperative mood (`Add X`, not `Added X`
   or `Adds X`).
2. Subject line **does not end with a period**.
3. Blank line between subject and body.
4. Body wrapped at 72 characters. Explain **why**, not what (the diff shows
   what).
5. Reference prior commits as `Fixes: <12-char-sha> ("<subject>")` when
   relevant.
6. Close with trailers: `Signed-off-by:` (required), `Co-Authored-By:`,
   `Reviewed-by:`, etc.

Placeholder subjects like `WIP`, `fix stuff`, `update` are not acceptable.

## Adding a new PoC

A new PoC (chapter NN) must include every item below. Anything missing
blocks merge.

```
dBPF-pocs/pocs/chNN-short-name/
├── chNN-short-name.bpf.c       # kernel-side BPF program; SEC("license") = "GPL";
├── chNN-short-name.c           # userspace loader
├── trigger.sh                  # chmod +x; emits CHNN_PROVEN or CHNN_SKIP
├── Makefile                    # typically 2 lines; see below
└── README.md                   # follow the template below
```

**Makefile** — use the shared rules unless you have a specific reason not
to:

```
APP := chNN-short-name
include ../../shared/common.mk
```

**Trigger contract** — `trigger.sh` must emit exactly one of the following
on stdout before exiting:

```
=== CHNN_PROVEN <field>=<value> [<field>=<value> ...] ===
=== CHNN_SKIP reason="<human-readable reason>" ===
```

The harness's `proof_marker` regex in `dBPF-pocs/harness/proof.py` must
accept both forms. A PoC that cannot fire on a given kernel must emit
`CHNN_SKIP` with a specific reason; silent failure is not acceptable.

The marker token must be a **specific** `CHxx_..._PROVEN` token — the
chapter id, optionally with a variant suffix (for example `CH25_PROVEN`, or
`CH06_SYNTH_PROVEN` for the ch06 synthetic-scaffold variant). Never match on
a bare `_PROVEN` substring: the regex has to be anchored on the chapter's own
token so one PoC's marker can never be counted for another.

**Harness registration** — every PoC needs a `Poc(...)` entry in
`dBPF-pocs/harness/proof.py`:

```python
Poc("chNN", "Human-readable title",
    "chNN-short-name",
    hooks=["kernel_symbol_or_tp:..."], prefix="[chNN]",
    mode="trigger-runs-loader", timeout=25,
    proof_marker=r"CHNN_PROVEN\s+.*|CHNN_SKIP\s+reason="),
```

`hooks` lists kernel symbols (for `/proc/kallsyms` preflight), tracepoint
names (`tp:cat/name`), LSM availability (`bpf-lsm`), or `veth` for XDP.
The harness skips the PoC cleanly if none of the hooks are present.

**README.md** — follow the existing pattern (see any PoC under
`dBPF-pocs/pocs/`). Standard sections:

- Title + Category + Primitive + Hook(s) + Architecture
- What this demonstrates
- What this does NOT do
- Prerequisites
- Files
- Build & Run
- Detection
- Mitigation

## Chapter prose

Each PoC ships alongside a chapter markdown under `_book_chapters/act-N/`.
The chapter's claims must match the PoC's behavior. Before submitting a
prose change, run the smoke test (if present) and/or the harness for that
PoC to confirm the claims still reflect observed behavior.

## Code style

- **C (userspace)** — 4-space indent (tabs forbidden), snake_case for
  functions, `#include` system headers before project headers, check every
  syscall return, no commented-out dead code.
- **BPF C (`.bpf.c`)** — same style; every file starts with
  `char LICENSE[] SEC("license") = "GPL";` after the includes; use
  `BPF_CORE_READ` macros for struct walks to stay CO-RE-clean.
- **Shell** — `#!/bin/bash`; `set +e` is acceptable because trigger scripts
  need to continue past individual step failures to emit their marker; use
  long-form conditionals (`if`), not `&&`/`||` chains, for multi-step flow.
- **Python** — PEP 8; type hints where the signature benefits.

No `TODO` / `FIXME` / `XXX` / `HACK` markers in production code. If a gap
exists, document it in the chapter, not in a source comment.

## Testing requirements

Before opening a PR:

1. **Smoke test** — if the PoC has a `smoke-test.sh`, it must exit 0.
2. **Harness run on linuxkit** — `bash dBPF-pocs/harness/run.sh chNN` must
   produce either `effect_demonstrated` or a defensible `skip` verdict.
3. **QEMU run (if applicable)** — if the PoC targets the secondary
   environment, `bash dBPF-pocs/run-qemu-tests.sh` must include it and
   produce a verdict.
4. **No new compiler warnings** — `make` in the PoC directory should build
   with `clang -Wall -Wextra` clean (build system defaults.)
5. **Chapter ↔ code consistency** — prose must describe the primitive the
   code actually implements. Drift is the reason the earlier drift-fix
   passes exist in the git history; don't add more.
6. **CHANGELOG.md updated** under `[Unreleased]`.

## PR checklist

Include this in your PR description:

```
- [ ] Signed-off-by trailer on every commit
- [ ] Commit subjects ≤ 72 chars, imperative mood, no trailing period
- [ ] Smoke test passes (if applicable)
- [ ] Harness emits defensible verdict on linuxkit
- [ ] QEMU run passes (if applicable)
- [ ] Chapter matches PoC code (no drift)
- [ ] CHANGELOG.md entry under [Unreleased]
- [ ] No new TODO/FIXME/XXX markers in source
- [ ] No binary artifacts in the diff (build/, *.o, *.qcow2, etc.)
```

## Review process

Reviewers will check:

- The code does what the chapter says, and only that.
- The trigger produces the marker under the right conditions and `CHNN_SKIP`
  under adverse conditions with a specific reason.
- The kernel-source references (file paths, symbol names, struct fields)
  are real. Fabricated symbols are a mandatory-rework finding.
- Commit history tells a coherent story.

Reviewers will not rewrite your branch. Expect iterative feedback.

## Questions

Open an issue or draft PR before starting a large change. The repo is small
and opinionated; surprise PRs that restructure multiple chapters are
unlikely to be accepted in their first form.
