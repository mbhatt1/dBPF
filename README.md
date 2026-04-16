# The Diabolical eBPF Field Manual

Source for [The Diabolical eBPF Field Manual](https://mbhatt1.github.io/dBPF/) — a
three-act book documenting what `CAP_BPF` (plus `CAP_PERFMON` or `CAP_SYS_ADMIN`)
actually permits on a modern aarch64 Linux kernel, paired with a reproducible
Docker harness that runs every primitive and prints observable before/after state.

The manuscript lives under `_book_chapters/` (canonical source, organized as
Act 1 / Act 2 / Act 3). Short blog-style teasers live under `_posts/`. The site
is built by GitHub Pages via `.github/workflows/jekyll.yml`.

## Companion repository

The proof-of-concept code and harness referenced throughout the book live in a
separate repo, [`dBPF-pocs`](https://github.com/mbhatt1/dBPF-pocs). Each chapter
points at the corresponding POC and harness entry (`dBPF-pocs/harness/proof.py`)
so claims can be reproduced end-to-end.

## Local development

```bash
bundle install
bundle exec jekyll serve --livereload
```

The site will be served at `http://localhost:4000/dBPF/`.
