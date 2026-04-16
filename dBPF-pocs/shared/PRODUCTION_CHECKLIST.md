# Production-readiness checklist — apply to every POC

Your POC may compile and attach — that's the floor. Production-ready means:

## BPF side (<name>.bpf.c)
1. **Every kprobe target verified** via `/proc/kallsyms` at load time. Use
   `bpf_program__set_autoload(prog, false)` in the loader if the symbol is
   missing. The BPF program itself should not rely on a symbol existing.
2. **No struct redefinitions** — rely on vmlinux.h only. If vmlinux.h lacks
   a type you need, define it under a different name (e.g., `my_vlan_hdr`).
3. **CO-RE everywhere**: `BPF_CORE_READ`, `bpf_core_field_exists`. No raw
   offset arithmetic.
4. **Bounds checks** for every user/kernel read. Verifier errors mean rework.
5. **Stack limit**: keep on-stack data ≤512B. Push large buffers to
   `BPF_MAP_TYPE_PERCPU_ARRAY` scratch slots.
6. **Ringbuf discipline**: always pair `reserve` with `submit`/`discard`.
   Never `submit` a NULL reservation.
7. **License + btf**: `char LICENSE[] SEC("license") = "GPL";` — non-negotiable
   for kprobes.
8. **No unused programs**: every SEC() must have either auto-attach or an
   explicit manual-attach path in the loader.

## Userspace loader (<name>.c)
1. **SIGINT/SIGTERM handler** sets `stop=1`; main loop checks it; cleanup
   runs (ring_buffer__free, skel__destroy) *in all exit paths*.
2. **Every libbpf call's return value checked.** Print a useful error
   message (libbpf_error, strerror(-err)) and exit non-zero on failure.
3. **Argument parsing**: use getopt-style short flags. Unknown flag prints
   usage and exits 2.
4. **Symbol preflight**: before load, grep `/proc/kallsyms` for each kprobe
   target. Call `bpf_program__set_autoload(..., false)` on missing ones;
   log which programs will/won't attach.
5. **Per-program attach with individual error reporting**. One failed
   attach should not kill the loader if others can proceed.
6. **Consistent log format**: `[<chXX>] tag=... field=...`. Prefer tab
   alignment or fixed column widths.
7. **Clean stderr vs stdout separation**: events to stdout, status to
   stderr, so `./prog > out.jsonl` keeps the event stream clean.
8. **No implicit-function-declaration warnings** — include `<bpf/bpf.h>`,
   `<bpf/libbpf.h>`, and any libc headers needed.
9. **Build with -Wall -Wextra -Werror** in the Makefile; no warnings.

## Makefile
1. `APP := chXX-name; include ../../shared/common.mk`. No per-POC deviations.
2. `clean` target works; `all` is default.
3. Rebuilds on `.bpf.c` or `.c` change. common.mk handles this.

## trigger.sh
1. First line `#!/bin/bash`, second `set +e` (we want to continue through
   probes that may legitimately fail).
2. Explicit echo of what's being triggered (`echo "=== <step> ==="`) so the
   output is readable as a demo.
3. Cleans up after itself (rmdir, ip link del, umount) — use `trap` for
   the unmount/delete lines.
4. Must work from any CWD — reference files via `$(dirname "$0")`.
5. `chmod +x trigger.sh` (mode 755 in git).

## README.md
1. Sections (in order): **Mechanism**, **Hook points**, **Build**, **Run**,
   **Evidence**, **Detection**, **Limitations / arch notes**.
2. **Evidence** section must show actual runtime output captured when the
   POC was last tested. No invented output.
3. **Limitations** explicitly states what does NOT work on Docker Desktop
   linuxkit aarch64 and why (error_injection allowlist, arch-specific
   symbols, LSM gating, etc.).
4. Build/Run commands are copy-pasteable.

## Makefile-level sanity: zero warnings policy
Compile each POC with:
```
cd /Users/mbhatt/spaceclaw/evilBPF/dBPF-pocs
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/<chXX> && make CFLAGS="-O2 -g -Wall -Wextra -Werror"'
```
All warnings must be fixed. If a libbpf header generates a warning you
can't fix, add a narrow `-Wno-<category>` to CFLAGS in common.mk — do NOT
suppress globally.

## What "done" looks like
- `make` succeeds with `-Wall -Wextra -Werror`.
- `./build/<name> --help` (or `-h`) prints usage.
- Running the binary cleanly attaches, tolerates missing symbols,
  streams events on stdout, logs status on stderr.
- SIGINT causes clean exit (no leaked bpf maps; verify with
  `bpftool map show` before/after).
- `trigger.sh` demonstrates the hook firing and the evidence block in
  the README matches current output.
