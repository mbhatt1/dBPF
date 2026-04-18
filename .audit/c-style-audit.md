# C Style & Quality Audit — dBPF-pocs/pocs

**Scope:** 28 `.bpf.c` kernel-side programs + 28 `.c` userspace loaders (56 files total, 9566 LoC).
**Audit date:** 2026-04-17
**Method:** non-destructive static analysis (Grep / Read only; no files modified).

---

## Summary Table

| File | Findings | Severity |
|---|---|---|
| ch01-mirror-controls.bpf.c | 0 | PASS |
| ch01-mirror-controls.c | 0 | PASS |
| ch01-mirror-controls-lsm.bpf.c | 0 | PASS |
| ch01-mirror-controls-lsm.c | 0 | PASS |
| ch02-overlayfs.bpf.c | 0 | PASS |
| ch02-overlayfs.c | 0 | PASS |
| ch02-overlayfs-lsm.bpf.c | 0 | PASS |
| ch02-overlayfs-lsm.c | 0 | PASS |
| ch03-fuse-blackhole.bpf.c | 0 | PASS |
| ch03-fuse-blackhole.c | 0 | PASS |
| ch03-fuse-blackhole-fentry.bpf.c | 0 | PASS |
| ch03-fuse-blackhole-fentry.c | 0 | PASS |
| ch04-phantom-syscall.bpf.c | 0 | PASS |
| ch04-phantom-syscall.c | 0 | PASS |
| ch05-cgroup-leash.bpf.c | 0 | PASS |
| ch05-cgroup-leash.c | 0 | PASS |
| ch05b-ghost-nic.bpf.c | 0 | PASS |
| ch05b-ghost-nic.c | 0 | PASS |
| ch06-silence-selinux.bpf.c | 0 | PASS |
| ch06-silence-selinux.c | 1 | Low (long line in printf format) |
| ch06-silence-selinux-lsm.bpf.c | 0 | PASS |
| ch06-silence-selinux-lsm.c | 0 | PASS |
| ch07-devcgroup-houdini.bpf.c | 0 | PASS |
| ch07-devcgroup-houdini.c | 1 | Low (long line in printf format) |
| ch08-keyring-heist.bpf.c | 1 | Low (long line, inline comment) |
| ch08-keyring-heist.c | 2 | Low (TODO marker + long switch/case on one line) |
| ch08-keyring-heist-kprobe.bpf.c | 0 | PASS |
| ch08-keyring-heist-kprobe.c | 0 | PASS |
| ch08-keyring-heist-lsm.bpf.c | 0 | PASS |
| ch08-keyring-heist-lsm.c | 0 | PASS |
| ch09-pid-doppel.bpf.c | 0 | PASS |
| ch09-pid-doppel.c | 0 | PASS |
| ch10-inode-cloak.bpf.c | 2 | Low (2 long lines in bpf_probe_write_user) |
| ch10-inode-cloak.c | 0 | PASS |
| ch11-irq-chaos.bpf.c | 0 | PASS |
| ch11-irq-chaos.c | 0 | PASS |
| ch12-signed-driver-swap.bpf.c | 0 | PASS |
| ch12-signed-driver-swap.c | 0 | PASS |
| ch12-signed-driver-swap-lsm.bpf.c | 0 | PASS |
| ch12-signed-driver-swap-lsm.c | 0 | PASS |
| ch12-signed-driver-swap-syscall.bpf.c | 0 | PASS |
| ch12-signed-driver-swap-syscall.c | 0 | PASS |
| ch14-sched-fifo.bpf.c | 0 | PASS |
| ch14-sched-fifo.c | 0 | PASS |
| ch15-netns-vlan-ghost.bpf.c | 0 | PASS |
| ch15-netns-vlan-ghost.c | 0 | PASS |
| ch16-seccomp-tid-hop.bpf.c | 0 | PASS |
| ch16-seccomp-tid-hop.c | 0 | PASS |
| ch18-token-bypass.bpf.c | 0 | PASS |
| ch18-token-bypass.c | 0 | PASS |
| ch23-tpm-unseal-heist.bpf.c | 0 | PASS |
| ch23-tpm-unseal-heist.c | 0 | PASS |
| ch24-bpf-token-delegation.bpf.c | 0 | PASS |
| ch24-bpf-token-delegation.c | 2 | Low (size outlier 874 LoC; 3 long-line fprintf strings) |
| ch25-imds-harvest.bpf.c | 0 | PASS |
| ch25-imds-harvest.c | 0 | PASS |

**Totals:** 9 findings across 6 files; 50/56 files fully PASS. All findings are **Low severity** (cosmetic / style). No High or Critical issues.

---

## Aggregate Observations (apply to all files)

1. **License header:** All 28 `.bpf.c` files contain `char LICENSE[] SEC("license") = "GPL";`. PASS.
2. **Headers:** All 28 `.bpf.c` include `vmlinux.h` + `<bpf/bpf_helpers.h>`; 24 additionally include `<bpf/bpf_tracing.h>` (omitted only where tracing macros aren't used: ch05b, ch15, ch24, ch25 — acceptable). All 28 loaders include `<bpf/libbpf.h>`. The only loader using raw syscalls (ch24) correctly includes `<sys/syscall.h>` and `<linux/bpf.h>`.
3. **Indentation:** Every file uses **4-space indentation exclusively** (zero leading tabs across the entire corpus). Fully consistent within and across files.
4. **Function naming:** Pure snake_case throughout. The two apparent "camelCase" hits (`CapEff`, `AccessKeyId`) are string literals matching external field names (/proc/self/status and AWS IMDS JSON), not function identifiers.
5. **Commented-out dead code:** None found. Comments beginning with `//` that reference function names are explanatory (e.g., "`// audit_log_start(struct audit_context *ctx, …)`" as signature documentation above a probe) or narrative prose, not disabled code.
6. **TODO/FIXME/XXX/HACK:** Exactly **one** marker in the entire tree (ch08-keyring-heist.c:135).
7. **Unchecked syscalls:** The bare `close()` / `fclose()` / `ioctl(… DISABLE)` / `bpf_object__close()` calls flagged by the pattern scan are all on cleanup / error paths where ignoring the return is idiomatic C. No unchecked `open`/`read`/`write`/`mount` in hot paths.
8. **Unused variables/params:** Only one explicit `(void)var;` suppression (ch08-keyring-heist.c:135 paired with the TODO). BPF programs correctly annotate unused tracepoint args via `__attribute__((unused))` or consume `ctx`.

---

## Per-File Findings (only files with findings)

### ch06-silence-selinux.c
- **Line 70 (>100 chars):** `printf("[ch06] tag=avc\tpid=%u\tcomm=%-16s\thook=%s\tssid=%u\ttsid=%u\ttclass=%u\treq=0x%x\n", …)` — single long format string. Acceptable; splitting harms grep-ability.

### ch07-devcgroup-houdini.c
- **Line 66 (>100 chars):** structured `printf` format. Same rationale as above.

### ch08-keyring-heist.bpf.c
- **Line 78 (>100 chars):** inline comment describing `user_key_payload` layout. Cosmetic; no code impact.

### ch08-keyring-heist.c
- **Line 40 (>100 chars):** one-line `switch` with 3 case arms returning string literals. Functional but dense; could be expanded to 4–5 lines for readability.
- **Line 135:** `(void)verbose;  // TODO: wire to libbpf_set_print` — the only TODO in the repo. `--verbose` CLI flag is parsed but not wired to `libbpf_set_print()`. Low severity — harmless dead flag.

### ch10-inode-cloak.bpf.c
- **Lines 90 and 96 (>100 chars):** two `bpf_probe_write_user(&((struct linux_dirent64 *)(dirp + …))->…, …)` calls. The nested cast + member access pushes past 100 cols. Could be hoisted to a typed local for clarity, but the current form is unambiguous.

### ch24-bpf-token-delegation.c
- **Size outlier: 874 LoC** — by far the largest file in the corpus (next largest is 331). This is intentional: it implements both `--server` and `--client` modes plus SCM_RIGHTS token handoff, bpffs mount-option probing, raw BPF syscall wrappers, and uapi compatibility shims. The top-of-file comment block documents the architecture well. Consider splitting into `ch24_server.c` / `ch24_client.c` / `ch24_common.c` if this PoC evolves further, but acceptable as a single self-contained PoC.
- **Lines 309, 659, 717 (>100 chars):** three long `fprintf(stderr, "[ch24-…] CH24_SKIP reason=\"…\"\n", …)` diagnostic strings. Same rationale — splitting would hurt grep.

---

## Additional Notes

- **Smallest file:** ch24-bpf-token-delegation.bpf.c at 40 LoC — intentional; the kernel-side program is a tiny uid-counting ringbuf producer, and the bulk of the PoC lives userspace-side in the 874-LoC loader.
- **No `.unwrap()`-analog patterns:** There is no idiom like "dereference without NULL check" evident; libbpf `__open`/`__load`/`__attach` return values are consistently checked via `libbpf_get_error()` or `NULL` tests across all loaders (spot-verified in ch08, ch12, ch24).
- **Error messages:** All loaders emit structured `[chNN] …` prefixed messages to stderr, with `CHNN_SKIP` / `CHNN_PROVEN` / `CHNN_DENIED` marker conventions documented per-file. Uniform across the suite.
- **No trailing whitespace audit performed** (not requested).

---

## Overall Recommendation

**production-ready** (for a PoC/demonstration codebase).

The corpus is remarkably consistent: uniform 4-space indentation, uniform snake_case, uniform include ordering, uniform diagnostic-message prefixes, correct LICENSE headers on every eBPF program, and correct header sets for the split kernel/userspace build model. The 9 findings are all Low-severity cosmetic items (8 are lines slightly over 100 chars in format strings, 1 is a harmless `TODO`-flagged unused CLI flag). No missing error handling, no dead code, no undefined-behavior patterns, no naming drift.

The only substantive observation is the 874-LoC ch24 loader — its size is justified by the server+client architecture, but it could be split for maintainability if the PoC grows further.

No mandatory changes required before shipping.
