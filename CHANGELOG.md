# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Dates are
ISO 8601.

## [Unreleased]

### Changed
- Repository prepared for external review: binary artifacts scrubbed from
  history via `git filter-repo` (repo size 2.0 GB → 4 MB), comprehensive
  `.gitignore` added, top-level `README.md`, `LICENSE`, `CONTRIBUTING.md`,
  and this `CHANGELOG.md` added.
- Audit reports added under `.audit/` for C code style, commit message
  quality, and chapter cross-reference integrity.

### Removed
- Scaffolding files (`LIBBPF_NOTES.md`, `REVIEW.md`) under Act 4 PoC
  directories — these were research notes, not shipped artifacts.
- All `build/` directory contents from git tracking; `.gitignore` now
  covers them so they stay local.

## [0.5.0] - 2026-05-20 — Full verification pass: Ubuntu 6.17 aarch64

### Verified
- All 25 POCs (ch01–ch18, ch23–ch25) run against Ubuntu 6.17.0-29-generic
  aarch64 in a Lima VM on Apple Silicon (macOS). Result: **24 proven, 1 skip
  (ch24), 0 failures**.
- ch24 (BPF Token Delegation) skipped on all tested kernels: `CONFIG_BPF_TOKEN=n`
  is absent on linuxkit 6.12, Fedora 42 6.14, and Ubuntu 6.17; requires
  kernel ≥ 6.9 with BPF token support explicitly enabled at build time.

### Fixed
- **ch01**: Added `bpf_send_signal(SIGUSR1)` — capability denial now
  delivers a real POSIX signal to the target process, not just a ringbuf
  event.
- **ch06**: Added `ch06-silence-selinux-lsm-synthetic` variant — attaches
  `lsm.s/file_open` directly without requiring `selinux_loaded()`, proving
  the deny-then-flip primitive on kernels without SELinux active.
- **ch10**: BPF map renamed `active` → `active_calls` to fix a symbol
  collision with a vmlinux.h kernel enum on kernel 6.17.
- **ch13**: `trigger.sh` updated for aarch64 — builds a kernel module that
  calls `powercap_register_control_type` (RAPL is x86-only); the analog
  variant uses `bpf_probe_write_user` on userspace sensor reads.
- **ch15**: Documents `--net=host` requirement for XDP to access host
  network interfaces.
- **ch17**: Documents custom `fw_trigger.ko` kernel module requirement;
  `test_firmware` is not loadable on Ubuntu 6.17.
- **ch23**: kprobe on `tpm2_unseal_trusted` confirmed attached; TPM keyctl
  path documented as unavailable in VM without boot-time TPM.

### Added
- `ch06-silence-selinux-lsm-synthetic/README.md` — full documentation for
  the synthetic SELinux bypass variant including mechanism, diff from sibling
  variants, build/run instructions, and proof marker.

## [0.4.0] - 2026-04-17 — Act 4: cross-boundary primitives

### Added
- **Chapter 23 — TPM Unseal Heist.** BPF retrobe on
  `tpm2_unseal_trusted` captures the plaintext payload of a kernel
  trusted-key immediately after the TPM hands it to the kernel. Primitive
  class: persistent theft against hardware-rooted keys. Validated
  structurally (builds clean, preflights correctly, skips honestly on
  kernels without a TPM device).
- **Chapter 24 — The Token Hand-off.** `BPF_TOKEN_CREATE` + bpffs
  `delegate_*` + `SCM_RIGHTS` fd passing lets an unprivileged process
  load BPF programs without `CAP_BPF`. Client uses raw `bpf_prog_load`
  and `bpf_map_create` with `.token_fd` opts; not the libbpf
  `bpf_token_path` helper (which requires caller `CAP_SYS_ADMIN`). Code
  is production-reviewed (see `.audit/c-style-audit.md`). Empirical
  result on Fedora 42 aarch64 6.14 under cloud-init: `BPF_TOKEN_CREATE`
  returns `EOPNOTSUPP` despite userns matching PID 1 — documented as
  environmental scar tissue across 8 iterations in the chapter text.
- **Chapter 25 — The Metadata Faucet.** XDP program taps HTTP traffic to
  the cloud instance metadata service (IMDSv2), parses the response JSON,
  and exfiltrates the IAM credential triple. Fires end-to-end on Fedora
  42 aarch64 QEMU against a Python mock IMDSv2 server (verified across 8
  boots: `CH25_PROVEN access_key_captured=yes token_captured=yes role=demo-role`).
- QEMU-based secondary test environment: Fedora 42 aarch64 cloud image
  + cidata ISO + virtio-9p share + `run-qemu-tests.sh` host driver +
  `qemu-runner.sh` and `act4-runner.sh` guest drivers.
- Smoke test at `dBPF-pocs/pocs/ch24-bpf-token-delegation/smoke-test.sh`
  (29/29 checks pass against the production ch24 code).

### Changed
- Synthesis chapters (Chapters 19, 20, 21, 22) and the preface updated
  for the 23-PoC total. New Shape D ("syscall-level rejection despite
  passing all documented preconditions") added to Chapter 21's skip
  taxonomy for the ch24 finding. Class IV (XDP packet-path) extended
  with ch25 in Chapter 22's mapping table.
- `proof.py` now registers 23 PoCs across four categories.

## [0.3.0] - 2026-04-16 — Synthetic/analog cleanup

### Removed
- Deleted all synthetic/analog PoCs that manufactured their own
  conditions rather than targeting real kernel surfaces:
  `ch06-silence-selinux-lsm-synthetic`, `ch07-devcgroup-houdini-lsm`
  (analog), `ch13-powercap-override-analog`, `ch17-acpi-wsmi-analog`.
- Deleted chapters 13 and 17 — their real primitives require x86 RAPL
  or ACPI, neither of which the aarch64 test matrix hosts; the analog
  variants that stood in for them demonstrated nothing about the
  chapter's actual target.

### Changed
- Chapter 1 promoted its real LSM variant to primary; kprobe+signal
  variant demoted to a sidebar. Chapter 6 retains the real LSM variant
  with honest QEMU-only skip documentation. Chapter 12 keeps the real
  LSM variant as primary with `ch12s` (syscall illusion) explicitly
  labeled as an illusion.
- Synthesis chapters recounted against the reduced PoC list.

## [0.2.0] - 2026-04-15 — Drift fixes

### Fixed
- Chapter prose realigned to code across 21 files after an editorial
  audit. Stale function names, missing struct fields, incorrect attach
  points, and orphaned harness entries corrected. See git log
  `drift-fix` commits for per-chapter detail.
- Harness `ch17` `proof_marker` regex rewritten to match the loader's
  actual output (was previously unmatchable).
- Chapter 22 BPF opcode values corrected (`BPF_OBJ_PIN=6`, not 8;
  aarch64 `__NR_bpf=280`, not 321).
- Chapter 15 `COVERT_VLAN_ID` corrected from 4242 (invalid 12-bit VID)
  to 142.

## [0.1.0] - 2026-04-01 — Initial public shape

### Added
- Act 1 (foundations, chapters 1–5b): kprobe/kretprobe observations,
  tail-call covert control plane, cgroup leash, XDP ghost NIC.
- Act 2 (mid-complexity, chapters 7–13): devcgroup signal, keyring heist,
  PID-NS doppelganger, inode cloak, IRQ timing channel, signed-driver
  swap variants, powercap override.
- Act 3 (closing, chapters 14–22): SCHED_FIFO impersonator, VLAN ghost,
  seccomp TID hop, token bypass, and the synthesis quadrilogy.
- Docker-based harness (`dBPF-pocs/harness/proof.py`) with rich TUI,
  per-POC verdict scraping, and `/tmp/proof-result.json` structured
  output.
