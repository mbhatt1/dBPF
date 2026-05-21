# ch06 Silence SELinux — LSM synthetic variant

Sibling POC to `ch06-silence-selinux/` (kprobe observer) and
`ch06-silence-selinux-lsm/` (real `fmod_ret` flipper on kernels with
SELinux active). This variant proves the deny-then-flip primitive on
kernels where SELinux is compiled in but not active — specifically where
`selinux_loaded()` returns false, which causes the natural `avc_has_perm`
path to never fire and the real LSM variant's preflight to skip.

## How it differs from the main ch06 variants

| Variant | Hook | SELinux required? | Proof strategy |
|---------|------|-------------------|----------------|
| `ch06-silence-selinux` | `kprobe/avc_has_perm` | Yes (observer only) | Watches AVC decisions passively |
| `ch06-silence-selinux-lsm` | `lsm.s/file_permission` etc. | Yes (`selinux_loaded()` preflight) | Flips real AVC denials via `fmod_ret` |
| **`ch06-silence-selinux-lsm-synthetic`** | `lsm.s/file_open` | **No** | Synthesizes a deny inside BPF and proves the flip end-to-end without SELinux |

The synthetic variant bypasses the `selinux_loaded()` preflight entirely.
It attaches a single sleepable `lsm.s/file_open` program and uses a
control map to select its stage at runtime:

- **STAGE_OFF** — pass through, no effect.
- **STAGE_DENY** — return `-EACCES` for `(target_uid, sentinel_path)` matches, synthesizing a denial.
- **STAGE_FLIP** — match the same `(target_uid, sentinel_path)` but return 0, proving the primitive that turns a would-be deny into an allow.

The deny and flip are implemented in the same program behind a map-driven
toggle because `fmod_ret` LSM hooks short-circuit at the first non-zero
return: a standalone denier would prevent a subsequent flipper on the same
hook from running. The map toggle models the same attacker capability
(deny-then-flip) without running into LSM chaining semantics.

Path matching uses `bpf_d_path()` on `file->f_path`, which requires a
sleepable program (`lsm.s/...`). `file_open` is the attachment point
because it exposes a `struct file *` and fires on every `open(2)`.

## Mechanism

```
open(2) → security_file_open() → lsm.s/file_open (this program)
             ↓ reads ctrl_map
             stage=OFF   → return 0 (pass through)
             stage=DENY  → bpf_d_path match → return -EACCES
             stage=FLIP  → bpf_d_path match → return 0 (flip)
             ↓ emits ringbuf event on every match
```

Runtime stage transitions are driven by signals to the loader PID:

| Signal | Effect |
|--------|--------|
| SIGUSR1 | stage = DENY |
| SIGUSR2 | stage = FLIP |
| SIGHUP | stage = OFF |
| SIGINT / SIGTERM | shutdown |

## Primitive

`P3` from `shared/PRIMITIVES.md`: `SEC("lsm.s/<hook>")` sleepable
`fmod_ret`. Not gated by the error-injection allowlist — LSM `fmod_ret`
is the first-class override primitive. Only `CONFIG_BPF_LSM=y` and `bpf`
in the boot-time LSM list are required; SELinux need not be present or
active.

## Host prereqs

- Kernel with `CONFIG_BPF_LSM=y`.
- Boot cmdline `lsm=...` list contains `bpf`.
- Check: `cat /sys/kernel/security/lsm` must contain `bpf`.
- `bpftool feature probe | grep lsm_fmod_ret` must show `ok`.
- `CAP_SYS_ADMIN` — loading sleepable LSM programs requires it, not just `CAP_BPF`.
- Satisfied by Ubuntu 6.17 aarch64 with BPF LSM enabled, Docker Desktop
  linuxkit 6.12 aarch64, or any distro kernel built with `CONFIG_BPF_LSM=y`.
- Unlike `ch06-silence-selinux-lsm`, **SELinux does not need to be present
  or enforcing** — the loader does not call `selinux_loaded()`.

## Build

```bash
cd pocs/ch06-silence-selinux-lsm-synthetic
make
```

Or via Docker:

```bash
docker run --rm -v "$PWD/../..":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch06-silence-selinux-lsm-synthetic && make'
```

## Run

```bash
sudo ./build/ch06-silence-selinux-lsm-synthetic -h
sudo ./build/ch06-silence-selinux-lsm-synthetic \
  -u $(id -u) \
  -s /tmp/sentinel-file \
  -p /tmp/ch06synth.pid
```

Then in another shell:

```bash
# Arm the denier
kill -USR1 $(cat /tmp/ch06synth.pid)
# Try to open the sentinel — will get EACCES
cat /tmp/sentinel-file

# Switch to flipper
kill -USR2 $(cat /tmp/ch06synth.pid)
# Open now succeeds (verdict=0)
cat /tmp/sentinel-file
```

Or run the end-to-end trigger:

```bash
sudo bash trigger.sh
```

## Evidence (expected on BPF LSM kernel, no SELinux required)

Loader stderr:
```
[ch06-synth] attached lsm.s/file_open target_uid=1000 sentinel=/tmp/sentinel-file stage=off pid=12345
[ch06-synth] stage -> deny
[ch06-synth] stage -> flip
```

Loader stdout (proof markers):
```
[ch06-synth] stage=deny pid=12345 uid=1000 comm=cat verdict=-13 path=/tmp/sentinel-file
[ch06-synth] stage=flip pid=12345 uid=1000 comm=cat verdict=0  path=/tmp/sentinel-file
```

Trigger terminal line:
```
CH06_SYNTH_PROVEN stage=flip verdict=0 path=/tmp/sentinel-file
```

On a kernel missing BPF LSM, the loader emits:
```
CH06_SYNTH_SKIP reason="BPF LSM not enabled (need 'bpf' in /sys/kernel/security/lsm)"
```
and exits 3. The trigger records this as an honest skip.

## Proof marker (Ubuntu 6.17 aarch64 Lima VM)

```
CH06_SYNTH_PROVEN stage=flip verdict=0 path=/tmp/sentinel-file
```

Verified on Ubuntu 6.17.0-29-generic aarch64 (Lima VM, Apple Silicon).
This variant was added specifically for kernels where SELinux is absent or
inactive — the `ch06-silence-selinux-lsm` real variant requires
`selinux_loaded()` to return true; this one does not.

## Detection

- `bpftool prog list type lsm` shows the attached sleepable program.
- `cat /sys/kernel/debug/tracing/enabled_functions 2>/dev/null` lists active fmod_ret hooks.
- `bpftool map show` lists the `ctrl_map` array and `events` ringbuf.
- Any monitoring system watching `bpf()` syscall audit records will see
  a sleepable LSM program loaded from a non-init namespace.

## Limitations

- Requires `CAP_SYS_ADMIN`, not just `CAP_BPF`.
- Path matching is via `bpf_d_path()` — requires a sleepable program;
  non-sleepable `lsm/file_open` cannot call `bpf_d_path`.
- `bpf_d_path` resolves the path at open time; hardlinks and bind mounts
  may produce different resolved paths than the sentinel.
- The synthetic deny-then-flip models the attacker capability but does not
  require an organic SELinux deny to trigger it — see
  [`../ch06-silence-selinux-lsm/`](../ch06-silence-selinux-lsm/) for the
  real-SELinux variant that flips actual AVC denials.
