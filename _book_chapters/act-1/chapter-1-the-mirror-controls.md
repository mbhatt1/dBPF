---
layout: book
title: "Chapter 1: The Mirror Controls"
date: 2025-01-31
---

# Chapter 1: The Mirror Controls

> **See also**: [Blog post]({{ site.baseurl }}/the-mirror-controls.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch01-mirror-controls-lsm) · [Legacy kprobe variant](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch01-mirror-controls)

> **Proof status**: Both `ch01-mirror-controls` (kprobe+kretprobe) and `ch01-mirror-controls-lsm` (BPF LSM fmod_ret) have been proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). The kprobe variant was updated to deliver `bpf_send_signal(SIGUSR1)` to the target process on every capability denial; the ringbuf event records this in the `signal_sent` field under tag `FLIP`. The `-a` wildcard flag was added to the userspace loader to arm wildcard targeting. The LSM variant required no changes.

I started this chapter wanting to override a capability check from BPF. I spent a week figuring out why that does not work on a stock kernel. I ended up writing two POCs. The second one — a BPF LSM program that returns `0` from `lsm/inode_permission` where the kernel would have returned `-EACCES` — is the one that actually grants access. That is the primary for this chapter. The first one, the kprobe on `cap_capable` with `bpf_send_signal`, is a cautionary tale documented in a sidebar below.

The primitive, stated plainly: on a kernel with `CONFIG_BPF_LSM=y` and `bpf` in `/sys/kernel/security/lsm`, a BPF program can attach as an fmod_ret hook on `security_inode_permission`, and its return value replaces the kernel's. If the kernel was going to deny a VFS access with `-EACCES`, the BPF program returns `0` and the read or write proceeds. There is no error-injection allowlist to clear, no silent no-op. The kernel actually permits the access. That is what I could not do with a kprobe.

## Preconditions and the skip story

The LSM fmod_ret path only exists on kernels built and booted to accept it. Three knobs matter:

1. **`CONFIG_BPF_LSM=y`** at kernel build time. Without this, the loader fails at `BPF_PROG_LOAD` with `-EINVAL`. Fedora 38+ ships it on by default; Docker Desktop's linuxkit VM does not.
2. **`bpf` in `/sys/kernel/security/lsm`**. The BPF LSM has to be in the active LSM set or fmod_ret programs have no chain to attach into. The loader reads `/sys/kernel/security/lsm`, looks for the substring `bpf`, and exits with `CH01_SKIP reason="BPF LSM not active"` if it is absent.
3. **Kernel 6.14+ for `lsm/inode_permission` specifically.** I tried `lsm/capable` first. On kernels where `security_capable` short-circuits around the LSM chain for non-root processes — which is the common case from about 6.12 onward — the program never fires on the calls that matter. `inode_permission` fires reliably on every `vfs_read` / `vfs_write`. On 6.14+ the fmod_ret machinery around it is stable.

If any of the three is missing, the loader emits a skip line and exits. There is no fallback to the kprobe variant inside this POC. A reader on linuxkit will see the skip and move on.

## Mechanism

The kernel-side program is 97 lines. The one fact everything else rests on: the `lsm/` program type is not a passive observer. A kprobe fires and returns without touching execution; an fmod_ret LSM hook has its return value injected back into the LSM chain. That difference is the whole chapter.

The load-bearing parts are the SEC string and the return-value convention:

```c
SEC("lsm/inode_permission")
int BPF_PROG(lsm_inode_permission, struct inode *inode, int mask, int ret)
```

The `lsm/` prefix classifies the program as `BPF_PROG_TYPE_LSM`. The suffix names the hook; libbpf resolves it against BTF at load time. The third parameter, `int ret`, is the verdict the hook chain has accumulated so far. **The program's return value replaces the hook's return value.** Return `0` and the access is permitted. Return a negative errno and it is denied.

The filter is a map lookup against a hash of target TGIDs, with `0` as a wildcard sentinel:

```c
static __always_inline int is_target(void)
{
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    unsigned int *hit = bpf_map_lookup_elem(&target_tgids, &tgid);
    unsigned int zero = 0;
    return (hit || bpf_map_lookup_elem(&target_tgids, &zero)) ? 1 : 0;
}
```

A uid-0 guard returns `ret` unchanged for root callers — overriding root-side denials causes loud, confusing breakage for no useful gain. The flip itself:

```c
int new_ret = ret;
if (ret != 0) {
    new_ret = 0;  // flip denial to allow
    flipped = 1;
}
return new_ret;
```

Control returns from the BPF trampoline back into the kernel's LSM machinery with `new_ret` as the verdict. `do_inode_permission` sees a `0`, `vfs_read` proceeds into the actual filesystem read path, and the bytes come back to the caller. No illusion, no forged payload: the kernel does the read.

The event emit path reads the dentry via `BPF_CORE_READ` to recover the filename. It emits only on flips; `inode_permission` fires thousands of times per second on a busy system, and emitting on every call fills the ringbuf in milliseconds.

## Hook points

Two hook points were tried. `lsm/inode_permission` is the one that ships: it fires as an fmod_ret hook on the inode access check, covering every `vfs_read`, `vfs_write`, and file open that exercises DAC, and its return value replaces the chain's verdict. `lsm/capable` was the first attempt; it short-circuits on 6.12+ for non-root callers in the common case and was abandoned.

## The kprobe-plus-signal variant that does not mutate

The original plan was to override `cap_capable` using `bpf_override_return(ctx, 0)` in a kretprobe. The program compiles. The verifier accepts it. The kretprobe attaches. The target process runs. `capset` fails with `EPERM`. The ringbuf records `flipped=1` for every denial that matched. The syscall still returns `EPERM`. The override is a silent no-op.

The mechanism is the `ALLOW_ERROR_INJECTION` allowlist. `bpf_override_return` only takes effect when the target function is annotated `ALLOW_ERROR_INJECTION(fn, ERRNO)` in kernel source. The set is deliberately small and excludes every security-decision function: `cap_capable`, `security_capable`, `avc_has_perm`, `security_inode_permission`. The runtime check is in the kprobe dispatch path. If `cap_capable` fails the check, the stored override is discarded with no error, no tracepoint, no dmesg line. The silence is intentional.

Confronted with that, I pivoted to `bpf_send_signal(SIGUSR1)` as a real effect. The signal does get delivered. The loader's ringbuf records `signal=1` on events where `bpf_send_signal` returned zero. The target process receives the signal. But a signal is not a capability grant. The `capset` that triggered the denial still fails with `EPERM`. The subsequent code path the caller wanted to run does not execute. It demonstrates that a BPF program on a non-allowlisted decision function can still have a side effect. It does not demonstrate capability override.

The kprobe variant is still in the tree under `ch01-mirror-controls/`. Run it on linuxkit or any default kernel to see the negative result: `bpftool prog show` confirms the program is loaded, the ringbuf confirms it fired, and the target's operation still fails. It is a useful negative: it shows exactly where the error-injection wall sits.

## Reproduction

```bash
# LSM variant (requires BPF LSM on boot cmdline)
cd dBPF-pocs/pocs/ch01-mirror-controls-lsm
make
sudo ./build/ch01-mirror-controls-lsm -a &     # wildcard targeting
sudo bash trigger.sh

# Kprobe variant (shows the negative result on any kernel)
cd dBPF-pocs/pocs/ch01-mirror-controls
make
sudo ./build/ch01-mirror-controls -t $(pidof target_proc)
```

Harness entry: `Poc("ch01", ...)` in `dBPF-pocs/harness/proof.py`. On linuxkit the LSM variant prints `CH01_SKIP` because Docker Desktop does not ship `CONFIG_BPF_LSM=y`. The kprobe variant runs on linuxkit and shows the signal-without-override result.

## Detection

The LSM POC is entirely legible to a defender watching BPF loads.

- `bpftool prog show --type lsm` lists every LSM BPF program. The chapter's program appears as type `lsm` with attach target `inode_permission`.
- `auditd` with `-a always,exit -F arch=b64 -S bpf -k bpf_syscall` captures the `BPF_PROG_LOAD` call.
- A sudden absence of `-EACCES` denials for a specific process is a behavioral tell; this program removes the denials rather than masking them.
- Baseline-diff of `bpftool prog show --json` catches the new program within one diff interval.

For the kprobe variant:

- `bpftool prog list` output (program type `kprobe`, attach name `cap_capable`).
- `/sys/kernel/debug/kprobes/list` showing the attached kprobe.
- `AUDIT_BPF_PROG_LOAD` records in `auditd`.

None of these are hidden by this chapter. Hiding load events is a separate primitive in its own chapter.

## Scope

The kprobe variant is a Class III primitive (out-of-band observation) plus a Class V side-effect (`bpf_send_signal`). It confirms the BPF program can act at the exact moment a security decision is made. It does not change the decision. The LSM variant is what makes the chapter title accurate: that is the primitive that actually controls the mirror. It is a first-class override for VFS access checks, not gated by the error-injection allowlist. The preconditions are real — if BPF LSM is not in the LSM list, the chapter skips honestly — but on any kernel that ships with BPF LSM active, the primitive is fully operational and leaves no trace in the denied-access log.

---

**Related material**

- Blog post: [The Mirror Controls]({{ site.baseurl }}/the-mirror-controls.html)
- POC source: [dBPF-pocs/pocs/ch01-mirror-controls-lsm/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch01-mirror-controls-lsm)
- Harness entry: search for `Poc("ch01", ...)` in `dBPF-pocs/harness/proof.py`
