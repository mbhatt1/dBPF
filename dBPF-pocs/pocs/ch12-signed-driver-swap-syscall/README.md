# ch12 — Signed-Driver Swap (syscall variant)

## Mechanism
Forges the return value of the module-load syscall(s) to 0 by attaching
`kretprobe/__arm64_sys_finit_module` and `kretprobe/__arm64_sys_init_module`
and calling `bpf_override_return(ctx, 0)`. On 6.12 aarch64 linuxkit, both
symbols are on the kernel's error-injection allowlist
(`/sys/kernel/debug/error_injection/list`), so the override is permitted.

This is an *illusion* bypass in the same class as ch14 (sched) and ch18
(token): the kernel's actual module loader still rejects the bytes (ELF
validation / signature check / etc.) — we only rewrite what userspace sees.
`lsmod` and `/proc/modules` show no change; only tools that trust the
syscall return value are fooled.

## Why this exists (vs the `-lsm` variant)
The original `ch12-signed-driver-swap-lsm` variant attempted to flip
`kernel_read_file` / `mod_verify_sig` LSM returns. That approach failed on
this kernel for two reasons:

1. **linuxkit kernel does not enforce module signatures**, so there are no
   natural denials to flip at `mod_verify_sig`.
2. **`insmod` of a non-ELF blob fails at ELF validation** inside the module
   loader before reaching the signature LSM hooks.

Moving the override to the syscall entry point sidesteps both: the
kretprobe fires regardless of *why* the loader failed, because it fires on
exit from the syscall, after every internal rejection path.

## Hook points
- `kretprobe/__arm64_sys_finit_module` (what modern `insmod`/`modprobe` use)
- `kretprobe/__arm64_sys_init_module` (legacy path)

Both are ERRNO-injectable on this kernel.

## Verification
```
docker run --rm --privileged --pid=host -v /sys:/sys \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v $PWD/../..:/w -w /w dbpf-harness:latest \
  bash -c 'cd /w/pocs/ch12-signed-driver-swap-syscall && make && bash trigger.sh'
```

Expected output:
```
BEFORE: insmod_rc=1 error_text="ENOEXEC"
...
AFTER: insmod_rc=0 lsmod_shows_module=no syscall_return_forged=yes
...
=== CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no ===
```

The ringbuf event confirms the override landed, with the kernel's original
return value visible:
```
[ch12s] FORGE pid=<N> comm=insmod syscall=finit_module orig_ret=-8 -> 0
```
(orig_ret=-8 is `-ENOEXEC`; rewritten to 0 before returning to userspace.)

## Detection
Defender observes any of:
- `lsmod` / `/proc/modules` does not list the supposedly-loaded module
- Kernel log (`dmesg`) shows the original module-loader error
  ("Invalid module format", signature failure, etc.)
- `insmod` success with no entry in `/sys/module/<name>/`
- Orchestrators that call `finit_module(2)` and then `stat("/sys/module/<name>")`
  catch the discrepancy immediately

The primitive only fools workflows that treat the syscall return as
authoritative proof of load. Any post-load verification via kernel state
(procfs/sysfs) defeats it.

## Modes
- `--all` — forge every caller's module-load syscall return (wildcard)
- `--tgid <pid>` — forge only calls from `<pid>` (repeatable, up to 1024)

## Blog post

See the chapter write-up: [`2025-03-01-ebpf-signed-driver-swap`](../../../_posts/2025-03-01-ebpf-signed-driver-swap.md) in the Diabolical eBPF Field Manual.
