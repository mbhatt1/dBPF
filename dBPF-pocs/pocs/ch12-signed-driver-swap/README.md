# ch12 — Signed-Driver Swap (observer)

## Mechanism
Attaches kprobes to the three functions the kernel calls when a module is
loaded:

- `load_module`      — top-level entry.
- `module_sig_check` — signature-presence gate.
- `mod_verify_sig`   — signature-verification body (+ kretprobe).

Each invocation emits a ringbuf event `{pid, comm, hook, modname, ret}`.
The first event triggers a `CH12_PROVEN hook=<name>` marker on stdout.

This is a pure observer. The mutating override lives in
`ch12-signed-driver-swap-lsm/`, which uses BPF LSM
`kernel_read_file` / `kernel_load_data` / `locked_down` fmod_ret to flip the
signature-check return code.

## Hook points
- `kprobe/load_module`
- `kprobe/module_sig_check`
- `kprobe/mod_verify_sig`
- `kretprobe/mod_verify_sig`

## Build
```
cd pocs/ch12-signed-driver-swap
make
```

## Run
```
sudo ./build/ch12-signed-driver-swap -h
sudo ./build/ch12-signed-driver-swap              # observer mode (all hooks)
sudo ./build/ch12-signed-driver-swap -v           # verbose libbpf
```

In another terminal:
```
sudo bash ./trigger.sh
```

## Evidence
On a stock kernel with `CONFIG_MODULE_SIG=y`:
```
[ch12] === symbol availability ===
  load_module          : present
  module_sig_check     : present
  mod_verify_sig       : present
[ch12] attached prog=kp_load_module
[ch12] attached prog=kp_module_sig_check
[ch12] attached prog=kp_mod_verify_sig
[ch12] attached prog=kr_mod_verify_sig
[ch12] attached=4	skipped=0
[ch12] status=ready	msg=sig-check observer active
[ch12] CH12_PROVEN hook=load_module
[ch12] tag=enter	pid=3914	comm=insmod          	hook=load_module	modname=(unknown)
[ch12] tag=enter	pid=3914	comm=insmod          	hook=module_sig_check	modname=fake
[ch12] tag=enter	pid=3914	comm=insmod          	hook=mod_verify_sig	modname=(unknown)
[ch12] tag=sig_ret	pid=3914	comm=insmod          	hook=mod_verify_sig_ret	ret=-74
```
`ret=-74` = `-EBADMSG` — the signature gate rejected the fake .ko.

## Detection
- `bpftool prog show | grep -E 'load_module|mod_verify_sig|module_sig_check'`
- `cat /sys/kernel/debug/tracing/kprobe_events` shows live entries.
- The `events` ringbuf is listed in `bpftool map show`.

## Limitations / arch notes
- **No module-signing symbols → honest skip.** If `/proc/kallsyms` contains
  none of `load_module`, `module_sig_check`, `mod_verify_sig`, the loader
  prints `CH12_SKIP reason="no module-signing symbols (kernel built without
  CONFIG_MODULE_SIG or symbols inlined)"` and exits 2.
- **Docker Desktop linuxkit (6.12, aarch64)** ships with
  `CONFIG_MODULE_SIG=n`; on that target this POC emits the skip marker.
- **Override requires BPF LSM.** `bpf_override_return` on `mod_verify_sig`
  is not in the kernel's error-injection allowlist. Use the LSM variant
  (`ch12-signed-driver-swap-lsm`) to flip the verdict via
  `SEC("lsm.s/kernel_read_file")` fmod_ret.

## Blog post

See the chapter write-up: [`2025-03-01-ebpf-signed-driver-swap`](../../../_posts/2025-03-01-ebpf-signed-driver-swap.md) in the Diabolical eBPF Field Manual.
