# BPF mutation primitives — what's actually possible

Every POC wants to *change* kernel behavior. This doc enumerates the
primitives BPF exposes, and, for each gated POC, names the one it needs.

## The primitive inventory

| # | Primitive | Where it can write | Gating |
|---|-----------|--------------------|--------|
| P1 | `bpf_override_return(ctx, v)` on kprobe/kretprobe | syscall/function return value | target fn must be in `/sys/kernel/debug/error_injection/list` (requires `ALLOW_ERROR_INJECTION()` annotation + `CONFIG_FUNCTION_ERROR_INJECTION=y`) |
| P2 | `bpf_probe_write_user(ptr, src, len)` | any userspace memory of current task | `bpf_capable()`; prints taint message; cannot write kernel mem |
| P3 | `SEC("lsm/<hook>")` + `fmod_ret` | return value of that LSM hook | `CONFIG_BPF_LSM=y` + `lsm=bpf,...` in boot cmdline |
| P4 | `SEC("fentry/<fn>") BPF_PROG + bpf_modify_return` | return value of BTF-traceable fn | fn must be in the kernel's `BTF_SET_START(bpf_modify_return_targets)` allowlist (tiny list) |
| P5 | `SEC("xdp")` / `SEC("tc")` packet manipulation | any byte in the skb/xdp packet | `CAP_NET_ADMIN` / `CAP_BPF` |
| P6 | `SEC("cgroup/...")` verdicts (sockops, skb, sysctl, sock_addr) | return allowed/denied for cgroup-scoped op | `CAP_BPF` on cgroup; `CONFIG_CGROUP_BPF=y` |
| P7 | Maps pinned at `/sys/fs/bpf/...` + userspace helper | anything the helper does | trivial |
| P8 | Tracepoint `bpf_get_current_task` + struct walk + ringbuf emit | **kernel read only** — no kernel write | N/A — observation primitive |

**Absent primitives**: there is no `bpf_probe_write_kernel`, no direct task
struct mutation, no IRQ-affinity knob, no ACPI AML injection, no MSR write.

## POC-by-POC: which primitive delivers the chapter's claim

| POC | Chapter claim | Right primitive | Current state |
|-----|---------------|-----------------|---------------|
| ch01 | Flip capability denies to grants | **P3** `lsm/capable` fmod_ret | ✓ LSM variant in `pocs/ch01-mirror-controls/lsm.bpf.c` |
| ch02 | Inject payload during overlay copy-up | **P3** `lsm/inode_copy_up_xattr` or `lsm/inode_setxattr`; plus P2 on the reader that later slurps the file | ✓ LSM variant (deny-targeted-paths); full inject needs post-copy-up `vfs_read` + P2 |
| ch03 | Silence audit events | **P4** `fentry/audit_log_start` + `bpf_modify_return` — audit_log_start IS a modify-return candidate on recent kernels | ✓ `ch03-fuse-blackhole/fentry.bpf.c` |
| ch06 | Force SELinux denials to grants | **P3** `lsm/inode_permission`, `lsm/file_permission`, `lsm/bprm_check_security` — return 0 to allow. LSM hooks run BEFORE SELinux's avc_has_perm so overriding the outer hook makes SELinux moot | ✓ `ch06-silence-selinux/lsm.bpf.c` |
| ch07 | Unrestricted device access | **P3** `lsm/inode_mknod` + `lsm/file_open` fmod_ret → 0 for matched paths | ✓ `ch07-devcgroup-houdini/lsm.bpf.c` |
| ch08 | Grant access to all keyring entries | **P3** `lsm/key_permission` fmod_ret → 0 | ✓ `ch08-keyring-heist/lsm.bpf.c` |
| ch11 | Force IRQ affinity to CPU0 as covert channel | **None** — IRQ affinity is controlled via `/proc/irq/<N>/smp_affinity` writes. BPF has no hook that steers irqdesc-level routing. Closest real path: P7 (userspace helper that writes the sysfs file triggered by a BPF event) | N/A — observer is the ceiling from pure BPF |
| ch12 | Swap signed kernel module payload | **P3** `lsm/kernel_read_file` (modern kernels) or `lsm/kernel_module_from_file` — return 0 after tampering with the buffer via P2 in the *userspace* module-loader context | ✓ `ch12-signed-driver-swap/lsm.bpf.c` |
| ch15 | Cross-ns traffic via hidden VLAN | **P5** XDP + `bpf_redirect_map` to DEVMAP across netns | ✓ already delivered in core POC |
| ch16 | Swap TID to evade seccomp | **None** — `current->tid` is in kernel memory; no primitive writes it. Seccomp filter eval runs *in-kernel* from `__secure_computing`, which is not in error_injection list and has no LSM hook. Closest real path: LD_PRELOAD or ptrace from userspace — neither is BPF | N/A |
| ch17 | Intercept ACPI AML → firmware | **None** on arm64 (no ACPI). On x86 with the right symbols, P1 on `acpi_evaluate_object` would observe; true injection needs kernel write = no primitive | N/A |

## Bottom line

- **ch01, ch02 (partial), ch03, ch06, ch07, ch08, ch12** — real mutation
  available via BPF LSM / fentry+modify_return. Needs the right host kernel
  (`lsm=bpf` enabled).
- **ch04, ch05 monitoring, ch05b, ch10, ch14, ch18** — already delivered in
  the core POCs via P1/P2/P5.
- **ch15** — already delivered via P5.
- **ch11, ch16, ch17** — no BPF primitive exists. Honest observer-only is
  the best BPF can do.
