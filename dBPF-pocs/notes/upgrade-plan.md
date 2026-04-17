# POC Upgrade Plan — Make All PoCs Have Real Effects

## Current State Audit

### Already LIVE (BPF modifies behavior + trigger emits PROVEN):
- ch01-mirror-controls-lsm: fmod_ret on security_capable (needs BPF LSM)
- ch02-overlayfs: BPF observer + userspace racer → RACE_WIN  
- ch02-overlayfs-lsm: fmod_ret blocks copy-up (needs BPF LSM)
- ch03-fuse-blackhole: bpf_override_return on audit_log_start
- ch05-cgroup-leash: bpf_probe_write_user on sys_read buffer
- ch05b-ghost-nic: XDP_DROP covert channel
- ch06-silence-selinux-lsm-synthetic: synthetic deny+flip (needs BPF LSM)
- ch10-inode-cloak: bpf_probe_write_user on getdents64 buffer
- ch12-signed-driver-swap-syscall: bpf_override_return on finit_module
- ch14-sched-fifo: bpf_override_return on sched_setscheduler
- ch15-netns-vlan-ghost: XDP strip+redirect (trigger broken: missing tcpdump)
- ch16-seccomp-tid-hop: bpf_override_return on __secure_computing  
- ch18-token-bypass: bpf_override_return on getuid/geteuid

### OBSERVE-ONLY base variants (need upgrade):
1. **ch01-mirror-controls** — kprobe cap_capable, override blocked by error_injection
2. **ch04-phantom-syscall** — tail-call exfil IS the effect, but no modification
3. **ch07-devcgroup-houdini** — kprobe observer only
4. **ch08-keyring-heist** — reads metadata only, not payload
5. **ch09-pid-doppel** — maps PIDs only, no cross-ns effect
6. **ch11-irq-chaos** — observes IRQs only, no covert channel proof
7. **ch13-powercap-override** — x86-only, no symbols (skip: analog exists)
8. **ch17-acpi-wsmi** — no ACPI on aarch64 (skip: analog exists)

### Environment-broken (trigger issues):
- **ch15-netns-vlan-ghost** — BPF is live, trigger needs tcpdump alternative

---

## Upgrade Strategy

### ch01-mirror-controls
**Problem**: bpf_override_return on cap_capable rejected (not in error_injection list).
**Fix**: Add kretprobe that uses `bpf_send_signal(SIGCONT)` on the target tgid when a capability is denied, proving the BPF program can affect the target process. Also add `bpf_probe_write_user` to corrupt the errno return path in userspace. The trigger verifies that the signal was received.
**Alternative**: Hook `__arm64_sys_openat` kretprobe — if target tgid gets -EACCES, use bpf_override_return to force return=fd (if in error injection list). 

### ch04-phantom-syscall  
**Problem**: Exfiltration works but there's no kernel-side modification.
**Fix**: Add `bpf_send_signal(SIGUSR1)` to the target on magic-marker detection, proving bidirectional control (not just exfil). Trigger verifies signal receipt.

### ch07-devcgroup-houdini (base)
**Problem**: Pure observer.
**Fix**: Add kretprobe on `devcgroup_check_permission` with `bpf_override_return(0)` to flip deny→allow. If error_injection blocks it, fall back to `bpf_probe_write_user` on the errno return value, or use `bpf_send_signal` to demonstrate process control.

### ch08-keyring-heist (base)
**Problem**: Reads metadata (serial, type, description) but not the actual secret.
**Fix**: Add `bpf_probe_read_kernel` on `key->payload.data[0]` (length=key->datalen) to exfiltrate actual key payload bytes into the ringbuf event. This turns observation into real credential exfiltration.

### ch09-pid-doppel
**Problem**: Maps host↔ns PIDs but doesn't demonstrate cross-namespace targeting.
**Fix**: Add `bpf_send_signal(SIGUSR1)` from the fork tracepoint to demonstrate that the observer can target a process in a different PID namespace using the mapped host PID.

### ch11-irq-chaos
**Problem**: Pure observer.
**Fix**: Add per-CPU timing measurement (ktime_get_ns deltas between IRQ events) and export via ringbuf to prove covert channel bandwidth. Add `bpf_override_return` on irq handler if in error injection list (IRQ suppression), or use per-CPU map writes as a cross-CPU signaling mechanism.

### ch15-netns-vlan-ghost (trigger fix)
**Problem**: BPF already strips VLAN tags + redirects. Trigger requires tcpdump.
**Fix**: Replace tcpdump dependency in trigger.sh with raw socket recv or /proc/net inspection.
