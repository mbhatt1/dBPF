---
layout: book
title: "Chapter 20: What We Proved — The Taxonomy"
date: 2026-01-10
---

# Chapter 20: What We Proved — The Taxonomy

> **Navigation**: [Chapter 20 — Taxonomy]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-3/chapter-22-the-defender-playbook.html)

The harness ran nineteen POCs on kernel 6.12.54-linuxkit aarch64 via Docker Desktop. Thirteen produced BEFORE/AFTER proof markers on stdout. The remaining six either required architectural context this kernel does not expose (BTF for a target struct was absent, or the subsystem — powercap RAPL, WMI on ACPI — was not present), or the program loaded and attached cleanly but sat on an enforcement point that was not active at runtime. Chapter 21 accounts for those. This chapter walks only the ones that produced effects, and puts them in five classes. The five-class taxonomy is the durable artifact of this book.

## The rule for inclusion

Each trigger must print a BEFORE line and an AFTER line showing state that actually changed, and a machine-grep-able `CHxx_PROVEN` marker must appear on stdout before the loader is torn down. Anything less is observation, not a proven primitive. "The kprobe fired and we logged the arguments" is not a primitive in this book; that is a telemetry feature. The bar is: userspace or the kernel saw something different after the probe attached than it saw before.

## The taxonomy

### Class I — Return-value override at the API boundary

The kernel's computation happened; the caller sees a different answer. This class is implemented with `kretprobe + bpf_override_return` (requires the target to be on `/sys/kernel/debug/error_injection/list`), or with the BPF LSM `fmod_ret` attach type (requires `CONFIG_BPF_LSM=y` and the target hook to be present), or with `XDP_DROP` at the netdev layer. All three share a shape: observe the kernel decision, replace the return value, let the caller proceed on the forged answer.

Representative chapters: ch01 (cap_capable / selinux_file_permission override — marker `CH01_WEAPON_PROVEN flips=N`), ch14 (sched_setscheduler forge to pretend SCHED_FIFO promotion succeeded — marker `SCHED_WEAPON_PROVEN flips=N`), ch18 (token-bypass syscall return forge — marker `TOKEN_FORGE_PROVEN uid_forges=N`), ch06 and ch07 LSM variants (SELinux AVC and devcgroup permission flips — markers `CH06_PROVEN flipped=N`, `CH07_CONCEPT_PROVEN before_rc=N after_rc=0`).

The framing matters: this class is an illusion against userspace consumers of the syscall return. Kernel-side decisions that happen later in the call chain — a subsequent LSM check on `current->cred`, a capability check performed inside the kernel against live credentials — are unaffected. The override lies to the userspace caller. It does not change what the kernel actually did.

### Class II — Userspace buffer rewrite via `bpf_probe_write_user`

The kernel produces a correct result and writes it to a userspace buffer. A BPF program waits for the syscall to return, computes where the buffer lives, and mutates it before the caller regains control. The caller then reads the mutated buffer as if it were the kernel's answer.

Representative chapters: ch05 (cgroup memory accounting — before `after_usage` reflects real allocation, after `zeroed=yes patched_events=N`, marker `CH05_PROVEN before_usage=X after_usage=0 zeroed=yes`), ch10 (getdents64 d_reclen swallow to hide directory entries — marker `CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes`).

The primitive needs a stable window: the kernel has written the buffer, the process has not yet been returned control, the memory page is still mapped and not about to be unmapped. `kretprobe` or `tp/syscalls/sys_exit_*` gives that window.

### Class III — Ringbuf exfiltration of kernel-internal state

Observation, not modification. A BPF program reads a kernel structure that userspace could not otherwise see — a credential, a key description, a seccomp decision for a sibling thread — and copies it out-of-band through a BPF ringbuf that the privileged loader is draining. The victim syscall returns whatever it would have returned; the fact of the read is the primitive.

Representative chapters: ch03 (FUSE request metadata via fentry — marker `CH03_PROVEN variant=fentry before=N after=M`), ch04 (phantom syscall field leakage — marker `CH04_PROVEN leaked_fields=N`), ch09 (PID-namespace cross-mapping — marker `CH09_PROVEN host_pid=N mapped=yes`), ch11 (per-IRQ timing sidechannel — marker `CH11_PROVEN events=N unique=M per_event_timing=yes`), ch16 (seccomp decision for another TID — marker `SECCOMP_SIDECHANNEL_PROVEN events=N`), ch08 (keyring description leakage — marker `CH08_PROVEN events=N`).

Important framing for ch16 specifically: seccomp's threat model is the filtered process itself. A privileged sibling holding `CAP_BPF` is explicitly outside that threat model. This primitive sits inside the gap the seccomp design already acknowledges; it is not a failure of seccomp. The chapter labels the marker `SIDECHANNEL` rather than `BYPASS` for exactly that reason.

### Class IV — Packet-path interception (XDP)

The BPF program runs as a peer to the netdev, below the IP stack and below every userspace observer. `XDP_DROP` makes packets vanish before `tcpdump` on the host sees them; `XDP_TX` and `bpf_redirect_peer` reroute them. Because XDP executes in the driver's rx path (or veth tx peer), packet captures taken above that layer do not see modifications.

Representative chapters: ch05b (ghost-NIC covert channel — packets vanish from `tcpdump` but are logged to ringbuf, marker `GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0`), ch15 (netns VLAN ghost cross-namespace redirect — marker `VLAN_GHOST_CROSSNS_PROVEN redirect_count=N`).

### Class V — Kernel-event-triggered userspace racer

The most composite primitive in the book. A BPF program watches a kernel event (a specific `kprobe` fires, a tracepoint records a specific inode being touched) and emits to ringbuf. A privileged userspace racer drains the ringbuf and, on seeing the target event, wins a write race against the legitimate code path — it writes to the promoted inode before the victim process reads.

Representative chapter: ch02 (OverlayFS copy-up race — ringbuf fires on `ovl_copy_up_one`, racer writes a payload to the upper-layer inode before the container reads back, marker `[ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=N hits=M`).

## A note on ch10 and the d_reclen trick

This is not a new idea. The `d_reclen` swallow trick for `getdents64` has been in rootkit proof-of-concepts since at least 2016. My contribution in chapter 10 is a modern-kernel CO-RE reproduction on 6.12 aarch64 with ringbuf evidence and reproducible before/after counts, not the primitive itself. Cite the prior art if you build on it.

## The meta-result

Every primitive in this book is one of three motions: change the syscall return, rewrite the user buffer, or copy the decision out-of-band. These three motions are what `CAP_BPF` grants. The nineteen chapters are demonstrations that granting `CAP_BPF` grants access to all three motions across a representative surface of kernel subsystems. That is the capability, operating as designed. The blue-team implication is in chapter 22.

## Summary table

| Chapter | Class | Effect demonstrated (marker) |
|---------|-------|------------------------------|
| ch01 | I | cap_capable / selinux_file_permission return forged to 0 (`CH01_WEAPON_PROVEN flips=N`) |
| ch02 | V | Racer wins copy-up write race, injects payload to upper layer (`[ch02] PWNED path=... bytes=... hits=...`) |
| ch03 | III | FUSE request metadata exfiltrated via fentry (`CH03_PROVEN variant=fentry before=N after=M`) |
| ch04 | III | Phantom-syscall kernel fields leaked to ringbuf (`CH04_PROVEN leaked_fields=N`) |
| ch05 | II | cgroup memory.current user buffer zeroed post-read (`CH05_PROVEN ... zeroed=yes patched_events=N`) |
| ch05b | IV | XDP drops packets; userspace tcpdump sees zero (`GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0`) |
| ch06 (LSM) | I | avc_has_perm flipped to allow via fmod_ret (`CH06_PROVEN flipped=N`) |
| ch07 (LSM) | I | devcgroup_inode_permission flipped via fmod_ret (`CH07_CONCEPT_PROVEN before_rc=N after_rc=0`) |
| ch08 | III | Keyring description leaked to ringbuf during keyctl (`CH08_PROVEN events=N`) |
| ch09 | III | Cross-namespace PID mapping exposed; host-PID kill confirmed (`CH09_PROVEN host_pid=N`) |
| ch10 | II | getdents64 d_reclen swallow hides entries (`CLOAK_PROVEN before_count=4 after_count=2 hidden=2`) |
| ch11 | III | Per-IRQ timing sidechannel with unique-event evidence (`CH11_PROVEN events=N unique=M`) |
| ch14 | I | sched_setscheduler return forged SCHED_FIFO (`SCHED_WEAPON_PROVEN flips=N`) |
| ch15 | IV | XDP cross-namespace VLAN redirect (`VLAN_GHOST_CROSSNS_PROVEN redirect_count=N`) |
| ch16 | III | Seccomp decision for a sibling TID exfiltrated (`SECCOMP_SIDECHANNEL_PROVEN events=N`) |
| ch18 | I | Token-bypass syscall return forged uid (`TOKEN_FORGE_PROVEN uid_forges=N`) |

## Onward

Chapter 21 does the opposite accounting: the six primitives that did not produce effects on this kernel, and the specific kernel-environment reasons they were refused. Chapter 22 maps the five classes above to the mitigations that actually apply to each.
