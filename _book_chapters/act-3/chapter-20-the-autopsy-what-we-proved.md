---
layout: book
title: "Chapter 20: What We Proved — The Taxonomy"
date: 2026-01-10
---

# Chapter 20: What We Proved — The Taxonomy

> **See also**: [Blog post]({{ site.baseurl }}/the-taxonomy.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

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

## Detailed walkthrough: Class I — return-value override

Four chapters implement Class I on kernels where the target function is on the error-injection allowlist, or where a BPF LSM hook admits an fmod_ret attach. Each has its own specific mechanics.

**ch01 — cap_capable and selinux_file_permission.** The POC in `dBPF-pocs/pocs/ch01-mirror-controls/` was the first chapter in the book, and it hit the first honest limit. `cap_capable` is not in `/sys/kernel/debug/error_injection/list` on linuxkit 6.12 aarch64 — the kprobe attaches, but `bpf_override_return` from the kretprobe is ignored by the kernel. The POC still logs every capability check that would have been flipped; that log alone is the `CH01_WEAPON_PROVEN flips=N` marker. The LSM variant in `ch01-mirror-controls-lsm/` attaches `SEC("lsm/file_permission")` with target-tgid filtering and actually returns 0 for the target — and because `CONFIG_BPF_LSM=y` on this kernel, the fmod_ret takes effect. A file `cat` from the target tgid succeeds even when DAC or an active LSM policy would normally deny it. That is the real Class I behavior; the original chapter is observational on this kernel.

**ch14 — sched_setscheduler forge.** `__arm64_sys_sched_setscheduler` *is* on the error-injection allowlist (syscall entry points almost always are). The POC in `dBPF-pocs/pocs/ch14-sched-fifo/` attaches a kretprobe and returns 0. The caller's `chrt -f 50 $$` gets rc=0, prints "SCHED_FIFO set". The kernel's `task_struct->policy` is unchanged; `sched_getscheduler($$)` on the same pid returns the real policy; `/proc/[pid]/sched` shows the real policy. Every userspace consumer of `sched_setscheduler`'s return value is fooled; every kernel-side check on `task->policy` is not. This is the clean case of the class: the lie is at the API boundary, the truth lives inside the kernel.

**ch18 — getuid token forge.** `__arm64_sys_getuid` and `__arm64_sys_geteuid` are both on the error-injection allowlist. The POC in `dBPF-pocs/pocs/ch18-token-bypass/` kretprobes both and returns 0. `id` reports `uid=0(root) gid=1001`. The `gid=1001` is the tell — the POC did not hook `getgid` or `getegid`, so the real gid shows through. A defender who reads both uid and gid and expects them to be consistent catches the half-hooked forge immediately. Kernel-side `current->cred->uid` is the real unprivileged uid; VFS, LSM, and capability checks all see the truth. `cat /etc/shadow` still returns `EACCES`.

**ch12 syscall variant — finit_module return forge.** `__arm64_sys_finit_module` is on the error-injection allowlist. The POC in `dBPF-pocs/pocs/ch12-signed-driver-swap-syscall/` kretprobes it and returns 0 on any `insmod` attempt against a non-ELF blob. `insmod` reports rc=0; `lsmod` is empty; `/proc/modules` shows no new module; `dmesg` shows the kernel's original ENOEXEC rejection. The userspace illusion is that the module loaded; any orchestrator that post-checks via `lsmod` catches it. The original LSM variant for module signature (flipping `mod_verify_sig`'s return) is a skip on this kernel because signature enforcement is off — Chapter 21 accounts for it.

Across these four, the common pattern: userspace reads a forged API return. Kernel-side enforcement reads real state. Anything that gates decisions on the kernel's actual state (credentials, policy, loaded modules) is unaffected. Anything that trusts the libc syscall wrapper's return value is fooled.

## Detailed walkthrough: Class II — userspace buffer rewrite

Two chapters, one primitive. `bpf_probe_write_user` waits for a syscall to finish, looks up the userspace buffer the kernel just wrote to, and mutates it before the caller regains control.

**ch05 — cgroup cpu.stat readback rewrite.** The POC walks `current->files->fdt->fd[fd]->f_path.dentry->d_name.name` via `BPF_CORE_READ` to identify reads of files named `cpu.stat`. On sys_exit_read with a successful return, the program calls `bpf_probe_write_user` to overwrite the user buffer with `"usage_usec 0\nuser_usec 0\nsystem_usec 0\n"`. The cgroup scheduler's accounting is unchanged — the cgroup keeps getting throttled if it exceeds quota. The observation plane is what lies. Every userspace tool that reads `cpu.stat` (node-exporter, cAdvisor, Datadog, Netdata, Sysdig, Grafana agent) reports zero CPU usage. Same mechanism trivially extends to `memory.current`, `io.stat`, `cpu.pressure` — swap the literal in the bounded compare.

**ch10 — getdents64 d_reclen swallow.** The POC attaches paired tracepoints on `sys_enter_getdents64` and `sys_exit_getdents64`. Entry stashes `(ubuf, count)` in a per-(pid, tgid) hash map. Exit walks the returned dirent stream (up to 64 entries per call, a verifier-bounded loop) and, for each entry whose name matches a hidden-set member, rewrites the *previous* entry's `d_reclen` to encompass the hidden entry. Userspace walkers advance by `d_reclen` each iteration and skip over the hidden file. The file is still on disk; `stat` by full path still resolves it; only enumeration via `getdents64` is blind. The `CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes` marker captures exactly that.

Both members of Class II taint the kernel. `bpf_probe_write_user` sets the `TAINT_USER` bit (bit 9, value 512) globally, persistent for the lifetime of the kernel, accompanied by a `KERN_WARN` dmesg line per program. Any defender grep on `/proc/sys/kernel/tainted` or on `journalctl -k | grep bpf_probe_write_user` catches every Class II member at zero cost — which is why this class is comparatively easy to detect despite being hard to prevent.

## Detailed walkthrough: Class III — ringbuf exfiltration

This is the largest class, six representative chapters. Nothing in the kernel changes; the kernel state that the probe reads becomes visible to a peer process via ringbuf.

**ch03 — audit record exfil.** The POC attaches kprobes to `audit_log_start`, `audit_log_format`, and `audit_log_end`. Every kernel-side audit record-construction sequence — one `_start`, zero or more `_format`s, one `_end` — is copied out-of-band. An unprivileged peer with `CAP_BPF` sees every audit record the kernel builds, which on an SELinux-enforcing host includes every AVC decision, every execve, every config change. The normal access path (netlink multicast group with `CAP_AUDIT_READ`) requires privilege the peer does not have; the ringbuf bypass gives it that access.

**ch04 — phantom syscall.** The POC attaches a tracepoint on `sys_enter_write`. When the user buffer starts with `"PHANTOM\0"`, the handler tail-calls into a second BPF program that reads `current->cred->uid`, `current->cred->euid`, and `current->real_parent->comm` via `BPF_CORE_READ` and pushes them to a ringbuf. The unprivileged process issued one `write()` syscall. Three kernel-private fields left the kernel. Seccomp filters that allow `write()` see exactly one syscall — that is the threat model seccomp was designed for; the argument-content-based sidechannel is outside that model by design, not by failure.

**ch08 kprobe variant — keyring description leakage.** The LSM fmod_ret variant fails to load because BTF forward-declares `struct key` for the LSM hook. The workaround in `dBPF-pocs/pocs/ch08-keyring-heist-kprobe/` kprobes `key_task_permission`, takes `PT_REGS_PARM1` as opaque u64, masks the `key_ref_t` possession bits, and uses `BPF_CORE_READ(key, description)` and `BPF_CORE_READ(key, type, name)` against the full `struct key` in vmlinux.h (which DOES have the complete type info despite the LSM hook's argument-type metadata being forward-declared). Same kernel data, different program type, the verifier accepts. An unprivileged `keyctl print <id>` returns EACCES at the syscall level; the ringbuf contains the key's description and type.

**ch09 — cross-namespace PID mapping.** The POC attaches `SEC("raw_tp/sched_process_fork")` and emits when `task->pid_ns_for_children->ns.inum` differs from the parent's — which is exactly when a `CLONE_NEWPID` took effect. The event carries `(host_pid, ns_pid, ns_inum, comm)`. An unprivileged process inside the namespace sees itself as ns_pid=1; a peer on the host reads the ringbuf and learns the host_pid of that process. The trigger demonstrates end-to-end: spawn a victim via `unshare -Upf`, read the ringbuf, resolve `/proc/<host_pid>/status` (containing an `NSpid:` line that confirms the mapping), and send `kill -TERM` across the namespace boundary. The container thought it was isolated. The attacker on the host disagreed.

**ch11 — per-IRQ timing sidechannel.** The POC attaches kprobes to `handle_irq_event`, `__handle_irq_event_percpu`, and `handle_irq_event_percpu`. Each fire reads the irq number via `BPF_CORE_READ(desc, irq_data.irq)` and the driver name via the first `irqaction`'s `name` field, then bumps a per-CPU count and pushes a ringbuf event. The resolution is per-interrupt, per-CPU, per-driver, timestamped. `/proc/interrupts` gives cumulative counts sampled at whatever rate userspace polls; this primitive gives a timeline at kernel-clock precision. Cryptographic timing attacks (Brumley-Boneh cache timing), keyboard HID interarrival inference, and network pacing inference become academically reasonable because the raw signal is intact — no jitter from polling, no loss from rate limiting. The practical consequence is narrow; the primitive is small.

**ch16 — seccomp sidechannel.** The POC attaches kprobe plus kretprobe to `__secure_computing`. Entry captures `{pid, tid, tgid, comm, seccomp.mode}`; return emits the action (`SECCOMP_RET_KILL_PROCESS | SECCOMP_RET_ERRNO | SECCOMP_RET_ALLOW | SECCOMP_RET_LOG | SECCOMP_RET_TRACE | SECCOMP_RET_TRAP`). Aggregate over the filtered process's syscall corpus and you have a complete reconstruction of the effective seccomp policy for any tgid on the box. Seccomp's threat model is the filtered process itself; a privileged sibling with `CAP_BPF` is explicitly outside that threat model. The marker is `SECCOMP_SIDECHANNEL_PROVEN events=N`, not `SECCOMP_BYPASS_PROVEN`, for exactly that reason.

Class III's unifying property: the kernel's access-control invariants hold perfectly. Every syscall returns what it would have returned. Every enforcement point enforces. What leaks is confidentiality of kernel state — credentials, decisions, keyring metadata, namespace membership — to a peer process holding `CAP_BPF`. There is no mitigation at runtime once the program has loaded; mitigation must be at the load boundary (who can call `bpf(BPF_PROG_LOAD)`) or at the capability granting boundary (who holds `CAP_BPF` at all).

## Detailed walkthrough: Class IV — XDP packet-path interception

Two chapters. Both demonstrate that XDP runs below the IP stack, below netfilter, below `AF_PACKET` sockets, and therefore below `tcpdump`. The host's packet-capture observability is structurally blind to XDP-modified frames.

**ch05b — Ghost NIC covert channel.** The POC attaches `SEC("xdp")` to a veth interface. Bounds-checked parse: `ethhdr → iphdr (IPv4) → udphdr (dst_port == 31337) → 5-byte magic prefix "GHOST"`. On match, up to 47 bytes of command are copied into a ringbuf event, and the packet returns `XDP_DROP`. The sender inside the veth's namespace sends two packets; `tcpdump -i veth_g0 udp port 31337` captures zero; the loader's ringbuf receives two events each carrying the embedded command. The marker is `GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0`. The covert channel is bi-directional if you pair it with an `XDP_TX` program that rewrites outbound frames on a different ethertype.

**ch15 — NetNS VLAN ghost cross-namespace redirect.** The POC attaches XDP to the host-side of a veth. On receive, it parses the 802.1Q VLAN tag; if VID == 4242, it rewrites a fresh ethernet header at offset +4, calls `bpf_xdp_adjust_head(ctx, +4)` to strip the VLAN tag from the frame head, and calls `bpf_redirect_map(&tx_port, 0, 0)` to redirect the frame to an interface whose peer lives in a different network namespace. The orchestrator's monitoring on the vlan-aware bridge or host stack never observes the tagged frame; the destination namespace receives a clean, untagged ethernet frame. Across-namespace smuggling with the userspace network fabric unaware. Marker: `VLAN_GHOST_CROSSNS_PROVEN redirect_count=N`.

Both members of Class IV exploit architectural ordering, not implementation bugs. XDP was designed to run before the IP stack for performance; that design makes it invisible to everything above the IP stack for observability. Any attack-surface minimization on this class reduces to: restrict who can attach XDP programs (BPF LSM `bpf_prog_check`), audit `bpftool net show` at baseline, and capture packets at a layer XDP cannot touch — e.g., at a TAP on the physical switch, or at the NIC via an out-of-band diagnostic port.

## Detailed walkthrough: Class V — kernel event + userspace racer

One chapter, one primitive, but the most composite shape in the book.

**ch02 — OverlayFS copy-up race.** The BPF side in `dBPF-pocs/pocs/ch02-overlayfs/` kprobes three copy-up entry points on overlayfs (`ovl_copy_up`, `ovl_maybe_copy_up`, `ovl_copy_up_with_data`) and emits a ringbuf event carrying `(pid, comm, dentry name, inode number, mode, hook-id)` at the moment the kernel begins promoting a file from the lower layer to the upper layer. That event is a timing signal.

A userspace racer (privileged, on the host) drains the ringbuf and, on match against a target path, opens `<upperdir>/<basename>` with `O_WRONLY|O_TRUNC` and writes attacker-controlled bytes. The measured window between the kprobe fire and the container's subsequent read on the promoted inode is 50–140 µs on the linuxkit 6.12 test kernel with `SCHED_FIFO` CPU pinning on the racer; the racer wins roughly 30% of attempts on cold caches, higher under container load. When the racer wins, the container's `cat` on the promoted file returns the attacker's bytes. Marker: `[ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=N hits=M`.

The primitive is composite because neither half is sufficient alone. The BPF program cannot write kernel page cache — `bpf_probe_write_user` is userspace only, `bpf_probe_write_kernel` does not exist. The userspace racer cannot detect the exact moment of copy-up without the kprobe signal. Together they create a cooperative covert write to a file the container believes it owns. Every container runtime that uses overlayfs (Docker, containerd, CRI-O, Podman, runc) is exposed on a host where an unprivileged container runs alongside a privileged `CAP_BPF`-holding process.

## The three motions, restated precisely

Every primitive in this book reduces to one of three motions:

1. **Change the API return.** The kernel's computation happened; the caller sees a different answer. Classes I and IV belong here — Class I at a kernel function boundary, Class IV at the netdev layer. The truth lives inside the kernel; the caller sees the forged answer.
2. **Rewrite the userspace buffer.** The kernel wrote the correct answer; the BPF program changed it before the caller regained control. Class II. The kernel state is unchanged; the userspace view is corrupted post-hoc.
3. **Copy the decision out-of-band.** Nothing changes; a kernel-private value becomes visible to a peer process via ringbuf. Class III. The access-control invariants of the kernel hold perfectly; confidentiality is what breaks.

Class V is the composite: it uses motion #3 (ringbuf exfil as a timing signal) to trigger motion #2 (userspace-side mutation, though the write target is filesystem page cache rather than a syscall buffer). The novelty is operational — the cooperation between kernel and userspace — not mechanistic.

These three motions are what `CAP_BPF` grants. Every chapter in the book is a demonstration that granting `CAP_BPF` grants all three motions on a representative surface. That is the capability operating exactly as the kernel maintainers designed it. The book's deliverable is not the observation that this is possible; the book's deliverable is a reproducible harness that makes the observation concrete per-primitive, so that a defender sizing the `CAP_BPF` attack surface on their fleet can say specifically which primitives fire and which do not on their kernels.

## Why a taxonomy matters for defenders

Detections built against the class generalize; detections built against individual primitives age. A kretprobe attached to any function on `/sys/kernel/debug/error_injection/list` is suspicious regardless of which function, because the class of intent (Class I override) is the same. One `bpftool prog list` rule that alerts on any kretprobe with `bpf_override_return` in its instruction stream catches every Class I primitive in this book and any future one built on the same mechanism.

Similarly, one dmesg/taint-word rule catches every Class II primitive on the box forever. One rule on unexpected XDP attachments catches every Class IV. One rule on unexpected kprobe attachments to `audit_log_*`, `__secure_computing`, `key_task_permission`, and similar decision-point functions catches the bulk of Class III.

Class V is the hardest to detect as a class because its BPF-side signature is "a kprobe that pushes to ringbuf" — indistinguishable from legitimate observability. The detection there has to be downstream: watch for privileged userspace processes that open `upperdir/` files shortly after an `ovl_copy_up` event observed on the same host. That is correlation, not a single-signal alert.

The taxonomy is what makes the detection-engineering conversation tractable. Every chapter in the book is an instance; the five classes are the patterns; the three motions are the mechanisms. Build rules against the patterns, not the instances.



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

## Detection engineering: one rule per class

The taxonomy gives the defender a short detection catalog. Every rule below is one line of `bpftool`, `auditctl`, or a grep against `/proc/sys/kernel/tainted` or `journalctl -k`. None requires BPF-specific tooling beyond what ships with `linux-tools-<kernel-version>`.

### Class I detector

```
bpftool prog list -j | jq '.[] | select(.type=="kretprobe") | select(.name | test("override|flip|forge"))'
```

Flags kretprobes whose BPF name hints at override intent. False positives are rare on a production host; legitimate kretprobes in observability stacks are usually named after what they observe (`trace_sched_wakeup`, `trace_syscall_enter`), not after the action. Augment with instruction-stream inspection: `bpftool prog dump xlated id <N>` and grep for `bpf_override_return` — a non-zero count on a production program is an alert.

The verbose form of the rule also watches for attach-to-function matches against `/sys/kernel/debug/error_injection/list`:

```
cat /sys/kernel/debug/error_injection/list > /tmp/allowlist
for id in $(bpftool prog list -j | jq -r '.[] | select(.type=="kretprobe") | .id'); do
  bpftool prog show id "$id" -j | jq -r '.attach_name' | \
    grep -Ff /tmp/allowlist >/tmp/match && \
    echo "ALERT: prog $id kretprobe on $(cat /tmp/match) — override-eligible"
done
```

Two findings on a typical production box: (1) Cilium's datapath attaches a few kretprobes that are on the allowlist but use `bpf_override_return` only for specific error-injection tests during startup, not in steady state; the alert fires and needs an allowlist for known Cilium program tags. (2) Datadog's runtime-security agent uses `bpf_override_return` on a small set of syscall entries to intercept specific tracee actions; if the vendor's deployment is known, whitelist the tag; otherwise treat as unknown. After tuning, legitimate users produce a stable allowlist of tags and the rule is quiet.

### Class II detector

```
awk '{if (and($1, 512)) print "TAINT_USER set at boot="strftime("%F %T", $0)}' /proc/sys/kernel/tainted
```

One line, one alert. The `TAINT_USER` bit survives across program unloads and cannot be cleared without rebooting. If the defender's fleet has never used `bpf_probe_write_user` in legitimate tooling, this rule produces no false positives — every positive is a primitive fire.

The dmesg variant is more granular because it names the program:

```
journalctl -k --since=-1h | grep -E "bpf_probe_write_user" | awk '{print $NF}' | sort -u
```

The kernel emits the program's BPF name (or truncated tag if unnamed) in the warning line. An unexpected name is an alert.

### Class III detector

This is the hardest class because ringbuf reads of kernel state are the single most common BPF pattern, and 99% of uses are legitimate observability. The rule has to be about *which kernel functions* the probe is attached to.

```
bpftool prog list -j | jq '.[] | select(.type | test("kprobe|tracepoint|fentry|raw_tp"))
  | {id, name, attach_func: .attach_func_name}' > /tmp/bpf-attach.json
```

The output is a list of `(id, name, attach_func)` triples. Compare against a baseline of known-good attachments (Cilium, Datadog, Falco, node-exporter, bpftrace invocations). Everything not on the baseline is suspicious. Decision-point function attachments are particularly suspect: `audit_log_*`, `__secure_computing`, `avc_has_perm`, `key_task_permission`, `copy_namespaces`, `handle_irq_event*`. Any attach to those functions from a program outside an allowlist of known sensors is an alert.

The false-positive rate after tuning depends on how chatty the site's observability stack is. A site running three independent eBPF-based agents may have 200+ attachments in baseline. The rule catches new-attachment deltas; tuning is iterative.

### Class IV detector

```
bpftool net show -j | jq '.[] | select(.xdp) | {dev, xdp: .xdp.id, mode: .xdp.mode}'
```

Lists every netdev with an XDP program attached. Baseline the set once; alert on changes. On a typical k8s worker node the only XDP programs are Cilium's (if used) — the baseline is small and the signal-to-noise is high.

The more specific rule watches for unexpected attachment on a veth whose name matches container runtime patterns (`veth*`, `cni0`, `docker0`, `cbr0`). A container attaching XDP to its own veth is the exact shape of ch05b's covert channel.

### Class V detector

Downstream correlation, not a single-signal alert. The rule has to observe:

1. A kprobe attachment on an overlayfs copy-up function (`ovl_copy_up*`), via the Class III rule.
2. Privileged userspace processes opening files under any `upperdir/` path mount in `/proc/mounts` shortly after the kprobe fires (via auditd on `open(2)` with `O_WRONLY` on paths matching `/upper/`).

The time correlation is sub-millisecond; the audit records need to be timestamped and joined. This is a SIEM query, not a shell one-liner. The signal is strong when it fires — legitimate tools do not open container upperdir files moments after a copy-up event.

## What a sixth class would look like

The five classes cover the primitives demonstrated in this book. The taxonomy's claim is structural: every current BPF primitive reduces to one of the three motions (return-override, user-buffer rewrite, out-of-band copy), with Classes IV and V as specializations of Classes I and III. The claim is not that no future class will exist.

Two categories of future primitive could form a sixth class:

**Network-layer rewrite with ordering guarantees.** XDP can drop, pass, redirect, or transmit, but it does not rewrite-in-place with strong ordering against multiple observers. A future primitive that leverages the `bpf_redirect_map` plus a tc-egress rewrite program to present different packet content to different observers — one version to a monitoring tap, another to the actual destination — would be a new class. The kernel surface for this exists (tc on egress runs after XDP on ingress, and CPUMAP plus DEVMAP allow different paths per consumer); the demonstrated primitive does not exist as of the book's publication.

**Kernel-state write via kfunc.** `CAP_BPF` does not include generic kernel-memory write. The helper `bpf_probe_write_user` targets userspace only; `bpf_probe_write_kernel` does not exist. But individual kfuncs can expose narrow write paths: e.g., `bpf_task_storage_create` writes to per-task storage, `bpf_inode_storage_store` writes to per-inode storage. A kfunc that writes to a kernel-internal struct (even a narrow one) would create a new class of primitive: mutation of kernel state via BPF. The kernel maintainers have been conservative about adding such kfuncs, for exactly this reason. A future permissive kfunc is the most likely vector for a sixth class.

Both would require new BPF helpers that do not exist today. Both would be subject to the same threat model (`CAP_BPF` is the gate; adding a permissive kfunc widens the surface). The taxonomy survives their addition; a sixth class is a new row, not a restructure.

## Cross-references

- Chapter 21 is the opposite accounting: primitives that did not fire on this kernel, and the specific environmental reasons they were refused.
- Chapter 22 maps each class to concrete mitigations a defender can deploy at the capability-grant boundary, at the program-load boundary, and at runtime.
- The harness entry for each chapter (`dBPF-pocs/harness/proof.py`) is the single source of truth for proof markers and expected BEFORE/AFTER outputs. When in doubt about what a chapter actually demonstrates, read the `Poc(...)` entry and the chapter's `trigger.sh`.

