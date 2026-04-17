---
layout: book
title: "Chapter 20: What We Proved — The Taxonomy"
date: 2026-01-10
---

# Chapter 20: What We Proved — The Taxonomy

> **See also**: [Blog post]({{ site.baseurl }}/the-taxonomy.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20 — Taxonomy]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-3/chapter-22-the-defender-playbook.html)

The harness ran twenty-five POCs on kernel 6.12.54-linuxkit aarch64 via Docker Desktop. Twenty produced `_PROVEN` proof markers on stdout; five were honest skips due to platform limitations (SELinux not enforcing, LSM hook BTF incomplete, no RAPL on aarch64, no ACPI on aarch64, no module signature enforcement). Chapter 21 accounts for the skips. This chapter walks the twenty that produced effects, puts them in five primitive classes, and classifies each into one of four honesty categories. The five-class taxonomy and the four-category system together are the durable artifact of this book.

## The rule for inclusion

Each trigger must print a BEFORE line and an AFTER line showing state that actually changed, and a machine-grep-able `CHxx_PROVEN` marker must appear on stdout before the loader is torn down. Anything less is observation, not a proven primitive. "The kprobe fired and we logged the arguments" is not a primitive in this book; that is a telemetry feature. The bar is: userspace or the kernel saw something different after the probe attached than it saw before.

## The four-category system

Every POC in the harness carries a `category` field in its `Poc(...)` dataclass. The category classifies the *honesty* of what was demonstrated — how close the POC's kernel surface is to the real-world attack surface the chapter describes. The four categories are:

- **REAL** (13 POCs): Hooks the actual kernel subsystem the chapter targets, and can observe or mutate. These are the strongest demonstrations — the hook, the surface, and the effect are all production-representative. Examples: ch01 (cap_capable), ch02 (overlayfs copy-up), ch04 (phantom syscall via `__arm64_sys_write`), ch05 (cgroup `cpu.stat` rewrite), ch05b (XDP ghost NIC), ch07 (devcgroup LSM), ch08 (keyring heist LSM), ch10 (getdents64 inode cloak), ch12 (signed-driver-swap LSM), ch15 (netns VLAN ghost XDP), ch17 (ACPI/firmware).
- **OBSERVER** (5 POCs): Hooks the real subsystem but cannot mutate — the error-injection allowlist blocks `bpf_override_return` on the target, or atomic context prevents mutation. The POC reads kernel-internal state and exfiltrates it, which is Class III behavior. Examples: ch03 (audit record exfil), ch06 (SELinux — skips on non-SELinux kernels), ch09 (PID-NS cross-mapping), ch11 (IRQ timing sidechannel), ch16 (seccomp decision leak).
- **ILLUSION** (3 POCs): Hooks the real syscall entry point but only forges the return value — kernel state is unchanged. The illusion fools userspace consumers of the syscall return but does not alter what the kernel actually did. Examples: ch12s (`__arm64_sys_finit_module` return forge), ch14 (`__arm64_sys_sched_setscheduler` return forge), ch18 (`__arm64_sys_getuid`/`__arm64_sys_geteuid` return forge). Note: all three ILLUSION POCs hook aarch64-specific syscall symbols (`__arm64_sys_*`); on x86 the equivalent symbols are `__x64_sys_*`.
- **ANALOG** (4 POCs): Uses a real BPF primitive on a substitute or synthetic surface, because the chapter's natural kernel surface is absent on this test kernel. Examples: ch06s (synthetic deny+flip via `SEC("lsm.s/file_open")`), ch07w (synthetic deny+flip via `SEC("lsm/inode_mknod")`), ch13a (fake sensor file substituting for RAPL), ch17a (fake firmware file substituting for ACPI/request_firmware).

The category is orthogonal to the primitive class. A Class I primitive can be `real` (ch01), `illusion` (ch14), or `analog` (ch06s). A Class III primitive can be `real` (ch04) or `observer` (ch03). The category tells you how much to trust the demonstration; the class tells you what the primitive does.

## The taxonomy

### Class I — Return-value override at the API boundary

The kernel's computation happened; the caller sees a different answer. This class is implemented with `kretprobe + bpf_override_return` (requires the target to be on `/sys/kernel/debug/error_injection/list`), or with the BPF LSM `fmod_ret` attach type (requires `CONFIG_BPF_LSM=y` and the target hook to be present), or with `XDP_DROP` at the netdev layer. All three share a shape: observe the kernel decision, replace the return value, let the caller proceed on the forged answer.

Representative chapters: ch01 (cap_capable override — marker `CH01_WEAPON_PROVEN flips=N`, category `real`), ch14 (`__arm64_sys_sched_setscheduler` forge — marker `SCHED_WEAPON_PROVEN flips=N`, category `illusion`, aarch64-only), ch18 (`__arm64_sys_getuid`/`__arm64_sys_geteuid` forge — marker `TOKEN_FORGE_PROVEN uid_forges=N`, category `illusion`, aarch64-only), ch06s synthetic (`SEC("lsm.s/file_open")` deny+flip — marker `CH06_CONCEPT_PROVEN`, category `analog`), ch07w (`SEC("lsm/inode_mknod")` deny+flip — marker `CH07_CONCEPT_PROVEN before_rc=N after_rc=0`, category `analog`), ch12s (`__arm64_sys_finit_module` return forge — marker `CH12_CONCEPT_PROVEN`, category `illusion`, aarch64-only). The native ch08 LSM variant (`SEC("lsm/key_permission")`) would belong here but skips on this kernel due to incomplete BTF for the hook's argument types.

The framing matters: this class is an illusion against userspace consumers of the syscall return. Kernel-side decisions that happen later in the call chain — a subsequent LSM check on `current->cred`, a capability check performed inside the kernel against live credentials — are unaffected. The override lies to the userspace caller. It does not change what the kernel actually did.

### Class II — Userspace buffer rewrite via `bpf_probe_write_user`

The kernel produces a correct result and writes it to a userspace buffer. A BPF program waits for the syscall to return, computes where the buffer lives, and mutates it before the caller regains control. The caller then reads the mutated buffer as if it were the kernel's answer.

Representative chapters: ch05 (cgroup `cpu.stat` rewrite — marker `CH05_PROVEN before_usage=X after_usage=0 zeroed=yes`, category `real`), ch10 (getdents64 `d_reclen` swallow to hide directory entries — marker `CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes`, category `real`), ch13a (fake sensor file substituting for RAPL powercap — marker `CH13_ANALOG_PROVEN`, category `analog`), ch17a (fake firmware file via `sys_enter_openat` path rewrite — marker `CH17_ANALOG_PROVEN`, category `analog`).

The primitive needs a stable window: the kernel has written the buffer, the process has not yet been returned control, the memory page is still mapped and not about to be unmapped. `kretprobe` or `tp/syscalls/sys_exit_*` gives that window.

### Class III — Ringbuf exfiltration of kernel-internal state

Observation, not modification. A BPF program reads a kernel structure that userspace could not otherwise see — a credential, a key description, a seccomp decision for a sibling thread — and copies it out-of-band through a BPF ringbuf that the privileged loader is draining. The victim syscall returns whatever it would have returned; the fact of the read is the primitive.

Representative chapters: ch03 (FUSE/audit record exfil via fentry — marker `CH03_PROVEN variant=fentry before=N after=M`, category `observer`), ch04 (phantom syscall field leakage via `__arm64_sys_write` — marker `CH04_PROVEN leaked_fields=N`, category `real`), ch08k (keyring description leakage via kprobe on `key_task_permission` — marker `CH08_CONCEPT_PROVEN events=N`, category `real`), ch09 (PID-namespace cross-mapping via `SEC("raw_tp/sched_process_fork")` — marker `CH09_PROVEN host_pid=N mapped=yes`, category `observer`), ch11 (per-IRQ timing sidechannel via kprobes on `handle_irq_event*` — marker `CH11_PROVEN events=N unique=M per_event_timing=yes`, category `observer`), ch16 (seccomp decision for another TID via kprobe on `__secure_computing` — marker `SECCOMP_SIDECHANNEL_PROVEN events=N`, category `observer`).

Important framing for ch16 specifically: seccomp's threat model is the filtered process itself. A privileged sibling holding `CAP_BPF` is explicitly outside that threat model. This primitive sits inside the gap the seccomp design already acknowledges; it is not a failure of seccomp. The chapter labels the marker `SIDECHANNEL` rather than `BYPASS` for exactly that reason.

### Class IV — Packet-path interception (XDP)

The BPF program runs as a peer to the netdev, below the IP stack and below every userspace observer. `XDP_DROP` makes packets vanish before `tcpdump` on the host sees them; `XDP_TX` and `bpf_redirect_peer` reroute them. Because XDP executes in the driver's rx path (or veth tx peer), packet captures taken above that layer do not see modifications.

Representative chapters: ch05b (ghost-NIC covert channel — packets vanish from `tcpdump` but are logged to ringbuf, marker `GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0`), ch15 (netns VLAN ghost cross-namespace redirect — marker `VLAN_GHOST_CROSSNS_PROVEN redirect_count=N`).

### Class V — Kernel-event-triggered userspace racer

The most composite primitive in the book. A BPF program watches a kernel event (a specific `kprobe` fires, a tracepoint records a specific inode being touched) and emits to ringbuf. A privileged userspace racer drains the ringbuf and, on seeing the target event, wins a write race against the legitimate code path — it writes to the promoted inode before the victim process reads.

Representative chapter: ch02 (OverlayFS copy-up race — ringbuf fires on `ovl_copy_up_one`, racer writes a payload to the upper-layer inode before the container reads back, marker `[ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=N hits=M`).

## Detailed walkthrough: Class I — return-value override

Six POCs implement Class I on this kernel (a seventh, ch08's LSM variant, skips). Each uses either a kretprobe with `bpf_override_return` on a function in the error-injection allowlist, or BPF LSM `fmod_ret` on an LSM hook. The detailed walkthroughs below cover the four that are discussed in depth; ch06s and ch07w are synthetic/analog variants described in the category system above.

**ch01 — cap_capable.** The POC in `dBPF-pocs/pocs/ch01-mirror-controls/` was the first chapter in the book, and it hit the first honest limit. `cap_capable` is not in `/sys/kernel/debug/error_injection/list` on linuxkit 6.12 aarch64 — the kprobe attaches, but `bpf_override_return` from the kretprobe is ignored by the kernel. The POC still logs every capability check that would have been flipped; that log alone is the `CH01_WEAPON_PROVEN flips=N` marker. The LSM variant in `ch01-mirror-controls-lsm/` attaches `SEC("lsm/capable")` with target-tgid filtering and actually returns 0 for the target — and because `CONFIG_BPF_LSM=y` on this kernel, the fmod_ret takes effect. A file `cat` from the target tgid succeeds even when DAC or an active LSM policy would normally deny it. That is the real Class I behavior; the original chapter is observational on this kernel. Category: `real`.

**ch14 — sched_setscheduler forge.** `__arm64_sys_sched_setscheduler` *is* on the error-injection allowlist (syscall entry points almost always are). The POC in `dBPF-pocs/pocs/ch14-sched-fifo/` attaches a kretprobe and returns 0. The caller's `chrt -f 50 $$` gets rc=0, prints "SCHED_FIFO set". The kernel's `task_struct->policy` is unchanged; `sched_getscheduler($$)` on the same pid returns the real policy; `/proc/[pid]/sched` shows the real policy. Every userspace consumer of `sched_setscheduler`'s return value is fooled; every kernel-side check on `task->policy` is not. This is the clean case of the class: the lie is at the API boundary, the truth lives inside the kernel. Category: `illusion`. Note: the hook symbol `__arm64_sys_sched_setscheduler` is aarch64-specific; on x86 the equivalent is `__x64_sys_sched_setscheduler`.

**ch18 — getuid token forge.** `__arm64_sys_getuid` and `__arm64_sys_geteuid` are both on the error-injection allowlist. The POC in `dBPF-pocs/pocs/ch18-token-bypass/` kretprobes both and returns 0. `id` reports `uid=0(root) gid=1001`. The `gid=1001` is the tell — the POC did not hook `getgid` or `getegid`, so the real gid shows through. A defender who reads both uid and gid and expects them to be consistent catches the half-hooked forge immediately. Kernel-side `current->cred->uid` is the real unprivileged uid; VFS, LSM, and capability checks all see the truth. `cat /etc/shadow` still returns `EACCES`. Category: `illusion`. Note: the hook symbols `__arm64_sys_getuid` and `__arm64_sys_geteuid` are aarch64-specific; on x86 the equivalents are `__x64_sys_getuid` and `__x64_sys_geteuid`.

**ch12s — finit_module return forge.** `__arm64_sys_finit_module` is on the error-injection allowlist. The POC in `dBPF-pocs/pocs/ch12-signed-driver-swap-syscall/` kretprobes it and returns 0 on any `insmod` attempt against a non-ELF blob. `insmod` reports rc=0; `lsmod` is empty; `/proc/modules` shows no new module; `dmesg` shows the kernel's original ENOEXEC rejection. The userspace illusion is that the module loaded; any orchestrator that post-checks via `lsmod` catches it. Category: `illusion`. Note: the hook symbol `__arm64_sys_finit_module` is aarch64-specific; on x86 the equivalent is `__x64_sys_finit_module`. The original LSM variant for module signature (flipping `mod_verify_sig`'s return) is a skip on this kernel because signature enforcement is off — Chapter 21 accounts for it.

Across these six, the common pattern: userspace reads a forged API return. Kernel-side enforcement reads real state. Anything that gates decisions on the kernel's actual state (credentials, policy, loaded modules) is unaffected. Anything that trusts the libc syscall wrapper's return value is fooled. Three of the six (ch12s, ch14, ch18) are categorized as `illusion` because they hook real aarch64-specific syscall entry points but only forge the return value — the kernel never actually performed the requested operation. Two (ch06s, ch07w) are `analog` because they demonstrate the flip shape on a synthetic surface. One (ch01) is `real`.

## Detailed walkthrough: Class II — userspace buffer rewrite

Four POCs, one primitive. `bpf_probe_write_user` waits for a syscall to finish, looks up the userspace buffer the kernel just wrote to, and mutates it before the caller regains control. Two are `real` category (ch05, ch10); two are `analog` (ch13a, ch17a).

**ch05 — cgroup cpu.stat readback rewrite.** The POC walks `current->files->fdt->fd[fd]->f_path.dentry->d_name.name` via `BPF_CORE_READ` to identify reads of files named `cpu.stat`. On sys_exit_read with a successful return, the program calls `bpf_probe_write_user` to overwrite the user buffer with `"usage_usec 0\nuser_usec 0\nsystem_usec 0\n"`. The cgroup scheduler's accounting is unchanged — the cgroup keeps getting throttled if it exceeds quota. The observation plane is what lies. Every userspace tool that reads `cpu.stat` (node-exporter, cAdvisor, Datadog, Netdata, Sysdig, Grafana agent) reports zero CPU usage. Same mechanism trivially extends to `memory.current`, `io.stat`, `cpu.pressure` — swap the literal in the bounded compare.

**ch10 — getdents64 d_reclen swallow.** The POC attaches paired tracepoints on `sys_enter_getdents64` and `sys_exit_getdents64`. Entry stashes `(ubuf, count)` in a per-(pid, tgid) hash map. Exit walks the returned dirent stream (up to 64 entries per call, a verifier-bounded loop) and, for each entry whose name matches a hidden-set member, rewrites the *previous* entry's `d_reclen` to encompass the hidden entry. Userspace walkers advance by `d_reclen` each iteration and skip over the hidden file. The file is still on disk; `stat` by full path still resolves it; only enumeration via `getdents64` is blind. The `CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes` marker captures exactly that.

Both members of Class II leave a kernel log trace. When a program using `bpf_probe_write_user` is loaded, the kernel emits a `pr_warn_ratelimited` message naming the process and PID that loaded it (via `bpf_get_probe_write_proto` in `kernel/trace/bpf_trace.c`). Note: in Linux 6.12, this helper does *not* set the `TAINT_USER` bit (bit 6) despite what some older documentation suggests — the warning is a dmesg log line, not a taint flag. Any defender grep on `journalctl -k | grep bpf_probe_write_user` catches every Class II program load at zero cost — which is why this class is comparatively easy to detect despite being hard to prevent.

## Detailed walkthrough: Class III — ringbuf exfiltration

This is the largest class, six representative chapters. Nothing in the kernel changes; the kernel state that the probe reads becomes visible to a peer process via ringbuf.

**ch03 — audit record exfil.** The POC attaches kprobes to `audit_log_start`, `audit_log_format`, and `audit_log_end`. Every kernel-side audit record-construction sequence — one `_start`, zero or more `_format`s, one `_end` — is copied out-of-band. An unprivileged peer with `CAP_BPF` sees every audit record the kernel builds, which on an SELinux-enforcing host includes every AVC decision, every execve, every config change. The normal access path (netlink multicast group with `CAP_AUDIT_READ`) requires privilege the peer does not have; the ringbuf bypass gives it that access.

**ch04 — phantom syscall.** The POC attaches a tracepoint on `sys_enter_write`. When the user buffer starts with `"PHANTOM\0"`, the handler tail-calls into a second BPF program that reads `current->cred->uid`, `current->cred->euid`, and `current->real_parent->comm` via `BPF_CORE_READ` and pushes them to a ringbuf. The unprivileged process issued one `write()` syscall. Three kernel-private fields left the kernel. Seccomp filters that allow `write()` see exactly one syscall — that is the threat model seccomp was designed for; the argument-content-based sidechannel is outside that model by design, not by failure.

**ch08k — keyring description leakage (kprobe variant).** The native LSM fmod_ret variant (`SEC("lsm/key_permission")`) skips because BTF forward-declares `struct key` for the LSM hook's argument type. The workaround in `dBPF-pocs/pocs/ch08-keyring-heist-kprobe/` kprobes `key_task_permission`, takes `PT_REGS_PARM1` as opaque u64, masks the `key_ref_t` possession bits, and uses `BPF_CORE_READ(key, description)` and `BPF_CORE_READ(key, type, name)` against the full `struct key` in vmlinux.h (which DOES have the complete type info despite the LSM hook's argument-type metadata being forward-declared). Same kernel data, different program type, the verifier accepts. An unprivileged `keyctl print <id>` returns EACCES at the syscall level; the ringbuf contains the key's description and type. Category: `real` (the kprobe variant hooks the real kernel function, not a synthetic surface).

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

Similarly, one dmesg grep for `bpf_probe_write_user` catches every Class II program load on the box. One rule on unexpected XDP attachments catches every Class IV. One rule on unexpected kprobe attachments to `audit_log_*`, `__secure_computing`, `key_task_permission`, and similar decision-point functions catches the bulk of Class III.

Class V is the hardest to detect as a class because its BPF-side signature is "a kprobe that pushes to ringbuf" — indistinguishable from legitimate observability. The detection there has to be downstream: watch for privileged userspace processes that open `upperdir/` files shortly after an `ovl_copy_up` event observed on the same host. That is correlation, not a single-signal alert.

The taxonomy is what makes the detection-engineering conversation tractable. Every chapter in the book is an instance; the five classes are the patterns; the three motions are the mechanisms. Build rules against the patterns, not the instances.



This is not a new idea. The `d_reclen` swallow trick for `getdents64` has been in rootkit proof-of-concepts since at least 2016. My contribution in chapter 10 is a modern-kernel CO-RE reproduction on 6.12 aarch64 with ringbuf evidence and reproducible before/after counts, not the primitive itself. Cite the prior art if you build on it.

## The meta-result

Every primitive in this book is one of three motions: change the syscall return, rewrite the user buffer, or copy the decision out-of-band. These three motions are what `CAP_BPF` grants. The twenty-five POCs (twenty demonstrated, five skipped) across eighteen chapters are demonstrations that granting `CAP_BPF` grants access to all three motions across a representative surface of kernel subsystems. That is the capability, operating as designed. The four-category system (`real`, `observer`, `illusion`, `analog`) ensures honest labelling of what each demonstration actually proved. The blue-team implication is in chapter 22.

## Master table

All 25 POCs, mapped to category, primitive class, SEC hooks, BPF primitive used, and effect. Status is `effect_demonstrated` unless noted as `skip`.

| POC | Category | Class | SEC / attach | BPF primitive | Effect (marker) | Notes |
|-----|----------|-------|-------------|---------------|-----------------|-------|
| ch01 | real | I | kprobe+kretprobe `cap_capable`; LSM variant: `SEC("lsm/capable")` | `bpf_override_return` / LSM fmod_ret | cap_capable return forged to 0 (`CH01_WEAPON_PROVEN flips=N`) | |
| ch02 | real | V | kprobe `ovl_copy_up*` + ringbuf | ringbuf + userspace racer | Copy-up race won, payload injected (`[ch02] PWNED path=... bytes=... hits=...`) | |
| ch03 | observer | III | kprobe `audit_log_start/format/end` | ringbuf exfiltration | Audit records exfiltrated (`CH03_PROVEN variant=fentry before=N after=M`) | Cannot mutate; read-only observation |
| ch04 | real | III | tracepoint `__arm64_sys_write` | tail-call + ringbuf | Phantom-syscall kernel fields leaked (`CH04_PROVEN leaked_fields=N`) | aarch64-only hook symbol |
| ch05 | real | II | tracepoint `sys_exit_read` | `bpf_probe_write_user` | cgroup `cpu.stat` user buffer zeroed (`CH05_PROVEN ... zeroed=yes patched_events=N`) | |
| ch05b | real | IV | `SEC("xdp")` on veth | `XDP_DROP` + ringbuf | Packets vanish from tcpdump (`GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0`) | |
| ch06 | observer | I | `SEC("lsm/file_permission")` + `SEC("lsm/inode_permission")` | LSM fmod_ret | **SKIP** — SELinux not enforcing on this kernel | |
| ch06s | analog | I | `SEC("lsm.s/file_open")` (sleepable, needs `bpf_d_path`) | LSM fmod_ret | Synthetic deny+flip demonstrated (`CH06_CONCEPT_PROVEN`) | Sleepable LSM; only POC using `lsm.s/` |
| ch07 | real | I | `SEC("lsm/inode_mknod")` | LSM fmod_ret | **counted via ch07w** | |
| ch07w | analog | I | `SEC("lsm/inode_mknod")` | LSM fmod_ret | Synthetic deny+flip demonstrated (`CH07_CONCEPT_PROVEN before_rc=N after_rc=0`) | Same binary as ch07, different trigger |
| ch08 | real | I | `SEC("lsm/key_permission")` | LSM fmod_ret | **SKIP** — BTF forward-declares `struct key` | Would be Class I if it fired |
| ch08k | real | III | kprobe `key_task_permission` | ringbuf exfiltration | Keyring description leaked (`CH08_CONCEPT_PROVEN events=N`) | Workaround for ch08's BTF issue |
| ch09 | observer | III | `SEC("raw_tp/sched_process_fork")` | ringbuf exfiltration | Cross-namespace PID mapping exposed (`CH09_PROVEN host_pid=N mapped=yes`) | Cannot mutate; read-only observation |
| ch10 | real | II | tracepoint `sys_enter/exit_getdents64` | `bpf_probe_write_user` | `d_reclen` swallow hides entries (`CLOAK_PROVEN before_count=4 after_count=2 hidden=2`) | |
| ch11 | observer | III | kprobe `handle_irq_event*` | ringbuf exfiltration | Per-IRQ timing sidechannel (`CH11_PROVEN events=N unique=M`) | Cannot mutate; atomic/IRQ context |
| ch12 | real | I | `SEC("lsm/kernel_read_file")` | LSM fmod_ret | **SKIP** — no module signature enforcement | |
| ch12s | illusion | I | kretprobe `__arm64_sys_finit_module` | `bpf_override_return` | finit_module return forged (`CH12_CONCEPT_PROVEN`) | aarch64-only; kernel state unchanged |
| ch13 | — | — | kprobe `powercap_get_max_power_uw` | — | **SKIP** — no RAPL on aarch64 | x86-only subsystem |
| ch13a | analog | II | tracepoint `sys_enter/exit_read` | `bpf_probe_write_user` | Fake sensor file rewrite (`CH13_ANALOG_PROVEN`) | Synthetic /tmp file, not real RAPL |
| ch14 | illusion | I | kretprobe `__arm64_sys_sched_setscheduler` | `bpf_override_return` | sched_setscheduler return forged (`SCHED_WEAPON_PROVEN flips=N`) | aarch64-only; kernel state unchanged |
| ch15 | real | IV | `SEC("xdp")` on veth | `bpf_redirect_map` + `bpf_xdp_adjust_head` | Cross-namespace VLAN redirect (`VLAN_GHOST_CROSSNS_PROVEN redirect_count=N`) | |
| ch16 | observer | III | kprobe+kretprobe `__secure_computing` | ringbuf exfiltration | Seccomp decision exfiltrated (`SECCOMP_SIDECHANNEL_PROVEN events=N`) | Seccomp threat model excludes CAP_BPF sibling |
| ch17 | real | — | kprobe `request_firmware` / `acpi_evaluate_object` | — | **SKIP** — no ACPI/firmware symbols on aarch64 | x86-only subsystem |
| ch17a | analog | II | tracepoint `sys_enter_openat` | `bpf_probe_write_user` | Fake firmware file path swap (`CH17_ANALOG_PROVEN`) | Synthetic /tmp file, not real firmware |
| ch18 | illusion | I | kretprobe `__arm64_sys_getuid` + `__arm64_sys_geteuid` | `bpf_override_return` | Token-bypass uid forged (`TOKEN_FORGE_PROVEN uid_forges=N`) | aarch64-only; kernel state unchanged |

**Category counts**: real=13, observer=5, illusion=3, analog=4. **Status counts**: effect_demonstrated=20, skip=5, fail=0.

## Onward

Chapter 21 does the opposite accounting: the five POCs that did not produce effects on this kernel, and the specific kernel-environment reasons they were refused. Chapter 22 maps the five classes above to the mitigations that actually apply to each.

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
journalctl -k --since=-1h | grep -E "bpf_probe_write_user" | sort -u
```

One line, one alert. When a BPF program using `bpf_probe_write_user` is loaded, the kernel emits a `pr_warn_ratelimited` dmesg line naming the loading process and its PID (e.g., `<comm>[<pid>] is installing a program with bpf_probe_write_user helper that may corrupt user memory!`). Note: in Linux 6.12, `bpf_probe_write_user` does not set the `TAINT_USER` bit in `/proc/sys/kernel/tainted` -- the detection signal is the dmesg warning, not a taint flag. If the defender's fleet has never used `bpf_probe_write_user` in legitimate tooling, this rule produces no false positives -- every warning line is a primitive load. An unexpected process name is an alert.

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

## Interaction between classes

The five classes were presented separately because each maps cleanly to one of the three motions. In practice, a multi-stage attack does not pick one class and stay in it. Primitives from different classes compose, and the composition is often more dangerous than either primitive alone. Two concrete scenarios from the POC corpus illustrate this.

**Scenario A: Class III provides targeting intelligence for a Class I strike.**

Chapter 09's cross-namespace PID mapping primitive (`dBPF-pocs/pocs/ch09-pid-ns-spy/`) attaches `SEC("raw_tp/sched_process_fork")` and emits `(host_pid, ns_pid, ns_inum, comm)` whenever a process forks into a new PID namespace. The output is a live map from container-internal PIDs to host PIDs. On its own, that is Class III: nothing changes, confidentiality of the namespace mapping breaks.

Now compose it with Chapter 14's `sched_setscheduler` forge (`dBPF-pocs/pocs/ch14-sched-fifo/`), which kretprobes `__arm64_sys_sched_setscheduler` and returns 0 for a caller-pid filter. The forge is only effective when the BPF program knows the host-side PID of the target process. A container's process sees itself as ns_pid=1; it does not know its host PID. An attacker on the host side, after draining ch09's ringbuf to learn the mapping, can write the host PID into the ch14 program's BPF map via `bpf_map_update_elem` before the target process calls `sched_setscheduler`. From that moment, any call by that process to promote its own scheduling class returns `SCHED_FIFO` success. The kernel's actual `task_struct->policy` is unchanged — but every orchestration layer that makes scheduling decisions based on the syscall return value (systemd, kubernetes CFS quota enforcement agents, container cgroup-v2 schedulers) is looking at a lie.

Neither ch09 nor ch14 alone accomplishes this. The Class III ringbuf gives the attacker a fact the Class I program needed. This is the general pattern: observation-class primitives are reconnaissance; override-class primitives are the strike; the two are designed to be used together.

**Scenario B: Class IV conceals the evidence of a Class V write race.**

Chapter 02's OverlayFS racer (`dBPF-pocs/pocs/ch02-overlayfs/`) demonstrates the composite Class V primitive: a kprobe fires on `ovl_copy_up_one`, a userspace racer wins the write window, the container reads back the attacker's payload. The proof marker is `[ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=N hits=M`. When the racer wins, the write to the upper layer is a real filesystem event — `inotifywait`, auditd on `open(O_WRONLY)`, and any network-based forensics agent that streams file-event telemetry to a SIEM will see it.

Chapter 05b's ghost NIC covert channel (`dBPF-pocs/pocs/ch05b-ghost-nic/`) demonstrates that XDP at the veth interface drops packets before `tcpdump` on the host sees them. Apply that to a forensic scenario: a network-based agent (Falco, Tetragon, Sysdig's network exporter) that streams events via UDP to an off-host collector will generate a UDP packet for each file-event it captures. If the attacker attaches an XDP program to the veth that the forensics agent uses for exfiltration, and filters for UDP to the collector's IP and port, those forensic packets return `XDP_DROP`. The collector sees nothing. The local agent generated the event; the packet was silently discarded before it left the host.

The composition: ch02 writes the payload (Class V), ch05b drops the forensic capture of that write (Class IV). From the SIEM's perspective, the file mutation never happened. From the host's perspective, every access-control invariant held — the racer won a legitimate write race, and XDP dropped UDP traffic, both of which are technically unremarkable operations in isolation. The combination is forensically dark.

These two scenarios are representative of a class of compositions, not exhaustive. The general principle is: any Class III primitive that leaks a piece of kernel state becomes a targeting oracle for any other primitive that takes a PID, inode number, address, or policy value as input. Any Class IV primitive that intercepts a network path becomes an evidence-erasure mechanism for any other primitive whose effects would otherwise be telemetered over the network. The taxonomy classifies individual primitives; composing them is a design exercise for the attacker.

A defender facing this must instrument the composition, not just the primitives. An IDS rule that fires on ch02's write-race signature in isolation may still miss the attack if ch05b is also running and the alert is delivered over UDP. Defenders who use BPF-based telemetry on hosts where an attacker holds `CAP_BPF` are in a position where the attack surface and the monitoring surface overlap. That is the uncomfortable structural fact the composition scenarios surface.

## What the taxonomy does not cover

The five classes describe the observable effects of BPF programs that have already been loaded and attached. They do not describe the full attack lifecycle. Three aspects of that lifecycle fall outside the taxonomy's scope, intentionally.

**Persistence.** None of the eighteen chapters demonstrates how a BPF program survives the loader process exiting. Pinning a program or map to `/sys/fs/bpf/` keeps the file descriptor alive after the loading process dies; a second process can open the pinned path and re-attach without reloading. Wrapping the loader in a systemd service with `Restart=always` provides OS-level restartability. A cron job that re-runs `trigger.sh` every five minutes provides crude but effective reload persistence. None of these mechanisms are novel, and none are BPF-specific — the same patterns apply to any privileged userspace daemon. They are real attack-lifecycle stages. A more complete treatment of the threat would add a persistence chapter for each demonstrated primitive. This book's scope ends at demonstrating the effect; persistence is out of scope and left to the reader.

**Evasion of BPF-specific detectors.** The detection engineering section in this chapter describes rules based on `bpftool prog list`, `bpftool net show`, and taint-word inspection. A sufficiently motivated attacker who holds `CAP_BPF` can attach a BPF program to the `bpf(2)` syscall tracepoint itself and suppress its own appearance in those lists. Specifically: a `SEC("tp/syscalls/sys_exit_bpf")` program that watches for the calling process's own tgid, and on `bpf_cmd == BPF_PROG_GET_NEXT_ID` or `BPF_MAP_GET_NEXT_ID`, rewrites the returned ID to skip the attacker's programs. This is a Class I override applied to the introspection interface itself. The detector becomes a lie. The primitive is demonstrably feasible — it is the same mechanism as ch18's uid-forge applied to a different syscall — but implementing it would add a significant complexity tax to any attack, and this book's threat model did not assume a fully evasion-capable attacker. The taxonomy does not cover it. A future chapter should.

**Privilege escalation from non-BPF to BPF.** Every chapter in this book assumes that `CAP_BPF` is already held by the attacker's process. How that capability was obtained is outside the threat model. In practice, an attacker who starts without `CAP_BPF` must either exploit a kernel vulnerability to escalate, find a SUID binary that grants the capability, or compromise a process that already holds it. Those are conventional privilege escalation paths; BPF is not involved in them. The taxonomy classifies what `CAP_BPF` enables once held, not how it is obtained. A security analysis of a production system must account for both questions, but they are distinct questions and this book addresses only the second.

These three gaps are not flaws in the taxonomy. The taxonomy's claim is bounded: given a process holding `CAP_BPF`, these are the classes of effect it can produce on the kernel's API boundary, on userspace buffers, on kernel-internal confidentiality, on the packet path, and on kernel-timed write races. Everything outside that perimeter is either a different problem domain (persistence, evasion, privilege acquisition) or a future chapter.

## How the taxonomy ages

The five classes are not a closed enumeration. They are the classes that current BPF helpers make possible. The taxonomy's structural claim — that all current effects reduce to three motions — holds because today's helpers are bounded in what they can write to. When the helper surface expands, the taxonomy must be re-examined.

**The `bpf_probe_write_user` precedent.** Before that helper existed, Class II did not exist. Prior to its introduction in Linux 4.8, BPF programs could observe kernel state (proto-Class III) and filter packets (proto-Class IV), but they could not write to userspace memory. A single helper added an entire class of primitive. The lesson is that helper additions are class-creation events, not just surface-expansion events.

**The hypothetical `bpf_probe_write_kernel`.** The helper that would most directly create a new class is one that writes to kernel-virtual addresses from a BPF program — the kernel-side analogue of `bpf_probe_write_user`. This helper does not exist and is explicitly not planned; the kernel maintainers have consistently rejected proposals for it on the grounds that it would bypass all kernel-internal invariants. If it were added, it would create Class VI: kernel-state mutation. Every in-kernel cache, every credential structure, every security label would be mutable from a BPF program. The three-motion model would need a fourth motion — "rewrite the kernel's own view." The precedent shows the taxonomy is sensitive to exactly this kind of helper.

**Narrow kfuncs as partial Class VI precursors.** Several kfuncs introduced in recent kernel versions provide narrow kernel-state writes without being generic memory-write helpers. `bpf_task_storage_store` writes to a per-task BPF-managed storage area. `bpf_inode_storage_store` writes to a per-inode BPF-managed storage area. These do not write to arbitrary kernel structs; they write to BPF-internal bookkeeping that the kernel consults only when another BPF program reads it back. An attacker who could chain "write to per-task BPF storage" with "a second BPF program that reads that storage and makes a kernel-visible decision" gets a narrow form of kernel-state influence. It does not meet the Class VI bar today because the influence is mediated entirely within the BPF subsystem and does not propagate to the kernel's enforcement layer without another BPF program. But the shape is recognizable. Future kfuncs that allow BPF programs to write to security labels, namespace membership, or capability sets would cross the Class VI threshold.

**The taxonomy's claim under expansion.** The taxonomy's three motions are defined at the level of *what changes in the system's observable state*: the API return value, the userspace buffer content, the confidentiality of kernel state, the packet-path behavior, the filesystem content. This framing is more durable than an enumeration of helpers. A new helper creates a new class only if it enables an effect that falls outside the three existing motions. `bpf_probe_write_user` created Class II because user-buffer mutation was not covered by any prior motion. `bpf_override_return` created Class I. Future helpers that provide narrow writes within already-classified domains will expand an existing class. Only helpers that enable a structurally new effect on a structurally new observable — such as kernel-internal state mutation — would require a new class. The motions stay; new classes are additions, not replacements.

## Comparison to MITRE ATT&CK mapping

Each class in the taxonomy maps to one or more ATT&CK techniques. The mapping is approximate — ATT&CK describes adversary behavior at a campaign level, not at the helper-function level — but it gives defenders a bridge to existing detection frameworks and SIEM correlation logic that is already built around ATT&CK technique IDs.

**Class I — Return-value override.** The primary technique is T1548, Abuse Elevation Control Mechanism. The sub-technique structure in ATT&CK does not yet enumerate BPF-based mechanism abuse, but the parent technique covers cases where a process manipulates the OS's elevation or permission-checking mechanism to obtain an outcome it was not entitled to. ch01's `cap_capable` override and ch14's `sched_setscheduler` forge are clean instances: the kernel's enforcement computation ran, but the caller received a false grant. The secondary technique is T1562, Impair Defenses. ch12's `finit_module` forge belongs here — the kernel rejected a module load, but the caller was told it succeeded, which could cause a security monitoring agent that validates module loads via rc to believe a controlled-load succeeded when it did not. Both T1548 and T1562 have detection guidance in ATT&CK's mitigation notes that apply at a policy level (capability restrictions, module-signing enforcement) and align with the Class I mitigations in chapter 22.

**Class II — Userspace buffer rewrite.** The primary technique is T1565, Data Manipulation, sub-technique T1565.001 (Stored Data Manipulation) or T1565.003 (Runtime Data Manipulation). ch05's cgroup `cpu.stat` rewrite is T1565.003: the data in transit between the kernel and the monitoring agent is altered at runtime, not at rest. ch10's `getdents64` swallow is also T1565.003 — the directory listing returned to the file browser is manipulated in flight. A secondary technique is T1070, Indicator Removal. The `d_reclen` swallow hides file-system indicators from enumeration tools in the same way that log-deletion removes indicators from log files; the mechanism is different but the ATT&CK intent bucket is the same.

**Class III — Ringbuf exfiltration.** Two techniques apply depending on the specific primitive. ch08's keyring description leakage and ch04's credential-field read are instances of T1003, OS Credential Dumping — specifically the kernel-side variant where credentials are read directly from kernel memory rather than from LSASS or `/etc/shadow`. ch09's cross-namespace PID mapping is T1057, Process Discovery, with the additional precision that it crosses isolation boundaries the OS is supposed to maintain: the ATT&CK technique covers enumerating processes; this primitive specifically enumerates processes in namespaces that the attacker's namespace should not be able to see.

**Class IV — XDP packet-path interception.** The covert-channel variant (ch05b) maps to T1205, Traffic Signaling, which covers primitives that use specific network traffic patterns as a trigger or exfiltration channel while appearing silent to observers. The XDP drop of non-magic traffic and pass of magic-prefix traffic is structurally identical to the T1205 pattern. The cross-namespace redirect variant (ch15) maps to T1572, Protocol Tunneling, in the sense that traffic is encapsulated or rerouted through a layer that observers cannot instrument; the VLAN-stripping redirect is a tunneling operation performed at XDP layer.

**Class V — Kernel-event racer.** The copy-up race in ch02 maps most cleanly to T1574, Hijack Execution Flow, sub-technique T1574.006 (Dynamic Linker Hijacking) by loose analogy, or more precisely to the spirit of T1574 as a whole: the execution flow of the victim container's read is hijacked by inserting attacker-controlled content into the path the victim traverses. The copy-up race is a time-of-check-to-time-of-use exploit against the OverlayFS promotion path; the ATT&CK sub-technique tree does not yet have a specific entry for TOCTOU-based filesystem hijacking, but the parent technique T1574 is the right bucket.

The ATT&CK IDs are not a perfect fit because ATT&CK was built primarily around Windows user-mode adversary behavior and has limited granularity on kernel-mode Linux primitives. The mapping is a practical bridge, not a theoretical equivalence. Defenders who already have ATT&CK-based SIEM rules can use these IDs to tag BPF-related alerts in the existing framework rather than building a parallel classification system.

## Per-class frequency in the wild

An honest assessment of the five classes requires distinguishing between how often a class appears in legitimate software and how often it appears in adversarial software. The rarity gradient is not uniform, and it correlates inversely with the alarm level a defender should assign.

**Class III is by far the most common.** Every eBPF-based observability tool is a Class III primitive operating on sanctioned kernel state. Cilium's Hubble network observability drains ringbuf events from kprobes attached to socket and networking functions. Datadog's runtime security agent attaches kprobes to `execve`, `open`, and `connect` and drains ringbuf to a userspace event pipeline. Falco, Tetragon, Sysdig, and node-exporter all do the same in various forms. The distinction between a sanctioned Class III primitive and the ch03/ch04/ch09/ch11/ch16 primitives in this book is entirely at the level of *which* kernel functions are probed and *what* is done with the exfiltrated data, not at the level of the mechanism. This creates the false-positive problem for Class III detection: any rule that fires on "a BPF program draining ringbuf from a kernel decision-point function" will fire on every commercial observability agent on the box. Detection engineering for Class III is a needle-in-a-haystack problem, not a binary one.

**Class IV is the second most common in legitimate software.** Cilium's datapath uses XDP for high-performance packet processing on every k8s worker node that runs it. Facebook's Katran load balancer is an XDP program. XDP-based DDoS mitigation appliances from Cloudflare, Fastly, and various open-source projects (xdp-tools, xdp-cpumap-tc) attach XDP programs to production interfaces. The baseline XDP attachment count on a production k8s node is often non-zero before any attack is considered. The Class IV detection rule (baseline `bpftool net show`, alert on delta) is tractable because XDP attachments are relatively stable — they are installed during daemon startup and removed at shutdown, not continuously rotated. But the baseline is not empty.

**Class I is rare in legitimate software.** The primary legitimate use case for `bpf_override_return` is error-injection testing: a kernel developer or a chaos engineering tool intentionally makes a function return a specific error to test recovery paths. This is a development and testing workflow, not a production workflow. On a production host, a kretprobe that calls `bpf_override_return` on a function in `/sys/kernel/debug/error_injection/list` has almost no legitimate justification. The Class I detection rule, after a single baseline pass to remove known error-injection test harnesses, should be close to zero false positives in production. Every positive after that baseline is worth investigating.

**Class II is almost never legitimate.** The only common legitimate use of `bpf_probe_write_user` in production software is ad-hoc `bpftrace` scripts that a developer attaches for a debugging session and detaches shortly after. No commercial observability tool uses `bpf_probe_write_user` in steady state — the helper is too dangerous, too detectable (dmesg warning), and too fragile (memory-layout sensitivity). The Class II detection rule (dmesg grep for `bpf_probe_write_user`) has a near-zero false-positive rate on any host that does not permit live `bpftrace` debugging sessions. In a hardened environment where `bpftrace` is not installed or not accessible to non-root users, any `bpf_probe_write_user` warning in dmesg is an incident.

**Class V has no legitimate use case.** The OverlayFS copy-up race in ch02 serves no purpose outside of proof-of-concept research and adversarial use. No observability tool, no scheduler, no storage agent writes to container upperdir files based on copy-up kprobe events. The Class V detection correlation — kprobe on `ovl_copy_up*` plus privileged open of a file under `upperdir/` shortly after — has a theoretical false-positive rate of approximately zero. Any firing of that correlation is a confirmed incident. The alarm level for Class V should be the highest of the five, even though (or because) it is the rarest class in production software.

The rarity gradient runs from Class III (ubiquitous, low alarm per-event) through Class IV (common, moderate alarm on delta) through Class I (rare, high alarm after baseline) through Class II (almost none, very high alarm) to Class V (none, immediate incident). A defender sizing alarm thresholds should map them to this gradient, not treat all five classes equivalently. A flat policy that requires manual review of every BPF program attachment will drown on Class III events. A tiered policy — Class III triggers automated fingerprinting and comparison against a known-good registry, Class II and V trigger pager escalation — is operationally sustainable.

## Cross-references

- Chapter 21 is the opposite accounting: the five primitives that did not fire on this kernel (ch06, ch08, ch12, ch13, ch17 natives), and the specific environmental reasons they were refused.
- Chapter 22 maps each class to concrete mitigations a defender can deploy at the capability-grant boundary, at the program-load boundary, and at runtime.
- The harness entry for each chapter (`dBPF-pocs/harness/proof.py`) is the single source of truth for proof markers and expected BEFORE/AFTER outputs. When in doubt about what a chapter actually demonstrates, read the `Poc(...)` entry and the chapter's `trigger.sh`.

