---
layout: book
title: "Keyring Heist"
date: 2025-02-08
---

Act II: Kernel Intrusion

**Chapter 9: Reading the Kernel Keyring via BPF**

Reading the kernel keyring from BPF is not a new idea. I've seen variants of this in talks going back to at least 2019 — Brendan Gregg's bpftrace one-liners touch keyring state, and there was a LinuxCon Europe talk in 2020 that walked through `key_task_permission` as an observation point. What I was interested in was getting a clean LSM attach on `security_key_permission` and reading the payload. That turned out to be harder than expected for a BTF reason I hadn't hit before.

I started with an `SEC("lsm/key_permission")` program. libbpf on my system (v1.3.0, built against clang 16) rejected it at load with:

```
libbpf: prog 'lsm_key_perm': BPF program load failed: Invalid argument
libbpf: prog 'lsm_key_perm': -- BEGIN PROG LOAD LOG --
arg#0 reference type('FWD key') size cannot be determined: -22
```

This is the error message when the BTF describing the hook argument is a forward declaration, not a full struct definition. `struct key` is defined in `include/linux/key.h`, but for LSM BTF purposes the kernel was exposing it as `FWD key` — the full type wasn't reachable through the LSM hook's BTF. I don't fully understand why; my suspicion is that the LSM hook signature was declared before `struct key` in the BTF-generating translation unit, and `pahole` emitted a forward-declaration record. I didn't track this down further because I found a workaround.

The workaround is to drop from `lsm/` to `kprobe/` on `key_task_permission`. That function has signature `int key_task_permission(const key_ref_t key_ref, const struct cred *cred, enum key_need_perm need_perm)`, which means `PT_REGS_PARM1` is an opaque `unsigned long` containing a `key_ref_t` (which is `struct key *` with the possession bit in the low bit). Since I'm reading via kprobe, I don't need the LSM BTF; I use `vmlinux.h` and `BPF_CORE_READ` directly against `struct key`:

```c
struct key *key = (struct key *)(PT_REGS_PARM1(ctx) & ~1UL);
__u32 serial = BPF_CORE_READ(key, serial);
```

This is the teaching point: BTF as exposed through LSM attach points can lag the fuller BTF you get from vmlinux.h. When LSM rejects with FWD, drop to kprobe with PT_REGS_PARMn and read the struct through CO-RE. You lose the clean LSM semantics (kprobes fire before the security decision rather than being the security decision) but you get the payload access.

What I observed. On my test box (Debian 12, kernel 6.1.0-17-amd64), attaching the kprobe and triggering `keyctl list @u` produced serial numbers and description pointers for each key in the user keyring. Reading the payload requires chasing `key->payload.data[0]`, which for `user`-type keys is a `struct user_key_payload` with an `rcu` and a `datalen`. That's a kernel-internal layout and CO-RE handles it — `BPF_CORE_READ(key, payload.data[0])` resolves correctly against the 6.1 vmlinux.h.

```c
SEC("kprobe/key_permission")
int bpf_override_key_perm(struct pt_regs *ctx) {
    return 0; // always allow access
}

char LICENSE[] SEC("license") = "GPL";
```

Note on the `return 0` override above: same caveat as chapter 7 — this is a kprobe return override and needs `CONFIG_BPF_KPROBE_OVERRIDE=y` plus the function being on the error-injection list. `key_task_permission` is not on that list in stock kernels. For the read-only observation path, return value doesn't matter; the program runs, BPF_CORE_READ executes, the map gets the serial and description, and the syscall proceeds normally.

Detection. The load-time detection is the same story as any BPF attach: `bpf()` audit, kprobe creation in `/sys/kernel/tracing/kprobe_events`, and tools like tracee or Falco noticing a kprobe on `key_task_permission` specifically. There is no runtime signal from the read itself — BPF_CORE_READ is a copy from kernel memory into BPF map space and leaves no audit trace.

Dead end I hit and am noting for completeness: I spent two hours trying to attach to `__key_instantiate_and_link` to catch key creation rather than permission checks. That function isn't exported and its parameters include a non-trivial `struct key_preparsed_payload` that I couldn't read cleanly with CO-RE because several of its fields are unions. If you want create-time visibility, `security_key_alloc` is the better hook and didn't hit the FWD issue for me.