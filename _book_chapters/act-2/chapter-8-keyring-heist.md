---
layout: book
title: "Chapter 8: Keyring Heist"
date: 2025-02-08
---

# Chapter 8: Reading the Kernel Keyring via BPF

> **See also**: [Blog post]({{ site.baseurl }}/keyring-heist.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch08-keyring-heist-kprobe) · [Chapter 21]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)

> **Proof status**: All three variants proved on Ubuntu 6.17.0-29-generic aarch64 (Lima VM); `ch08-keyring-heist`, `ch08-keyring-heist-kprobe`, and `ch08-keyring-heist-lsm`. The kprobe variant sidesteps the BTF FWD issue on `struct key` via `PT_REGS_PARM1` + CO-RE. The LSM variant uses a raw-context workaround to avoid touching the FWD-typed argument at ctx[0]. The syscall boundary enforces; the decision point leaks.

libbpf rejected the LSM fmod_ret load with `arg0 type FWD is not a struct`. The kernel's BTF forward-declares `struct key` for the LSM hook. Kprobe on `key_task_permission` with opaque `PT_REGS_PARM1` and `BPF_CORE_READ` against the full struct in `vmlinux.h` loaded clean; same data, different verifier posture.

That sentence is the whole finding. The rest of this chapter is how I got there and what actually works, because I spent longer than I wanted arguing with the verifier about a type mismatch that had nothing to do with my program.

## The natural path, and why it died

I wanted a BPF LSM program on `security_key_permission`. Sit on the hook the kernel invokes for every keyring permission decision, fmod_ret, read `struct key` cleanly off arg0, forward the serial and description to userspace. This is the program I would show an auditor.

It did not load. The verifier output was unambiguous:

```
libbpf: prog 'lsm_key_perm': BPF program load failed: Invalid argument
libbpf: prog 'lsm_key_perm': -- BEGIN PROG LOAD LOG --
arg#0 reference type('FWD key') size cannot be determined: -22
```

`struct key` is fully defined in `include/linux/key.h`. It is fully defined in my generated `vmlinux.h`. The verifier does not care about either of those. It cares about the BTF metadata for the LSM hook's parameter, and in the BTF I had, that parameter was a `BTF_KIND_FWD`; a forward declaration with no size. fmod_ret type-matching refuses to bind an argument whose size it cannot determine. That refusal is correct. It is also absolute.

I spent a while trying to see whether I could rebuild vmlinux BTF with pahole in a different order. I did not get there. The hook's argument BTF is baked into the kernel image. The LSM path was dead on this kernel image, full stop.

## What loaded

Kprobe on `key_task_permission`. Same data path reaches here; the LSM hook is downstream. The signature is:

```c
int key_task_permission(const key_ref_t key_ref,
                        const struct cred *cred,
                        enum key_need_perm need_perm);
```

`key_ref_t` is an opaque pointer with its low bits used as possession flags. From a kprobe, `PT_REGS_PARM1(ctx)` gives me an `unsigned long` with no type expected. I mask the flags, cast to `struct key *`, and `BPF_CORE_READ` resolves against the full struct definition in vmlinux.h. The verifier is happy because the kprobe argument is `struct pt_regs *`, not a kernel struct; the FWD issue never enters the picture.

```c
SEC("kprobe/key_task_permission")
int BPF_KPROBE(kp_key_task_permission)
{
    unsigned long raw = (unsigned long)PT_REGS_PARM1(ctx);
    struct key *k = (struct key *)(raw & ~3UL);

    __u32 serial = BPF_CORE_READ(k, serial);

    struct key_type *kt = BPF_CORE_READ(k, type);
    const char *tn = BPF_CORE_READ(kt, name);
    bpf_probe_read_kernel_str(&e->type_name, sizeof(e->type_name), tn);

    const char *desc = BPF_CORE_READ(k, description);
    bpf_probe_read_kernel_str(&e->description, sizeof(e->description), desc);

    return 0;
}
```

`keyctl list @u` in one shell produced ringbuf events in the other: serial numbers, type names (`user`, `keyring`, `logon`), descriptions. The kernel's access check ran to completion and returned its real answer. I did not mutate any permission decision.

## What I gave up to get it

The kprobe fires before the security decision, not as the security decision. For observation this is fine. If I were writing an enforcement bypass I would need `bpf_override_return`, which needs `ALLOW_ERROR_INJECTION` on `key_task_permission`; and it is not there.

## The LSM workaround (ch08-keyring-heist-lsm)

The raw-context workaround that landed in `ch08-keyring-heist-lsm` bypasses `BPF_PROG()` entirely and uses a raw context signature: `int lsm_key_permission(unsigned long long *ctx)`. With raw context, the program manually reads only the context slots it needs at known offsets, skipping the FWD-typed arg0:

```c
SEC("lsm/key_permission")
int lsm_key_permission(unsigned long long *ctx)
{
    unsigned int need_perm = (unsigned int)ctx[2];  // arg2: need_perm
    int ret = (int)ctx[3];                          // arg3: chain result
    // ctx[0] is key_ref (FWD type); deliberately skipped
    // ctx[1] is cred; skipped
    ...
}
```

This loads successfully because the verifier never sees a typed access to the FWD `key_ref_t` at ctx[0]. The trade-off: the LSM variant cannot read the key's serial number or type name. Those require dereferencing `key_ref`, which lives at ctx[0]. But the LSM variant can mutate; it can flip deny to allow via fmod_ret. The kprobe variant can observe the full key metadata. Two variants, complementary capabilities.

## Detection

Kprobe attachment on `key_task_permission` is itself the signal. `bpftool prog show type kprobe` lists the attached program. `/sys/kernel/tracing/kprobe_events` shows the registered probe by name. `bpf()` syscall auditing with `BPF_PROG_LOAD` records the load.

There is no runtime signal from the reads themselves. `BPF_CORE_READ` is a kernel-memory copy into BPF map space and leaves no audit trace. The primitive's footprint is entirely at attach.

> **See also**: [POC source; ch08-keyring-heist-kprobe](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch08-keyring-heist-kprobe) · Harness entry: `Poc("ch08k", ...)` in `dBPF-pocs/harness/proof.py`
