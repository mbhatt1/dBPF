---
layout: book
title: "Keyring Heist"
date: 2025-02-08
poc_dir: dBPF-pocs/pocs/ch08-keyring-heist-kprobe
---

# Keyring Heist

> **See also**: [Book chapter]({{ site.baseurl }}/book/act-2/chapter-8-keyring-heist.html) · [Skip accounting (Ch 21)]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) · [Workaround POC](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch08-keyring-heist-kprobe)

libbpf rejected the LSM fmod_ret load with `arg0 type FWD is not a struct`. The kernel's BTF forward-declares `struct key` for the LSM hook. Kprobe on `key_task_permission` with opaque `PT_REGS_PARM1` and `BPF_CORE_READ` against the full struct in `vmlinux.h` loaded clean — same data, different verifier posture.

That sentence is the whole finding. The rest of this post is how I got there and what actually works, because I spent longer than I wanted arguing with the verifier about a type mismatch that had nothing to do with my program.

## The natural path, and why it died

I wanted a BPF LSM program on `security_key_permission`. The intent was the clean one: sit on the hook the kernel invokes for every keyring permission decision, fmod_ret, read `struct key` cleanly off arg0, forward the serial and description to userspace. This is the program I would show an auditor. It's the one that would be easy to defend as an "observation-only" instrument on a production box.

It did not load. The verifier output was unambiguous:

```
libbpf: prog 'lsm_key_perm': BPF program load failed: Invalid argument
libbpf: prog 'lsm_key_perm': -- BEGIN PROG LOAD LOG --
arg#0 reference type('FWD key') size cannot be determined: -22
```

`struct key` is fully defined in `include/linux/key.h`. It's fully defined in my generated `vmlinux.h`. The verifier doesn't care about either of those; it cares about the BTF metadata for the LSM hook's parameter, and in the BTF I had, that parameter was a `BTF_KIND_FWD` — a forward declaration with no size. fmod_ret type-matching refuses to bind an argument whose size it cannot determine. That refusal is correct. It's also absolute. There is no verifier flag to override it. The LSM path was dead on this kernel image, full stop.

I spent a while trying to see whether I could rebuild vmlinux BTF with pahole in a different order to promote the FWD to a full definition. I didn't get there. The hook's argument BTF is baked into the kernel image; I would have had to rebuild the kernel itself. For a POC whose goal is "read keyring state from a BPF program," that's the wrong investment.

## What loaded

Kprobe on `key_task_permission`. Same data path reaches here; the LSM hook is downstream of this function on the permission-check code path. The signature is:

```c
int key_task_permission(const key_ref_t key_ref,
                        const struct cred *cred,
                        enum key_need_perm need_perm);
```

`key_ref_t` is an opaque pointer with its low 2 bits used as possession flags. From a kprobe, `PT_REGS_PARM1(ctx)` gives me an `unsigned long` with no type expected; I mask the flags, cast to `struct key *`, and then `BPF_CORE_READ` resolves against the full struct definition in vmlinux.h. The verifier is happy because the kprobe argument is `struct pt_regs *`, not a kernel struct — the FWD issue never enters the picture.

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

That's the read. `keyctl list @u` in one shell produced ringbuf events in the other: serial numbers, type names (`user`, `keyring`, `logon`), descriptions. The payload chase (`k->payload.data[0]` for `user`-type keys) resolves cleanly via CO-RE against the 6.12 aarch64 vmlinux.h I generated on the test box. I did not mutate any permission decision; the kernel's access check ran to completion and returned its real answer.

## What I gave up to get it

The kprobe fires before the security decision, not as the security decision. This is a narrow distinction that matters for any primitive that would try to mutate outcomes — `bpf_override_return` on `key_task_permission` would need it in `ALLOW_ERROR_INJECTION`, and it isn't there. For a read-only observation POC this is fine; the ringbuf captures everything I wanted from the data path and the kernel's verdict stays intact. If I were writing an enforcement bypass I would need a different primitive.

## Detection

Kprobe attachment on `key_task_permission` is itself the signal. `bpftool prog show type kprobe` lists the attached program; `/sys/kernel/tracing/kprobe_events` shows the registered probe by name. `bpf()` syscall auditing with `BPF_PROG_LOAD` records the load; a policy that rejects kprobes on kernel-internal keyring symbols catches this at load time. There is no runtime signal from the reads themselves — `BPF_CORE_READ` is a kernel-memory copy into BPF map space and leaves no audit trace. The primitive's footprint is entirely at attach, which is where defense belongs.

---
**Related material**
- Full chapter: [Chapter 8 — Keyring Heist]({{ site.baseurl }}/book/act-2/chapter-8-keyring-heist.html)
- Workaround POC: [dBPF-pocs/pocs/ch08-keyring-heist-kprobe/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch08-keyring-heist-kprobe)
- Harness entry: `Poc("ch08k", ...)` in `dBPF-pocs/harness/proof.py`
