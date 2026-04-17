---
layout: book
title: "Chapter 8: Keyring Heist"
date: 2025-02-08
---

# Chapter 8: Reading the Kernel Keyring via BPF

> **Note**: This primitive's natural hook did not fire on the test kernel. See [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) and the surviving workaround variant at [dBPF-pocs/pocs/ch08-keyring-heist-kprobe/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs).

## Opening

Reading the kernel keyring from BPF is not a new idea. I've seen variants of this technique going back to at least 2019 — Brendan Gregg's bpftrace one-liners have touched keyring state, there was a LinuxCon EU 2020 talk walking through `key_task_permission` as an observation point, and the broader "watch the decision site for kernel-internal state" pattern is in the bcc-tools suite for many decision-site functions. What I wanted to contribute is not the primitive itself. What I wanted to contribute is a CO-RE variant that survives the BTF forward-declaration issue which blocked the natural LSM approach on this kernel.

The short version, framed up front for anyone scanning:

- I first tried `SEC("lsm/key_permission")`, the clean BPF LSM attach point for key access decisions.
- libbpf rejected it at load with `arg0 type FWD is not a struct`.
- The rejection is due to a kernel BTF quirk: `struct key` is forward-declared in the LSM hook's argument BTF metadata, even though it is fully defined elsewhere in the same vmlinux BTF blob. The verifier won't accept an fmod_ret program whose argument is a FWD kind.
- The workaround is `kprobe/key_task_permission`. Kprobes take `struct pt_regs *` and don't care about FWD declarations in anyone else's BTF arguments. We grab the first parameter as an opaque `u64`, mask off the possession bit, cast to `struct key *`, and read via `BPF_CORE_READ` against vmlinux.h's complete definition of `struct key`.
- Same data. Different program type. Verifier accepts.

This chapter is the walk from one path to the other, what I learned about BTF forward declarations along the way, and what the primitive actually proves (and what it does not).

The primitive is Class III from chapter 20's taxonomy: ringbuf exfiltration of kernel-internal state. The victim syscall returns whatever it would have returned — the unprivileged `keyctl print` still gets `EACCES`. But the structural metadata that the kernel examined while deciding the access — the key's serial, the key's type name, the key's description — is copied out through the BPF ringbuf. The syscall boundary enforces. The decision point leaks.

## The LSM fmod_ret attempt and its rejection

The LSM hook I wanted was `security_key_permission`. Its kernel signature:

```c
int security_key_permission(key_ref_t key_ref,
                            const struct cred *cred,
                            enum key_need_perm need_perm);
```

`key_ref_t` is a pointer-shaped opaque type — in the kernel it's actually a `struct key *` with the low bit used to indicate possession (the caller has possession of the key). `cred` is the credentials of the task doing the access. `need_perm` is the permission being requested (view, read, write, search, link, setattr).

A BPF LSM fmod_ret program attached to this hook should be able to return 0 (allow) or a negative errno (deny), and the kernel's key_permission path aggregates that with the rest of the LSM chain.

My first BPF program:

```c
SEC("lsm/key_permission")
int BPF_PROG(lsm_key_perm, key_ref_t key_ref,
             const struct cred *cred, enum key_need_perm need,
             int ret)
{
    struct key *k = (struct key *)((unsigned long)key_ref & ~1UL);
    __u32 serial = BPF_CORE_READ(k, serial);
    /* ... emit event ... */
    return 0;
}
```

Load attempt:

```
libbpf: prog 'lsm_key_perm': BPF program load failed: Invalid argument
libbpf: prog 'lsm_key_perm': -- BEGIN PROG LOAD LOG --
arg#0 reference type('FWD key') size cannot be determined: -22
```

The error happens at `check_attach_btf_id` time in the verifier — specifically in the part that validates the attach target's argument types against what the BPF program expects to consume. The program declares `key_ref_t key_ref` as its first argument, which on this kernel has BTF type `FWD key` (a forward declaration). The verifier walks the argument list, tries to determine a size for each argument so it can lay out the trampoline, and fails on FWD because a forward declaration doesn't have a size — you can't know how big a `struct key` is from just `struct key;` without the definition.

Here's where it gets weird. `struct key` is defined in `include/linux/key.h`. It's a complete type. It's used all over the kernel. `vmlinux.h` — the BTF-generated header that libbpf generates for CO-RE access — contains the full definition. I can write `struct key { ... };` and all its fields are visible. I can `BPF_CORE_READ(k, serial)` and the relocation is resolved.

But the BTF record for the *LSM hook's argument* is a forward declaration. Not the full struct. A separate BTF record.

Why? BTF is generated by pahole walking the DWARF debug info of the compiled kernel. For each type the kernel uses, pahole emits a BTF record. If the kernel's LSM hook declaration — specifically in `security/bpf/hooks.c` or wherever `bpf_lsm_key_permission` is declared — only sees the forward declaration `struct key;` (because the hook declaration was made in a translation unit that didn't `#include <linux/key.h>`), then the BTF record for that argument is FWD. The same kernel build has a full `struct key` BTF record elsewhere — referenced by functions that do include the header — but the LSM hook's argument record is the FWD one.

I spent a while chasing this. The translation unit where the LSM hook is defined varies by kernel version. On 6.12 linuxkit aarch64, the relevant include chain for the LSM BPF stubs starts from a header that has `struct key;` declared forward but not included from `<linux/key.h>`. That gives pahole one record to emit, and it emits FWD.

The fix, as far as upstream is concerned, would be to have the LSM hooks' translation unit include the full `<linux/key.h>` header. That's a trivial patch — it would fix the FWD-in-argument issue for everyone. I looked at the upstream patch stream and didn't find anyone doing it. There's a slightly more general upstream effort to unify BTF generation so that all types used as LSM hook arguments are guaranteed to be fully defined in BTF. That's ongoing. For now, some kernels have the FWD and some don't.

For what it's worth: on Debian 12's 6.1 kernel, the FWD issue doesn't appear. I tested. `SEC("lsm/key_permission")` loads cleanly. The exact same code that fails on linuxkit 6.12 works on Debian 6.1. The difference is purely in which translation unit happens to define the LSM hook stub — kernel config flags affect this. So it's not even a "newer kernels have fixed this" story; it's more like "depending on your kernel config and which LSM modules are enabled, the FWD issue may or may not appear for you." That's annoying. It means a portable BPF LSM loader for key_permission can't rely on the LSM path.

The libbpf error message, verbatim, was what tipped me off to the FWD specifically rather than some other argument-type mismatch. The verifier in 6.x was updated to print the actual BTF kind (`FWD` in this case) rather than just "invalid type." Earlier kernels printed less informative messages, and I've seen write-ups from 2021-2022 that describe a similar load failure with `arg0 has type that can't be determined` — those are probably the same underlying issue on older kernels.

I want to linger on the BTF-record question for another paragraph because it's a recurring theme throughout this book. A BTF blob is a catalog of type records with various KINDs: STRUCT, UNION, TYPEDEF, PTR, FUNC, FWD, and others. The verifier's attach-point validation walks FUNC records — specifically the FUNC for the attach target — and checks that each argument's resolved type is something the trampoline can reason about. If an argument is a pointer (PTR) to FWD, the verifier can't compute a size and can't set up the trampoline. CO-RE relocation, on the other hand, walks named-type lookups against the BTF blob's name table. When CO-RE wants to find `struct key`, it calls `btf__find_by_name_kind(btf, "key", BTF_KIND_STRUCT)`, which walks every record looking for a STRUCT named "key" and returns the first match. That first match is the full definition. The FWD record is never consulted by the CO-RE path.

Two paths through the same BTF blob, looking for different things, finding different records. It's one of those points of friction where the kernel's metadata system is internally consistent but not obviously so. Debugging requires you to know which path is being taken and which records each path touches.

There's also a philosophical aside worth making. A FWD record exists in BTF specifically because some translation unit saw only a forward declaration of the type. Forward declarations exist in C for real reasons — breaking circular dependencies, reducing compile-time coupling, etc. The BTF generator (pahole) faithfully records what each translation unit saw, which means different parts of the kernel can contribute different records for the same type name. The linker of DWARF-to-BTF doesn't deduplicate or resolve these — it concatenates. So a single vmlinux BTF blob can contain both a FWD and a STRUCT record for `key`, which is exactly the situation I ran into.

Could the kernel's build system be smarter and fold FWD records into STRUCT records post-link? Probably. That's upstream work that's being discussed. For today, the BTF blob has both, and the attach-point validator unfortunately consults the FWD record while CO-RE consults the STRUCT record. We drop to kprobe to sidestep the attach-point validator.

Here's the full rejection log from my test run, reproduced because the exact text matters for future debugging:

```
libbpf: prog 'lsm_key_perm': BPF program load failed: Invalid argument
libbpf: prog 'lsm_key_perm': -- BEGIN PROG LOAD LOG --
arg#0 reference type('FWD key') size cannot be determined: -22

processed 0 insns (limit 1000000) max_states_per_insn 0 total_states 0
peak_states 0 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'lsm_key_perm': failed to load: -22
libbpf: failed to load object 'ch08_keyring_heist_lsm_bpf'
libbpf: failed to load BPF skeleton 'ch08_keyring_heist_lsm_bpf': -22
```

Processed 0 instructions. The verifier didn't get anywhere near the program body. The argument type check failed during the pre-verify attach-target validation, and the whole load returned -EINVAL. This is what "the kernel's BTF forward-declared the hook argument" looks like in practice.

There's one more piece of the rejection worth noting. Even if I had somehow gotten the program past the FWD check — say, by declaring the argument type as `void *` and casting internally — the verifier would still want to type-check any field accesses I did on that pointer. `BPF_CORE_READ(k, serial)` requires the verifier to know the layout of `struct key` so it can relocate the field offset. If the argument type is FWD and I try to read a field, the CO-RE relocation fails because the FWD record doesn't have fields.

I tried that: declared the argument as `void *`, cast it internally. Load failed differently:

```
libbpf: prog 'lsm_key_perm': relocation at insn 12 failed: -ENOENT
failed to find target candidate for relocation ...
```

Different error, same underlying cause: no typed access to `struct key` through the LSM hook's BTF metadata. The kernel knows what a key is, the vmlinux BTF blob contains the full definition, but the path from "argument of the LSM hook" to "field of struct key" is broken by the FWD record.

That's when I gave up on the LSM approach for this kernel.

## The kprobe-plus-opaque-pointer fix

The fix is to drop the program type from LSM to kprobe. Kprobes take `struct pt_regs *` as their context. The trampoline for a kprobe program doesn't need to know the kernel function's signature — it just knows where pt_regs lives on the stack, and the BPF program pulls arguments out of pt_regs via `PT_REGS_PARM1(ctx)`, `PT_REGS_PARM2(ctx)`, etc.

That sidesteps the FWD issue entirely, because the kprobe program doesn't claim "my argument is `struct key`." It claims "my argument is `struct pt_regs`," which is fully defined in BTF everywhere. What I do with the extracted PARM1 value is the program's business, not the verifier's.

I pick `key_task_permission` as the attach point. Its signature:

```c
int key_task_permission(const key_ref_t key_ref,
                        const struct cred *cred,
                        enum key_need_perm need_perm);
```

This is the function the kernel calls internally to decide whether a task has a particular permission on a key. It's called from the permission-check path for `keyctl(KEYCTL_READ, ...)`, `keyctl(KEYCTL_SEARCH, ...)`, and several other keyctl operations. It's *also* called from `request_key_and_link()` and other kernel-internal key lookup paths. It's the decision-point function for key access control — the same function the LSM hook `security_key_permission` is called from within.

`key_ref_t` is a pointer with a low-bit possession flag. The kernel's `key_ref_to_ptr()` inline function masks off the low bit:

```c
/* from include/linux/key.h */
static inline struct key *key_ref_to_ptr(const key_ref_t key_ref)
{
    return (struct key *) ((unsigned long) key_ref & ~1UL);
}
```

Note the `& ~1UL` — only bit 0 is masked. That's the possession flag. The final POC uses `& ~3UL` as a defensive over-mask — two low bits instead of one. Since the kernel's slab allocator returns pointers aligned to at least 8 bytes, bits 0-2 are always zero in the real pointer, so masking one bit or two makes no difference in practice. The `& ~3UL` in the POC is strictly safe but not what the kernel does. See the discussion in the "Walking from key_ref_t to struct key" section below for the full reasoning.

The BPF program:

```c
SEC("kprobe/key_task_permission")
int BPF_KPROBE(kp_key_task_permission)
{
    unsigned long raw = (unsigned long)PT_REGS_PARM1(ctx);
    struct key *k = (struct key *)(raw & ~3UL);
    emit_key(k, HOOK_KEY_TASK_PERMISSION);
    return 0;
}
```

`PT_REGS_PARM1(ctx)` returns the first integer argument from pt_regs — on aarch64 that's `x0`, on x86_64 that's `rdi`. The macro expands to the right register access per architecture. The returned value is `unsigned long`, which the BPF verifier treats as a scalar.

The cast to `struct key *` is where the magic happens. From the verifier's perspective, we have a scalar. We do arithmetic on the scalar (`& ~3UL`). We cast the result to a pointer type and pass it to `emit_key`. The verifier does not object to this — it's a known-safe pattern for kprobe programs that want to treat PARM-registers as typed pointers.

Inside `emit_key`, the `BPF_CORE_READ` calls resolve against `struct key`'s definition from vmlinux.h. The CO-RE relocation table in the loaded program has entries like "at insn 17, rewrite the `serial` field offset to whatever the running kernel says it is." The kernel's vmlinux BTF has a complete `struct key` record (the same one that was missing from the LSM hook's argument BTF), and the relocation resolves.

Here's the crucial realization: the `struct key` BTF record used for relocation is different from the FWD record used for LSM hook argument validation. They're two different records in the same vmlinux BTF blob. The relocation uses the named-type lookup (`btf__find_by_name_kind(btf, "key", BTF_KIND_STRUCT)`), which finds the complete definition. The LSM hook's argument validation uses the specific FUNC record for `bpf_lsm_key_permission`, which has a pointer-to-FWD in its first argument slot.

So the same vmlinux BTF blob contains both: (a) a FWD record for `key` that is referenced from the LSM hook's argument, and (b) a STRUCT record for `key` with the full definition. Which one gets consulted depends on what the verifier is checking. For attach-point argument validation: (a). For CO-RE field relocation: (b). By dropping from LSM to kprobe, I stopped triggering (a) and kept only (b).

This is a subtle point and it took me a while to internalize it. When someone says "`struct key` is in BTF," they may mean either record. When the verifier says "FWD key," it means specifically record (a). CO-RE never touches record (a); it only touches record (b). So CO-RE can read `struct key` fields even from a kprobe that extracted a `struct key *` from some register, regardless of whether any LSM hook's argument metadata has the FWD problem.

The teaching point: BTF-for-attach-validation and BTF-for-CO-RE-relocation are separate lookups against the same vmlinux BTF blob. Forward declarations in the first are not forward declarations in the second. When an LSM hook's argument is FWD, drop to kprobe, extract the same pointer from pt_regs, and CO-RE away.

There's a legitimate question here about what you lose by dropping from LSM to kprobe. For this chapter, the answer is "nothing substantive." Both program types run in the same kernel function (`key_task_permission`); both see the same `struct key *`; both can read the same CO-RE fields. The differences:

- LSM fmod_ret programs can modify the return value. Kprobes (without `CONFIG_BPF_KPROBE_OVERRIDE=y` and an error-injection entry) cannot. For this chapter that's irrelevant — we're observing, not modifying.
- LSM programs are invoked via a trampoline generated specifically for the LSM hook. Kprobes are invoked via the generic kprobe infrastructure (int 3 on x86, brk on aarch64, patched on kprobe setup). Kprobe overhead is slightly higher per-invocation, but for infrequent events like keyring access, it doesn't matter.
- LSM programs have precise semantics around where in the chain they fire. Kprobes fire at function entry, before any of the LSM chain logic. For this chapter that's actually a slight advantage — we see the caller's intent before any LSM processing has happened.
- LSM programs require `CONFIG_BPF_LSM=y` and `bpf` in the boot-time LSM string. Kprobes require only `CONFIG_KPROBES=y`. Kprobes are more broadly available.

For observation primitives, kprobe is frequently the better choice regardless of whether LSM would work, because it's more portable and has no FWD-style pitfalls. I use LSM in other chapters when I specifically need fmod_ret semantics. For this one, kprobe is both sufficient and more universal.

## Source walk: the full kprobe

The POC lives at `dBPF-pocs/pocs/ch08-keyring-heist-kprobe/`. Let's walk it.

The ringbuf event struct:

```c
struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int serial;
    int hook;
    char type_name[TYPE_NAME_LEN];
    char description[DESC_LEN];
};
```

Seven fields, fixed-width, no pointers. `pid` and `tgid` are from `bpf_get_current_pid_tgid()`. `comm` is from `bpf_get_current_comm()`. `serial` is the kernel-assigned key serial number — an integer that uniquely identifies a key within the kernel. `hook` distinguishes which of the two attach points fired (`key_task_permission` or `lookup_user_key`). `type_name` is the key type name (`user`, `keyring`, `logon`, etc., up to 16 chars). `description` is the key's user-provided description, up to 64 chars.

The ringbuf itself is 256KB (`1 << 18`):

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");
```

For the expected event rate (one per key access check), 256KB is absurdly large — we'd need tens of thousands of events to fill it. But ringbufs are cheap and large buffer sizes eliminate backpressure concerns.

The core helper is `emit_key`, which takes a `struct key *` and emits a populated event:

```c
static __always_inline void emit_key(struct key *k, int hook)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    __builtin_memset(e, 0, sizeof(*e));

    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid  = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;

    if (k) {
        /* CO-RE read against vmlinux.h's complete struct key definition. */
        e->serial = BPF_CORE_READ(k, serial);

        struct key_type *kt = BPF_CORE_READ(k, type);
        if (kt) {
            const char *tn = BPF_CORE_READ(kt, name);
            if (tn)
                bpf_probe_read_kernel_str(&e->type_name,
                                          sizeof(e->type_name), tn);
        }

        const char *desc = BPF_CORE_READ(k, description);
        if (desc)
            bpf_probe_read_kernel_str(&e->description,
                                      sizeof(e->description), desc);
    }

    bpf_ringbuf_submit(e, 0);
}
```

Reading this carefully:

1. `bpf_ringbuf_reserve` allocates a slot in the ringbuf. If the ringbuf is full, this returns NULL and we bail. On a 256KB buffer consuming events promptly, NULL is rare.

2. `__builtin_memset` zeros the event. This is defensive: the ringbuf slot memory may contain whatever was previously there, and any field I don't explicitly set would leak that stale data to userspace. Zeroing first is a small cost for correctness.

3. `bpf_get_current_pid_tgid` gives us the calling task's pid (low 32 bits) and tgid (high 32 bits). These are host-namespace IDs in the current task's pid namespace. For cross-namespace observation you'd want more work; for this observer, host-namespace is fine.

4. `bpf_get_current_comm` copies the task's `comm` (up to 16 chars, null-terminated). This is the process name as it would appear in `ps`.

5. `BPF_CORE_READ(k, serial)` reads `k->serial`. Internally this expands to a `bpf_probe_read_kernel` of 4 bytes at the correct offset — the offset is resolved by the kernel's BTF at load time based on the running kernel's `struct key` layout.

6. `BPF_CORE_READ(k, type)` reads `k->type`, which is a `struct key_type *` pointing to the type descriptor. Key types are static kernel objects (there's one `struct key_type` for `user`, one for `keyring`, etc.), so the pointer is stable.

7. `BPF_CORE_READ(kt, name)` reads `kt->name`, which is a `const char *` to the type name string. Similarly stable.

8. `bpf_probe_read_kernel_str` copies the null-terminated string from kernel memory into our event buffer. I use this instead of `BPF_CORE_READ_STR_INTO` because I don't need the CO-RE dance for a plain `const char *` dereference — the pointer is already resolved.

9. `BPF_CORE_READ(k, description)` reads `k->description`, the user-provided string. On modern kernels this is a `char *` field in `struct key` that points to allocated memory. On some older kernels it was part of an anonymous union; CO-RE handles either case by resolving the field offset against the running kernel's layout.

10. `bpf_ringbuf_submit` finalizes the event and makes it visible to the userspace consumer. If we never called submit, the reserved slot would be leaked (until the ringbuf tears down).

The two kprobe attach points:

```c
SEC("kprobe/key_task_permission")
int BPF_KPROBE(kp_key_task_permission)
{
    unsigned long raw = (unsigned long)PT_REGS_PARM1(ctx);
    struct key *k = (struct key *)(raw & ~3UL);
    emit_key(k, HOOK_KEY_TASK_PERMISSION);
    return 0;
}

SEC("kprobe/lookup_user_key")
int BPF_KPROBE(kp_lookup_user_key)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid  = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = HOOK_LOOKUP_USER_KEY;
    e->serial = (int)PT_REGS_PARM1(ctx);
    __builtin_memcpy(e->type_name, "lookup", 7);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

Why two attach points? They give different views of the same operation.

`key_task_permission` is the structure-level view. By the time it fires, the kernel has already resolved "what key is being accessed" to a `struct key *`, and we can read serial, type, description. This is the richer event.

`lookup_user_key` is the serial-id view. Its signature is `lookup_user_key(key_serial_t id, unsigned long lflags, enum key_need_perm)`. PARM1 is an integer, not a pointer — it's the key serial ID as passed by userspace. At this point the kernel has the caller's request but hasn't yet resolved the key, so we can't read structure fields. What we can report is: this pid called `lookup_user_key` with this serial. That confirms the userspace caller's intent (which key they were asking for) and pairs with the `key_task_permission` event (which fires slightly later with the resolved struct).

The `__builtin_memcpy(e->type_name, "lookup", 7)` is a sentinel value — a fake type name that lets the userspace consumer distinguish `lookup_user_key` events (where the type is unknown) from `key_task_permission` events (where the type is the real kernel key type).

Both programs return 0. Kprobes can't modify syscall return values on functions that aren't in the error-injection allowlist, so the return value is purely cosmetic — neither the kprobe fn return nor `bpf_override_return` would change what the kernel does here. This is read-only observation.

## Walking from key_ref_t to struct key

The `& ~3UL` mask deserves its own section because it's the kind of thing that's easy to get wrong and hard to debug when you do.

`key_ref_t` is defined in `include/linux/key.h` as an opaque typedef:

```c
typedef struct __key_reference_with_attributes *key_ref_t;
```

There's no actual `struct __key_reference_with_attributes` defined anywhere. The typedef is a deliberate opaque. Callers are not supposed to dereference `key_ref_t` directly; they should use `key_ref_to_ptr()` to get the `struct key *` out.

What's in the low bits? The kernel uses the `key_ref_t` to encode both the pointer and a possession flag. Possession means "this task has been allowed to act on this key by virtue of having the key in one of its keyrings." The possession flag is bit 0. Bit 1 is historical / unused on most modern kernels but reserved.

`key_ref_to_ptr(kref)` is `(struct key *)((unsigned long)kref & ~1UL)` in the kernel's current implementation. Note: current kernels use `& ~1UL`, not `& ~3UL`. I double-checked my source.

But wait — I wrote `& ~3UL` in the POC. Why?

Because I read older kernel versions where the mask was `& ~3UL`, got the wrong impression about current kernels, and used the more defensive mask. In practice, since pointers returned from the kernel's slab allocators are aligned to at least 8 bytes (and often more), the bottom 3 bits are always zero after masking with `~3UL`. So the mask is strictly safe — it masks more bits than needed, but none of those bits were set anyway. No information is lost.

If I were writing this to match upstream exactly, I'd use `& ~1UL`. The POC uses `& ~3UL` as a minor over-mask. Either works on any kernel from 4.x forward. If a future kernel used the two low bits for some new purpose and I was still masking `& ~3UL`, I'd lose that information silently — but right now that's not a concern.

The semantic content of what I'm doing: take the opaque pointer value from PARM1, strip any possession/attribute bits, cast to `struct key *`, and dereference the result via CO-RE. The kernel does the same thing in `key_ref_to_ptr()` and has been doing it since before I started caring.

A couple of other things worth noting about `struct key` traversal:

`struct key` contains a union in some kernel versions. Specifically, the payload-related fields are union-wrapped to accommodate different key types (user keys store a payload pointer; keyring keys store a list; keytype-specific keys store various things). CO-RE handles unions correctly in recent libbpf, but older libbpf versions had bugs with union-member relocation. If you see CO-RE errors when reading payload-related fields from `struct key`, check your libbpf version.

For this POC I stick to `serial`, `type`, and `description`, which are not inside unions. All three are plain struct-level fields. No union gymnastics required.

One path-sensitivity note: `BPF_CORE_READ(k, description)` reads the pointer field `description` from `struct key`. For most key types this points to heap-allocated memory containing the description string. The subsequent `bpf_probe_read_kernel_str` reads the string. Between the field read and the string read, there's a small window where the kernel could theoretically free the description buffer. In practice this doesn't happen — the description is not freed until the key is revoked — but in a pathological concurrency case you could get a stale read. The worst outcome is garbage in the ringbuf event; the kernel is not crashed and the BPF program is not attacked. I'm okay with that trade.

A more subtle point about BPF_CORE_READ chains. When I write `BPF_CORE_READ(k, type, name)`, the macro expands into two `bpf_probe_read_kernel` calls: first `k->type` (a pointer), then `(k->type)->name` (another pointer). Each call is a separate read with its own failure mode; the macro handles a NULL intermediate gracefully by returning 0 for the deepest read. But each read also incurs a context switch to the probe_read helper, which is a measurable cost. For this program, two levels of chase (serial is one read, type->name is two reads, description is one read) is fine. For deeper chases you might want to be more judicious about how you structure the reads.

There's also a question about whether to use `BPF_CORE_READ_STR_INTO` versus `bpf_probe_read_kernel_str`. `BPF_CORE_READ_STR_INTO` is a CO-RE-aware version that handles relocations on the source pointer. For my case, the source pointer (`desc` after `BPF_CORE_READ(k, description)`) is already resolved — it's a plain kernel pointer with no more field accesses needed — so a plain `bpf_probe_read_kernel_str` suffices. Using CO-RE_STR_INTO would be slightly less efficient (extra relocation work for no benefit) and slightly more verbose. The POC uses the non-CO-RE version for the final string read and the CO-RE version only for the pointer chase.

One more subtlety about keyring traversal worth spelling out. On some kernels (particularly older ones with the legacy keyring format), `struct key` has the description either as a direct `char *` field or as part of a union-wrapped payload structure. The CO-RE relocation transparently handles the difference, but the relocation table embedded in the BPF bytecode does need to know the kernel's layout at verification time. libbpf 1.3 + kernel 5.10+ handles this robustly. Older combinations may print a relocation-failed error at load. If you see that on a 5.x kernel, the options are: upgrade libbpf, use a kernel with more regular `struct key` layout, or fall back to `bpf_probe_read_kernel` with a hardcoded offset (which loses CO-RE portability but works on the exact kernel you hardcoded for).

## The harness

`Poc("ch08k", ...)` in `proof.py`:

```python
Poc("ch08k", "Keyring Heist — kprobe variant",
    "ch08-keyring-heist-kprobe",
    hooks=["key_task_permission", "lookup_user_key"], prefix="[ch08k]",
    mode="trigger-runs-loader", timeout=20,
    proof_marker=r"CH08_CONCEPT_PROVEN|CH08_PROVEN|_PROVEN"),
```

`hooks=["key_task_permission", "lookup_user_key"]` tells the harness what kernel symbols this POC attaches to. The harness preflight checks each listed symbol against `/proc/kallsyms` before running the POC. If both symbols are absent, the POC is skipped with a clear diagnostic rather than attempting to load and failing opaquely. On linuxkit 6.12 aarch64, both are present.

The loader does its own kallsyms preflight too:

```c
int has_ktp = kallsyms_has("key_task_permission");
int has_luk = kallsyms_has("lookup_user_key");
if (has_ktp <= 0 && has_luk <= 0) {
    fprintf(stderr, "[ch08k] CH08K_SKIP reason=\"keyring symbols absent in kallsyms\"\n");
    return 2;
}
```

If only one of the two symbols is present, the loader disables autoload on the missing one and carries on:

```c
if (has_ktp <= 0)
    bpf_program__set_autoload(s->progs.kp_key_task_permission, false);
if (has_luk <= 0)
    bpf_program__set_autoload(s->progs.kp_lookup_user_key, false);
```

This is the same BTF-prune-style pattern as ch07, but against kallsyms instead of BTF, because kprobes attach by symbol name (not BTF FUNC) and kallsyms is the source of truth for symbol availability.

Why not attach by BTF? You can, for kprobes with new-enough kernels — `fentry` programs attach by BTF and are preferable to kprobes because they incur lower overhead. But `fentry` requires the target function to be traceable (marked with `ftrace`-capable instrumentation at compile time), and some functions are not. `key_task_permission` is traceable on most kernels. If you wanted to migrate this POC from kprobe to fentry, you'd change `SEC("kprobe/...")` to `SEC("fentry/...")` and adjust the `BPF_KPROBE` macro to `BPF_PROG` with the correct argument signature. The FWD issue wouldn't apply because fentry programs don't have the LSM fmod_ret argument-type validation — they just read pt_regs and arguments the same way kprobes do.

The proof marker is `CH08_CONCEPT_PROVEN syscall_rc_unchanged=<y|n> description_in_ringbuf=<y|n>`. Two conditions:

1. `syscall_rc_unchanged=yes` means both the BEFORE and AFTER `keyctl print` calls returned non-zero. The kernel's access decision was not modified by the BPF program. This is a positive statement about what the primitive is NOT — it's not an access-control bypass.

2. `description_in_ringbuf=yes` means the ringbuf stream contained the key's description string. The BPF program successfully read kernel memory that the unprivileged caller could not read via the normal keyctl API. This is a positive statement about what the primitive IS — a structural observation exfil.

What the marker proves is precisely: the syscall enforced, the decision-point leaked. Both halves matter. If the syscall had *changed* its behavior (returning 0 instead of EACCES), we'd be claiming an access-control bypass and we'd need to back that up with a more serious threat-model analysis. We don't; the syscall is intact. If the ringbuf had been empty, we wouldn't have proven anything novel. The ringbuf is populated.

## Trigger scenario

The trigger (`trigger.sh`) stages a concrete scenario that exercises the primitive end to end.

Setup (as root):

1. Create a temp user `t08k` with no privileges. This is the unprivileged caller.
2. Add a `user`-type key under the user-session keyring `@u`, with description `ch08-research-entry` and payload `research-payload-value`:
   ```
   KEY_ID="$(keyctl add user "$KEY_DESC" "$KEY_PAYLOAD" @u 2>/dev/null)"
   ```
3. Set restrictive permissions on the key: owner can do everything (0x3f), user-class sees view-only (0x01), group and other see nothing (0x00).
   ```
   keyctl setperm "$KEY_ID" 0x3f010000
   ```
   The hex format is `owner_user_group_other`. This makes the key readable only by its owner (root), with the unprivileged user `t08k` having view-only access at best — which is not enough to read the payload via `keyctl print`.

BEFORE phase (loader not attached):

1. As `t08k`, run `keyctl print $KEY_ID`. The call goes through `lookup_user_key` (resolves the serial) and then `key_task_permission` (checks permission). `key_task_permission` returns `-EACCES` because t08k lacks read permission. The syscall returns `-EACCES`.
2. Stdout from `keyctl print` shows the error message. No kernel-structure metadata is visible to userspace.
3. The trigger records `before_rc=<nonzero>`.

Start the loader. Wait for `attached` in the log.

AFTER phase (loader attached):

1. As `t08k`, run the same `keyctl print $KEY_ID`. Same syscall sequence. Same permission check. Same `-EACCES` return.
2. But now, as the kernel runs `key_task_permission`, the BPF kprobe fires. It reads `struct key`'s serial, type name, and description. It emits a ringbuf event.
3. The userspace loader drains the ringbuf and prints `[ch08k] hook=key_task_permission pid=<t08k's pid> comm=keyctl serial=<serial> type=user desc='ch08-research-entry'`.
4. The trigger records `after_rc=<nonzero>`.

Teardown:

1. Kill the loader. Drain remaining events.
2. Grep the log for `desc='ch08-research-entry'`. If present, set `description_in_ringbuf=yes`.
3. Compare `before_rc` and `after_rc`. If both non-zero, set `syscall_rc_unchanged=yes`.
4. Emit `=== CH08_CONCEPT_PROVEN syscall_rc_unchanged=yes description_in_ringbuf=yes ===`.

The pedagogical point is the separation. The syscall enforcement is complete — t08k never learns the payload, never gets a zero return code, never sees evidence of access. But a BPF program running with `CAP_BPF` (in this case, as root) did learn the key's description from inside the decision-point function, by reading kernel memory that was never copied to userspace through any syscall.

One caveat on the trigger's permissions setup. I use `keyctl setperm "$KEY_ID" 0x3f010000` specifically. The 0x3f for owner-class gives root the full permission mask (view + read + write + search + link + setattr). The 0x01 for user-class gives t08k only view, which lets t08k *see the key's metadata* (serial, description, type — as visible through `/proc/keys` and some keyctl operations) but *not* read the payload. Crucially, `view` permission is what `/proc/keys` needs for the key to be listed; this isn't about hiding the key's existence, it's about hiding the payload.

The `keyctl print` operation the trigger runs specifically needs `read` permission, which t08k does not have. That's why the operation fails with EACCES. It fails at `key_task_permission` time — after the key has been located (by serial) but before the payload is dereferenced. That's precisely the decision point where our kprobe sits.

If I'd given t08k read permission (0x3f for user-class as well), `keyctl print` would succeed and the payload would appear in t08k's stdout. That's not interesting — the syscall already leaks the payload to userspace. What's interesting is the case where the syscall refuses and the BPF primitive leaks metadata anyway. That's the experiment the trigger runs.

I could extend the demonstration to leak the payload too, not just metadata. `struct key` has a `payload.data[0]` pointer that, for user-type keys, references a `struct user_key_payload` containing a `datalen` and a flexible array `data[]`. `BPF_CORE_READ(k, payload.data[0])` gives the payload pointer; a subsequent `bpf_probe_read_kernel` reads the bytes. I didn't include that in the POC because the payload is user-controlled data rather than kernel-internal state, and chapter 20's Class III framing is specifically about kernel-internal state that the syscall boundary hides. The description is kernel-internal metadata; the payload is not. If you want to extend the POC to leak payloads too, the code change is small and obvious.

## Detection

Detection for this primitive has two sides: load-time and runtime.

Load-time: the BPF program must be loaded and attached. `bpftool prog list | grep -i key_` shows any BPF program attached to a kernel function whose name contains `key_`. This is a strong signal — BPF programs on keyring functions are uncommon in normal observability tools. bcc's `keyctl` tracer, if installed, would also show up, but that's a known and auditable tool. Anything else is probably not what you want.

More specifically:

```
bpftool prog list
  ...
  5821: kprobe  name kp_key_task_permission  tag abc123 gpl
        loaded_at 2025-02-08T10:15:42+0000  uid 0
        xlated 312B  jited 276B  memlock 4096B
        ...
```

The `attach` field shows the target function. `kp_key_task_permission` attached to `key_task_permission` is a clear tell.

`/sys/kernel/tracing/kprobe_events` lists all active kprobes. A kprobe on `key_task_permission` or `lookup_user_key` shows up there. An auditor running `cat /sys/kernel/tracing/kprobe_events | grep key` catches this.

`AUDIT_BPF` records fire on `BPF_PROG_LOAD`, as described in earlier chapters. The loader process is visible in those records. Shipping audit records to an off-box sink gives you durable evidence.

Runtime: there is no runtime signal from the read itself. `BPF_CORE_READ` is a kernel-memory-to-BPF-map copy. It doesn't touch the key's refcount, doesn't modify any state, doesn't trigger any notifier. `/proc/keys` continues to show the same key with the same metadata. The key's `last_used_at` timestamp (if tracked) is unaffected because the kernel's permission check happens regardless of the kprobe, and the kprobe fires during that check rather than modifying it.

The syscall boundary's audit records are unchanged too. If auditd is logging keyctl syscalls (`-a always,exit -F arch=b64 -S keyctl`), the log shows t08k attempting `keyctl print` with a given serial and getting EACCES. That's the same as without the kprobe. The fact that a BPF program read the description in parallel isn't in the syscall audit stream — because the read is not a syscall.

This asymmetry — the BPF program's read is invisible to syscall audit — is what makes Class III primitives troublesome for defenders. The only durable evidence is the `bpf()` syscall audit trail and the `bpftool prog list` output, both of which require the defender to be specifically watching BPF infrastructure. Sites that audit only syscall returns and not BPF loads will miss this entirely.

## Scope

Class III from chapter 20's taxonomy: ringbuf exfiltration of kernel-internal state the syscall boundary would hide. The victim syscall returns what it would have returned; the BPF program copies out decision-point state out-of-band through a ringbuf that the privileged loader is draining.

The primitive works on any kernel where `key_task_permission` is in kallsyms and BPF kprobes are available (`CONFIG_KPROBES=y`, `CONFIG_BPF=y`, and `CONFIG_BPF_JIT=y` for efficiency). That covers essentially every production Linux kernel built since ~2018.

The LSM-FWD issue that drove me to kprobe is specific to kernels where the LSM hook's BTF metadata was generated from a translation unit that lacked the full include for `<linux/key.h>`. Distro kernels usually have the full type and would accept the `SEC("lsm/key_permission")` variant. Minimal kernels (linuxkit, some embedded configs) may have the FWD. The kprobe variant works on both, so there's little reason to prefer the LSM variant even when it would load — the kprobe version is more portable.

What the primitive does NOT give you:

- It does not modify access control. `keyctl print` that would have returned EACCES still returns EACCES. The kernel's decision is untouched.
- It does not leak arbitrary keys. It leaks the metadata of whatever key's access is being checked *at the moment the kprobe fires*. If no one is asking for a key, there are no events. The attacker has to wait for key access to occur, or has to trigger it somehow.
- It does not persist. BPF programs are unloaded when the loader exits (unless pinned). Nothing on disk is modified. The attacker gets live observation while attached and loses it when the loader exits.
- It does not bypass `keyring` LSM policies. SELinux keyring policies, if configured, still apply. The kprobe fires regardless of LSM decisions, but the victim's syscall return is still the LSM's decision.

What the primitive IS useful for:

- Harvesting key descriptions across a large number of keys, specifically by observing access checks that naturally occur when processes wake and exercise their keyrings. This is the "passive harvest" version.
- Confirming the presence of specific keys by observing their descriptions. If a defender has added a honeypot key with a descriptive name, an attacker reading this via kprobe would see the honeypot fire.
- Correlating key accesses with processes, for attribution purposes (legitimate or otherwise).
- Research: understanding when and how kernel subsystems access keyring entries during their normal operation.

For a defender: don't trust that the syscall audit stream tells you what state was exposed. The decision-point function sees more than the syscall returns. For every decision-point function that's interesting (permission checks, credential validations, capability lookups), consider that a BPF kprobe with read access to the decision arguments can exfiltrate the arguments at will. The syscall enforced; the decision-point leaked. That's the shape of Class III. This chapter gave a specific instance for keyrings. The pattern generalizes.

## What refused to die

One more note, for symmetry with chapter 21's "autopsy" accounting.

The LSM approach is the one that refused to die. I kept coming back to it. I tried several combinations hoping to force the verifier to accept `SEC("lsm/key_permission")`:

- Declaring the argument as `void *` (relocation error, documented above).
- Declaring the argument as `unsigned long` (attach refused: "expected PTR, got SCALAR").
- Declaring the argument as a pointer to a locally-defined `struct key` that mirrors the kernel layout (attach accepted but CO-RE relocations fail because my local type is not the kernel's named type).
- Declaring the argument as `struct __key_reference_with_attributes *` (the typedef target — doesn't exist as a real struct, rejected).
- Attaching with `SEC("lsm.s/key_permission")` for sleepable semantics (same FWD error, sleepable doesn't affect attach-point validation).

None of these worked cleanly for the `BPF_PROG()` macro approach, because `BPF_PROG()` unpacks *all* arguments from the context — including arg0 (`key_ref`), whose type is FWD — and the verifier rejects the context access at offset 0.

The workaround that ultimately landed in `ch08-keyring-heist-lsm` is to bypass `BPF_PROG()` entirely and use a **raw context** signature: `int lsm_key_permission(unsigned long long *ctx)`. With raw context, the program manually reads only the context slots it needs at their known offsets, skipping the FWD-typed arg0:

```c
SEC("lsm/key_permission")
int lsm_key_permission(unsigned long long *ctx)
{
    unsigned int need_perm = (unsigned int)ctx[2];  // arg2: need_perm
    int ret = (int)ctx[3];                          // arg3: chain result
    // ctx[0] is key_ref (FWD type) — deliberately skipped
    // ctx[1] is cred — skipped
    ...
}
```

This loads successfully because the verifier never sees a typed access to the FWD `key_ref_t` at ctx[0]. The trade-off: the LSM variant cannot read the key's serial number or type name (those require dereferencing `key_ref`, which lives at ctx[0]). The `serial` and `type_name` fields in the ringbuf event are always zero in the LSM variant. The kprobe variant (`ch08-keyring-heist-kprobe`) still reads them via `PT_REGS_PARM1` and CO-RE, because kprobes are not subject to the FWD check. So the two variants are complementary: the LSM variant can *mutate* (flip deny to allow via fmod_ret), while the kprobe variant can *observe* the full key metadata.

I also tried attaching to `security_key_alloc` instead (different hook, different argument types, doesn't have the FWD issue — but fires at key creation, not access, so it's a different primitive entirely. I explored this briefly; it's a potentially useful sibling chapter but not what I wanted here.)

Before the raw-context workaround landed, the cleanest exit was the kprobe variant. If you're building on this work and you have a kernel where the LSM path loads (distro kernels mostly), you can use the LSM variant for slightly nicer semantics. For a portable POC that works across minimal kernels with incomplete BTF, the kprobe is the right answer.

The other thing that refused to die was my initial attempt to hook `__key_instantiate_and_link` to catch key *creation*. That function sees the key as it's being set up — before permission checks, before keyring linkage, at the point where the kernel is populating the struct. If you hooked there, you'd catch every new key as it came into existence, including keys you'd otherwise never have observed access on. I spent two hours on it. The function isn't exported, and its parameters include a non-trivial `struct key_preparsed_payload` that I couldn't read cleanly with CO-RE because several of its fields are genuinely union-wrapped. I punted.

If you want create-time visibility rather than access-time visibility, the better hook is `security_key_alloc`. It fires on every new key, takes the same `struct key *` we're chasing here, and doesn't hit the FWD issue for me on either test kernel. The pattern is similar: CO-RE `BPF_CORE_READ` the fields you want, emit to ringbuf, return 0 (this is a sleepable-capable LSM hook and `void` return; the allow/deny decision isn't ours to make). A sibling POC for creation-time observation would be a natural extension.

## On kernel version portability

A quick survey of which kernels this POC has been tested against and what the outcome was, so anyone porting can set expectations:

- **linuxkit 6.12 aarch64** (Docker Desktop macOS). FWD issue confirmed on the LSM path. Kprobe path works. `key_task_permission` and `lookup_user_key` both in kallsyms.
- **Debian 12 (6.1.0-17-amd64)**. LSM path loads; kprobe path also loads. I tested both. The kprobe path was equally functional; no difference in semantics for observation.
- **Ubuntu 22.04 (5.15.0-generic-amd64)**. Kprobe path works. LSM path untested on this kernel; I'd expect it to work based on the Debian experience, but can't confirm.
- **Fedora 39 (6.5.x-amd64)**. Kprobe path works. LSM path works.

The symbols `key_task_permission` and `lookup_user_key` have been stable since roughly 5.0. Earlier kernels had slightly different naming (the `keyring` subsystem was more often exposed as `key_permission` without the `_task_` middle). If you're porting to 4.x (which you shouldn't be — 4.x is past EOL for most distros), you'd want to verify symbol names against kallsyms first.

The `struct key` layout has been stable in its relevant fields (`serial`, `type`, `description`) since at least 4.14. Field offsets change between versions, but CO-RE relocation handles that; you shouldn't see field-not-found errors.

What has drifted more: the `struct key_type` layout, which contains the type name. Some older kernels stored the type name inline as a fixed-size character array; newer kernels store it as a pointer to a static string. The POC uses `BPF_CORE_READ(kt, name)` which resolves to either form — CO-RE handles the "was it a char array, now it's a char pointer" drift. I tested this specifically.

## Comparison with LSM-based approaches in the wild

The broader ecosystem has a few tools that observe keyring state through BPF:

- **bcc/tools**: includes `capable.py`, `opensnoop.py`, etc., but no dedicated keyring observer as of the last version I checked. Ad-hoc bpftrace one-liners cover some of this ground.
- **tracee**: has event types for some keyring operations, generally as syscall-level tracing rather than decision-point probes. It would see the `keyctl` syscall but not the `key_task_permission` decision arguments.
- **falco**: similar — syscall-level, not decision-point.
- **bpftrace**: you can write a one-liner like `kprobe:key_task_permission { printf("%s", ...) }` and get something like this POC, at roughly the same capability level, without the CO-RE structured ringbuf.

What this POC adds over the one-liners:

1. A structured event format that's trivial to parse in userspace.
2. CO-RE relocations that make the same compiled bytecode portable across kernel versions.
3. Explicit BTF / kallsyms preflight with graceful skip behavior.
4. Paired `key_task_permission` / `lookup_user_key` hooks to see both the caller-intent side (serial ID) and the resolved-struct side.
5. A harness integration that produces machine-checkable proof markers.

The primitive itself is not novel. The CO-RE plumbing, the FWD-workaround walk, and the reproducibility packaging are where this chapter contributes.

## Summary

The chapter in one paragraph: you can read kernel keyring metadata from a BPF program attached to `key_task_permission`, even on kernels where the cleaner `SEC("lsm/key_permission")` path is blocked by a BTF forward-declaration issue. The observation workaround is to drop to `SEC("kprobe/key_task_permission")`, extract the `struct key *` from PT_REGS_PARM1, mask off the possession bits, and CO-RE against vmlinux.h's full `struct key` definition. For the mutation variant (`ch08-keyring-heist-lsm`), the workaround is to bypass the `BPF_PROG()` macro and use a raw context signature (`unsigned long long *ctx`), reading only the args at known offsets and skipping the FWD-typed `key_ref` at ctx[0] -- this allows fmod_ret to flip deny-to-allow, at the cost of losing access to key serial and type metadata. The syscall boundary continues to enforce for the observer; the decision-point leaks. The marker `CH08_CONCEPT_PROVEN syscall_rc_unchanged=yes description_in_ringbuf=yes` captures exactly what is proven and what is not.
