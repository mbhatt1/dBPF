---
layout: book
title: "Chapter 13: Powercap Override"
date: 2025-03-10
---

# Chapter 13: An x86-Only Primitive, Tested on aarch64

> **Note**: This primitive's natural hook did not fire on the test kernel. See [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) and the surviving workaround variant at [dBPF-pocs/pocs/ch13-powercap-override-analog/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs).

## The Honest Opening

I want to be fully honest about this one before describing anything else. Intel RAPL is x86-only; the powercap framework itself is architecture-independent (it also has ARM SCMI and DTPM backends), but the RAPL targets I care about require x86. On the aarch64 linuxkit kernel I am using as my test bed, `CONFIG_POWERCAP` is off and none of the RAPL-related symbols exist. My loader preflighted four targets — `powercap_register_control_type`, `powercap_get_max_power_uw`, `powercap_get_energy_uj`, `thermal_zone_device_update` — and every single one came back absent in `/proc/kallsyms`. The primary POC cannot fire on this host. I don't get to pretend otherwise, and this chapter is not going to.

What this chapter does instead is document two separate things. First, what the primitive shape of a powercap override would look like on an x86 Intel host where the symbols exist — the hooks, the attach points, the expected data flow, the detection posture. Second, an analog I actually ran on aarch64 to demonstrate the same userspace-illusion mechanic against a synthetic sensor, using tracepoints on `sys_enter_read` and `sys_exit_read` plus `bpf_probe_write_user` to rewrite a reader's user buffer in flight.

The analog is not a RAPL exploit. It is a demonstration that the same primitive — intercepting a read syscall and overwriting the returned bytes — can be aimed at any file-backed sensor. The mechanism is portable; the target is synthetic. The primitive shape is identical to what a real RAPL override would use; the thing being overridden is a userspace-written file instead of a kernel-provided sysfs attribute. That is as far as I can honestly take the demonstration on this host.

This chapter is going to spend more time than usual distinguishing between what the primitive does and what a RAPL attack would do. That distinction matters because it is easy to confuse the two, and because the prior draft of this chapter conflated them in exactly the way a good adversarial write-up should not.

## What the Real Primitive Would Look Like on x86

On an Intel x86 host with `CONFIG_POWERCAP=y` and `CONFIG_X86_INTEL_RAPL=y` (which is the default on any modern distro kernel), the relevant kernel framework is `powercap`. It lives in `drivers/powercap/` in the source tree, and it provides a generic interface for devices that can limit or measure power — CPU packages via RAPL, DRAM, uncore, and some specialized accelerators. The userspace interface is sysfs, rooted at `/sys/class/powercap/`.

The hooks of interest for a BPF attack:

| Hook | Purpose | On aarch64 linuxkit |
| --- | --- | --- |
| `kprobe/powercap_register_control_type` | fires once per driver init (rapl, scmi, dtpm) | ABSENT |
| `kprobe/powercap_get_max_power_uw` | any read from `max_power_uw` constraint (callback in `powercap_zone_ops`) | ABSENT |
| `kprobe/powercap_get_energy_uj` | any read from energy counter (callback in `powercap_zone_ops`) | ABSENT |
| `kprobe/thermal_zone_device_update` | thermal engine notifications | ABSENT |

On an Intel host where these resolve, the observer half of the attack is straightforward. Attach kprobes, pull arguments out of `pt_regs`, emit ringbuf events tagged with PID, comm, and the raw first two arguments to each call. That gives a defender precise visibility into who is touching the power envelope and when. It also gives an attacker precise visibility into where the monitoring stack is looking for RAPL data, which is useful recon for the offense.

The override half is more interesting and has multiple possible attach points depending on the exact attack goal.

**Goal 1: Make the power monitoring show idle power while the chip is actually boiling.** The attacker wants `turbostat`, `netdata`, Kepler, `perf stat -e power/energy-pkg/`, or whatever else reads the RAPL energy counter, to see a flat line while the chip is running at full blast. The cleanest attach point is `kretprobe/powercap_get_energy_uj` returning a fixed value — or ideally, a slowly-incrementing value that looks like idle but is not frozen. Userspace consumers that read `/sys/class/powercap/intel-rapl:0/energy_uj` go through this path. If the function is in `ALLOW_ERROR_INJECTION`, a kretprobe-plus-override lands. I do not have an x86 host to check the allowlist against, but the powercap framework was authored with testing in mind and some of its functions do have the annotation.

**Goal 2: Raise the power cap past what the BIOS or OS configured.** The attacker wants to run the chip past its thermal limits — for a cryptocurrency mining or a thermal-attack scenario. The attach point here is a kprobe on the `set_power_limit_uw` callback in the powercap zone ops (the specific function name depends on the RAPL driver implementation), rewriting the value being written or intercepting it entirely. This requires the function to be in the error-injection allowlist (unlikely) or an LSM-level bypass on the sysfs write (more plausible). The effect is that the chip runs with a higher TDP than the OS believes, consuming more power and producing more heat than the envelope allows.

**Goal 3: Suppress thermal-trip-critical notifications.** The attacker wants to combine goal 2 with defeating the kernel's thermal engine, so the chip can run past its junction temperature without the OS taking any emergency action. Attach point is `kprobe/thermal_zone_device_update` or `kretprobe/thermal_critical_notify`, intercepting the critical-temperature notification path. On a healthy chip this is a tightly-coupled safety mechanism; bypassing it is a recipe for actual hardware damage, and the attack is only interesting in scenarios where the attacker doesn't care about damaging the hardware.

For the first goal — which is the most commonly cited attack in the literature — the LSM-over-sysfs approach is probably more robust than the kprobe approach, because the sysfs attribute is a direct file-read from userspace, and `security_file_permission` is a reliable LSM hook with documented override semantics. The attack would:

1. Attach a BPF LSM fmod_ret program to `security_file_permission`.
2. Identify target reads via the file path (`/sys/class/powercap/intel-rapl:0/energy_uj`).
3. For reads from defender-class processes, return success (allow the read).
4. Meanwhile, arrange for the data actually returned to userspace to be a forged value.

Step 4 is the tricky one. The LSM hook is a policy decision point; it does not get to modify the bytes returned. To modify the bytes, you need a separate mechanism — and that mechanism is exactly what this chapter's analog demonstrates on aarch64: tracepoints on `sys_exit_read` plus `bpf_probe_write_user` to rewrite the reader's buffer in flight.

So the full x86 RAPL attack, as I would build it if I had the host, would be: a tracepoint-plus-`bpf_probe_write_user` program matching reads of the RAPL sysfs attribute by basename, rewriting the returned bytes to a low-looking energy value. That is precisely the mechanism the analog at `ch13-powercap-override-analog/` implements, except pointed at `/tmp/ch13_sensor_energy_uj` instead of `/sys/class/powercap/intel-rapl:0/energy_uj`. Same tracepoints, same helper, same flow, different target.

The only part of the attack that would differ on x86 RAPL is the basename match in the BPF program and the fake payload (something that looks like a valid energy microjoule reading in text, like `0\n` or `100\n`). The rest of the BPF code is portable.

I say this with high confidence because I have traced the code paths: `cat /sys/class/powercap/intel-rapl:0/energy_uj` on an x86 host calls `openat` on the sysfs file, then `read` on the returned fd, and the read ultimately produces bytes by calling the `energy_uj_show` callback registered by `intel_rapl_common`. The userspace-visible read is an ordinary `read(2)` syscall; the tracepoint on `sys_exit_read` fires after the sysfs read has produced bytes but before the bytes propagate to userspace; `bpf_probe_write_user` can rewrite the user-space buffer at that point, exactly as the analog does. The pattern is well-established; the reason I have not built the real thing is that I do not have the host, not that the primitive is exotic.

## The Analog on aarch64

What I did build is a userspace analog that reproduces the motion of the attack on a surface that exists on aarch64. It consists of three programs: a sensor daemon (`sensor_daemon.c`), a sensor reader (`sensor_reader.c`), and the BPF loader (`ch13-powercap-override-analog.c` plus the bytecode in `ch13-powercap-override-analog.bpf.c`). The analog target is `/tmp/ch13_sensor_energy_uj`. The BPF program matches reads of that file by basename and rewrites the returned bytes with `"0\n"`.

The purpose of the analog is to prove the mechanism end-to-end. A reader `cat`s the sensor file, the daemon is continuously updating the file with increasing energy values, and the BPF program makes every read look like the energy counter is stuck at zero. Defender-class tooling that consumes the sensor sees flat zero; the underlying file is actually climbing. The illusion is identical in shape to what a real RAPL attack would produce against `intel-rapl:0/energy_uj`.

I want to be explicit: the analog is not proof that the real attack works on x86. It is proof that the primitive shape — tracepoint-plus-`bpf_probe_write_user` on the read syscall — functions correctly against a file-backed sensor. Porting to x86 RAPL requires access to an x86 host with the real sysfs attribute and the basename-match logic updated. I am confident the port would work based on code-path analysis; I have not run it.

The analog target is deliberately at `/tmp/` because the BPF program needs to match by basename, and I did not want the match to accidentally fire against any other file on the system. The daemon writes with atomic rename (write to `.tmp`, rename over the target) so the reader never sees a partial update; this matches the atomicity contract of sysfs reads, which always see a consistent snapshot.

## Source Walk: The Sensor Daemon

The sensor daemon at `sensor_daemon.c` is a small C program that writes a monotonically increasing energy value to the target file every 100ms. Key excerpt:

```c
#define TARGET "/tmp/ch13_sensor_energy_uj"
#define TMPTGT "/tmp/ch13_sensor_energy_uj.tmp"

int main(int argc, char **argv)
{
    unsigned long long step = 100;  // energy units per tick
    unsigned long long base = 100;  // start value
    unsigned int       interval_ms = 100;
    int                iterations  = -1;  // -1 = forever
    ...
    unsigned long long energy = base;
    int fd = open(TMPTGT, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ...
    char line[64];
    int  nlen = snprintf(line, sizeof(line), "%llu\n", energy);
    if (write(fd, line, (size_t)nlen) != nlen) {
        perror("sensor: write seed"); close(fd); return 1;
    }
    close(fd);
    if (rename(TMPTGT, TARGET) < 0) { perror("sensor: rename"); return 1; }
    ...
```

The atomic-rename pattern (open tmp, write tmp, rename to target) is essential for correctness. `rename(2)` is atomic on a single filesystem; a reader that has just finished `open(TARGET, O_RDONLY)` holds a reference to one inode, and a subsequent rename does not affect that reader's view. If the daemon wrote in-place, a reader could catch a half-written file and get corrupt bytes. The rename pattern gives the reader the atomicity guarantee that a real sysfs attribute provides via the kernel's own show-callback mechanism.

The main loop ticks every 100ms, adds the step (default 100) to the energy counter, and writes the new value. Over a three-second BEFORE window, the energy climbs from 100 to 3100 — 30 ticks. That's the climbing baseline the trigger script is looking for.

Command-line flags are there to tune the rate (`--interval-ms`), the step (`--step`), the starting value (`--base`), and the iteration count (`--iterations`). For the trigger, defaults are used; the values produce enough climb to be visually obvious in the BEFORE output without taking too long.

The daemon exits cleanly on SIGINT/SIGTERM via a signal handler that sets a stop flag. The trigger script kills the daemon in its cleanup handler after the AFTER window completes.

## Source Walk: The Sensor Reader

The reader at `sensor_reader.c` is even simpler. Excerpt:

```c
#define TARGET "/tmp/ch13_sensor_energy_uj"

int main(int argc, char **argv)
{
    int iterations = 3;
    unsigned int interval_ms = 1000;
    const char *tag = "reader";
    ...
    size_t cap = 128;
    char  *buf = malloc(cap);
    ...
    for (int i = 0; i < iterations && !stop; i++) {
        int fd = open(TARGET, O_RDONLY);
        ...
        memset(buf, 0, cap);
        ssize_t n = read(fd, buf, cap - 1);
        close(fd);
        ...
        if (n > 0 && buf[n - 1] == '\n') buf[n - 1] = 0;
        buf[n] = 0;
        fprintf(stdout, "[%s] iter=%d value=%s\n", tag, i, buf);
        ...
    }
```

Three iterations by default, one second apart. Each iteration: open the target, read into a heap-allocated buffer, print the value.

The heap allocation is important. `bpf_probe_write_user` writes to a user-space memory region, and it has to write to memory that is writable in the reader's address space. `malloc` gives us a heap page that is readable and writable. A stack buffer would also work, but the heap is the more conservative choice because stack pages have some OS-level protection games that can fail on constrained systems. Either way, the thing the helper writes to has to be in the reader's process map with write permission from userspace.

The `tag` field is there so the trigger can distinguish BEFORE-run output (`[before]`) from AFTER-run output (`[after]`) in a combined log. No other purpose.

The trim-trailing-newline logic keeps the output clean: if the value ends with `\n`, replace it with `\0` before printing. That way the log line is `[reader] iter=0 value=12345` instead of `[reader] iter=0 value=12345\n` with a bare newline trailing. Cosmetic but useful.

## Source Walk: The BPF Program

The BPF object at `ch13-powercap-override-analog.bpf.c` is where the primitive actually lives. I will walk it top to bottom.

The disclaimer at the top of the file is deliberately long:

```c
// ch13 powercap-override ANALOG
// ---------------------------------------------------------------------------
// DISCLAIMER: Intel RAPL / powercap is x86-only. The test kernel here is
// aarch64 linuxkit, so the real subsystem does not exist on this host. This
// analog reproduces the *primitive shape* of the attack on a surface that
// *does* exist: a userspace "sensor daemon" that writes to a plain file, and
// a reader that cats that file. The BPF program uses the same ch05 pattern —
// tracepoints on sys_enter_read / sys_exit_read plus bpf_probe_write_user —
// to rewrite the reader's user buffer in flight.
//
// This is NOT a RAPL exploit. It demonstrates the motion: intercept the
// read syscall, identify the file by basename, rewrite the returned bytes
// before the syscall returns to userspace.
```

I put that in the source because I wanted the scope explicit in the code itself, not just in chapter text. Anyone opening the bpf.c file should read the scope disclaimer before the code. The "NOT a RAPL exploit" phrase is blunt on purpose — it is the exact claim I did not want this chapter's draft to slide into.

Event structure:

```c
struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    long         orig_bytes;
    int          patched;
};
```

Basic per-event metadata: the PID, the TGID, the comm (for visual identification in the log), the original byte count that `read(2)` returned (what the file actually provided), and a flag indicating whether we patched the user buffer. The original byte count is interesting because on an untouched read of the sensor file, it will be the length of the value text — something like 4-8 bytes. After patching, the reader sees only `"0\n"`, but the original count tells us how much real content the syscall had produced.

Maps:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct rctx {
    unsigned long buf;
    unsigned int  is_sensor;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);     // pid_tgid
    __type(value, struct rctx);
    __uint(max_entries, 10240);
} inflight SEC(".maps");
```

Ringbuf for events (256 KiB, plenty for a POC that fires a handful of times). The `inflight` map is where per-read state lives: keyed by `pid_tgid` (the full 64-bit identifier), value is the user-buffer pointer and a flag saying whether this read is against the sensor file.

The inflight map has to live across the syscall: entered at `sys_enter_read`, consumed at `sys_exit_read`. Between enter and exit, the read executes and produces bytes; the BPF program needs to remember the user buffer's address and the "is this a sensor read" flag so that the exit hook knows where to write the forgery.

The basename match:

```c
// Basename we're watching: "ch13_sensor_energy_uj" (21 chars, fits in 24).
// We compare byte-by-byte to keep the verifier happy on every kernel.
static __always_inline int is_sensor_name(const char *nm)
{
    // 'c','h','1','3','_','s','e','n','s','o','r','_',
    // 'e','n','e','r','g','y','_','u','j','\0'
    return nm[0]=='c' && nm[1]=='h' && nm[2]=='1' && nm[3]=='3' &&
           nm[4]=='_' && nm[5]=='s' && nm[6]=='e' && nm[7]=='n' &&
           nm[8]=='s' && nm[9]=='o' && nm[10]=='r' && nm[11]=='_' &&
           nm[12]=='e' && nm[13]=='n' && nm[14]=='e' && nm[15]=='r' &&
           nm[16]=='g' && nm[17]=='y' && nm[18]=='_' && nm[19]=='u' &&
           nm[20]=='j' && nm[21]==0;
}
```

Byte-by-byte comparison against a 22-character literal (21 chars plus NUL). Ugly but portable. A more elegant approach would use `__builtin_strcmp` or similar, but the verifier has historically been picky about loop-based string operations, and this explicit unrolled form gets accepted on every kernel version I have tested. For a real RAPL attack, this would be a comparison against `"energy_uj"` or a longer string matching `intel-rapl:N/energy_uj`; the mechanics are identical.

The `__always_inline` is necessary because the verifier needs to see the function body inline in the caller to track pointer provenance; a real function call would obscure that.

The enter hook:

```c
SEC("tp/syscalls/sys_enter_read")
int tp_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long id   = bpf_get_current_pid_tgid();
    int           fd   = (int)ctx->args[0];
    unsigned long buf  = (unsigned long)ctx->args[1];

    // Walk current->files->fdt->fd[fd] to get the open file, then its
    // dentry->d_name.name. Same CO-RE chain ch05 uses.
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(t, files);
    if (!files) return 0;
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) return 0;
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if ((unsigned int)fd >= max_fds) return 0;
    struct file **farr = BPF_CORE_READ(fdt, fd);
    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &farr[fd]);
    if (!f) return 0;

    const unsigned char *name = BPF_CORE_READ(f, f_path.dentry, d_name.name);
    char nm[24] = {};
    bpf_probe_read_kernel_str(&nm, sizeof(nm), name);

    struct rctx r = { .buf = buf, .is_sensor = 0 };
    if (is_sensor_name(nm))
        r.is_sensor = 1;

    bpf_map_update_elem(&inflight, &id, &r, BPF_ANY);
    return 0;
}
```

This is the standard ch05-pattern CO-RE walk for "find the open file at this fd and get its dentry name." Step by step:

1. `bpf_get_current_task()` gets the current task_struct.
2. `task->files` is the `files_struct` holding the task's open file descriptor table.
3. `files->fdt` is the `fdtable` — the actual array of open file pointers.
4. `fdt->max_fds` bounds the fd range. If the requested fd is out of range, abort.
5. `fdt->fd` is the file pointer array. Read the fd-th entry.
6. `file->f_path.dentry->d_name.name` is the basename of the file.

The `bpf_probe_read_kernel_str` at the end copies the name into a local 24-byte buffer. The size is chosen to fit the longest basename we expect to match plus some headroom; 24 bytes covers `ch13_sensor_energy_uj\0` (22 bytes) with room to spare.

The basename match runs against the local buffer. If it matches, the `is_sensor` flag is set. Either way, the per-read record is stored in the inflight map keyed by the pid_tgid.

A detail worth highlighting: we record the user buffer pointer (`ctx->args[1]`) at enter time, not exit. This is because `ctx->args[1]` at enter is the second argument to `read(2)` — the destination buffer. At exit, the args are gone (exit tracepoints expose only the return value). Capture the buffer at enter, use it at exit.

The exit hook:

```c
SEC("tp/syscalls/sys_exit_read")
int tp_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    unsigned long id = bpf_get_current_pid_tgid();
    struct rctx *r = bpf_map_lookup_elem(&inflight, &id);
    if (!r) return 0;

    long ret = ctx->ret;
    int  patched = 0;

    if (ret > 0 && r->is_sensor) {
        // Replace the read() result with "0\n". This mirrors what a real
        // RAPL override would do: make the energy counter look static/zero
        // to any userland observer.
        static const char fake[] = "0\n";
        long n = sizeof(fake) - 1;   // 2 bytes
        if (n > ret) n = ret;
        bpf_probe_write_user((void *)r->buf, fake, n);
        // Best-effort: NUL out a few more bytes so trailing garbage from the
        // real read doesn't trip a naive reader that keeps scanning.
        if (ret > n) {
            static const char zeros[16] = {};
            long tail = ret - n;
            if (tail > (long)sizeof(zeros))
                tail = sizeof(zeros);
            bpf_probe_write_user((void *)(r->buf + n), zeros, tail);
        }
        patched = 1;
    }

    if (r->is_sensor) {
        struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid        = id & 0xffffffff;
            e->tgid       = id >> 32;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            e->orig_bytes = ret;
            e->patched    = patched;
            bpf_ringbuf_submit(e, 0);
        }
    }

    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
```

Look up the inflight record. If missing (no matching enter), bail. If the read returned positive bytes and the target flag is set, patch: write `"0\n"` at the user buffer, then NUL out up to 16 trailing bytes to scrub any real content the read had produced.

The `static const char fake[] = "0\n"` is a BPF-local string. The compiler emits it into the program's data section; at runtime, the verifier confirms it is read-only and bounded. Passing it to `bpf_probe_write_user` is fine because the helper takes a generic pointer with a size.

The trailing NUL scrub is best-effort. If the original read produced more than 18 bytes (2 for "0\n" + up to 16 for zeros), there might be some real content past byte 18 that a very careful reader could pick up. In practice the analog target is always under 16 bytes (the daemon writes values like `12345\n`, which is under 10 bytes), so the tail scrub covers the full content. For a real RAPL attack, the energy_uj file produces maybe 15-20 bytes, and the scrub size would need to be expanded accordingly.

The ringbuf emit always fires if `is_sensor` is set, regardless of whether we patched. This gives visibility into the case where the read returned zero or negative (EOF, error) on a sensor file — we did not patch, but we saw the read.

Cleanup: delete the inflight entry. Without this, the map would accumulate stale entries from reads that never reach exit (rare but possible), and eventually fill up.

## Source Walk: The Userspace Loader

The loader at `ch13-powercap-override-analog.c` is minimal. It opens, loads, and attaches the skeleton; pumps the ringbuf; and exits cleanly on signal.

```c
skel = ch13_powercap_override_analog_bpf__open_and_load();
...
int err = ch13_powercap_override_analog_bpf__attach(skel);
...
rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
...
fprintf(stderr, "[ch13-analog] attached — sensor override active (Ctrl-C to exit)\n");

while (!stop) {
    int n = ring_buffer__poll(rb, 200);
    if (n < 0 && n != -EINTR) {
        fprintf(stderr, "[ch13-analog] ring_buffer__poll: %s\n", strerror(-n));
        break;
    }
}
```

No kallsyms preflight here because the attach targets are tracepoints, which are more stable across kernel versions than kprobes. The tracepoint definitions `syscalls/sys_enter_read` and `syscalls/sys_exit_read` have existed since the tracing subsystem's introduction and are unlikely to change. If they were absent, `open_and_load` would fail with a specific error.

The event handler:

```c
static int handle_event(void *ctx, void *data, size_t sz)
{
    ...
    const struct evt *e = data;
    if (e->patched) patched_count++;
    printf("[ch13-analog] pid=%-7u comm=%-16s sensor_read_bytes=%-4ld patched=%d\n",
           e->pid, e->comm, e->orig_bytes, e->patched);
    ...
}
```

Logs one line per event with the PID, comm, original byte count from the read, and patched flag. The `patched_count` global accumulates across the run; it is printed at shutdown.

## The Trigger and the Proof Marker

The trigger at `trigger.sh` runs a three-phase comparison:

Phase 1: start the sensor daemon, wait for it to produce the target file, confirm readable.

Phase 2: BEFORE run — execute the reader for three iterations (1s interval), capture output. No BPF attached. Expected output is the climbing energy values: `value=100`, `value=200`, `value=300` or similar. The trigger extracts the first and last values.

Phase 3: start the BPF loader, wait for it to report "attached," then AFTER run — execute the reader again for three iterations. Expected output is `value=0`, `value=0`, `value=0`. The BPF program patches every read of the sensor file.

Relevant proof-marker logic:

```bash
AFTER_FIRST="$(grep '\[after\] iter=0' "$AFTER_LOG" | sed -n 's/.*value=\([0-9][0-9]*\).*/\1/p')"
AFTER_LAST="$(grep '\[after\] iter=2'  "$AFTER_LOG" | sed -n 's/.*value=\([0-9][0-9]*\).*/\1/p')"
ZERO_COUNT="$(grep -c '\[after\] .* value=0$' "$AFTER_LOG")"
...
PATCHED_COUNT="$(grep -c 'patched=1' "$LOADER_LOG")"
...
echo "=== CH13_ANALOG_PROVEN before_climb=${BEFORE_FIRST:-?}->${BEFORE_LAST:-?} after=${AFTER_LAST:-?} zero_reads=${ZERO_COUNT} patched_events=${PATCHED_COUNT} disclaimer=\"same primitive as RAPL override; real RAPL is x86-only\" ==="
```

The marker reports: the BEFORE climb (first and last observed values in the BEFORE run), the AFTER value (last observed in the AFTER run), the count of zero-valued reads in the AFTER log, and the count of patched events in the loader log. The `disclaimer=` field is explicit in the marker so that any automated consumer reading the output sees the scope statement.

For a successful run, expected marker is:

```
CH13_ANALOG_PROVEN before_climb=100->300 after=0 zero_reads=3 patched_events=3 disclaimer="same primitive as RAPL override; real RAPL is x86-only"
```

Three zero reads in the AFTER log, three patched events in the loader log, BEFORE climb confirming the daemon was actually producing increasing values. The numbers match: every read the reader issued against the sensor file was intercepted, the user buffer was rewritten, and the reader saw zero.

The harness entry in `dBPF-pocs/harness/proof.py` is:

```python
Poc("ch13a", "Powercap Override — userspace sensor analog",
    "ch13-powercap-override-analog",
    hooks=["tp:syscalls/sys_enter_read", "tp:syscalls/sys_exit_read"],
    prefix="[ch13-analog]", mode="trigger-runs-loader", timeout=25,
    proof_marker=r"CH13_ANALOG_PROVEN|CH13_CONCEPT_PROVEN|_PROVEN"),
```

Two tracepoint hooks declared (using the `tp:` prefix the harness understands for tracepoint availability checks). The `mode="trigger-runs-loader"` flag means the trigger script is responsible for starting and stopping the loader, not the harness. Timeout of 25 seconds covers the full before-after-verdict cycle with headroom.

## Why bpf_probe_write_user Is the Load-Bearing Helper

Of all the BPF helpers, `bpf_probe_write_user` is the most consequential one for this primitive, and it deserves its own section because the security model around it is unusual.

The helper writes to a user-space memory region. Its signature is:

```c
long bpf_probe_write_user(void *dst, const void *src, u32 len);
```

`dst` is a user-space pointer, `src` is a kernel-side buffer (typically a BPF program local), and `len` is the byte count. The helper returns 0 on success or a negative errno on failure (bad pointer, wrong page permissions, etc.).

The security model around this helper is: the writing program must have `CAP_SYS_ADMIN` or `CAP_BPF`, the target process's memory must be writable by the kernel (which it ordinarily is, for pages in the process's address space), and the kernel logs a warning at the first use of this helper per boot. That last point is interesting — the warning appears in `dmesg` repeatedly (rate-limited) whenever the helper is invoked. The actual kernel source at `kernel/trace/bpf_trace.c:365` uses `pr_warn_ratelimited`, not `pr_warn_once`. It looks like:

```
BPF tracing program ch13_powercap_override_analog is writing to user space memory.
This is a potentially dangerous operation.
```

The warning is deliberate. The kernel developers who added this helper wanted it to be possible (for legitimate debugging and observability use cases) but also wanted it to be noisy, so that any system with audit-log monitoring would surface the use. A defender running `dmesg -w | grep 'writing to user space'` would see the warning each time the primitive fires (subject to rate limiting).

This is a meaningful detection signal. Most BPF programs do not touch user-space memory; the ones that do are typically in a narrow set (debugging tools, some profilers). A warning when user-space write fires is high-signal.

For an attacker, the warning is annoying but not fatal. Because it is `pr_warn_ratelimited`, it fires repeatedly — not just once per boot — but the rate limiter suppresses rapid-fire repetitions. If the defender is not log-monitoring, the warnings may evaporate into the kernel log and get overwritten eventually. For a defender who is log-monitoring, each firing is a signal that a user-space-writing BPF program is active, with the program's name visible.

The attacker countermeasures are limited. Because the warning is rate-limited rather than once-per-boot, sustained use of the helper produces ongoing dmesg evidence. The best the attacker can do is minimize invocations and hope the rate-limited warnings fall below the defender's log-monitoring noise floor.

For the analog specifically, the warning appears on first load. If you run `dmesg` right after starting the loader, you see it. This is not a defect in the primitive; it is the kernel's security model for user-space writes.

## Pages, Permissions, and When the Helper Fails

Some details on when `bpf_probe_write_user` can fail, because the failure modes affect both the attack and the detection.

The helper writes via `copy_to_user` internally, which respects page permissions. If the target page is read-only, the write fails with `-EFAULT` and the BPF program sees the error. In practice, heap pages (from malloc) are writable; stack pages are writable; text pages are not; some mmap'd regions are read-only depending on flags.

The reader in the analog uses `malloc` to allocate the buffer, so the buffer is on the heap, and the heap is writable. The write succeeds. If the reader used a `mmap(..., PROT_READ, MAP_PRIVATE, ...)` region to hold the read buffer, the write would fail.

Swapped-out pages are also a failure mode: if the target page is swapped to disk, the helper cannot page it in (BPF programs cannot block on disk I/O), so the write fails with `-EFAULT`. In practice for a reader actively executing a `read` syscall, the page is hot — it was just touched by the kernel writing read contents into it — so the helper almost always succeeds.

Page-fault-on-write could be a problem on systems with fork-based copy-on-write pages. If the reader has just been forked and not yet written to the buffer, the page is COW-shared with the parent. `bpf_probe_write_user` would trigger the COW fault, which would block. I have not seen this failure in practice because the reader always does a `memset(buf, 0, cap)` before `read`, which breaks any COW sharing before the BPF helper fires. But it is a theoretical edge case.

For a real RAPL attack, the user-space buffer is whatever the monitoring tool allocated. Most monitoring tools read into a heap buffer; `turbostat` does, `netdata`'s intel_rapl plugin does. Mmap-based reads are rare for this kind of data. The write should succeed in the overwhelming majority of cases.

## Page Size and Byte Alignment

The BPF verifier requires `bpf_probe_write_user` calls to stay within a bounded size. The helper itself will not write past the `len` argument, but the verifier wants to see that `len` is a small compile-time-known number or a variable bounded to a small value.

In the analog, the writes are `sizeof(fake) - 1 = 2` bytes and `sizeof(zeros) = 16` bytes. Both are constants; the verifier has no trouble with them. For a dynamically-sized write — say, matching the exact length of the original read — you would need to bound the length to some maximum via a `min` operation. The verifier on 6.12 accepts:

```c
if (n > 32) n = 32;
bpf_probe_write_user(buf, src, n);
```

But not:

```c
bpf_probe_write_user(buf, src, n);  // unbounded n
```

Even if you can prove to yourself that `n` is bounded, the verifier wants the bound to be explicit. This is a common friction point and the reason BPF programs that touch user memory have a lot of `if (n > CONST) n = CONST` guardrails sprinkled through them.

Byte alignment is not generally enforced for `bpf_probe_write_user` — it is a byte-granular copy, and the target does not need to be aligned to any boundary. This is convenient for writing into arbitrary string positions within a larger buffer.

## Detection for the Real Thing on x86

Now back to the real-attack scenario. If this primitive were deployed against an x86 Intel host targeting RAPL, what does the detection playbook look like?

**Turbostat's own sanity check.** `turbostat --debug` prints both RAPL-derived power (from the energy_uj counters) and per-core P-state/C-state data derived from MSRs (aperf, mperf, etc.). The per-core data is independent of the powercap framework; it comes from `rdmsr` on IA32_MPERF/APERF. Any persistent discrepancy between "this core is clearly running at its turbo P-state for 20 seconds" (from aperf/mperf) and "the package energy counter hasn't budged" (from RAPL) is a signal. A competent admin reading turbostat output would notice.

**Perf cross-check.** `perf stat -e power/energy-pkg/` reads the same RAPL energy counter but through a different kernel path: `perf_event` instead of sysfs. Some BPF primitives that target sysfs via `security_file_permission` or tracepoint-plus-write would not affect the perf path, because perf does not go through `sys_enter_read` on a regular file. Running turbostat and perf simultaneously on the same host and looking for drift is a cheap check.

Note: the analog primitive in this chapter would not affect perf either, because perf reads do not go through `sys_enter_read`. The primitive is narrow to userspace reads of the sysfs attribute. A smarter attacker would layer multiple primitives — tracepoint-plus-write for sysfs, LSM-level interception for perf — to cover both paths. The detection then becomes "run two independent tools and look for disagreement," which is harder to fool but still tractable.

**MSR direct read.** `rdmsr 0x611` reads the MSR_PKG_ENERGY_STATUS register directly, bypassing the powercap framework entirely. This requires CAP_SYS_RAWIO and the `msr` kernel module. An admin with an independent MSR-based monitoring path would see the truth regardless of what the powercap framework reports to regular userspace tools. This is the nuclear option on the detection side, but it is what serious power monitoring looks like — independent paths, cross-checked, with one of them hard to fool from BPF.

**Off-host monitoring.** A baseboard management controller (BMC) reading power via IPMI or Redfish is fully independent of the OS. The BMC reads power from the PSU or VRM directly; anything a BPF program does in the host kernel is invisible to the BMC. For production deployments where the power reporting actually matters (datacenter thermal budgets, hyperscaler cost monitoring), BMC-based telemetry is the source of truth. The OS-side tools are convenience; the BMC is accountability.

**BPF detection.** `bpftool prog show type tracepoint | grep -iE 'sys_(enter|exit)_read'` finds tracepoints on the read syscalls. On a well-run host, the list of legitimate programs that tracepoint the read syscall is small (typically a handful of observability tools); anything unexpected warrants investigation. `bpftool prog dump jited` would show the program's instructions, which a skilled analyst could recognize as "this program matches a specific filename and rewrites a user buffer." The byte-by-byte basename match is an easily-recognized pattern in decoded BPF.

**File-integrity monitoring.** Outbound data validation: monitoring tools that forward power readings upstream (to Prometheus, to a hyperscaler metrics pipeline) can add sanity checks — "this reading is suspiciously constant for 5 minutes, alert." This is the end-to-end detection posture: you cannot rely on the primitive's origin point being safe, but you can validate the outputs and alert on anomalies.

For a defender, the detection layering is: independent MSR or BMC read as the source of truth, multiple BPF-visible tools as convenience sources, alerting on discrepancy between the sources. The primitive this chapter describes fools the convenience sources; it does not fool the source of truth. The gap is the attacker's window.

## Detection for the Analog

For the aarch64 analog specifically, detection is:

`bpftool prog show type tracepoint` lists the attached tp programs. `bpftool map dump name inflight` shows the currently-in-flight reads being tracked. The basename-match logic is visible in the program's JIT-ed output if you dump it.

`ls /sys/kernel/tracing/events/syscalls/sys_exit_read/enable` — if enabled on a host that has no tracing user, something is registered.

An alternate reader that does not use `read(2)` defeats the primitive entirely. The most obvious alternate is `mmap(2)` on the target file, which reads the file contents via page faults handled directly by the VFS, not through the read syscall. My BPF program does not hook page faults. A reader that opens the target with `mmap` sees the real file contents.

For a defender, the detection story is: know what programs are attached, run a shadow reader that uses a different I/O path, and alert on disagreement. The analog is narrow enough that any of these catches it.

## Scope: Class II Primitive, Synthetic Target

The scope for this chapter, compressed:

Class II primitive: tracepoint-plus-`bpf_probe_write_user` on the read-syscall exit path, modifying user-buffer contents based on a basename match on the open file. Same primitive class as ch10 (dirent hiding) and ch17 (firmware blob redirection).

Real target on x86: the RAPL energy counter at `/sys/class/powercap/intel-rapl:0/energy_uj`, making idle-looking values appear to power-monitoring tools while the chip actually runs at full load. Not tested by me because I do not have an x86 host; codepath analysis suggests it ports directly.

Analog target on aarch64: a userspace sensor daemon's output file, demonstrating the primitive mechanism against a surface that exists on the test kernel. Proven by the `CH13_ANALOG_PROVEN` marker.

The analog does not claim to be the real thing. It claims to prove the mechanism. The gap between "proven mechanism" and "working attack" is the host-specific porting work that I have not done. A reader who takes this chapter and ports it to an x86 host with access to real RAPL would have the working attack; on my setup, they have the mechanism demonstration.

## What a RAPL Attack Cascade Would Actually Look Like

If you had the full x86 environment and wanted to build the complete attack (not just the read-overwrite primitive), the cascade of BPF programs looks something like this.

First, a tracepoint-plus-write program on `sys_exit_read` matching `/sys/class/powercap/intel-rapl:0/energy_uj` and variants. This makes the RAPL energy counter look static to userspace readers that use `read(2)`.

Second, a BPF LSM fmod_ret program on `security_file_permission` for the same sysfs paths. This catches tools that do permission checks without actually reading — rare but possible. The LSM program returns success (allow read) so the reader proceeds; the read itself is then rewritten by the first program.

Third, a kprobe or tracepoint on the perf subsystem's RAPL event handler (`rapl_event_update` or similar, depending on the kernel version). Perf reads of the energy counter bypass the sysfs path entirely; they go through `perf_event_read` and directly read the MSR. Overriding perf requires either an MSR-read interception (ugly, potentially requires MSR-read tracing which is not a thing BPF does cleanly) or rewriting the perf sample records before they reach userspace. This is the hardest part of the cascade and may not be fully achievable from BPF.

Fourth, a tracepoint on `sys_exit_openat` that tracks process-IDs opening `/dev/cpu/*/msr`. If a process opens the MSR device, it is probably going to read power-related MSRs directly, and this is the point to set a flag that causes subsequent `read` calls on that fd to be rewritten. But `/dev/cpu/N/msr` reads go through the msr driver's read callback, not through regular sys_exit_read handling — they bypass some of the tracepoint observation. This path might require a different primitive entirely.

Fifth, a kprobe on `thermal_zone_device_update` to intercept thermal notifications. This requires `ALLOW_ERROR_INJECTION` annotation on the target, which may or may not be present on the host. If present, override-return to prevent the thermal engine from raising critical-temperature events. If absent, use an LSM hook on thermal-related sysfs writes to suppress defender-visible thermal state changes.

The attack cascade is: visible RAPL reading shows idle, perf shows idle, MSR direct shows idle, thermal notifications are suppressed, chip runs past thermal limits. Four BPF programs, each attacking a different observation path, layered to cover the space.

The defense is the same space in reverse: independent observation paths, cross-checked, with at least one path that BPF cannot touch. BMC-based power monitoring is the usual "BPF cannot touch" path — the BMC reads from VRM shunts or PSU telemetry, completely outside the OS. An attacker with root on the OS cannot change what the BMC sees.

Building the full cascade is substantial engineering work. It is the difference between "I have one primitive" and "I have a full attack chain." The chapter does not include the full cascade because the first primitive is already a whole chapter; the cascade belongs in a follow-up or in a dedicated threat-model document.

## What the Analog Tells Us About Real-World Detection Difficulty

The analog is a narrow demonstration, but it is a useful way to think about how hard real-world detection is.

A defender running the analog sees `CH13_ANALOG_PROVEN` and a clear `before_climb=100->300 after=0` delta. The detection is obvious because the BEFORE and AFTER are run back-to-back and the primitive is in wildcard mode (matches every reader). In a real attack, the attacker would not be in wildcard mode — they would match only the specific monitoring tool's PID, or only monitor processes that look like monitoring (match on comm prefix "netdata" or "turbostat"). The detection gets harder the narrower the targeting.

A defender running two independent monitors — one `cat`-based, one `mmap`-based — sees disagreement: the `cat` reader shows zero, the `mmap` reader shows the climbing values. The disagreement is the detection. But most monitoring systems only run one implementation of "read the counter," not two. The shadow-reader pattern is a defensive tool that is not yet common in practice.

A defender running `dmesg -w` during the attack sees the "writing to user space memory" warning at BPF load. If they were watching dmesg. If they were not — if dmesg was scrolling past due to other activity, or the system's log aggregator was debouncing — the warning might not be noticed. The detection is cheap to observe but requires someone to be looking.

A defender running `bpftool prog show` periodically sees the program in the list. This is reliable but requires a cadence — if the polling interval is longer than the attack window, the program may be loaded and unloaded between polls.

Each of these detection paths has a cost (build the shadow reader, monitor dmesg, poll bpftool) and a blind spot. The defender's job is to stack enough paths that the attacker cannot cover all of them simultaneously. The attacker's job is to find the paths that are not covered.

The analog's existence is, in this sense, a research tool for defenders as much as an attack demonstration. It makes the primitive concrete enough to test detection tooling against. A defender can run the analog, run their detection pipeline, and confirm whether the pipeline catches it. If yes, the detection is robust against this primitive; if no, there is a blind spot to fix.

## Factual Note

The chapter draft I started from described "attaching an eBPF program to `rapl_write_power_limit()`" and "forcing the limit to its maximum" so that "temperatures spiked and hardware warnings fired." That language implied the attack had run on my test kernel. It had not. On my test kernel the function does not exist.

What ran on the test kernel is the analog described above. The analog demonstrates the primitive shape using a userspace sensor daemon and reader. The real attack against RAPL — which I have described in code-path detail above — would require an x86 Intel host with `CONFIG_POWERCAP=y`, which the test bed lacks.

Neither claim is that the real attack is impossible, unproven, or theoretical in some derogatory sense. The codepath analysis is concrete, the primitive (tracepoint-plus-`bpf_probe_write_user`) is the same mechanism that chapter 10 used to hide dirents on the same kernel, and the port to RAPL is a matter of changing the basename match and the fake payload. I just have not had an x86 host on which to prove the full end-to-end.

The honest posture, which I keep coming back to: the primary POC (direct kprobes on the powercap framework) cannot fire on aarch64 linuxkit because the subsystem does not exist. The analog demonstrates the primitive shape using a userspace sensor. Neither claims to be a working RAPL override on this host. I have not tested the LSM-over-sysfs path on an Intel host. What I have demonstrated is the mechanism; the specific target it would be pointed at on x86 remains untested by me, flagged as such, and left as an exercise for anyone with the appropriate test bed.
