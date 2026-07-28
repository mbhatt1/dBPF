# ch06 Silence SELinux — LSM variant (OBSERVER; the flip is impossible)

Sibling POC to `ch06-silence-selinux/` (kprobe observer on SELinux's AVC).
This variant attaches real BPF LSM hooks. It was intended to *change*
SELinux decisions (deny → allow); live testing proves that is **impossible**.
What it can honestly do is *observe* allowed decisions.

## Why the "silence" flip is impossible (proven, not asserted)

The Linux LSM framework runs hooks as an **ordered, deny-wins chain**.
`call_int_hook()` walks the registered modules for a hook and **stops at the
first module that returns a non-default (nonzero) value**. The active order
on any stock kernel places `selinux` *before* `bpf`:

```
$ cat /sys/kernel/security/lsm
lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm
```

Consequences:

1. When SELinux **denies**, it returns `-EACCES` first and the chain
   short-circuits — the bpf hook is **never invoked** for that access.
2. The bpf hook therefore only ever runs when everything before it returned
   0, so the trailing `ret` arg it receives is **always 0**. The flip
   condition (`ret != 0`) is never true.
3. Returning 0 from a later hook cannot un-select the `-EACCES` the framework
   already chose.

A BPF LSM hook can thus only make policy **more** restrictive (turn an
*allow* into a *deny*, since it runs after SELinux's allow). It can **never**
relax a SELinux denial. "Silencing SELinux" via BPF LSM is a category error.

## Live proof (Fedora 43, kernel 6.17.1-300.fc43.aarch64, SELinux enforcing)

A custom SELinux type `ch06deny_t` was installed (CIL module) so that the
running `unconfined_t` domain is genuinely denied `read` on a labeled file:

```
$ cat deny.txt                 # baseline, no BPF
cat: deny.txt: Permission denied          # EACCES, AVC permissive=0
```

With all three hooks attached in wildcard "flip every deny" mode, 150
denied reads + several denied execs were driven through the chain:

```
active_deny_ret_last = 1        # still Permission denied, WITH bpf active
FLIP_lines           = 0        # production loader emitted ZERO flips

==== EVENT SUMMARY (orig_ret==0 | orig_ret!=0 | flipped) ====
  file_permission      zero=2330   nonzero=0  flipped=0
  inode_permission     zero=31646  nonzero=0  flipped=0
  bprm_check_security  zero=155    nonzero=0  flipped=0
  first_nonzero_event: (none)

# audit.log during the loader-active window:
avc: denied { read } ... comm="cat" tcontext=...:ch06deny_t ... permissive=0
   (150 such denials, all still enforced)
```

Across ~34,000 hook invocations while 150+ real SELinux denials were
occurring, the hook saw a nonzero `ret` **zero** times — it never even
observes a denial, let alone flips one.

## What ch06 CAN honestly do: observe allowed decisions

The ~34,000 `orig_ret==0` events above are the honest capability: these
hooks fire on every SELinux-**permitted** file/inode/exec operation and can
read and export those decisions. ch06 is a **BPF LSM observer of allowed
operations** (and, if extended, an additional *deny* layer) — not a silencer.

| Hook | Fires on | Observable |
|------|----------|------------|
| `lsm/file_permission` | vfs read/write/exec on an open file | allowed file I/O |
| `lsm/inode_permission` | path-walk / open-time check | allowed path traversal + open |
| `lsm/bprm_check_security` | execve of a binary | allowed program execution |

## Host prereqs

- Kernel with `CONFIG_BPF_LSM=y` and `CONFIG_SECURITY_SELINUX=y`.
- Boot cmdline `lsm=…` containing both `bpf` and `selinux`.
- `cat /sys/kernel/security/lsm` must contain **both** `bpf` and `selinux`.
- `bpftool feature probe | grep lsm` shows `program_type lsm available`.
- CAP_SYS_ADMIN to load LSM programs.

## Build / Run

```
make
sudo ./build/ch06-silence-selinux-lsm -a      # attach + observe (wildcard)
sudo bash trigger.sh                           # end-to-end honest demo
```

## Status

**OBSERVER-PROVEN, SILENCER DISPROVEN** on Fedora 43 / kernel 6.17.1
(Lima VM `dbpf-fedora`, SELinux enforcing).

The earlier "PROVEN flip" claim (with `orig=-13 -> 0` sample output) was
**not reproducible and is false**: BPF LSM cannot flip a SELinux denial for
the structural reason documented above. The hooks attach and observe
allowed decisions correctly; the deny→allow path is dead code on any real
SELinux host.

## Limitations / honest caveats

- Cannot relax any SELinux (or other earlier-ordered LSM) denial. Deny-wins.
- Can only ADD restrictions (allow→deny), which is the intended, safe use of
  BPF LSM as a MAC layer.
- DAC and pre-LSM checks are independent and unaffected either way.
