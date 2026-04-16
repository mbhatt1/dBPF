# ch07 — Device-cgroup Houdini (observer)

## Mechanism
kprobe + kretprobe on `devcgroup_check_permission` stream every decision
the device cgroup makes (type = char/block, major, minor, access mask,
verdict). Observation-only on a stock kernel — the inner
`__devcgroup_check_permission` is usually inlined and not kprobe-able.

## Hook points
- `kprobe/devcgroup_check_permission`
- `kretprobe/devcgroup_check_permission`

## Build
    docker run --rm -v "$PWD/../..":/work -w /work dbpf-base \
      bash -c 'cd pocs/ch07-devcgroup-houdini && make'

## Run
    sudo ./build/ch07-devcgroup-houdini
    sudo bash trigger.sh

## Evidence
On a non-privileged cgroup, `dd if=/dev/mem` triggers a deny:
    [ch07] pid=1234 comm=dd type=C major=1 minor=1 access=0x1 verdict=-1
On clean exit the loader emits one of:
    [ch07] CH07_PROVEN events=N denies=M
    [ch07] CH07_SKIP reason="no deny observed ..."

## Detection
- `bpftool prog show | grep devcgroup`
- `/sys/kernel/debug/tracing/kprobe_events`

## Limitations
- Privileged Docker containers set `devices.list = a *:* rwm` — root bypasses
  the cgroup entirely, so no denies are observed unless you run inside an
  unprivileged user or a restricted cgroup.
- Actual mutation (grant unrestricted device access) requires BPF LSM — see
  `pocs/ch07-devcgroup-houdini-lsm/`.

## Blog post

See the chapter write-up: [`2025-02-07-device-cgroup-houdini`](../../../_posts/2025-02-07-device-cgroup-houdini.md) in the Diabolical eBPF Field Manual.
