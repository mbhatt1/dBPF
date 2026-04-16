# ch08 — Keyring Heist (observer)

## Mechanism
kprobe on `key_task_permission` and `lookup_user_key`. For each call, CO-RE
reads `struct key → {serial, datalen, type->name, description}` and emits a
ringbuf event. No mutation — observation with full metadata disclosure.

## Hook points
- `kprobe/key_task_permission`
- `kprobe/lookup_user_key`

## Build
    docker run --rm -v "$PWD/../..":/work -w /work dbpf-base \
      bash -c 'cd pocs/ch08-keyring-heist && make'

## Run
    sudo ./build/ch08-keyring-heist
    sudo bash trigger.sh

## Evidence
    [ch08] hook=key_task_perm   pid=1234 comm=keyctl serial=0x3843722f type=user desc='ch08-test-101' len=21
On clean exit:
    [ch08] CH08_PROVEN events=N   (if ≥3 events captured)
    [ch08] CH08_SKIP reason="..." (otherwise)

## Detection
- `bpftool prog show | grep key_`
- `/sys/kernel/debug/tracing/kprobe_events`

## Limitations
- Observer-only. Real mutation requires BPF LSM fmod_ret on
  `security_key_permission` — see `pocs/ch08-keyring-heist-lsm/`.
- Does not attempt to read `key->payload` (requires invoking the key's
  `type->read` method, which is not safe from BPF).

## Blog post

See the chapter write-up: [`2025-02-08-keyring-heist`](../../../_posts/2025-02-08-keyring-heist.md) in the Diabolical eBPF Field Manual.
