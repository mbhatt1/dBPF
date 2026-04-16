# ch05b — Ghost NIC

## Mechanism
XDP program on a veth that swallows a covert C2 channel. UDP packets to
port 31337 whose payload begins with the magic bytes `GHOST` are parsed,
the trailing command bytes are extracted into a ringbuf event, and the
packet is `XDP_DROP`ed before the IP stack ever sees it. tcpdump, raw
sockets, nftables and userspace listeners all see nothing; only the loader
that owns the ringbuf consumes the command stream.

## Hook points
- `SEC("xdp")` attached to a netdev (drv-mode, falling back to skb-mode):
  full ethernet → IPv4 → UDP parse with bounds checks at every step,
  5-byte magic match, copy up to 47 bytes of command, `XDP_DROP`.

## Build
```
cd pocs/ch05b-ghost-nic
make
```

## Run
```
sudo ./build/ch05b-ghost-nic --help
sudo ./build/ch05b-ghost-nic -i veth_g0          # drv-mode, fallback to skb
sudo ./build/ch05b-ghost-nic -i veth_g0 -S       # force skb-mode
sudo ./build/ch05b-ghost-nic -i veth_g0 -v       # libbpf debug

# End-to-end demo (creates veth, ns, sends packets, cleans up):
sudo ./trigger.sh
```

The loader detaches XDP on every exit path — clean shutdown via SIGINT,
attach failure, ring buffer error, or SIGTERM. The trigger script's
`trap ... EXIT` removes `veth_g0` and `ghost_ns` even if the loader or
packet send fails.

## Evidence
Captured runtime output:
```
=== veth pair up ===
veth_g0          UP             ...
veth_g1@if13     UP             ...
[ghost] attached XDP (skb-mode) to veth_g0 ifindex=13
[ghost] polling — Ctrl-C to detach and exit
=== sending magic UDP to 10.66.66.1:31337 from inside ghost_ns ===
sent 2 ghost packets
[ghost] DROPPED pkt 10.66.66.2:49330 -> 10.66.66.1:31337 cmd='/bin/id > /tmp/pwned'
[ghost] DROPPED pkt 10.66.66.2:49330 -> 10.66.66.1:31337 cmd='exfil-command-2'
[ghost] detached XDP from ifindex=13
[ghost] shutdown (rc=0)
```

A concurrent `tcpdump -i veth_g0 udp port 31337` capture shows zero packets
— the XDP_DROP happens before the kernel's ingress tap.

## Detection
- `ip link show veth_g0` reports the `xdp` / `xdpgeneric` flag.
- `bpftool net show` lists every XDP attachment system-wide with prog id.
- `bpftool prog show id <id>` exposes the program's name (`xdp_ghost`),
  load time, and pinned maps.
- Defenders can compare netdev `Rx` byte/packet counters against what
  socket-layer observers (tcpdump, conntrack) report; ghost packets
  increment hardware/driver counters but never reach the stack.

## Limitations / arch notes
- Requires `CAP_NET_ADMIN` + `CAP_BPF` (or root). Native (drv-mode) XDP
  needs driver support; veth supports XDP but on some kernels only via
  `XDP_FLAGS_SKB_MODE` — the loader auto-falls-back, or you can force
  skb-mode with `-S`.
- IPv4 only. IPv6, VLAN-tagged, and encapsulated frames pass through.
- Magic match is the literal ASCII string `GHOST` followed by up to 47
  bytes of command. No authentication: anyone on a connected segment can
  inject commands. A real implementation would HMAC the payload.
- Docker Desktop (linuxkit aarch64): `vmlinux.h` is generally available
  via `/sys/kernel/btf/vmlinux`, but XDP attachment to host-managed veths
  inside the linuxkit VM has been flaky — easier to test on a stock
  Linux host or a privileged Linux VM.
- This POC uses an XDP program, not kprobes, so the kallsyms preflight is
  not applicable. Attach errors (no XDP support, mode unavailable) are
  surfaced via libbpf `strerror()`.

## Blog post

See the chapter write-up: [`2025-02-04-the-ghost-nic`](../../../_posts/2025-02-04-the-ghost-nic.md) in the Diabolical eBPF Field Manual.
