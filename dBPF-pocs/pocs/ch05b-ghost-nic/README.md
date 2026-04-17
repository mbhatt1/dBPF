# Ch05b -- Ghost NIC

**Category**: REAL
**Primitive**: XDP + XDP_DROP for covert C2 channel
**Hook(s)**: `SEC("xdp")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

An XDP program on a veth swallows a covert C2 channel. UDP packets to port 31337 whose payload begins with the magic bytes `GHOST` are parsed, command bytes are extracted into a ringbuf event, and the packet is `XDP_DROP`ed before the IP stack ever sees it. tcpdump, raw sockets, nftables, and userspace listeners all see nothing.

## What this does NOT do

IPv4 only -- IPv6, VLAN-tagged, and encapsulated frames pass through. No authentication: anyone on a connected segment can inject commands. A real implementation would HMAC the payload. Native (drv-mode) XDP needs driver support; some kernels only support `XDP_FLAGS_SKB_MODE` on veth.

## Prerequisites

- `CAP_NET_ADMIN` + `CAP_BPF` (or root)
- XDP support on the target netdev (veth supports XDP, drv or skb mode)
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch05b-ghost-nic.bpf.c` | Kernel-side BPF program (XDP: parse, match magic, XDP_DROP) |
| `ch05b-ghost-nic.c` | Userspace loader with drv/skb-mode fallback |
| `trigger.sh` | Activity generator (creates veth, ns, sends magic UDP packets) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch05b-ghost-nic -i veth_g0
# In another terminal:
sudo bash trigger.sh
```

## Detection

- `ip link show <ifname>` reports the `xdp` / `xdpgeneric` flag.
- `bpftool net show` lists every XDP attachment system-wide with prog id.
- `bpftool prog show id <id>` exposes the program's name (`xdp_ghost`), load time, and pinned maps.
- Compare netdev `Rx` byte/packet counters against what socket-layer observers (tcpdump, conntrack) report; ghost packets increment hardware/driver counters but never reach the stack.
