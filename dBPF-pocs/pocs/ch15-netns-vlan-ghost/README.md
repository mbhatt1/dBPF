# Ch15 -- NetNS VLAN Ghost

**Category**: REAL
**Primitive**: XDP + bpf_xdp_adjust_head + bpf_redirect_map for covert cross-namespace traffic
**Hook(s)**: `SEC("xdp")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

An XDP program on the host-side of a veth pair strips 802.1Q VLAN tags (VID 4242) and optionally redirects the untagged frame to a device in a different network namespace via `bpf_redirect_map`. The orchestrator's monitoring on the VLAN-aware bridge or host stack never observes the tagged frame (XDP runs before the stack); the destination namespace receives a clean, untagged ethernet frame.

## What this does NOT do

The book's chapter imagines a `kprobe/__netif_receive_skb_core` hook rewriting namespace metadata. That mutation is rejected by the verifier (skb writes from kprobe context are blocked). XDP + `bpf_redirect_map` is the honest, working expression of the same primitive. Docker Desktop linuxkit aarch64 veth drivers do NOT implement native XDP; falls back to SKB-mode.

## Prerequisites

- `CAP_NET_ADMIN` + `CAP_BPF` (or root)
- XDP support on the target netdev (veth supports XDP in drv or skb mode)
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch15-netns-vlan-ghost.bpf.c` | Kernel-side BPF program (XDP: VLAN strip + bpf_redirect_map) |
| `ch15-netns-vlan-ghost.c` | Userspace loader with strip-only and redirect modes |
| `trigger.sh` | Activity generator (creates netns, sends VLAN-4242 AF_PACKET frames) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch15-netns-vlan-ghost --skb -i veth_host -o veth_host2
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool net show dev <ifname>` lists XDP programs attached to an interface -- almost nothing legitimate loads XDP on container veths.
- `bpftool map dump name tx_port` reveals DEVMAP entries pointing at veths whose peers live in foreign namespaces.
- `ip -d link show dev <ifname>` annotates `xdpgeneric/xdp/xdpoffload` when an XDP program is attached.
- Audit any process loading XDP that calls `bpf_xdp_adjust_head` + `bpf_redirect_map` together -- that pair is rare outside dataplanes.
