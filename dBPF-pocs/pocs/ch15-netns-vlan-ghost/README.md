# ch15 — NetNS VLAN Ghost

## Mechanism
An XDP program attached to the host-side of a veth pair inspects every
ingress frame. When it finds an 802.1Q header with VID 4242
(`COVERT_VLAN_ID`) it:
1. Saves the original MAC src/dst and the inner ethertype.
2. Rewrites a fresh 14-byte ethernet header at offset +4 of the buffer
   (overlaying the old src_mac tail, the 0x8100 ethertype, and the
   VLAN TCI).
3. Calls `bpf_xdp_adjust_head(ctx, +4)` to trim the leading 4 bytes
   so the new untagged ethernet header becomes the packet head.
4. If userspace registered an egress ifindex in the `tx_port` DEVMAP
   (slot 0) and `cfg[0] == 1`, calls `bpf_redirect_map(&tx_port, 0, 0)`;
   otherwise returns `XDP_PASS`.

The result: traffic tagged with VID 4242 on `veth_host` can be ferried
onto `veth_host2` — a veth whose peer lives in a *different* network
namespace. The orchestrator's monitoring on the vlan-aware bridge or
host stack never observes the tagged frame (XDP runs before the stack);
the destination namespace receives a clean, untagged ethernet frame.

The book's chapter imagines a `kprobe/__netif_receive_skb_core` hook
rewriting namespace metadata. That exact mutation is not permitted by
the verifier (skb writes from kprobe context are rejected, and the
function is not in `/sys/kernel/debug/error_injection/list`). XDP +
`bpf_redirect_map` to a device in another netns is the honest, working
expression of the same primitive on 6.12.

## Hook points
- `SEC("xdp")` `xdp_vlan_ghost` on the ingress veth.
- `BPF_MAP_TYPE_DEVMAP tx_port` (slot 0 → egress ifindex) drives
  `bpf_redirect_map`.
- `BPF_MAP_TYPE_ARRAY cfg` (slot 0 = mode flag, slot 1 = audit copy of
  egress ifindex).

## Build
```
cd /Users/mbhatt/spaceclaw/evilBPF/dBPF-pocs
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch15-netns-vlan-ghost && make'
```

## Run
```
./build/ch15-netns-vlan-ghost --help
./build/ch15-netns-vlan-ghost --skb -i veth_host -o veth_host2
./build/ch15-netns-vlan-ghost -i veth_host                    # strip-only
./build/ch15-netns-vlan-ghost veth_host veth_host2            # back-compat
```
SIGINT/SIGTERM detaches XDP from every interface it attached to; if the
loader exits via any error path, `detach_all()` still runs.

End-to-end demo (creates ghost_a / ghost_b netns, sends one
VLAN-4242-tagged AF_PACKET frame from inside ghost_a, sniffs egress on
veth_host2):
```
docker run --rm --privileged --pid=host \
  -v "$PWD":/work -w /work \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  dbpf-base bash pocs/ch15-netns-vlan-ghost/trigger.sh
```

## Evidence
Captured running `bash trigger.sh` inside the privileged dbpf-base
container (linuxkit aarch64, XDP forced to SKB-mode):
```
=== loading XDP ghost on veth_host -> redirect to veth_host2 (SKB-mode) ===
[ch15] tag=ready ingress=veth_host ifidx=42 mode=redirect egress=veth_host2 ifidx=44 xdp_flags=0x2

=== sending 5 VLAN-4242 AF_PACKET frames from inside ghost_a ===
sent 5 VLAN-4242 covert frames

=== loader ringbuf events ===
[vghost] ifin=42 vid=4242 inner=0x88b5 ee:f0:6e:11:22:33 -> ff:ff:ff:ff:ff:ff  STRIP+REDIRECT ifout=44
[vghost] ifin=42 vid=4242 inner=0x88b5 ee:f0:6e:11:22:33 -> ff:ff:ff:ff:ff:ff  STRIP+REDIRECT ifout=44
... (5 lines total)

=== tcpdump on veth_host2 ===
ee:f0:6e:11:22:33 > ff:ff:ff:ff:ff:ff, ethertype Unknown (0x88b5), length 78: ...
```
The tcpdump frame is **untagged** (no `vlan 4242` in the dissector
output) — proving the BPF program stripped the tag before the egress
veth saw the redirected packet.

## Detection
- `bpftool net show dev <ifname>` lists XDP programs attached to an
  interface — almost nothing legitimate loads XDP on container veths.
- `bpftool prog show` plus `bpftool map dump name tx_port` reveals
  DEVMAP entries pointing at veths whose peers live in foreign
  namespaces.
- `ip -d link show dev <ifname>` annotates `xdpgeneric/xdp/xdpoffload`
  when an XDP program is attached.
- Audit any process loading XDP that calls `bpf_xdp_adjust_head` +
  `bpf_redirect_map` together — that pair is rare outside dataplanes.

## Limitations / arch notes
- **Docker Desktop linuxkit aarch64**: veth drivers do NOT implement
  native XDP; the loader falls back to SKB-mode (or use `--skb` to
  skip the probe). Native-mode redirect is unavailable.
- `bpf_redirect_map` to a device in another netns requires the egress
  device to also have an XDP program loaded on many kernels; the
  loader attaches the same program there.
- The verifier rejects skb writes from kprobe context, so the book's
  `__netif_receive_skb_core` mutation cannot be done directly. XDP at
  the NIC edge is the equivalent primitive.
- `arping` and `ping` won't generate the covert frames reliably; the
  trigger uses an embedded AF_PACKET sender for deterministic VLAN-4242
  emission with inner ethertype 0x88b5 (IEEE Local Experimental).

## Blog post

See the chapter write-up: [`2025-04-15-netns-vlan-ghost`](../../../_posts/2025-04-15-netns-vlan-ghost.md) in the Diabolical eBPF Field Manual.
