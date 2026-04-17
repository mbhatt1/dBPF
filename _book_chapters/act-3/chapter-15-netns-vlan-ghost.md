---
layout: book
title: "Chapter 15: NetNS VLAN Ghost"
date: 2025-04-15
---

# Chapter 15: Cross-Namespace Redirect via XDP and DEVMAP

> **See also**: [Blog post]({{ site.baseurl }}/netns-vlan-ghost.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch15-netns-vlan-ghost) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

Cross-namespace XDP redirect via `bpf_redirect_map` is not novel. Cilium's datapath has used the pattern since approximately 2019 for legitimate cross-namespace forwarding in service-mesh topologies. `tc-bpf` and `xdp-tutorial` examples have demonstrated it in pedagogical form for about the same span. The primitive is mature, documented, and shipping in a large fraction of production Kubernetes clusters today.

What is new in this chapter is the *direction*. Cilium uses the redirect to pull traffic into the right namespace on the way toward a pod. This POC uses the redirect to ferry covert, VLAN-tagged traffic between two tenant-style namespaces without the tagged frames ever being visible to the host-side VLAN-aware bridge or netfilter. The orchestrator's "VLAN 4242 is trunk traffic for tenant A" configuration is bypassed because the XDP program strips the tag before the stack sees the frame, and then redirects the now-untagged payload into a peer veth in a namespace that was supposed to be isolated. The VLAN tag never reaches the bridge, netfilter never sees the frame, and the destination namespace receives an ordinary-looking ethernet frame on its ingress device.

The threat model to be honest about: VLAN-based segmentation was never designed to resist host-level XDP. XDP runs as a peer to the netdev, below the bridge layer, below netfilter, below anything a VLAN-aware config could enforce. A program attached to the host side of a veth sees every frame that arrives at the device, tagged or untagged, before the orchestrator's policy has any chance to act. If you have `CAP_BPF` on the host — and in most of the multi-tenant deployments where VLANs are the isolation mechanism, *somebody* has that capability — there is no VLAN-enforcement layer that XDP cannot preempt. Calling this a "VLAN escape" is overselling it. A more accurate framing: host-level XDP is a privileged capability, and the orchestrators that depend on VLAN segmentation for tenant isolation are depending on an assumption (no unsanctioned XDP) that they do not usually enforce.

## The Original Outline and Why It Did Not Work

My first instinct was the one the original chapter outline called for: a kprobe on `__netif_receive_skb_core` that rewrites namespace metadata on an incoming skb and lets the kernel re-receive it on the other side. On paper, the idea is clean — the skb carries its own namespace pointer (`skb->skb_iif` or, more usefully, the `dev` pointer that encodes the net namespace), and if you could rewrite that pointer from inside the kprobe, the subsequent processing would deliver the frame into a different namespace.

The verifier rejects that. Two reasons, both well-known but worth stating plainly.

First, writes to `sk_buff` from kprobe context are not permitted. The `sk_buff` is a complex kernel data structure with pointer-validity invariants the verifier cannot track across arbitrary writes. Kprobes can *read* skbs (via `bpf_probe_read_kernel` or CO-RE accessors) but cannot write them. This is not an oversight; it is a deliberate design choice. An skb write from a kprobe is the kind of thing that, if permitted, would let a malformed BPF program corrupt the network stack's state in ways the verifier could not predict.

Second, `__netif_receive_skb_core` is not in `/sys/kernel/debug/error_injection/list`. I checked. `bpf_override_return` against it would either fail at load or silently degrade. Even if the verifier allowed skb writes, the function's position in the receive path (deep inside the network stack, between `netif_receive_skb` and the protocol dispatch) is not an error-boundary position and the kernel does not annotate it as injectable.

So the kprobe-rewrite-and-redispatch path is closed on 6.12. The correct way to express the same primitive is XDP — which attaches *before* `__netif_receive_skb_core`, runs with a different execution context (not a kprobe, not bound by kprobe-write restrictions), and has a first-class helper (`bpf_redirect_map`) for the "redirect to another device" operation. XDP is allowed to mutate the packet data buffer; XDP is allowed to change the packet's destination device via `bpf_redirect_map`; XDP's verifier rules are well-suited to the "parse, bounds-check, mutate, redirect" shape.

So the chapter's working implementation is XDP. The original outline's hook point was wrong. I have preserved the kprobe sketch in the book as a cautionary note rather than scrubbing it — the dead end is instructive, and "try the kprobe, hit the verifier wall, fall back to XDP" is the research experience I want to document faithfully.

## Topology

The demo topology is two network namespaces connected through the host. Symbolically:

```
ghost_a (attacker)  <--veth_a---veth_host-->  [host]  <--veth_host2---veth_b-->  ghost_b (victim)
```

- `ghost_a` is a network namespace representing tenant A. It has a veth called `veth_a`. The peer of that veth, `veth_host`, lives in the host namespace.
- `ghost_b` is a second namespace representing tenant B. It has a veth called `veth_b` whose peer `veth_host2` lives in the host namespace.
- The two veth pairs are *not* bridged together. In a legitimate deployment, frames emitted on `veth_a` arrive on `veth_host` and terminate there; there is no L2 path to `veth_host2`.
- The attacker is in `ghost_a`. The goal is to deliver a frame from `ghost_a` into `ghost_b` without any packet-routing configuration in the host having a path between them.

The XDP program runs on the host-side `veth_host`. When a frame tagged with VLAN 4242 arrives from `ghost_a`, the program strips the VLAN tag, and `bpf_redirect_map`s the now-untagged frame to `veth_host2`. The kernel delivers it across the veth pair into `ghost_b`. The victim namespace receives a frame it was never supposed to see.

The trigger script (`trigger.sh`) builds the topology from scratch with `ip netns add ghost_a`, `ip netns add ghost_b`, `ip link add veth_host type veth peer name veth_a netns ghost_a`, and the mirror on the other side. It assigns IPs (`192.168.77.1/24` on `veth_host`, `192.168.77.4/24` on `veth_host2`, `192.168.77.2/24` inside `ghost_a`, `192.168.77.3/24` inside `ghost_b`), brings everything up, and demonstrates that there is no L2 path between the namespaces under normal operation.

That "no path" property is the control. The BEFORE phase of the trigger sends three VLAN-4242-tagged frames from inside `ghost_a` and runs `tcpdump` on `veth_host2` expecting to see zero. It sees zero; the frames arrive at `veth_host`, the host has nothing configured to forward them to `veth_host2`, and they are dropped. The AFTER phase loads the XDP program and sends three more frames. `tcpdump` on `veth_host2` now sees three untagged frames with inner ethertype `0x88b5` (IEEE Local Experimental 1), which is what the BPF program produced after strip-and-redirect.

BEFORE and AFTER on the same script, same netns, same sender: that is the proof. The path didn't exist and then existed, and the only change between the two phases is the XDP program attached to `veth_host`.

## The XDP Program, Line by Line

The attached program is `ch15-netns-vlan-ghost.bpf.c`. Walk it in order.

```c
#define COVERT_VLAN_ID 4242
#define ETH_P_8021Q    0x8100
#define VLAN_VID_MASK  0x0FFF
```

`4242` was chosen because it does not collide with any of the VLANs I use in other test harnesses. The 802.1Q ethertype is the standard `0x8100`. The VID mask is the low 12 bits of the TCI field (Tag Control Information); the upper 4 bits are PCP (Priority Code Point, 3 bits) and DEI (Drop Eligible Indicator, 1 bit), both of which we do not care about for matching.

```c
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 4);
} tx_port SEC(".maps");
```

`tx_port` is the DEVMAP. `BPF_MAP_TYPE_DEVMAP` is the map type used by `bpf_redirect_map` for device-destination redirects. The value stored at each index is an ifindex (integer device ID). The map is populated by userspace at program startup; slot 0 holds the egress ifindex (`veth_host2`'s ifindex, in the demo). `max_entries=4` is generous — we only use slot 0 in this program, but the kernel insists on a valid size and rounding up costs nothing.

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");
```

Standard ringbuf for audit events. 256 KiB is enough for thousands of events before userspace pulls them.

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 2);
} cfg SEC(".maps");
```

Two-slot config array. Slot 0 is the mode flag (1 = redirect, 0 = strip-only). Slot 1 is an audit copy of the egress ifindex (so ringbuf events can record where the redirect would have gone, even in strip-only mode). This is how the loader tells the program whether to redirect or just strip and let the frame proceed through `XDP_PASS`.

```c
SEC("xdp")
int xdp_vlan_ghost(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
```

The XDP context exposes `data` and `data_end` as pointers to the packet buffer. The cast through `long` is the standard idiom — the context fields are 32-bit integers holding packet-buffer addresses, and the compiler needs the explicit widening.

```c
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_8021Q)) return XDP_PASS;
```

Parse the ethernet header. The bounds check `(void *)(eth + 1) > data_end` is the verifier's price of entry: every byte read from the packet buffer must be preceded by a bounds check that proves the access is in-range. The verifier tracks `data` and `data_end` as separate pointer registers and insists that every load happen only after a bounds check has been proven against `data_end`.

If the ethertype is not `0x8100`, this is not an 802.1Q frame and we fall through to `XDP_PASS`.

```c
    struct vlan_hdr *vh = (void *)(eth + 1);
    if ((void *)(vh + 1) > data_end) return XDP_PASS;

    unsigned short tci = bpf_ntohs(vh->h_vlan_TCI);
    unsigned short vid = tci & VLAN_VID_MASK;
    if (vid != COVERT_VLAN_ID) return XDP_PASS;
```

Parse the VLAN header. `vlan_hdr` comes from `vmlinux.h` and has the standard layout: a 16-bit TCI followed by a 16-bit inner ethertype. Extract the VID from the TCI and compare against 4242. Frames tagged with any other VID fall through.

```c
    unsigned char dst_mac[6], src_mac[6];
    __builtin_memcpy(dst_mac, eth->h_dest,   6);
    __builtin_memcpy(src_mac, eth->h_source, 6);
    __be16 inner = vh->h_vlan_encapsulated_proto;
```

Save the original MAC addresses and the inner ethertype *before* we mutate the buffer. This is important: the strip operation rewrites the buffer layout, and the verifier will invalidate pointers that were valid before the mutation. Any data we want to preserve past the strip must be copied into local stack variables first.

```c
    struct ethhdr *shifted = (struct ethhdr *)((void *)eth + 4);
    if ((void *)(shifted + 1) > data_end) return XDP_PASS;
    __builtin_memcpy(shifted->h_dest,   dst_mac, 6);
    __builtin_memcpy(shifted->h_source, src_mac, 6);
    shifted->h_proto = inner;
```

This is the clever part, and worth a careful read. The trick is that `bpf_xdp_adjust_head(ctx, +4)` trims 4 bytes off the head of the packet. So if I write a fresh 14-byte ethernet header at offset +4 (relative to the original packet start), after the adjust-head call that new header becomes offset 0 — i.e., the packet head.

The original packet layout is:

```
[0..14)  ethhdr (dst_mac, src_mac, 0x8100)
[14..18) vlan_hdr (TCI, inner_proto)
[18..)   payload
```

After the rewrite at offset +4 but before adjust_head:

```
[0..4)   old ethhdr prefix (dst_mac[0..4])  <-- will be trimmed
[4..18)  NEW ethhdr (dst_mac, src_mac, inner_proto)
[18..)   payload (unchanged)
```

After `bpf_xdp_adjust_head(ctx, +4)`:

```
[0..14) NEW ethhdr (dst_mac, src_mac, inner_proto)
[14..)  payload (unchanged)
```

The packet is now 4 bytes shorter and the VLAN tag is gone. The inner ethertype (`0x88b5` in the demo) is now the outermost ethertype. Any downstream consumer sees an untagged ethernet frame.

The bounds check `(void *)(shifted + 1) > data_end` is necessary because the write at offset +4 through +17 overlaps the original VLAN header and part of the payload. The verifier needs to prove the range is in-bounds.

Why write the new header at offset +4 rather than just calling `adjust_head(+4)` first and then writing at offset 0? Because `adjust_head` invalidates pointers. Every pointer into the packet data — including `eth`, `vh`, `data`, `data_end` — becomes invalid after the call. You must re-read `ctx->data` and `ctx->data_end` after `adjust_head` and re-parse. Writing the new header first, then adjusting, lets us do the rewrite with the still-valid pointers and then invalidate.

```c
    if (bpf_xdp_adjust_head(ctx, 4) < 0) return XDP_PASS;

    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *neweth = data;
    if ((void *)(neweth + 1) > data_end) return XDP_PASS;
```

Call `adjust_head(+4)` to trim the leading 4 bytes. Re-read `data` and `data_end`; re-parse the (new) ethernet header; bounds-check again. The re-parse is not strictly needed for the redirect — we don't read `neweth` in what follows — but the verifier may or may not require it depending on how aggressive its path analysis is on a given kernel version. I keep it defensively.

```c
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->ifindex_in = ctx->ingress_ifindex;
        e->vlan_id = vid;
        e->inner_proto = bpf_ntohs(inner);
        __builtin_memcpy(e->dst_mac, dst_mac, 6);
        __builtin_memcpy(e->src_mac, src_mac, 6);
        e->action = 2;  // default: strip+pass
        e->redirect_ifindex = 0;

        unsigned int zero = 0;
        unsigned int *mode = bpf_map_lookup_elem(&cfg, &zero);
        unsigned int one_k = 1;
        unsigned int *tgt = bpf_map_lookup_elem(&cfg, &one_k);
        if (mode && *mode == 1 && tgt) {
            e->redirect_ifindex = *tgt;
            e->action = 1;      // strip+redirect
        }
        bpf_ringbuf_submit(e, 0);
    }
```

Emit an audit event. The event carries the ingress ifindex, the VID we matched, the inner ethertype, both MACs, and the action we're about to take. Actions: `0` = untouched pass (not used on this path), `1` = strip+redirect, `2` = strip+pass.

The `cfg[0]`/`cfg[1]` lookup is slightly redundant with the lookup we are about to do for the redirect decision. I could have stored `mode` and `tgt` once in locals and reused. The redundancy costs two map lookups per covert frame; frames are rare; I optimized for clarity.

```c
    unsigned int zero = 0;
    unsigned int *mode = bpf_map_lookup_elem(&cfg, &zero);
    if (mode && *mode == 1) {
        return bpf_redirect_map(&tx_port, 0, 0);
    }
    return XDP_PASS;
}
```

The actual redirect. If `cfg[0] == 1`, call `bpf_redirect_map(&tx_port, 0, 0)` — redirect to the device stored at index 0 of `tx_port`. The third argument is flags, `0` for no special behavior. If mode is off, just `XDP_PASS` — the frame continues through the stack, untagged.

`bpf_redirect_map` returns an action code (`XDP_REDIRECT`) that the XDP framework interprets. The redirect is deferred to the end of the program; the kernel actually performs the redirect in `xdp_do_redirect()` after the XDP program returns. That deferred execution is important because it means `bpf_redirect_map` cannot fail in the traditional sense — it returns an action, and if the action is invalid (e.g., the device doesn't exist or isn't XDP-capable), the redirect simply drops the frame. We do not get a per-frame failure signal.

## DEVMAP: Populating from Userspace

The DEVMAP is populated in the loader at startup:

```c
unsigned int devkey = 0;
err = bpf_map__update_elem(s->maps.tx_port, &devkey, sizeof(devkey),
                           &ifidx_out, sizeof(ifidx_out), BPF_ANY);
```

`ifidx_out` is the ifindex of the egress veth (e.g., `veth_host2`), obtained via `if_nametoindex()`. The key is `0` — slot 0 of the DEVMAP. The value is the ifindex.

This is the "ghost" wiring — the program doesn't know at compile time which device to redirect to; userspace tells it at load time. Changing the target is a map update away. A more elaborate attacker could update the DEVMAP dynamically in response to external triggers, effectively steering covert traffic to different destinations over time. The POC keeps it static for clarity.

The DEVMAP's content is visible via `bpftool map dump name tx_port`:

```
# bpftool map dump name tx_port
[{
    "key": 0,
    "value": {
        "ifindex": 44,
        "ifname": "veth_host2"
    }
}]
```

If `ifindex` points at a device whose peer lives in a foreign netns, that is the suspicious signature. Cilium's DEVMAPs legitimately have this shape (their peers live in pod netns by design), so the presence of a cross-namespace DEVMAP target is not itself proof of malice — but in an environment where no legitimate dataplane should be doing cross-namespace redirects, it is a strong signal.

## The Verifier's Rewrite Constraints

XDP's verifier rules are stricter than kprobe's in some ways and looser in others. The key constraints for this program:

1. **Bounds checks before every read**. Every byte of packet data read requires a proven bounds check against `data_end`. The verifier tracks the bounds through control flow; `if ((void*)(eth+1) > data_end) return XDP_PASS;` proves that after the conditional branch, `eth[0..sizeof(*eth)]` is accessible.

2. **Bounds checks before every write**. Same story for writes. `shifted->h_dest = ...` requires the verifier to have seen a bounds check proving the write is in-range.

3. **Pointer invalidation after `bpf_xdp_adjust_head`**. Any pointer into the packet buffer (any derivative of `ctx->data`) is invalidated by a call to `adjust_head`. You must re-read `ctx->data` and `ctx->data_end` and derive fresh pointers.

4. **No unbounded loops**. XDP programs must have a verifiable upper bound on their instruction count. The verifier tracks all branches and rejects programs it cannot prove terminate. The VLAN strip is straight-line code, so this is not an issue here, but it matters for programs that iterate over packet data.

5. **Tail call depth limits**. Not relevant here; this program is single-shot.

The VLAN-strip rewrite hit exactly one of these in development. An earlier draft wrote the new ethernet header at offset 0 *after* calling `adjust_head(-4)` (which would have extended the packet; wrong direction). That draft worked conceptually but produced a packet 4 bytes longer than the original, not shorter. I flipped it to `adjust_head(+4)` and wrote the new header at +4 before the adjust, as documented above. The verifier accepted both forms; the semantics only worked for the +4-before-adjust version.

A subtler verifier interaction: the order of the `if` checks after `adjust_head` matters. The verifier re-runs its pointer analysis after the helper call, and if the code reads `data_end` before re-reading `data`, the verifier will reject on the grounds that `data_end` has a stale bound. The pattern that works is always: re-read `data`, re-read `data_end`, then re-derive any packet pointers.

## DEVMAP, Native Mode, and Linuxkit

`bpf_redirect_map` into a DEVMAP has two execution modes: native and generic.

- **Native mode** requires the egress device's driver to implement `xdp_xmit`. Most physical NIC drivers do; veth implementations depend on the kernel version. On recent mainline, veth has native XDP support on the ingress side but not the transmit side, which complicates `redirect_map` into a veth destination.
- **Generic/SKB mode** handles `redirect_map` by rebuilding an skb and delivering it through the normal receive path on the destination device. This is slower and has a different visibility profile but works on every driver.

On linuxkit 6.12 aarch64 — which is Docker Desktop's VM on Apple Silicon — veth drivers do not implement native XDP. The loader attempts native mode first, falls back to generic, and the trigger script passes `--skb` explicitly to skip the native probe. The loader logs `xdp_flags=0x2` which corresponds to `XDP_FLAGS_SKB_MODE`.

The generic-mode path works. Frames still arrive at the destination. The observable performance hit is not relevant for a covert-channel POC — we're sending three frames, not three million per second.

The loader's attach logic:

```c
static int attach_xdp(int ifindex, int prog_fd, bool force_skb,
                      unsigned int *out_flags)
{
    int err;
    if (!force_skb) {
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
        if (!err) { *out_flags = XDP_FLAGS_DRV_MODE; return 0; }
        fprintf(stderr, "[ch15] drv-mode failed on ifindex=%d (%s); "
                        "trying skb-mode\n", ifindex, strerror(-err));
    }
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (!err) { *out_flags = XDP_FLAGS_SKB_MODE; return 0; }
    ...
```

Try DRV first, fall back to SKB. `force_skb` skips the DRV probe entirely. This ordering costs one failed attach per attach attempt but keeps the code one path, and the DRV-first preference means production environments with native-capable NICs will get the fast path.

## Attaching on Both Sides

A subtle requirement: for `bpf_redirect_map` into a cross-namespace DEVMAP target to work reliably on many kernels, the *destination* device also needs an XDP program attached. This is a compatibility quirk of the redirect path, not a design requirement; the kernel is checking for XDP-capability-on-both-sides as a pre-condition for the redirect to succeed.

The loader attaches the same program on both ingress and egress:

```c
if (attach_xdp(ifidx_in, prog_fd, force_skb, &g_xdp_flags) != 0) { ... }
g_attached_ifindex_in = ifidx_in;

if (ifn_out) {
    unsigned int egress_flags = 0;
    if (attach_xdp(ifidx_out, prog_fd, force_skb, &egress_flags) != 0) {
        fprintf(stderr, "[ch15] WARNING: egress XDP attach to %s failed; "
                        "redirect may not work\n", ifn_out);
    } else {
        g_attached_ifindex_out = ifidx_out;
    }
}
```

The egress attach is best-effort; a failure is logged as a warning rather than a hard failure, because on some kernels the redirect works without it. On linuxkit 6.12 the egress attach succeeds, so the warning path is not exercised in the demo.

The two `g_attached_ifindex_*` globals are tracked so `detach_all()` can clean up every attach on exit:

```c
static void detach_all(void)
{
    if (g_attached_ifindex_in) {
        int err = bpf_xdp_detach(g_attached_ifindex_in, g_xdp_flags, NULL);
        if (err) fprintf(stderr, "[ch15] detach ingress failed: %s\n",
                         strerror(-err));
        g_attached_ifindex_in = 0;
    }
    if (g_attached_ifindex_out) {
        int err = bpf_xdp_detach(g_attached_ifindex_out, g_xdp_flags, NULL);
        ...
```

SIGINT and SIGTERM both go through the same `on_sig` handler which sets `stop`; the poll loop exits, falls through to `out:`, and `detach_all()` runs. Any early-exit path also runs `detach_all()` via the `goto out`. This matters because a dangling XDP attach on a veth survives the loader's death and is annoying to clean up manually.

## The Trigger's Sender

Covert-frame generation is not trivial. `arping` and `ping` do not emit VLAN-tagged frames reliably, and even if they did, the inner ethertype would be wrong. The trigger embeds a Python AF_PACKET sender:

```python
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
s.bind((ifname.decode(), 0))
info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR,
                   struct.pack('256s', ifname[:15]))
src_mac = info[18:24]
dst_mac = b'\xff\xff\xff\xff\xff\xff'
tci = (0 << 13) | 4242
vlan_hdr  = struct.pack('!HH', 0x8100, tci)
inner_eth = struct.pack('!H', 0x88b5)
payload   = b'GHOSTVLAN-covert-channel-message\x00' * 2
frame = dst_mac + src_mac + vlan_hdr + inner_eth + payload
for _ in range(3):
    s.send(frame)
```

A raw AF_PACKET socket, bound to `veth_a` inside `ghost_a`. The frame is constructed byte-by-byte: broadcast destination, the local veth's MAC as source, the VLAN header (0x8100 ethertype + TCI with VID 4242), the inner ethertype 0x88b5, and a recognizable payload. Three frames, sent sequentially.

The choice of 0x88b5 as the inner ethertype is deliberate: it is IEEE Local Experimental 1, one of two ethertypes reserved for research and experimental use. It is unused by any standard protocol. That makes the AFTER-side tcpdump filter trivially precise: `tcpdump -i veth_host2 'ether proto 0x88b5'` matches only these frames and nothing else in the noise of a container host. The BEFORE count (expected zero) and AFTER count (expected three) are both scraped from the tcpdump output to produce the proof marker.

Broadcast destination MAC was chosen over unicast to sidestep any MAC-learning or ARP-resolution questions. The frame floods to every listening interface on its broadcast domain (which, after the XDP program runs, is the `veth_host2` destination), and we observe it there.

## BEFORE/AFTER Discipline

`trigger.sh` is structured as a three-phase proof:

1. **Setup**: create `ghost_a`, `ghost_b`, the two veth pairs, assign IPs, bring interfaces up. Verify the topology is in place. This phase should produce no covert-channel evidence.

2. **BEFORE**: start `tcpdump -i veth_host2 -c 3 'ether proto 0x88b5'` in the background. Send three VLAN-4242-tagged frames from inside `ghost_a` on `veth_a`. Wait up to 2 seconds for tcpdump to capture or time out. Expect capture count 0 (no XDP, no path from veth_a/veth_host to veth_host2).

3. **AFTER**: load the XDP program on `veth_host -> veth_host2`. Start a fresh tcpdump with the same filter. Send three more frames. Expect capture count 3, with untagged ethertype 0x88b5.

Proof markers emitted to stdout:

```
=== BEFORE (no XDP) === tcpdump_on_other_ns=0
=== AFTER  (XDP active) === tcpdump_on_other_ns=3 (untagged, ethertype 0x88b5)
=== VLAN_GHOST_CROSSNS_PROVEN redirect_count=3 ===
```

The harness regex matches `VLAN_GHOST_CROSSNS_PROVEN` to mark the chapter proven. The redirect count comes from counting `STRIP+REDIRECT` lines in the loader's ringbuf output, which is an independent sanity check — the BPF program's ringbuf events and tcpdump's packet capture should agree on the count.

The BEFORE phase is essential. Without it, an observer who saw three frames on `veth_host2` after the XDP load could reasonably ask: "how do you know those frames came through the XDP redirect, rather than some preexisting path?" The zero-count BEFORE proves there was no path, so the three-count AFTER can only come from the redirect. Without the baseline the proof is ambiguous.

## What The Harness Captures

`Poc("ch15", ...)` in `proof.py`:

```python
Poc("ch15", "NetNS VLAN Ghost (XDP VID=4242)", "ch15-netns-vlan-ghost",
    hooks=["veth"], prefix="[vghost]", mode="trigger-runs-loader",
    timeout=20,
    proof_marker=r"VLAN_GHOST_CROSSNS_PROVEN"),
```

`hooks=["veth"]` is a soft assertion — not a kallsyms check (veth is a driver, not a function) but a reminder in the report of what kernel surface the chapter touches. `mode="trigger-runs-loader"` tells the harness to drive the trigger script rather than launch the loader binary directly. `timeout=20` is enough for the BEFORE/AFTER cycle plus cleanup.

The `[vghost]` prefix is what the loader emits on stdout for each ringbuf event. The harness aggregates these into the per-chapter section of the HTML report.

## Segmentation Implications

VLAN-based tenant isolation in multi-tenant host networking is common in a few places:

1. **OpenStack / OpenvSwitch**: OVS is often configured with VLAN trunks per-tenant. Tenant A sees VID 100, tenant B sees VID 200. The bridge enforces the mapping.

2. **Some Cilium configurations**: in L2 mode with VLAN-tagged underlays.

3. **Generic KVM / libvirt**: VLAN interfaces (`vlan0.100`) attached to bridges, with VMs connected through the bridges.

4. **Enterprise bare-metal K8s**: some clusters use VLAN trunking on the node's NIC and per-namespace VLAN sub-interfaces.

In every one of these, the VLAN boundary is a *policy* enforcement layer, not a *physical* one. The policy is implemented at the bridge or at the netfilter layer — but XDP runs before both. A host-level XDP program attached to the right interface sees tagged frames first, can strip or rewrite them, and can redirect them to any destination it has an ifindex for.

This is not a Cilium bug. It is not an OVS bug. It is an architectural property of XDP: XDP is a privileged, low-level packet-manipulation surface, and any deployment that depends on higher-level segmentation must also enforce that unprivileged tenants cannot load XDP programs. The enforcement story for "no unprivileged XDP" is `unprivileged_bpf_disabled=1` plus careful management of `CAP_BPF` capability grants. Many deployments ship with neither in place.

I want to be careful with the framing here because "VLAN escape" is the kind of headline that prompts vendors to deny the finding. The finding is correct and the vendors would be correct to deny. The correct framing is: *if your tenant isolation story depends on VLAN tags, and you grant privileged access to a node-local surface that can attach XDP, you have a gap*. Most orchestrators document this somewhere; few make it prominent.

## Detection

Detection is straightforward if you know what to look for.

**`bpftool net show dev <ifname>`** lists XDP programs attached to an interface. Almost nothing legitimate loads XDP on container veths (the exceptions being Cilium and a few other CNI datapaths). A datapath-class program on a veth in a conventional workload is a reliable signal.

**`bpftool prog show`** combined with `bpftool map dump name tx_port` reveals DEVMAP entries and their target ifindexes. Walking all DEVMAPs on a host and cross-checking their targets against expected namespace boundaries is a useful audit. Cross-namespace DEVMAP targets, in environments where no legitimate dataplane should have them, are the strongest signal.

**`ip -d link show dev <ifname>`** annotates `xdpgeneric`, `xdp`, or `xdpoffload` when a program is attached. Output like `link/ether ... xdpgeneric id <N>` is visible on the attached interface.

**Helper-pair audit**: programs that call both `bpf_xdp_adjust_head` and `bpf_redirect_map` are rare outside dataplane software. `bpftool prog dump xlated` shows the helper-call opcodes. A program with that pair, not belonging to a known CNI, is worth flagging.

**Off-host taps**: if the orchestrator's management plane can tap the upstream switch or the NIC itself (via mirror port or `hwtraffic`), it sees every frame that enters the host regardless of what XDP does on the host. An upstream tap would show the VLAN-4242 frames leaving `ghost_a` before the XDP strip, which is an out-of-band confirmation that the tagged frame was real. Cross-referencing the upstream capture against the on-host netfilter logs (which would show *no* VID 4242 frames because XDP preempted the stack) reveals the XDP interposition.

The off-host tap is the hardest-to-evade detection. Everything above it runs on the compromised host and is potentially subject to the same attacker who attached the XDP program.

## Comparison to Cilium's Legitimate Use

Cilium's datapath attaches XDP programs to veth devices and uses DEVMAPs for redirect. The syntactic pattern is identical to ch15. The difference is policy and provenance:

- Cilium's programs are loaded by the Cilium agent as part of its documented datapath setup. Their DEVMAP targets are the peers of pod veths, all within the cluster's expected topology. Auditing them against Cilium's configuration produces no surprises.
- Ch15's program is loaded by an arbitrary process with `CAP_BPF` on the host. Its DEVMAP target is a veth in a namespace that was supposed to be isolated from the source namespace. The topology does not match any legitimate datapath.

A defender who understands Cilium's footprint can carve it out: "these are the XDP programs Cilium manages; any others are suspicious." A defender who does not use Cilium and has no other legitimate XDP users has an even simpler rule: "any XDP program on any interface is suspicious."

The same logic applies to other legitimate XDP users (Calico with eBPF dataplane, some service meshes, `xdp-filter` tooling). Enumerate the legitimate sources, everything else is a finding.

## The `cfg` Array as a Runtime Switch

I want to come back to the `cfg` map because it illustrates a small design pattern worth calling out.

The XDP program has two operational modes: strip-only and strip-and-redirect. The distinction exists because the useful primitive is not always "move the frame." Sometimes the attacker wants to strip the tag and let the frame proceed through the host stack as an untagged frame, injecting it into the host's routing path. In that case the orchestrator's VLAN-aware policy is still bypassed (the stack sees an untagged frame, no VID policy applies) but the frame arrives in the host namespace rather than the victim namespace.

Building this as a runtime switch rather than two separate programs has a cost: every matched frame does an extra map lookup. It also has a benefit: the same loaded program can be retargeted without detach-and-reload, which means the switch is invisible on `bpftool prog show` (the program ID doesn't change). An attacker who wants to remain stealthy while retargeting can update `cfg[0]` from userspace without detaching the program from the interface.

The choice to keep the DEVMAP target in `cfg[1]` as well as `tx_port[0]` is defensive audit. If the audit ringbuf event records `cfg[1]`, then an auditor reading the event stream can reconstruct the intended destination even if `tx_port` has been cleared or re-pointed in the interim. The redundancy costs one map lookup per event but makes forensic analysis of a captured ringbuf self-contained.

## Why `bpf_redirect_map` Rather Than `bpf_redirect`

There are two XDP redirect helpers. `bpf_redirect(ifindex, flags)` redirects by ifindex; `bpf_redirect_map(map, key, flags)` redirects via a DEVMAP entry. Both exist because they have different performance characteristics.

`bpf_redirect_map` batches. Multiple packets redirected to the same DEVMAP entry within the same NAPI poll cycle are delivered together to the destination. This matters for throughput on fast paths; it does not matter for a covert channel sending three frames. The reason I used `bpf_redirect_map` anyway is that the DEVMAP is the standard pattern in modern datapath code, the helper is slightly more flexible (you can update the map to retarget), and the verifier rules around it are well-tested.

`bpf_redirect` without the map is the older helper. It is still supported and works for this use case. I did not use it because the documentation in the kernel source (`Documentation/networking/xdp.rst`) makes the batch-friendly map variant the recommended form, and ch15's presence in a book about primitives is better served by the recommended form.

## Inner Ethertype 0x88b5 and Protocol Choice

I chose `0x88b5` (IEEE Local Experimental 1) deliberately. The alternatives I considered:

- **0x0800 (IPv4)**: would make the payload look like ordinary IP traffic. The host stack would potentially route it, which defeats the covert-channel property (the host sees what looks like a routable frame). A bad choice for a proof because the downstream effect would depend on what the host's routing table does.

- **0x86DD (IPv6)**: same issue as IPv4.

- **0x0806 (ARP)**: the host stack would process ARP replies and might respond or cache entries, again defeating the cleanliness of the proof.

- **0x88B5 / 0x88B6 (IEEE Local Experimental)**: reserved for experimental use, unused in practice, will not be processed by the host stack as a known protocol. `0x88b5` specifically is reserved for "Local Experimental Ethertype 1" per IEEE 802. The host stack will receive the frame, recognize it as unknown, and drop it — exactly what I want for the proof. The frame is observable to tcpdump (which does not interpret protocol, it just captures bytes) but invisible to anything that cares about protocol semantics.

- **Custom ethertype not in any registry**: I considered picking a random value like `0xFEED` but chose against it because unregistered ethertypes might accidentally collide with some vendor's private assignment, and the IEEE-reserved value is safer.

The payload string `GHOSTVLAN-covert-channel-message` is there for easy visual identification in hex dumps. When debugging, `tcpdump -x` output shows the payload bytes and I can grep for the string without false positives.

## Ringbuf Events vs. tcpdump

The trigger uses *both* the BPF program's ringbuf events and an independent tcpdump to confirm the redirect. This double-entry bookkeeping is deliberate.

The ringbuf event is emitted by the BPF program itself, from inside the XDP hook. It proves the program matched and executed the strip-and-redirect logic. If the ringbuf says `STRIP+REDIRECT`, the program reached that code path.

The tcpdump on `veth_host2` is an independent observer. It runs in userspace, looks at packets arriving on the destination device, and counts frames matching the inner ethertype filter. If tcpdump captures the frame, the frame actually reached the destination — not just "the program said it would redirect, but the redirect silently failed."

The two numbers should agree: redirect_count (from ringbuf) == tcpdump_count. If they disagree, something went wrong and the disagreement narrows the cause. If ringbuf shows 3 redirects but tcpdump shows 0, the redirect helper returned XDP_REDIRECT but the kernel dropped the frame downstream — look for missing XDP attach on the destination veth, or `net.core.bpf_jit_harden` issues. If tcpdump shows 3 but ringbuf shows 0, someone else is injecting frames and the proof is not clean — worth investigating.

In every run I have done on linuxkit 6.12 aarch64, the two numbers agree at exactly 3. The `VLAN_GHOST_CROSSNS_PROVEN` marker emits with `redirect_count=3`.

## Signal Handling in the Loader

One last nuts-and-bolts detail. The loader installs signal handlers *before* the XDP attach:

```c
/* Install signal handlers BEFORE attach so a fast Ctrl-C between
 * attach and the poll loop still detaches via atexit-equivalent. */
if (signal(SIGINT,  on_sig) == SIG_ERR ||
    signal(SIGTERM, on_sig) == SIG_ERR) {
    fprintf(stderr, "[ch15] signal(): %s\n", strerror(errno));
    return 1;
}
```

The comment calls out why: if SIGINT arrives in the window between `bpf_xdp_attach()` succeeding and the first `ring_buffer__poll()` call, we still want `detach_all()` to run. The handler sets the `stop` flag; the poll loop is not yet running, but the code path after the attach goes through a single `goto out` that runs `detach_all()` unconditionally. The handler's only job is to make the poll loop exit once it starts; between attach and poll the exit is driven by the code noticing `stop` on the first loop iteration, but the handler being in place ensures no unhandled SIGINT kills the process with the XDP attach still live.

This is the kind of paranoid cleanup that matters for a POC you'll run hundreds of times during development. Orphan XDP attaches on interfaces surviving a crashed loader are annoying to diagnose (`bpftool net show` will show an anonymous program ID, you have to detach by ifindex, the veth may have been deleted making detach impossible). Investing in the cleanup path up front saves debugging time later.

## A Bigger Thought on XDP and Trust Boundaries

I want to end with a framing question rather than a conclusion.

XDP is a mature, well-designed, high-performance packet processing layer. It is used correctly and legitimately by Cilium, Katran, xdp-filter, and a long tail of commercial and open-source dataplane software. Its design assumes that the operator who attaches XDP programs to interfaces is trusted — they have `CAP_BPF`, they are part of the privileged admin plane.

In orchestrator architectures that have grown out of Linux containers, the admin plane and the tenant plane have been getting uncomfortably close. On many Kubernetes clusters, `CAP_BPF` can be granted to pods via pod-security-policy or its successors. On some bare-metal multi-tenant setups, tenants have direct privileged access to the host. On serverless platforms that expose a userspace kernel interface (e.g., gVisor, or Firecracker in some configurations), the boundary is different but the question is the same.

Ch15 does not exploit a bug in XDP or in the kernel. It uses XDP exactly as documented, for a purpose that falls within the stated capability of the primitive. The "finding" — if there is one — is about the downstream orchestrator's trust model. If your orchestrator's policy is "tenant A cannot reach tenant B," and your enforcement depends on VLAN tags, and unprivileged users can load XDP, then your enforcement is bypassable by design.

The productive fix is not to patch XDP. It is to re-read your orchestrator's threat model and ask: which privileged capabilities are exposed to which tenants? Is `CAP_BPF` in that list? Is `unprivileged_bpf_disabled` set? If a tenant runs XDP on a veth whose peer lives in their own pod, does the host's segmentation policy still hold?

Different orchestrators answer these questions differently. The answers have been evolving. Reading ch15 as a bug report would be wrong. Reading it as a prompt to revisit your trust model is the intended interpretation.

## Further Reading on the Primitive

I want to credit the upstream material I leaned on for the XDP mechanics:

- The `xdp-tutorial` repository on GitHub (`xdp-project/xdp-tutorial`). The packet rewriting and redirect examples are pedagogical and directly inspired the VLAN-strip implementation.
- The Cilium datapath code. Reading `bpf/bpf_lxc.c` and `bpf/bpf_host.c` in the Cilium source tree was the clearest demonstration of the cross-namespace redirect pattern in production.
- Toke Høiland-Jørgensen's XDP tutorial materials. The verifier's packet-bounds discipline is documented there in more detail than the kernel docs usually cover.
- `Documentation/networking/filter.rst` and `Documentation/networking/xdp.rst` in the kernel source — authoritative but terse.

None of these describe the covert-channel direction, because none of them are attacker-oriented. The contribution of this chapter is framing the existing, well-documented primitive as a cross-namespace covert channel and walking through the BEFORE/AFTER proof structure. The mechanics are identical to the legitimate use; the ethics are different.

## DEVMAP vs CPUMAP vs XSKMAP

Briefly worth noting the three map types that XDP redirect helpers work with, because they are different tools for different purposes:

- **DEVMAP** (`BPF_MAP_TYPE_DEVMAP`): key is an index, value is an ifindex. Used by `bpf_redirect_map` to redirect to a network device. This is what ch15 uses.
- **CPUMAP** (`BPF_MAP_TYPE_CPUMAP`): key is an index, value is a CPU number. Used to redirect packets for processing on a different CPU (typical for packet steering / load spreading in DDoS-resistant datapaths).
- **XSKMAP** (`BPF_MAP_TYPE_XSKMAP`): key is an index, value is an AF_XDP socket. Used to redirect packets to userspace via AF_XDP (zero-copy userspace networking).

For the covert-channel primitive, DEVMAP is the right choice — we want the frame delivered to a device, not a CPU or a userspace socket. CPUMAP could be used creatively (send the covert frame to a specific CPU whose processing is being observed by another BPF program) but that is an order of magnitude more complex and not needed for the proof.

An XSKMAP variant would be interesting: redirect covert frames to an AF_XDP socket owned by the attacker process, so the attacker receives them directly in userspace without going through the kernel network stack at all. This is the inverse direction of ch15 (the attacker pulls frames out of the network, rather than injects them into a namespace), and it represents a different class of covert channel — an exfiltration channel where the attacker receives data directly from userland on a physical NIC. I have not built this variant; it is a natural extension.

## Error Modes I Hit During Development

A few gotchas that ate development time, documented so the next implementer does not re-discover them.

**adjust_head returning -EINVAL**. The first time I ran the program, `bpf_xdp_adjust_head(ctx, +4)` returned `-EINVAL` and the frame went through `XDP_PASS` unmutated. The cause was that the packet arrived with `data` already at a position where shrinking by 4 would violate the minimum headroom. Ethernet frames from veth have a specific headroom budget; my original attempt to use `adjust_head(+8)` (to also strip the 802.1Q TCI and expose a deeper inner header) hit this limit. Shrinking by 4 works. Shrinking by 8 does not on this kernel.

**Pointer invalidation subtlety**. I described this above but a concrete error: an earlier draft re-read `data_end` but not `data` after `adjust_head`. The verifier rejected with:

```
R1 pointer arithmetic on pkt pointer prohibited after helper call
```

It took me an hour to figure out that the issue was pointer *register* invalidation in the verifier's analysis, not packet-buffer invalidation. Re-reading both `data` and `data_end` fixed it.

**DEVMAP entry not settable before XDP attach on target**. I tried populating the DEVMAP *before* attaching XDP to the target device. The update succeeded, but the redirect later returned 0 captured frames. Reordering to "attach both devices first, then populate DEVMAP" fixed it. The reason, as best I can tell, is that the kernel checks DEVMAP entries against XDP-capability at the point of `bpf_redirect_map` execution, and the target device is only flagged XDP-capable once a program is attached to it. Populating the map before the target has an attached program results in an entry that is silently invalid until the attach happens, and my first pass's `bpf_redirect_map` ran before the re-check. Ordering matters.

**SKB-mode vs DRV-mode attach flag mismatch**. On detach, if you attached with `XDP_FLAGS_SKB_MODE` you must detach with `XDP_FLAGS_SKB_MODE`. Detaching with the wrong flag returns `-EINVAL`. The loader tracks `g_xdp_flags` at attach time and uses the same flag on detach. If attach succeeded in SKB mode on ingress but in DRV mode on egress (hypothetically), the current code would use the ingress flag for both detaches, which might fail on the egress. In practice on linuxkit both end up SKB.

**Setting the egress veth MTU down or carrier off**. An early aborted run had the egress veth carrier down because I forgot `ip link set veth_host2 up`. The XDP program ran, the redirect returned `XDP_REDIRECT`, but the frame was dropped at egress because the device was down. The ringbuf event shows `STRIP+REDIRECT` in this failure mode — the program executed the redirect code path — but tcpdump sees nothing. This is exactly the disagreement case I called out in the ringbuf/tcpdump section above. The BEFORE/AFTER discipline catches it (if AFTER shows 0 tcpdump, something is wrong), but the diagnosis requires understanding that a `XDP_REDIRECT` action does not guarantee delivery.

## Why I Kept the Kprobe Sketch in the Book

The chapter retains the kprobe-on-`__netif_receive_skb_core` snippet from the original outline, even though it does not work:

```c
SEC("kprobe/__netif_receive_skb_core")
int ghost_vlan(struct pt_regs *ctx) { ... }
```

I kept it because the dead end is useful. A reader who sees this chapter and reaches for the chapter outline will think "kprobe on the receive path, rewrite the skb's namespace metadata, let the kernel re-receive." That intuition is natural. It is wrong for two independent reasons (verifier rejects skb writes, symbol not in error_injection list). The XDP path is the correct expression of the same primitive. The book's job is to teach that redirect-via-XDP-is-the-answer, and leaving the kprobe fantasy uncorrected in the reader's mind would be worse than keeping it visible and annotating it as the wrong path.

A reader who sees only the working XDP code might wonder why I picked XDP rather than kprobe; the answer is "because kprobe doesn't work, I tried it." Showing the dead end makes the reasoning explicit.

This is a broader editorial pattern across these chapters. Chapter 16's aspirational "borrow a TID" bypass is similarly annotated as not-working-on-this-kernel. The honest framing gives readers the epistemic artifact, not just the finished code.

## An Aside on Performance

The primitive is not performance-critical — three frames per demo — but the underlying XDP+DEVMAP datapath is capable of line-rate forwarding on 10G+ NICs. If an attacker wanted to use this for sustained covert traffic (exfiltration at meaningful bandwidth), the primitive would not be a bottleneck. The constraints are:

- **XDP generic mode** caps throughput at the same order as normal stack handling. Fine for covert channels, slow for bulk transfer.
- **XDP native mode** handles millions of packets per second per core. Bulk exfil is practical if the NIC supports it.
- **DEVMAP batching** aggregates multiple redirects to the same target into one NAPI delivery. For sustained flows this matters; for bursty covert channels it is noise.

The detection signal does not scale with throughput. `bpftool prog show` shows the program regardless of whether it has forwarded 3 frames or 3 billion. A defender who checks the attached-program list periodically catches the primitive whether the channel is used heavily or not. That asymmetry (static signal, variable payload) is a nice property for detectors — you do not need to watch the traffic, just watch the program list.

## Concluding on the Threat Model

To close this chapter cleanly: ch15 is a proof that XDP can ferry traffic between netns-isolated peers on a host with `CAP_BPF`. The primitive is documented, legitimate, and widely deployed in production for legitimate reasons. The misuse direction is mechanical — flip the DEVMAP target to a victim namespace, filter for a covert VID, strip, redirect.

The defenders I have spoken with about this class of primitive consistently ask the same question: "why is this not already locked down?" The answer is that the primitive sits at the intersection of multiple subsystems (BPF, netns, veth) and no single subsystem's threat model covers it. XDP's threat model assumes privileged operators. netns's threat model assumes kernel-level namespace isolation, which is preempted by XDP. veth's threat model is "point-to-point virtual ethernet," which does not care what BPF programs attach to the endpoints. Each subsystem is internally consistent. The emergent property of "no cross-namespace XDP redirect" is nobody's responsibility.

This is a recurring theme. The Linux kernel is a collection of subsystems with their own threat models, and the interactions between them are where primitives accumulate. Ch14 is about the interaction between syscall entry wrappers and `bpf_override_return`. Ch15 is about the interaction between XDP and netns. Ch16 is about the interaction between seccomp and kprobe observability. Ch18 is about the interaction between syscall returns and userspace identity caching. Each chapter's primitive is a gap at a subsystem boundary, and the defender needs a cross-cutting view that no single subsystem provides.

That is the implicit argument of the whole book. The chapters are case studies; the pattern is what matters.

## Hook points

**Category: REAL.** This is actual VLAN header manipulation and cross-namespace packet redirect, not a userspace illusion. The XDP program physically strips the 802.1Q tag and `bpf_redirect_map` delivers the frame to a device in a different network namespace. The orchestrator's VLAN-enforcement layer is preempted because XDP runs before the bridge and netfilter.

- `SEC("xdp")` `xdp_vlan_ghost` on the ingress veth.
- `BPF_MAP_TYPE_DEVMAP tx_port` (slot 0 → egress ifindex) drives `bpf_redirect_map`.
- `BPF_MAP_TYPE_ARRAY cfg` (slot 0 = mode flag, slot 1 = audit copy of egress ifindex).

```c
SEC("kprobe/__netif_receive_skb_core")
int ghost_vlan(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    // Detect covert VLAN tag
    if (skb_vlan_tag_present(skb) && skb_vlan_tag_get(skb) == COVERT_VLAN_ID) {
        // Rewrite namespace metadata for cross-namespace routing
        redirect_skb_to_namespace(skb, target_ns);
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
```

(The kprobe snippet above is the rejected original sketch; the working code is an XDP program that adjusts the head and redirects via DEVMAP. See the POC repo.)

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

SIGINT/SIGTERM detaches XDP from every interface it attached to; if the loader exits via any error path, `detach_all()` still runs.

End-to-end demo (creates ghost_a / ghost_b netns, sends one VLAN-4242-tagged AF_PACKET frame from inside ghost_a, sniffs egress on veth_host2):

```
docker run --rm --privileged --pid=host \
  -v "$PWD":/work -w /work \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  dbpf-base bash pocs/ch15-netns-vlan-ghost/trigger.sh
```

## Detection

- `bpftool net show dev <ifname>` lists XDP programs attached to an interface. Almost nothing legitimate loads XDP on container veths; a datapath-class program on a veth in a conventional workload is a reliable signal.
- `bpftool prog show` plus `bpftool map dump name tx_port` reveals DEVMAP entries pointing at veths whose peers live in foreign namespaces.
- `ip -d link show dev <ifname>` annotates `xdpgeneric`, `xdp`, or `xdpoffload` when an program is attached.
- The `bpf_xdp_adjust_head` plus `bpf_redirect_map` helper pair is rare outside dataplane software. Auditing programs that call both is worthwhile.

## Limitations / arch notes

- Docker Desktop linuxkit aarch64: veth drivers do not implement native XDP; the loader falls back to SKB-mode (or use `--skb` to skip the probe). Native-mode redirect is unavailable.
- `bpf_redirect_map` to a device in another netns requires the egress device to also have an XDP program loaded on many kernels; the loader attaches the same program there.
- The verifier rejects skb writes from kprobe context, so the chapter's original `__netif_receive_skb_core` mutation cannot be done directly. XDP at the NIC edge is the equivalent primitive.
- `arping` and `ping` will not generate the covert frames reliably; the trigger uses an embedded AF_PACKET sender for deterministic VLAN-4242 emission with inner ethertype `0x88b5`.
