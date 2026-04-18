// Ch15 NetNS VLAN Ghost — XDP program detects covert 802.1Q VLAN tag 4242
// on ingress, strips the tag in-place (shifting MAC header forward by 4B
// via bpf_xdp_adjust_head), then bpf_redirect_map()s the packet to a peer
// interface that lives in a different netns. To the orchestrator the
// "clean" vlan-free packet appears on the other side; the VLAN-tagged
// original never reaches the stack.
//
// Hook: SEC("xdp") — stable on 6.12 aarch64.
// Maps:
//   tx_port : DEVMAP (index 0 -> target ifindex) used by bpf_redirect_map.
//   events  : RINGBUF — audit record for every covert packet we moved.
//
// The book's prose invokes __netif_receive_skb_core; on 6.12 that symbol
// exists in kallsyms but kprobing it and mutating skb->dev is forbidden
// (skb writes rejected by verifier). XDP at the NIC edge is the honest,
// working expression of the same "haunt multiple realities" primitive.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define COVERT_VLAN_ID 142   // 12-bit VID range: 0-4095; old value 4242 overflowed
#define ETH_P_8021Q    0x8100
#define VLAN_VID_MASK  0x0FFF

/* vlan_hdr comes from vmlinux.h */

// Workaround: clang-19 BPF backend aggressively dead-code-eliminates
// XDP packet-parsing logic at -O2. barrier_var() (from bpf_helpers.h)
// forces the compiler to keep values alive after critical reads.

struct evt {
    unsigned int ifindex_in;
    unsigned int redirect_ifindex;
    unsigned short vlan_id;
    unsigned short inner_proto;
    unsigned char  src_mac[6];
    unsigned char  dst_mac[6];
    int            action; // 0=pass, 1=stripped+redirected, 2=stripped+pass
};

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 4);
} tx_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// config: index 0 holds a flag (1 = redirect, 0 = strip only)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 2);
} cfg SEC(".maps");

SEC("xdp")
int xdp_vlan_ghost(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    __be16 proto = eth->h_proto;
    barrier_var(proto);
    if (proto != bpf_htons(ETH_P_8021Q)) return XDP_PASS;

    struct vlan_hdr *vh = (void *)(eth + 1);
    if ((void *)(vh + 1) > data_end) return XDP_PASS;

    unsigned short tci = bpf_ntohs(vh->h_vlan_TCI);
    barrier_var(tci);
    unsigned short vid = tci & VLAN_VID_MASK;
    barrier_var(vid);
    if (vid != COVERT_VLAN_ID) return XDP_PASS;

    // Save original MAC addrs + inner proto BEFORE we mutate the buffer.
    unsigned char dst_mac[6], src_mac[6];
    __builtin_memcpy(dst_mac, eth->h_dest,   6);
    __builtin_memcpy(src_mac, eth->h_source, 6);
    __be16 inner = vh->h_vlan_encapsulated_proto;

    // Strip the 4-byte VLAN header:
    //  Original packet layout:
    //    [0..14) ethhdr (dst,src,0x8100) [14..18) vlan_hdr(TCI, inner) [18..) payload
    //  Target layout (after strip):
    //    [0..14) ethhdr (dst,src,inner) [14..) payload
    //  Technique: write a fresh 14-byte ethernet header at offset +4 of
    //  the current buffer (overlaying the last 2 bytes of src_mac, the
    //  old ethertype, and the vlan header), then call
    //  bpf_xdp_adjust_head(+4) to trim the first 4 bytes so the new
    //  header becomes the packet head.
    // Rewrite ethhdr at offset +4 (which becomes offset 0 after adjust).
    struct ethhdr *shifted = (struct ethhdr *)((void *)eth + 4);
    if ((void *)(shifted + 1) > data_end) return XDP_PASS;
    __builtin_memcpy(shifted->h_dest,   dst_mac, 6);
    __builtin_memcpy(shifted->h_source, src_mac, 6);
    shifted->h_proto = inner;

    /* NB: we have already corrupted buf[4..18) with the shifted ethhdr.
     * If adjust_head fails, the VLAN header at [14..16) is overwritten
     * with inner_proto bytes and src_mac[0..4) is overwritten — passing
     * this malformed frame up the stack is strictly worse than dropping.
     * We deliberately XDP_DROP on failure rather than leak a corrupted
     * frame to the kernel. */
    if (bpf_xdp_adjust_head(ctx, 4) < 0) return XDP_DROP;

    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *neweth = data;
    if ((void *)(neweth + 1) > data_end) return XDP_PASS;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->ifindex_in = ctx->ingress_ifindex;
        e->vlan_id = vid;
        e->inner_proto = bpf_ntohs(inner);
        __builtin_memcpy(e->dst_mac, dst_mac, 6);
        __builtin_memcpy(e->src_mac, src_mac, 6);
        e->action = 2;
        e->redirect_ifindex = 0;

        unsigned int zero = 0;
        unsigned int *mode = bpf_map_lookup_elem(&cfg, &zero);
        unsigned int one_k = 1;
        unsigned int *tgt = bpf_map_lookup_elem(&cfg, &one_k);
        if (mode && *mode == 1 && tgt) {
            e->redirect_ifindex = *tgt;
            e->action = 1;
        }
        bpf_ringbuf_submit(e, 0);
    }

    // Redirect via DEVMAP index 0 -> ghost egress interface (userspace
    // populated that slot at startup). If mode=0 or map empty, fall
    // through to XDP_PASS with the tag already stripped.
    unsigned int zero = 0;
    unsigned int *mode = bpf_map_lookup_elem(&cfg, &zero);
    if (mode && *mode == 1) {
        return bpf_redirect_map(&tx_port, 0, 0);
    }
    return XDP_PASS;
}
