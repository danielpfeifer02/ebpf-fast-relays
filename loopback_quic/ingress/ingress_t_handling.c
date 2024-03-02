#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

// to read trace: sudo cat /sys/kernel/tracing/trace_pipe
// activate go: export PATH=$PATH:/usr/local/go/bin

#define DEST_PORT 4242 // see loopback_quic/quic_traffic.go

SEC("xdp")
int handle_ingress(struct xdp_md *ctx)
{

    // bpf_printk("Start inspection...\n");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    unsigned int payload_size;
    struct ethhdr *eth = data;
    unsigned char *payload;
    struct udphdr *udp;
    struct iphdr *ip;

    // Too small to contain an Ethernet header
    if ((void *)eth + sizeof(*eth) > data_end) {
        // bpf_printk("Something was dropped (1)\n");
        return XDP_PASS;
    }

    // Too small to contain an IP header
    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        // bpf_printk("Something was dropped (2)\n");
        return XDP_PASS;
    }

    // Not a UDP packet
    if (ip->protocol != IPPROTO_UDP) {
        // bpf_printk("Something was dropped (ip protocol was not upd but: %d)\n", ip->protocol);
        return XDP_PASS;
    }

    // Too small to contain a UDP header (TODO: check if this is necessary)
    udp = (void *)ip + sizeof(*ip);
    if ((void *)udp + sizeof(*udp) > data_end) {
        // bpf_printk("Something was dropped (4)\n");
        return XDP_PASS;
    }

    // Wrong destination port
    if (udp->dest != ntohs(DEST_PORT) && udp->source != ntohs(DEST_PORT)) {
        // bpf_printk("Something was dropped (5)\n");
        return XDP_PASS;
    }

    // Point to start of payload.
    payload = (unsigned char *)udp + sizeof(*udp);
    payload_size = ntohs(udp->len) - sizeof(*udp);
    if ((void *)payload + payload_size > data_end) {
        // bpf_printk("Something was dropped (6)\n");
        return XDP_PASS;
    }

    bpf_printk("[ingress xdp] packet is entering (payload size: %d)\n", payload_size);
    unsigned char payload_buffer[10] = {0}; // TODO size 10 enough or off by one?
    bpf_probe_read_kernel(payload_buffer, sizeof(payload_buffer), payload);
    bpf_printk("[ingress xdp] first 10 bytes of payload: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                payload_buffer[0], payload_buffer[1], payload_buffer[2], payload_buffer[3], payload_buffer[4],
                payload_buffer[5], payload_buffer[6], payload_buffer[7], payload_buffer[8], payload_buffer[9]);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";