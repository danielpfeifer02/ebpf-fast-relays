#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

// to read trace: sudo cat /sys/kernel/tracing/trace_pipe
// activate go: export PATH=$PATH:/usr/local/go/bin

#define DEST_PORT 4242 // see loopback_quic/quic_traffic.go
#define MAX_ENTRIES 1

struct quic_header_wrapper {
    uint8_t header_t;
};

struct meta {
    int connIdLength;
};

// Define a map to store one element of type struct meta
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct meta);
    __uint(max_entries, MAX_ENTRIES);
} meta SEC(".maps");

// in userspace: "int map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "name", sizeof(int), sizeof(struct meta), MAX_ENTRIES, 0);"

SEC("xdp")
int handle_ingress(struct xdp_md *ctx)
{
    
    int index = 0;
    struct meta *meta_value = bpf_map_lookup_elem(&meta, &index);
    if (!meta_value) {
        bpf_printk("meta table value is null\n");
        return XDP_PASS;
    }

    int connIdLength = meta_value->connIdLength;

    bpf_printk("[ingress xdp] connIdLength: %d\n", connIdLength);

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

    unsigned char payload_buffer[100] = {0}; // TODO size 10 enough or off by one?
    bpf_probe_read_kernel(payload_buffer, sizeof(payload_buffer), payload);


    struct quic_header_wrapper *header = (struct quic_header_wrapper *)payload_buffer;
    if (header->header_t&0x80) {
        bpf_printk("[ingress xdp] LONG HEADER\n");
    } else {
        bpf_printk("[ingress xdp] SHORT HEADER\n");
        int shl = 1;

        if (connIdLength == 0) { // this has the downside that we ignore packet with connection id length 0 (special case)
            bpf_printk("[ingress xdp] connection id length not found\n");
            return XDP_PASS;
        }

        // we need to get the packet number. To do that first we need the packet number length (mask: 0x03, no shift)
        int packet_number_length = header->header_t&0x03;
        bpf_printk("[ingress xdp] packet number length: %d\n", packet_number_length);

        // now we get the actual packet number (packet number length is number of bytes)
        int packet_number = 0;
        int pnoffset = shl + connIdLength;
        if (packet_number_length == 1) {
            packet_number = payload_buffer[pnoffset];
        } else if (packet_number_length == 2) {
            packet_number = payload_buffer[pnoffset] << 8 | payload_buffer[pnoffset+1];
        } else if (packet_number_length == 3) {
            packet_number = payload_buffer[pnoffset] << 16 | payload_buffer[pnoffset+1] << 8 | payload_buffer[pnoffset+2];
        } else if (packet_number_length == 4) {
            packet_number = payload_buffer[pnoffset] << 24 | payload_buffer[pnoffset+1] << 16 | payload_buffer[pnoffset+2] << 8 | payload_buffer[pnoffset+3];
        }

        bpf_printk("[ingress xdp] packet number (%d bytes long): %d\n", packet_number_length, packet_number);
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";