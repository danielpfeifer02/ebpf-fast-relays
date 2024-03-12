#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

// to read trace: sudo cat /sys/kernel/tracing/trace_pipe
// activate go: export PATH=$PATH:/usr/local/go/bin

#define DEST_PORT 4242 // see loopback_quic/quic_traffic.go

struct quic_header_wrapper {
    uint8_t header_t;
};

// Define a map to store if adpative streaming is enabled
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, char);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} adaptive_flag SEC(".maps");

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
        return XDP_PASS;
    }

    // Too small to contain an IP header
    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    int ip_version = ip->version;
    // For now only support IPv4
    if (ip_version != 4) {
        bpf_printk("[ingress xdp] dropping something that is not IPv4\n");
        return XDP_PASS;
    }

    // Not a UDP packet
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    // Too small to contain a UDP header (TODO: check if this is necessary)
    udp = (void *)ip + sizeof(*ip);
    if ((void *)udp + sizeof(*udp) > data_end) {
        return XDP_PASS;
    }

    // Wrong destination port
    if (udp->dest != ntohs(DEST_PORT) && udp->source != ntohs(DEST_PORT)) {
        return XDP_PASS;
    }

    // Point to start of payload.
    payload = (unsigned char *)udp + sizeof(*udp);
    payload_size = ntohs(udp->len) - sizeof(*udp);
    if ((void *)payload + payload_size > data_end) {
        return XDP_PASS;
    }

    bpf_printk("[ingress xdp] A packet is entering (payload size: %d)\n", payload_size);

    int index = 0;
    char *adaptive_streaming = bpf_map_lookup_elem(&adaptive_flag, &index);
    if (adaptive_streaming == NULL) {
        bpf_printk("[ingress xdp] ERROR: cannot determine if adaptive streaming is enabled\n");
        return XDP_PASS;
    }

    if (*adaptive_streaming) {
        bpf_printk("[ingress xdp] ADAPTIVE STREAMING IS ENABLED\n");
    } else {
        bpf_printk("[ingress xdp] ADAPTIVE STREAMING IS DISABLED\n");
    }

    struct quic_header_wrapper header;
    bpf_probe_read_kernel(&header, sizeof(header), payload);
    if (header.header_t&0x80) {

        int version = 0;
        for (int i=1; i<5; i++) {
            char tmp;
            bpf_probe_read_kernel(&tmp, sizeof(tmp), payload+i);
            version = version << 8 | tmp;
        }

        bpf_printk("[ingress xdp] LONG HEADER (for version: %d)\n", version); 

    } else {
        bpf_printk("[ingress xdp] SHORT HEADER\n");

        char conn_id_start = 1;

        char prio;
        bpf_probe_read_kernel(&prio, sizeof(prio), payload+conn_id_start);

        if (prio == 0x00) {
            bpf_printk("[ingress xdp] LOW PRIORITY\n");
            if (*adaptive_streaming) {
                bpf_printk("[ingress xdp] DROPPING LOW PRIORITY PACKET\n");
                return XDP_DROP;
            }
        } else if (prio == 0x01) {
            bpf_printk("[ingress xdp] HIGH PRIORITY\n");
        } else {
            bpf_printk("[ingress xdp] ERROR: unknown priority\n");
        }

    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";