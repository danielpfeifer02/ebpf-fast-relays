#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

// to read trace: sudo cat /sys/kernel/tracing/trace_pipe
// activate go: export PATH=$PATH:/usr/local/go/bin

#define DEST_PORT 4242 // see loopback_quic/quic_traffic.go
#define MAX_ENTRIES 16

struct quic_header_wrapper {
    uint8_t header_t;
};

struct meta_s {
    int dst_conn_id_len;
    int src_conn_id_len;
};

struct key_s {
    int src_port;
    int dst_port;
};

// Define a map to store one element of type struct meta
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, struct meta_s);
    __uint(max_entries, MAX_ENTRIES);
} meta SEC(".maps");

// in userspace: "int map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "name", sizeof(int), sizeof(struct meta), MAX_ENTRIES, 0);"

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

    int src_port = ntohs(udp->source);
    int dst_port = ntohs(udp->dest);

    // Point to start of payload.
    payload = (unsigned char *)udp + sizeof(*udp);
    payload_size = ntohs(udp->len) - sizeof(*udp);
    if ((void *)payload + payload_size > data_end) {
        // bpf_printk("Something was dropped (6)\n");
        return XDP_PASS;
    }

    bpf_printk("[ingress xdp] packet is entering (payload size: %d)\n", payload_size);

    struct key_s index = {
        .src_port = src_port,
        .dst_port = dst_port
    };
    struct meta_s *meta_data = bpf_map_lookup_elem(&meta, &index);
    if (meta_data == 0) {
        struct meta_s tmp = {
            .dst_conn_id_len = 0,
            .src_conn_id_len = 0
        };
        meta_data = &tmp;
        bpf_map_update_elem(&meta, &index, meta_data, BPF_ANY);
    } else {
        bpf_printk("[ingress xdp] meta table is at %p \
        (src (%d) conn id len: %d, \
        dst (%d) conn id len: %d)\n", 
        meta_data, src_port, meta_data->src_conn_id_len, dst_port, meta_data->dst_conn_id_len);
    }

    if (meta_data->src_conn_id_len > 20 || meta_data->dst_conn_id_len > 20) {
        bpf_printk("[ingress xdp] ERROR: conn id length is too long\n");
        return XDP_PASS;
    }

    int cidLen = meta_data->src_conn_id_len;


    bpf_printk("[ingress xdp] cidLen: %d\n", cidLen);

    unsigned char payload_buffer[256] = {0}; // TODO size 256 enough?
    bpf_probe_read_kernel(payload_buffer, sizeof(payload_buffer), payload);


    struct quic_header_wrapper *header = (struct quic_header_wrapper *)payload_buffer;
    if (header->header_t&0x80) {

        // check for type == 0x02 (Handshake) to get the right conn id length
        int type = (header->header_t&0x30) >> 4;
        if (type != 0x02) {
            return XDP_PASS;
        }

        bpf_printk("[ingress xdp] LONG HEADER (handshake type)\n");

        //TODO differentiate between src and dst conn id length
        //TODO support retry packets


        // the 7th byte is the destination connection id length
        int dst_connection_id_length = payload_buffer[6];

        // the (7 + dst_connection_id_length + 1)th byte is the source connection id length
        int src_connection_id_length = payload_buffer[6 + dst_connection_id_length + 1];

        struct meta_s meta_datas = { // TODO check if reference or copy is used (i.e. malloc needed?)
            .dst_conn_id_len = dst_connection_id_length,
            .src_conn_id_len = src_connection_id_length
        };

        // TODO update more specific based on uniquely identifying the connection
        bpf_map_update_elem(&meta, &index, &meta_datas, BPF_ANY); 

    } else {
        bpf_printk("[ingress xdp] SHORT HEADER\n");
        int shl = 1;

        if (cidLen == 0) { // this has the downside that we ignore packet with connection id length 0 (special case)
            bpf_printk("[ingress xdp] connection id length not found\n");
            return XDP_PASS;
        }

        // we need to get the packet number. To do that first we need the packet number length (mask: 0x03, no shift)
        int packet_number_length = header->header_t&0x03;
        bpf_printk("[ingress xdp] packet number length: %d\n", packet_number_length);

        // now we get the actual packet number (packet number length is number of bytes)
        int packet_number = 0;

        // unsigned char so that the verfication works for all packet number lengths
        unsigned char pnoffset = shl + cidLen;

        if (packet_number_length == 1) {
            packet_number = payload_buffer[pnoffset];
        } else if (packet_number_length == 2) {
            packet_number = payload_buffer[pnoffset] << 8 | payload_buffer[pnoffset+1];
        } else if (packet_number_length == 3) {
            packet_number = payload_buffer[pnoffset] << 16 | payload_buffer[pnoffset+1] << 8 | payload_buffer[pnoffset+2];
        } else if (packet_number_length == 4) {
            packet_number = payload_buffer[pnoffset] << 24 | payload_buffer[pnoffset+1] << 16 | payload_buffer[pnoffset+2] << 8 | payload_buffer[pnoffset+3];
        }

        bpf_printk("[ingress xdp] packet number (%d bytes long): %d (based on connection id length: %d)\n", 
                    packet_number_length, packet_number, cidLen);
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";