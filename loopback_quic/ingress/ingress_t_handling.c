#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

// to read trace: sudo cat /sys/kernel/tracing/trace_pipe
// activate go: export PATH=$PATH:/usr/local/go/bin

#define DEST_PORT 4242 // see loopback_quic/quic_traffic.go
#define MAX_ENTRIES_META 16
#define MAX_ENTRIES_PAYLOAD 256
#define MAX_CONNECTION_ID_LENGTH 20

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
    __uint(max_entries, MAX_ENTRIES_META);
} meta SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, char);
    __uint(max_entries, MAX_ENTRIES_PAYLOAD);
} payload_mp SEC(".maps");

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
        bpf_printk("[ingress xdp] meta table is at %p (src (%d) conn id len: %d, dst (%d) conn id len: %d)\n", 
        meta_data, src_port, meta_data->src_conn_id_len, dst_port, meta_data->dst_conn_id_len);
    }

    if (meta_data->src_conn_id_len > 20 || meta_data->dst_conn_id_len > 20) {
        bpf_printk("[ingress xdp] ERROR: conn id length is too long\n");
        return XDP_PASS;
    }

    int short_header_conn_id_len = 4; //meta_data->dst_conn_id_len; // TODO not working yet


    bpf_printk("[ingress xdp] short_header_conn_id_len: %d\n", short_header_conn_id_len);

    // TODO kinda useless for now since header protection still present
    // unsigned char payload_buffer[256] = {0}; // TODO size 256 enough?
    // bpf_probe_read_kernel(&payload_mp, sizeof(MAX_ENTRIES_PAYLOAD), payload);


    // TODO handle more than one quic packet in the payload

    struct quic_header_wrapper header;
    bpf_probe_read_kernel(&header, sizeof(header), payload); //TODO not ideal since only one byte?
    if (header.header_t&0x80) {

        // char long_packet_type = (header->header_t&0x30) >> 4;
        // char packet_number_length = header->header_t&0x03;
        int version = 0;
        for (int i=1; i<5; i++) {
            char tmp;
            bpf_probe_read_kernel(&tmp, sizeof(tmp), payload+i);
            version = version << 8 | tmp;
        }
        // start after version field which means we have already read 5 bytes
        int next_ptr = 5;

        bpf_printk("[ingress xdp] LONG HEADER (for version: %d)\n", version); 

        // the 6th byte of all long headers is the destination connection id length
        unsigned char dst_connection_id_length;
        bpf_probe_read_kernel(&dst_connection_id_length, sizeof(dst_connection_id_length), payload+next_ptr);
        next_ptr++;

        unsigned char dst_connection_id[MAX_CONNECTION_ID_LENGTH] = {0};
        bpf_probe_read_kernel(&dst_connection_id, sizeof(dst_connection_id), payload+next_ptr);
        for(int i=dst_connection_id_length; i<MAX_CONNECTION_ID_LENGTH; i++) {
            dst_connection_id[i] = 0;
        }
        next_ptr += dst_connection_id_length;

        // the (6 + dst_connection_id_length + 1)th byte of all long headers is 
        // the source connection id length
        unsigned char src_connection_id_length;
        bpf_probe_read_kernel(&src_connection_id_length, sizeof(src_connection_id_length), payload+next_ptr);
        next_ptr++;

        unsigned char src_connection_id[MAX_CONNECTION_ID_LENGTH] = {0};
        bpf_probe_read_kernel(&src_connection_id, sizeof(src_connection_id), payload+next_ptr);
        for(int i=src_connection_id_length; i<MAX_CONNECTION_ID_LENGTH; i++) {
            src_connection_id[i] = 0;
        }
        next_ptr += src_connection_id_length;

        bpf_printk("[ingress xdp] destination connection id length: %d\n", dst_connection_id_length);
        
        bpf_printk("[ingress xdp] destination connection id (first 10 bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", 
            dst_connection_id[0], dst_connection_id[1], dst_connection_id[2], dst_connection_id[3], dst_connection_id[4], 
            dst_connection_id[5], dst_connection_id[6], dst_connection_id[7], dst_connection_id[8], dst_connection_id[9]);
        
        bpf_printk("[ingress xdp] source connection id length: %d\n", src_connection_id_length);

        bpf_printk("[ingress xdp] source connection id (first 10 bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", 
            src_connection_id[0], src_connection_id[1], src_connection_id[2], src_connection_id[3], src_connection_id[4], 
            src_connection_id[5], src_connection_id[6], src_connection_id[7], src_connection_id[8], src_connection_id[9]);


#ifdef DEBUG
        long_header_type_version_print((header.header_t&0x30) >> 4);
#endif

        // // this means we already have a connection id length for dst
        // if (meta_data->dst_conn_id_len > 0) { 
        //     if (dst_connection_id_length > 0 && dst_connection_id_length != meta_data->dst_conn_id_len) {
        //         bpf_printk("[ingress xdp] ERROR: destination connection id length changed\n");
        //         return XDP_PASS;
        //     } else if (dst_connection_id_length == 0) {
        //         dst_connection_id_length = meta_data->dst_conn_id_len;
        //     }
        // }
        // if (meta_data->src_conn_id_len > 0) { // this means we already have a connection id length for src
        //     if (src_connection_id_length > 0 && src_connection_id_length != meta_data->src_conn_id_len) {
        //         bpf_printk("[ingress xdp] ERROR: source connection id length changed\n");
        //         return XDP_PASS;
        //     } else if (src_connection_id_length == 0) {
        //         src_connection_id_length = meta_data->src_conn_id_len;
        //     }
        // }

        struct meta_s meta_datas = { // TODO check if reference or copy is used (i.e. malloc needed?)
            .dst_conn_id_len = dst_connection_id_length,
            .src_conn_id_len = src_connection_id_length
        };

        // TODO update more specific based on uniquely identifying the connection
        bpf_map_update_elem(&meta, &index, &meta_datas, BPF_ANY); 

    } else {
        bpf_printk("[ingress xdp] SHORT HEADER\n");
        // int shl = 1;

        // if (short_header_conn_id_len == 0) { // this has the downside that we ignore packet with connection id length 0 (special case)
        //     bpf_printk("[ingress xdp] connection id length not found\n");
        //     return XDP_PASS;
        // }

        // // we need to get the packet number. To do that first we need the packet number length (mask: 0x03, no shift)
        // int packet_number_length = header.header_t&0x03;
        // bpf_printk("[ingress xdp] packet number length: %d\n", packet_number_length);

        // now we get the actual packet number (packet number length is number of bytes)
        // int packet_number = 0;

        // unsigned char so that the verfication works for all packet number lengths
        // unsigned char pnoffset = shl + short_header_conn_id_len;

        // bpf_printk("[ingress xdp] packet number hex: %02x %02x %02x %02x\n", payload_buffer[pnoffset], payload_buffer[pnoffset+1], payload_buffer[pnoffset+2], payload_buffer[pnoffset+3]);

        // if (packet_number_length == 1) {
        //     packet_number = payload_buffer[pnoffset];
        // } else if (packet_number_length == 2) {
        //     packet_number = payload_buffer[pnoffset] << 8 | payload_buffer[pnoffset+1];
        // } else if (packet_number_length == 3) {
        //     packet_number = payload_buffer[pnoffset] << 16 | payload_buffer[pnoffset+1] << 8 | payload_buffer[pnoffset+2];
        // } else if (packet_number_length == 4) {
        //     packet_number = payload_buffer[pnoffset] << 24 | payload_buffer[pnoffset+1] << 16 | payload_buffer[pnoffset+2] << 8 | payload_buffer[pnoffset+3];
        // }

        // bpf_printk("[ingress xdp] packet number (%d bytes long): %d (based on connection id length: %d)\n", 
        //             packet_number_length, packet_number, short_header_conn_id_len);
    }
    
    return XDP_PASS;
}

void long_header_type_version_print(int long_header_type) {
    switch(long_header_type) {
            case 0x00:
                bpf_printk("[ingress xdp] long packet type: initial\n");

                /* Initial packet structure: 
                    Initial Packet {
                        Header Form (1) = 1,
                        Fixed Bit (1) = 1,
                        Long Packet Type (2) = 0,
                        Reserved Bits (2),
                        Packet Number Length (2),
                        Version (32),
                        Destination Connection ID Length (8),
                        Destination Connection ID (0..160),
                        Source Connection ID Length (8),
                        Source Connection ID (0..160),
                        ...
                    }
                    // Since we wan to decide based on the connection id we
                    // do not care about the rest of the packet                
                */

                break;
            case 0x01:
                bpf_printk("[ingress xdp] long packet type: 0-RTT\n");

                /* 0-RTT packet structure: 
                    0-RTT Packet {
                        Header Form (1) = 1,
                        Fixed Bit (1) = 1,
                        Long Packet Type (2) = 1,
                        Reserved Bits (2),
                        Packet Number Length (2),
                        Version (32),
                        Destination Connection ID Length (8),
                        Destination Connection ID (0..160),
                        Source Connection ID Length (8),
                        Source Connection ID (0..160),
                        ...
                    }
                    // Since we wan to decide based on the connection id we
                    // do not care about the rest of the packet                
                */

                break;
            case 0x02:
                bpf_printk("[ingress xdp] long packet type: Handshake\n");

                /* Handshake packet structure: 
                    Handshake Packet {
                        Header Form (1) = 1,
                        Fixed Bit (1) = 1,
                        Long Packet Type (2) = 2,
                        Reserved Bits (2),
                        Packet Number Length (2),
                        Version (32),
                        Destination Connection ID Length (8),
                        Destination Connection ID (0..160),
                        Source Connection ID Length (8),
                        Source Connection ID (0..160),
                        ...
                    }
                    // Since we wan to decide based on the connection id we
                    // do not care about the rest of the packet                
                */

                break;
            case 0x03:
                bpf_printk("[ingress xdp] long packet type: Retry\n");

                /* Retry packet structure: 
                    Retry Packet {
                        Header Form (1) = 1,
                        Fixed Bit (1) = 1,
                        Long Packet Type (2) = 3,
                        Unused (4),
                        Version (32),
                        Destination Connection ID Length (8),
                        Destination Connection ID (0..160),
                        Source Connection ID Length (8),
                        Source Connection ID (0..160),
                        Retry Token (..),
                        Retry Integrity Tag (128),
                    }
                    // Since we wan to decide based on the connection id we
                    // do not care about the rest of the packet                
                */

                break;
            default:
                bpf_printk("[ingress xdp] ERROR: unknown long packet type\n");
        }
}

char _license[] SEC("license") = "GPL";