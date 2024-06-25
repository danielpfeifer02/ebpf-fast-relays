#include "../main/tc_common.c"

/*
 - This program is intercepting incoming packets from the client side
 - and makes sure that new clients are "registered" in the client_data map
 - as well as separate maps that allow iteration over the clients in the
 - egress program.
 - Here only long headers are considered, since they are used primarily
 - in the initial handshake phase and that way we can avoid looking at
 - short headers containing ACKs once the connection is established.
 */

__section("ts_ingress")
int tc_ts_ingress(struct __sk_buff *skb)
{

        // Get data pointers from the buffer.
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        // If the packet is too small to contain the headers we expect
        // we can directly pass it through.
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
                return TC_ACT_OK;
        }

        // Load ethernet header.
        struct ethhdr *eth = (struct ethhdr *)data;

        // Load IP header.
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        // If the packet is not a UDP packet we can pass it through
        // since QUIC is built on top of UDP.
        if (ip->protocol != IPPROTO_UDP) {
                return TC_ACT_OK;
        }

        // Load UDP header.
        struct udphdr *udp = (struct udphdr *)(ip + 1);

        // If the packet is not addressed to the port where our relay is
        // listening we can pass it through since the packet is from a 
        // different program.
        if (udp->source != RELAY_PORT) {
                return TC_ACT_OK;
        }

        // Load UDP payload as well as UDP payload size.
        void *payload = (void *)(udp + 1);
        uint32_t payload_size = ntohs(udp->len) - sizeof(*udp);

        // If the payload is not in the buffer we need to pull it in.
        if ((void *)payload + payload_size > data_end) {

                // We need to use bpf_skb_pull_data() to get the rest of the packet.
                // If the pull fails we can pass the packet through.
                if(bpf_skb_pull_data(skb, (data_end-data)+payload_size) < 0) {
                        bpf_printk("[tc_ts_handling_ingress] Failed to pull data");
                        return TC_ACT_OK;
                }

                // Once we have pulled the data we need to update the pointers.
                data_end = (void *)(long)skb->data_end;
                data = (void *)(long)skb->data;
                eth = (struct ethhdr *)data;
                ip = (struct iphdr *)(eth + 1);
                udp = (struct udphdr *)(ip + 1);
                payload = (void *)(udp + 1);
        }      

        // We load the first byte of the QUIC payload to determine the header form.
        uint8_t quic_flags;
        SAVE_BPF_PROBE_READ_KERNEL(&quic_flags, sizeof(quic_flags), payload);
        uint8_t header_form = (quic_flags & 0x80) >> 7;

        // We only consider short headers here.
        if (header_form == 0) {

                // Only thing to change is the timetamp.
                uint8_t pn_len = (quic_flags & 0x03) + 1;

                uint32_t quic_payload_offset = 1 /* Header */+ CONN_ID_LEN + pn_len;

                uint8_t frame_type;
                SAVE_BPF_PROBE_READ_KERNEL(&frame_type, sizeof(frame_type), payload + quic_payload_offset);

                if (!IS_STREAM_FRAME(frame_type)) {
                        bpf_printk("[tc_ts_handling_ingress] Not a stream frame");
                        return TC_ACT_OK;
                }
                
                uint8_t offset_present = frame_type & 0x04;
                uint8_t length_present = frame_type & 0x02;

                uint32_t stream_data_offset = 0;
                struct var_int stream_id;
                read_var_int(payload + quic_payload_offset + 1, &stream_id, NO_VALUE_NEEDED);
                stream_data_offset += bounded_var_int_len(stream_id.len);

                if (offset_present) {
                        struct var_int offset;
                        read_var_int(payload + quic_payload_offset + 1 + stream_data_offset, &offset, NO_VALUE_NEEDED);
                        stream_data_offset += bounded_var_int_len(offset.len);
                }
                if (length_present) {
                        struct var_int length;
                        read_var_int(payload + quic_payload_offset + 1 + stream_data_offset, &length, NO_VALUE_NEEDED);
                        stream_data_offset += bounded_var_int_len(length.len);
                }

                stream_data_offset += TS_OFF_INGRESS;

                uint64_t timestamp = bpf_ktime_get_tai_ns();
                uint32_t overall_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)+ quic_payload_offset + 1 /* Frame type */ + stream_data_offset;
                bpf_skb_store_bytes(skb, overall_off, &timestamp, sizeof(timestamp), 0);

                bpf_printk("[tc_ts_handling_ingress] Timestamp added to packet");


        }

        return TC_ACT_OK;
}
