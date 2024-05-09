#include "tc_common.c"

__section("ingress")
int tc_ingress(struct __sk_buff *skb)
{

        if (TURNOFF) {
                bpf_printk("Dropping because of turn off\n");
                return TC_ACT_OK;
        }

        // uint32_t zero = 0;
        // uint32_t *pack_ctr = bpf_map_lookup_elem(&packet_counter, &zero);
        // if (pack_ctr != NULL && *pack_ctr == 1) {
        //         bpf_printk("Packet counter drop\n");
        //         return TC_ACT_OK;
        // }




        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;


        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
                return TC_ACT_OK; // Not enough data
        }

        // Load ethernet header
        struct ethhdr *eth = (struct ethhdr *)data;

        // Load IP header
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        // Check if the packet is UDP
        if (ip->protocol != IPPROTO_UDP) {
                return TC_ACT_OK;
        }

        // Load UDP header
        struct udphdr *udp = (struct udphdr *)(ip + 1);

        // Check if the packet is QUIC
        if (udp->source != SERVER_PORT) {
                return TC_ACT_OK;
        }


        // Load UDP payload
        void *payload = (void *)(udp + 1);
        uint32_t payload_size = ntohs(udp->len) - sizeof(*udp);

        if ((void *)payload + payload_size > data_end) {

                // bpf_printk("[ingress startup tc] payload is not in the buffer");

                // We need to use bpf_skb_pull_data() to get the rest of the packet
                if(bpf_skb_pull_data(skb, (data_end-data)+payload_size) < 0) {
                        bpf_printk("[ingress startup tc] failed to pull data");
                        return TC_ACT_OK;
                }
                data_end = (void *)(long)skb->data_end;
                data = (void *)(long)skb->data;
        
        }

        // ! TODO: does this maybe cause the error with the 0x00 quic flags?
        // relaod pointers
        eth = (struct ethhdr *)data;
        ip = (struct iphdr *)(eth + 1);
        udp = (struct udphdr *)(ip + 1);
        payload = (void *)(udp + 1);

        uint8_t quic_flags;
        bpf_probe_read_kernel(&quic_flags, sizeof(quic_flags), payload);
        uint8_t header_form = (quic_flags & 0x80) >> 7;

        // redirecting short header packets
        if (header_form == 0) {

                // check that the packet actually contains payload (frame type 0x08-0x0f)
                // TODO: what if there are multiple frames in one packet besides the stream frame?
                uint8_t pn_len = (quic_flags & 0x03) + 1;
                uint8_t frame_type;
                uint16_t frame_off = 1 /* Short header bits */ + CONN_ID_LEN + pn_len;
                bpf_probe_read_kernel(&frame_type, sizeof(frame_type), payload + frame_off);

                // bpf_printk("Type of frame: %02x\n", frame_type);
                if (!SUPPORTED_FRAME(frame_type)) {
                        bpf_printk("Not a stream or datagram frame (%02x)\n", frame_type);
                        return TC_ACT_OK;
                }

                // get number of clients
                uint32_t zero = 0;
                uint32_t *num_clients = bpf_map_lookup_elem(&number_of_clients, &zero);
                if (num_clients == NULL) {
                        bpf_printk("No number of clients found\n");
                        return TC_ACT_OK;
                }

                // bpf_printk("Short header - redirecting for %d clients\n", *num_clients);

                // TODO probably not working bc of concurrency (maybe some hash map to look up ctr value for a packet or save inside of packet bytes?)
                // ! TODO change from packet ctr to aving index inside of packet
                // // set packet_counter to 1 
                // // uint32_t pack_ctr = 1;
                // // bpf_map_update_elem(&packet_counter, &zero, &pack_ctr, BPF_ANY);

                // set udp checksum to 0
                uint16_t old_checksum;
                bpf_probe_read_kernel(&old_checksum, sizeof(old_checksum), &udp->check);
                uint16_t zero_checksum = 0;
                uint32_t checksum_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + 6 /* Everything before checksum */;
                bpf_skb_store_bytes(skb, checksum_off, &zero_checksum, sizeof(zero_checksum), 0);

                uint16_t old_port;
                bpf_probe_read_kernel(&old_port, sizeof(old_port), &udp->dest);

                uint8_t old_conn_id[CONN_ID_LEN];
                bpf_probe_read_kernel(old_conn_id, sizeof(old_conn_id), payload + 1 /* Short header flags */);
                uint32_t conn_id_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 1;

                for (uint32_t i=0; i<MAX_CLIENTS; i++) {
                        if (i >= *num_clients) {
                                break;
                        }
                        // TODO set some part of the packet to "i" so that we can identify at egress
                        // since we do not need the connection id anymore once we're at the egress
                        // we can use it to store the index ctr
                        // TODO: change to zero index
                        uint32_t index = i + 1;
                        // we use the second byte of the connection id to store the index
                        // since the first byte is encoding the priority 
                        uint32_t index_off = conn_id_off + 1;
                        bpf_skb_store_bytes(skb, index_off, &index, sizeof(uint32_t), 0);

                        uint16_t dst_port_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + 2 /* SRC PORT */;
                        uint16_t mrk = PORT_MARKER;
                        bpf_skb_store_bytes(skb, dst_port_off, &mrk, sizeof(mrk), 0);

                        bpf_printk("Redirecting to client %d\n", i);
                        bpf_clone_redirect(skb, veth2_egress_ifindex, 0); // TODO: bpf_redirect or bpf_clone_redirect?
                
                }

                // set udp port to RELAY_PORT again
                uint16_t relay_port_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + 2 /* SRC PORT */;
                bpf_skb_store_bytes(skb, relay_port_off, &old_port, sizeof(old_port), 0);

                // set udp checksum back to old value
                bpf_skb_store_bytes(skb, checksum_off, &old_checksum, sizeof(old_checksum), 0);

                // set connection id back to old value
                bpf_skb_store_bytes(skb, conn_id_off, old_conn_id, CONN_ID_LEN, 0);

                // hand over to userspace so that packet can be ACKed
                return TC_ACT_OK;
        
        }

        // bpf_printk("[ingress tc]\n");
        return TC_ACT_OK;

}
