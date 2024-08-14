#include "tc_common.c"

/*
 - This program is intercepting incoming packets from the video server,
 - duplicates and redirects them directly to egress. The initial copy of 
 - the packet is still passed up to userspace so that the bpf program
 - does not need to handle any connection related logic (e.g. ACKs).
 - Also the userspace will handle any caching that is expected 
 - of the relay.
 */

__section("ingress")
int tc_ingress(struct __sk_buff *skb)
{

        // In case the TURNOFF flag is set the bpf program will not do anything
        // and the packet will be passed through immediately.
        if (TURNOFF) {
                bpf_printk("Dropping because of turn off\n");
                return TC_ACT_OK;
        }

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

        // If the packet is not sent from the port where the server is
        // listening we can pass it through since the packet is from a 
        // different program.
        if (udp->source != SERVER_PORT) {
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
                        bpf_printk("[ingress startup tc] failed to pull data");
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

        // We only consider short header packets here.
        if (header_form == 0) {

                // We need to check that the packet actually contains a supported frame.
                // We only need to look at the first frame since the underlying QUIC library is
                // expected to handle supported frames with separate packets.
                uint8_t pn_len = (quic_flags & 0x03) + 1;
                uint8_t frame_type;
                // The frame starts after:
                // - Short header bits (1 byte)
                // - Connection ID (16 bytes - per design)
                // - Packet number (variable length - read before)
                uint16_t frame_off = 1 /* Short header bits */ + CONN_ID_LEN + pn_len;
                SAVE_BPF_PROBE_READ_KERNEL(&frame_type, sizeof(frame_type), payload + frame_off);

                // Checking that the frame is supported.
                if (!SUPPORTED_FRAME(frame_type)) {
                        bpf_printk("Not a stream or datagram frame (%02x)\n", frame_type);
                        return TC_ACT_OK;
                }

                // To know how often the packet needs to be redirected we need to look up the number of clients.
                // The number of clients is kept up to date by the userspace program.
                uint32_t zero = 0;
                uint32_t *num_clients = bpf_map_lookup_elem(&number_of_clients, &zero);
                if (num_clients == NULL) {
                        bpf_printk("No number of clients found\n");
                        return TC_ACT_OK;
                }

                // We set the UDP checksum to 0 to avoid issues with checksums
                // and make packet more easily identifiable at egress.
                // However, we need to save the old checksum since we will
                // still pass the initial packet up to userspace.
                uint16_t old_checksum;
                SAVE_BPF_PROBE_READ_KERNEL(&old_checksum, sizeof(old_checksum), &udp->check);
                uint16_t zero_checksum = 0;
                uint32_t checksum_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + 6 /* Everything before checksum */;
                bpf_skb_store_bytes(skb, checksum_off, &zero_checksum, sizeof(zero_checksum), 0);

                // We also need to save the old port since we will redirect the packet to userspace.
                uint16_t old_port;
                SAVE_BPF_PROBE_READ_KERNEL(&old_port, sizeof(old_port), &udp->dest);

                // We also need to save the old connection id since we will redirect the packet to userspace.
                uint8_t old_conn_id[CONN_ID_LEN];
                SAVE_BPF_PROBE_READ_KERNEL(old_conn_id, sizeof(old_conn_id), payload + 1 /* Short header flags */);
                uint32_t conn_id_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 1;

                for (uint32_t i=0; i<MAX_CLIENTS; i++) {
                        if (i >= *num_clients) {
                                break;
                        }
                        // Since we do not need the connection id anymore once we're at the egress
                        // we can use it to store the index of the for loop. At egress the bpf program
                        // can then handle the packet containing the i-th index so fit the i-th client.
                        // We need index + 1 since we want to avoid 0 as an index. // TODO: start with 0?
                        uint32_t index = i + 1;
                        // We use the second byte of the connection id to store the index
                        // since the first byte is encoding the priority which will also
                        // be looked at by the egress program.
                        uint32_t index_off = conn_id_off + 1;
                        bpf_skb_store_bytes(skb, index_off, &index, sizeof(uint32_t), 0);

                        // To make the packet more identifiable as a redirected packet we set the
                        // destination port to a marker value.
                        uint16_t dst_port_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + 2 /* SRC PORT */;
                        uint16_t mrk = PORT_MARKER;
                        bpf_skb_store_bytes(skb, dst_port_off, &mrk, sizeof(mrk), 0);

                        // bpf_printk("Redirecting to client %d\n", i);
                        
                        // We need to use clone_redirect to redirect the packet to the egress program
                        // since otherwise we get errors when changing the packet in here.
                        if (TURNOFF_INGRESS_FORWARDING) {
                                break; // TODO: not the most efficient place for this check but works for now
                        }
                        bpf_clone_redirect(skb, veth2_egress_ifindex, 0);
                
                }

                // Before passing the packet on to userspace we need to set UDP port to RELAY_PORT again
                uint16_t relay_port_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + 2 /* SRC PORT */;
                bpf_skb_store_bytes(skb, relay_port_off, &old_port, sizeof(old_port), 0);

                // Before passing the packet on to userspace we need to set udp checksum back to old value
                bpf_skb_store_bytes(skb, checksum_off, &old_checksum, sizeof(old_checksum), 0);

                // Before passing the packet on to userspace we need to set connection id back to old value
                bpf_skb_store_bytes(skb, conn_id_off, old_conn_id, CONN_ID_LEN, 0);

                // Now we just pass on the packet to userspace.
                return TC_ACT_OK;
        
        }

        return TC_ACT_OK;
}
