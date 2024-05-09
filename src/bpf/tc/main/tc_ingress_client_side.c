#include "tc_common.c"

__section("ingress_from_client")
int tc_ingress_from_client(struct __sk_buff *skb)
{

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
        if (udp->dest != RELAY_PORT) {
                return TC_ACT_OK;
        }

        // TODO: for now just drop QUIC answers to avoid protocol violation
        // struct client_info_key_t key = {
        //         .ip_addr = ip->saddr,
        //         .port = udp->source,
        // };
        // uint8_t *conn_established = bpf_map_lookup_elem(&connection_established, &key);
        // if (conn_established != NULL && *conn_established == 1) {
        //         return TC_ACT_OK;
        // }
        // uint8_t established = 1;
        // bpf_map_update_elem(&connection_established, &key, &established, BPF_ANY);


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

        eth = (struct ethhdr *)data;
        ip = (struct iphdr *)(eth + 1);
        udp = (struct udphdr *)(ip + 1);
        payload = (void *)(udp + 1);

        uint8_t quic_flags;
        bpf_probe_read_kernel(&quic_flags, sizeof(quic_flags), payload);
        uint8_t header_form = (quic_flags & 0x80) >> 7;

        if (header_form == 1) {
                // Long header
                // bpf_printk("Long header\n");

                uint8_t packet_type = (quic_flags & 0x30) >> 4;

                // bpf_printk("Packet type: %02x\n", packet_type);

                // Packet types are:
                // 0x00 - Initial
                // 0x01 - 0-RTT
                // 0x02 - Handshake
                // 0x03 - Retry

                // Load connection id
                uint8_t dst_connection_id_offset = 6;
                uint8_t src_connection_id_offset = 6 + CONN_ID_LEN + 1;

                uint8_t dst_connection_id[CONN_ID_LEN];
                uint8_t src_connection_id[CONN_ID_LEN];

                bpf_probe_read_kernel(dst_connection_id, sizeof(dst_connection_id), payload + dst_connection_id_offset);
                bpf_probe_read_kernel(src_connection_id, sizeof(src_connection_id), payload + src_connection_id_offset);

                // ! both src and dst mac are correct here since
                // ! src mac does not change and dst mac is the relay
                uint8_t src_mac[MAC_LEN]; // mac address of the client
                bpf_probe_read_kernel(src_mac, sizeof(src_mac), eth->h_source);
                uint8_t dst_mac[MAC_LEN]; // mac address of the relay
                bpf_probe_read_kernel(dst_mac, sizeof(dst_mac), eth->h_dest);
                uint32_t src_ip_addr; // ip address of the client
                bpf_probe_read_kernel(&src_ip_addr, sizeof(src_ip_addr), &ip->saddr);
                uint32_t dst_ip_addr; // ip address of the relay
                bpf_probe_read_kernel(&dst_ip_addr, sizeof(dst_ip_addr), &ip->daddr);
                uint16_t src_port; // port of the client
                bpf_probe_read_kernel(&src_port, sizeof(src_port), &udp->source);
                uint16_t dst_port; // port of the relay
                bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &udp->dest);

                // uint8_t prio;
                // bpf_probe_read_kernel(&prio, sizeof(prio), payload + 1 /* Long header flags */ 
                //                                                    + 4 /* Version */ 
                //                                                    + 1 /* DST CONN ID Len */ 
                //                                                    + CONN_ID_LEN /* DST CONN ID */
                //                                                    + 1 /* SRC CONN ID Len */);
                // bpf_printk("PRIO: %02x\n", prio);

                struct client_info_key_t key = {
                        .ip_addr = src_ip_addr, // identifying will be the ip of the client
                        .port = src_port,       // and the port of the client
                };


                struct client_info_t value = {
                        .src_mac = {0},
                        .dst_mac = {0},
                        .src_ip_addr = dst_ip_addr, // the source ip will be the ip of the relay
                        .dst_ip_addr = src_ip_addr, // the destination ip will be the ip of the client
                        .src_port = dst_port, // the source port will be the port of the relay
                        .dst_port = src_port, // the destination port will be the port of the client
                        .connection_id = {0},
                        .priority_drop_limit = 0,
                };

                for (int i = 0; i < MAC_LEN; i++) {
                        value.src_mac[i] = dst_mac[i]; // the source mac will be the mac of the relay
                }
                for (int i = 0; i < MAC_LEN; i++) {
                        value.dst_mac[i] = src_mac[i]; // the destination mac will be the mac of the client
                }
                for (int i = 0; i < CONN_ID_LEN; i++) {
                        value.connection_id[i] = src_connection_id[i];
                }

                // Look up the client id
                uint32_t *cid = bpf_map_lookup_elem(&client_id, &key);
                if (cid == NULL) {
                        // bpf_printk("First occurence of key\n");
                        // Get the next client id
                        uint32_t zero = 0;
                        uint32_t *next_client_id = bpf_map_lookup_elem(&id_counter, &zero);
                        if (next_client_id == NULL) {
                                bpf_printk("No next client id found\n");
                                return TC_ACT_OK;
                        }
                        uint32_t new_counter = (*next_client_id + 1) % MAX_CLIENTS;
                        // bpf_printk("New client id: %d\n", new_counter);
                        bpf_map_update_elem(&id_counter, &zero, &new_counter, BPF_ANY);
                        bpf_map_update_elem(&client_id, &key, next_client_id, BPF_ANY);
                        cid = next_client_id;
                }

                // bpf_printk("Client id: %d\n", *cid);

                // Update the client data map
                bpf_map_update_elem(&client_data, cid, &value, BPF_ANY);

        }

        return TC_ACT_OK;
}
