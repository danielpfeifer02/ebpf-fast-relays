#include "tc_common.c"

/*
 - This program is intercepting incoming packets from the client side
 - and makes sure that new clients are "registered" in the client_data map
 - as well as separate maps that allow iteration over the clients in the
 - egress program.
 - Here only long headers are considered, since they are used primarily
 - in the initial handshake phase and that way we can avoid looking at
 - short headers containing ACKs once the connection is established.
 */

__section("ingress_from_client")
int tc_ingress_from_client(struct __sk_buff *skb)
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
        if (udp->dest != RELAY_PORT) {
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

        // We only consider long headers here.
        if (header_form == 1) {

                // Packet types are:
                // 0x00 - Initial
                // 0x01 - 0-RTT
                // 0x02 - Handshake
                // 0x03 - Retry
                // uint8_t packet_type = (quic_flags & 0x30) >> 4;

                // Save connection id offsets.
                uint8_t dst_connection_id_offset = 6;
                uint8_t src_connection_id_offset = 6 + CONN_ID_LEN + 1;

                // Create a temporary buffer to store the connection ids.
                uint8_t dst_connection_id[CONN_ID_LEN];
                uint8_t src_connection_id[CONN_ID_LEN];

                // Load the connection ids for the client and the relay.
                SAVE_BPF_PROBE_READ_KERNEL(dst_connection_id, sizeof(dst_connection_id), payload + dst_connection_id_offset);
                SAVE_BPF_PROBE_READ_KERNEL(src_connection_id, sizeof(src_connection_id), payload + src_connection_id_offset);

                // Load mac, ip and port information for the client and the relay.
                // Both src and dst mac are correct here since
                // src mac does not change and dst mac is the relay.
                uint8_t src_mac[MAC_LEN]; // mac address of the client
                SAVE_BPF_PROBE_READ_KERNEL(src_mac, sizeof(src_mac), eth->h_source);
                uint8_t dst_mac[MAC_LEN]; // mac address of the relay
                SAVE_BPF_PROBE_READ_KERNEL(dst_mac, sizeof(dst_mac), eth->h_dest);
                uint32_t src_ip_addr; // ip address of the client
                SAVE_BPF_PROBE_READ_KERNEL(&src_ip_addr, sizeof(src_ip_addr), &ip->saddr);
                uint32_t dst_ip_addr; // ip address of the relay
                SAVE_BPF_PROBE_READ_KERNEL(&dst_ip_addr, sizeof(dst_ip_addr), &ip->daddr);
                uint16_t src_port; // port of the client
                SAVE_BPF_PROBE_READ_KERNEL(&src_port, sizeof(src_port), &udp->source);
                uint16_t dst_port; // port of the relay
                SAVE_BPF_PROBE_READ_KERNEL(&dst_port, sizeof(dst_port), &udp->dest);

                // Create a key to index the map containing client information.
                // Identification will be the ip and the port of the client.
                struct client_info_key_t key = {
                        .ip_addr = src_ip_addr, 
                        .port = src_port,
                };

                // If the connection established map has no entry for the client
                // we need to create one.
                // TODO: if there exists an entry we probably do not need to be here -> check
                uint8_t *established = bpf_map_lookup_elem(&connection_established, &key);
                if (established == NULL) {
                        uint8_t zero = 0;
                        bpf_map_update_elem(&connection_established, &key, &zero, BPF_ANY);
                }

                // Store the client information in a struct to be stored in the 
                // map containing client information.
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

                // The source mac will be the mac of the relay.
                for (int i = 0; i < MAC_LEN; i++) {
                        value.src_mac[i] = dst_mac[i];
                }
                // The destination mac will be the mac of the client.
                for (int i = 0; i < MAC_LEN; i++) {
                        value.dst_mac[i] = src_mac[i];
                }
                // The connection id of the client will be the source connection id.
                for (int i = 0; i < CONN_ID_LEN; i++) {
                        value.connection_id[i] = src_connection_id[i];
                }

                // Look up the client id to see if the client is already registered.
                uint32_t *cid = bpf_map_lookup_elem(&client_id, &key);

                // If the client is not registered we need to register it by
                // using the next available client id.
                if (cid == NULL) {
                        uint32_t zero = 0;
                        uint32_t *next_client_id = bpf_map_lookup_elem(&id_counter, &zero);
                        if (next_client_id == NULL) {
                                bpf_printk("No next client id found\n");
                                return TC_ACT_OK;
                        }
                        // We make sure the next client id is not too big.
                        // This wrap around might cause overwriting of existing clients
                        // if the next counter is used later on after the wrap around.
                        uint32_t new_counter = (*next_client_id + 1) % MAX_CLIENTS;
                        bpf_map_update_elem(&id_counter, &zero, &new_counter, BPF_ANY);
                        bpf_map_update_elem(&client_id, &key, next_client_id, BPF_ANY);
                        cid = next_client_id;
                }

                // We update the client data map to store the newest client information.
                // This happens no matter if the client is already registered or not to 
                // make sure the information is up to date once the handshake is complete.
                // Changes in the client information (e.g. connection id) will be updated
                // in the relay user space program.
                bpf_map_update_elem(&client_data, cid, &value, BPF_ANY);

        }

        return TC_ACT_OK;
}
