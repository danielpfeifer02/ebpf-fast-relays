#include "tc_common.c"

/*
 - This program will intercept every packet going from the relay to the client.
 - This includes the packets that have been redirected from ingress to egress
 - without going through userspace.
*/

__section("egress")
int tc_egress(struct __sk_buff *skb)
{

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
                bpf_printk("Not enough data\n");
                return TC_ACT_OK; // Not enough data
        }

        // Load ethernet header.
        struct ethhdr *eth = (struct ethhdr *)data;

        // Load IP header.
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        // TODO: is ICMP needed?
        // If the packet is not a UDP packet we can pass it through
        // since QUIC is built on top of UDP.
        if (ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_ICMP) {
                bpf_printk("Not UDP\n");
                return TC_ACT_OK;
        }

        // Load UDP header.
        struct udphdr *udp = (struct udphdr *)(ip + 1);

        // If the packet is not sent from the port where our relay is
        // listening we can pass it through since the packet is from a 
        // different program.
        if (udp->source != RELAY_PORT) {
                bpf_printk("Not QUIC (port: %d)\n", htons(udp->source));       
                return TC_ACT_OK;
        }

        // We need a separate indicator if the packet has come from userspace
        // so that we can, in case the packet is QUIC, do the packet number 
        // translation to avoid protocol violations / disturbances caused by
        // wrong packet numbers. This could happen since the userspace effectively
        // does not know about the packets that are redirected from ingress.
        uint8_t user_space = 0;

        // In case the packet was redirected from ingress the packet number is always
        // set to zero.
        if (udp->check != 0) {
                bpf_printk("Checksum not 0 (%d)\n", udp->check);    
                user_space = 1;
                udp->check = 0;
        }

        // In case the packet was redirected from ingress the destination port is always
        // set to a special port marker.
        if (udp->dest != PORT_MARKER) {
                bpf_printk("Not the correct dest port (%d)\n", htons(udp->dest));
                user_space = 1;
        }

        // TODO: needed? Wireshark shows ICMP packets that also have a QUIC payload? 
        // Since QUIC can also send ICMP packets we need to consider them as well.
        if (ip->protocol == IPPROTO_ICMP) {
                bpf_printk("ICMP packet\n");
                user_space = 1;
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

        // In case the priorities of a stream are exchanged on the stream when creating
        // it we might want to catch such a (likely 1 byte) payload and directly pass
        // it on to the client (considering packet number translation of course).

        // We load the first byte of the QUIC payload to determine the header form.
        uint8_t quic_flags;
        SAVE_BPF_PROBE_READ_KERNEL(&quic_flags, sizeof(quic_flags), payload);
        uint8_t header_form = (quic_flags & 0x80) >> 7;

        // The redirected packet is a short header
        if (header_form == 0) {

                // When a short header packet arrives at the egress interface
                // which is sent from user space we only update the packet number
                if (user_space) {

                        // Read dst ip and port.
                        uint32_t dst_ip_addr;
                        SAVE_BPF_PROBE_READ_KERNEL(&dst_ip_addr, sizeof(dst_ip_addr), &ip->daddr);
                        uint16_t dst_port;
                        SAVE_BPF_PROBE_READ_KERNEL(&dst_port, sizeof(dst_port), &udp->dest);

                        // Create key to update the client information
                        struct client_info_key_t key = {
                                .ip_addr = dst_ip_addr,
                                .port = dst_port,
                        };

                        // Here we translate the packet number of the outgoing packet to 
                        // the packet number which will actually be sent out (the one in
                        // the bpf map)
                        uint8_t pn_len = (quic_flags & 0x03) + 1;
                        uint32_t old_pn = read_packet_number(payload, pn_len, 1 /* Short header bits */ + CONN_ID_LEN);

                        // Now we lookup the next packet number for the connection.
                        uint32_t *new_pn = bpf_map_lookup_elem(&connection_current_pn, &key);
                        uint32_t zero = 0;
                        // If there is no packet number found it is the first request for that
                        // connection so we create a new entry of zero in the map.
                        if (new_pn == NULL) {
                                bpf_map_update_elem(&connection_current_pn, &key, &zero, BPF_ANY);
                                bpf_printk("No packet number found\n");
                                new_pn = &zero;
                        }
                        
                        // Saving the offset of the packetnumber within the short header.
                        uint32_t pn_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 1 /* Short header flags */ + CONN_ID_LEN;
                        
                        // Here we make sure that we use all the bytes that were used for the packet number
                        // in the initial packet (and only those).
                        // TODO: this might cause a problem if the packet number length e.g. is still 
                        // TODO: two bytes for the userspace packet but needs more (i.e. something like
                        // TODO: four) bytes to store the packet number that is acutally used. This could
                        // TODO: e.g. be circumvented by always using four bytes, or by telling userspace 
                        // TODO: the needed size.
                        uint8_t new_pn_bytes[4];
                        if (pn_len == 1) {
                                new_pn_bytes[0] = *new_pn;
                        }
                        else if (pn_len == 2) {
                                new_pn_bytes[0] = (*new_pn & 0xff00) >> 8;
                                new_pn_bytes[1] = *new_pn & 0x00ff;
                        }
                        else if (pn_len == 3) {
                                new_pn_bytes[0] = (*new_pn & 0xff0000) >> 16;
                                new_pn_bytes[1] = (*new_pn & 0x00ff00) >> 8;
                                new_pn_bytes[2] = *new_pn & 0x0000ff;
                        }
                        else if (pn_len == 4) {
                                new_pn_bytes[0] = (*new_pn & 0xff000000) >> 24;
                                new_pn_bytes[1] = (*new_pn & 0x00ff0000) >> 16;
                                new_pn_bytes[2] = (*new_pn & 0x0000ff00) >> 8;
                                new_pn_bytes[3] = *new_pn & 0x000000ff;
                        }
                        bpf_skb_store_bytes(skb, pn_off, new_pn_bytes, pn_len, 0);
                        

                        // We create a key for the mapping of kernel- to user-packet-number.
                        struct client_pn_map_key_t pn_key = {
                                .key = key,
                                .packet_number = *new_pn,
                        };
                        bpf_map_update_elem(&connection_pn_translation, &pn_key, &old_pn, BPF_ANY);

                        // Increment the kernel packet number of the connection and update the
                        // internal counter.
                        *new_pn = *new_pn + 1;
                        bpf_map_update_elem(&connection_current_pn, &key, new_pn, BPF_ANY);

                        uint64_t time_ns = bpf_ktime_get_tai_ns();

                        store_pn_and_ts(pn_key.packet_number, time_ns, dst_ip_addr, dst_port);

                        // In case the frame contains an offset field we need to read it and hand it to the userspace
                        // for potential retransmissions. In case it is not present the offset is to be interpreted as 0. 
                        uint64_t data_offset = 0;

                        // Change stream id if unistream is used
                        uint8_t frame_type;
                        uint16_t frame_off = 1 /* Short header bits */ + CONN_ID_LEN + pn_len;
                        SAVE_BPF_PROBE_READ_KERNEL(&frame_type, sizeof(frame_type), payload + frame_off);

                        uint8_t is_retransmission = 0; // if packet is stream frame it might be a retransmission
                        if (IS_STREAM_FRAME(frame_type)) {
                                // Check if the stream is a unidirectional stream
                                // Unidirectional streams are identified by the second
                                // least significant bit of the stream id being set to 1.
                                uint8_t mask = 0x03;
                                uint32_t stream_id_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 
                                                        1 /* Header flags */ + CONN_ID_LEN + pn_len + 1 /* Frame type (0x08-0x0f) */;
                                uint32_t stream_id_off_from_quic = 1 /* Header byte */ + CONN_ID_LEN + pn_len + 1 /* Frame type (0x08-0x0f) */;
                                struct var_int stream_id = {0};
                                // TODO: userspace should make sure that the size of the stream id is always 8 byte to ensure that bpf counter always has space
                                read_var_int(payload + stream_id_off_from_quic, &stream_id, VALUE_NEEDED); 
                                uint8_t is_unidirectional_and_server_side = stream_id.value & mask;

                                // If the stream is unidirectional we need to update the stream id
                                if (is_unidirectional_and_server_side == mask) {
                                        update_stream_id(stream_id, skb, stream_id_off, &key, RELAY_ORIGIN);
                                }

                                // Check if the offset field is present and potentially read it.
                                uint8_t off_bit_set = frame_type & 0x04;
                                if (off_bit_set) {
                                        struct var_int stream_offset = {0};
                                        uint32_t stream_offset_off = stream_id_off + bounded_var_int_len(stream_id.len);
                                        read_var_int(payload + stream_offset_off, &stream_offset, VALUE_NEEDED);
                                        data_offset = stream_offset.value;
                                }

                                // Check if the packet is a retransmission
                                struct packet_identification_t packet_id = {
                                        .stream_id = stream_id.value,
                                        .packet_number = old_pn,
                                        .connection_id = {0},
                                        .padding = {0},
                                };
                                void *conn_id_off = payload + 1 /* Short header flags */;
                                SAVE_BPF_PROBE_READ_KERNEL(&packet_id.connection_id, sizeof(packet_id.connection_id), conn_id_off);
                                
                                uint8_t *pack_is_retr = bpf_map_lookup_elem(&packet_is_retransmission, &packet_id);
                                
                                if (pack_is_retr != NULL && *pack_is_retr == 1) {
                                        bpf_printk("Retransmission detected for packet (%u -> %u) at %lu\n", old_pn, pn_key.packet_number, time_ns);
                                        is_retransmission = 1;
                                }
                                
                        }

                        // The userspace needs to know the translation of the
                        // packet number so an easy way is to also register the packet.
                        // The registration is also needed for retransmissions since those 
                        // can get lost and require a retransmission of a retransmission.
                        // Since the userspace does not register the retransmissions itself 
                        // (since they are created manually in a hacky way) we need to register 
                        // here.
                        struct register_packet_t pack_to_reg = {
                                .packet_number = pn_key.packet_number,
                                .timestamp = time_ns,
                                .length = payload_size, // TODO: check if this is the same as the actual length field (if present) - maybe it's not needed bc only one frame per packet?
                                .offset = data_offset,
                                // .server_pn = -1, // -1 means that the packet is from userspace // TODO: how to handle?  
                                .server_pn = old_pn,
                                .flags = VALID_FLAG | USERSPACE_FLAG | (is_retransmission ? RETRANSMISSION_FLAG : 0),
                        };
                        store_packet_to_register(pack_to_reg);
                        bpf_printk("Old packet number: %d, New packet number: %d\n", old_pn, pn_key.packet_number);

                        return TC_ACT_OK;
                }

                // We retreive the index that has been stored in the connection id
                // at ingress. The index is the second byte of the connection id.
                uint32_t index;
                void *index_off = payload + 1 /* Short header flags */ + 1 /* Prio in conn id */;
                SAVE_BPF_PROBE_READ_KERNEL(&index, sizeof(index), index_off);

                // Now we get the client information for the index-th client.
                // This assumes that we can linearly access the clients in the map.
                struct client_info_t *value;

                // TODO: this might cause errors if we allow removal of clients
                // TODO: because then the clients are no longer linearly accessible.
                value = bpf_map_lookup_elem(&client_data, &index);
                // In case there is no index-th client, just drop the packet
                // as it is an unnecessary duplication.
                if (value == NULL) {
                        bpf_printk("No client data found for redirection index %d\n", index);
                        return TC_ACT_SHOT;
                }

                // Change the key to access the client information.               
                struct client_info_key_t key = {
                        .ip_addr = value->dst_ip_addr,
                        .port = value->dst_port,
                };

                // Drop if the connection is not yet fully established.
                uint8_t *established = bpf_map_lookup_elem(&connection_established, &key);
                if (established == NULL || *established == 0) {
                        bpf_printk("Connection not established\n");
                        return TC_ACT_SHOT;
                }

                // The first byte of the connection id is the priority of the packet.
                // We load the priority and in case priority-drop is set we drop / pass
                // the packet based on the priority.
                uint8_t client_prio_drop_limit = value->priority_drop_limit;
                uint8_t packet_prio; 
                SAVE_BPF_PROBE_READ_KERNEL(&packet_prio, sizeof(packet_prio), payload + 1 /* Short header flags */);

                if (PRIO_DROP && packet_prio < client_prio_drop_limit) { //  == 1) { //
                        bpf_printk("Packet priority lower than client priority threshold!\n");
                        return TC_ACT_SHOT;
                }


                // Generally we would want to find the stream frames in the QUIC payload
                // generically by using a function like the following, but this seems to
                // be too complex for the bpf verifier to handle.
                // For now it suffices to assume the first frame is a stream frame since
                // the underlying QUIC implementation will ensure this.

                // Set the payload to the start of the stream frame
                // since we only care about the stream frame
                /*
                void *stream_start;
                get_stream_frame_start(payload, payload_size, &stream_start);
                if (stream_start == NULL) {
                        bpf_printk("No stream frame found\n");
                        return TC_ACT_SHOT;
                }
                payload = stream_start;
                */
                
               // To be able to access the payload we need to know the length of the packet number.
               // Then we can read the frame type and determine if it is a stream frame or a datagram frame.
                uint8_t pn_len = (quic_flags & 0x03) + 1;
                uint8_t frame_type;
                uint16_t frame_off = 1 /* Short header bits */ + CONN_ID_LEN + pn_len;
                SAVE_BPF_PROBE_READ_KERNEL(&frame_type, sizeof(frame_type), payload + frame_off);

                // In case the frame is a stream frame we need to read the stream offset.
                // In case it is not present it is to be interpreted as 0.
                uint64_t data_offset = 0;

                
                if (IS_STREAM_FRAME(frame_type) && SINGLE_STREAM_USAGE) {

                        // In case we have a stream frame and the stream is used for multiple packets
                        // (i.e. not one stream per packet) we need to make some extra considerations 
                        // like handling the stream offset.
                        // TODO: distinction single vs. multiple stream usage needed?
                        bpf_printk("Single-stream-usage not supported yet\n");
                        return TC_ACT_SHOT;
                       
                } else if (IS_STREAM_FRAME(frame_type) && !SINGLE_STREAM_USAGE) {


                        // Change stream id if unistream is used
                        
                        // Check if the stream is a unidirectional stream
                        // Unidirectional streams are identified by the second
                        // least significant bit of the stream id being set to 1.
                        uint8_t mask = 0x03;
                        uint32_t stream_id_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 
                                                1 /* Header flags */ + CONN_ID_LEN + pn_len + 1 /* Frame type (0x08-0x0f) */;
                        uint32_t stream_id_off_from_quic = 1 /* Header byte */ + CONN_ID_LEN + pn_len + 1 /* Frame type (0x08-0x0f) */;
                        struct var_int stream_id = {0};
                        // TODO: userspace should make sure that the size of the stream id is always 8 byte to ensure that bpf counter always has space
                        read_var_int(payload + stream_id_off_from_quic, &stream_id, VALUE_NEEDED); 
                        uint8_t is_unidirectional_and_server_side = stream_id.value & mask;

                        // bpf_printk("stream id to be updated: %d\n", stream_id.value);

                        // If the stream is unidirectional we need to update the stream id
                        if (is_unidirectional_and_server_side == mask) {
                                update_stream_id(stream_id, skb, stream_id_off, &key, MEDIA_SERVER_ORIGIN);
                        }

                        // Check if the offset field is present and potentially read it.
                        uint8_t off_bit_set = frame_type & 0x04;
                        if (off_bit_set) {
                                struct var_int stream_offset = {0};
                                uint32_t stream_offset_off = stream_id_off_from_quic + bounded_var_int_len(stream_id.len);
                                read_var_int(payload + stream_offset_off, &stream_offset, VALUE_NEEDED);
                                data_offset = stream_offset.value;
                        }

                } else if (IS_DATAGRAM_FRAME(frame_type)) {

                        // TODO: anything to do for datagram frames?

                } else {
                        // For now we only pass on stream frames and datagram 
                        // frames. If other frames should be passed on as well
                        // just add another "else if" above with the 
                        // appropriate frame type check.
                        bpf_printk("Non-stream frame and non-datagram frame\n");
                        return TC_ACT_SHOT;
                }

                // We have read the client information and can now change the packet
                // such that it is correctly sent to the client.

                // For the mac addresses it is enough to use value->mac
                // instead of &value->mac mac is saved as an array.
                
                // Set src_mac to value->src_mac.
                uint32_t src_mac_off = 6 /* DST MAC */;
                bpf_skb_store_bytes(skb, src_mac_off, value->src_mac, MAC_LEN, 0);

                // Set dst_mac to value->dst_mac.
                uint32_t dst_mac_off = 0;
                bpf_skb_store_bytes(skb, dst_mac_off, value->dst_mac, MAC_LEN, 0);

                // TODO: turn ip addr setting to function: https://elixir.bootlin.com/linux/v4.9/source/samples/bpf/tcbpf1_kern.c#L51
                // Set src_ip to value->src_ip_addr.
                uint32_t src_ip_off = sizeof(struct ethhdr) + 12 /* Everything before SRC IP */;
                uint32_t old_src_ip;
                SAVE_BPF_PROBE_READ_KERNEL(&old_src_ip, sizeof(old_src_ip), &ip->saddr);
                bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_src_ip, value->src_ip_addr, sizeof(value->src_ip_addr));
                bpf_skb_store_bytes(skb, src_ip_off, &value->src_ip_addr, sizeof(value->src_ip_addr), 0);

                // TODO: turn ip addr setting to function: https://elixir.bootlin.com/linux/v4.9/source/samples/bpf/tcbpf1_kern.c#L51
                // Set dst_ip to value->dst_ip_addr.
                uint32_t dst_ip_off = sizeof(struct ethhdr) + 12 /* Everything before SRC IP */ +  4 /* SRC IP */;
                uint32_t old_dst_ip;
                SAVE_BPF_PROBE_READ_KERNEL(&old_dst_ip, sizeof(old_dst_ip), &ip->daddr);
                bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_dst_ip, value->dst_ip_addr, sizeof(value->dst_ip_addr));
                bpf_skb_store_bytes(skb, dst_ip_off, &value->dst_ip_addr, sizeof(value->dst_ip_addr), 0);

                // Set src_port to value->src_port.
                uint16_t src_port_tmp = value->src_port;
                uint32_t src_port_tmp_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
                bpf_skb_store_bytes(skb, src_port_tmp_off, &src_port_tmp, sizeof(src_port_tmp), 0);

                // Set dst_port to value->dst_port.
                uint16_t dst_port_tmp = value->dst_port;
                uint32_t dst_port_tmp_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + 2 /* SRC PORT */;
                bpf_skb_store_bytes(skb, dst_port_tmp_off, &dst_port_tmp, sizeof(dst_port_tmp), 0);

                // Set connection_id to value->connection_id.
                uint32_t conn_id_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 1 /* Short header flags */;
                bpf_skb_store_bytes(skb, conn_id_off, value->connection_id, CONN_ID_LEN, 0);
                        
                // TODO: We cannot just write the packet number into the packet
                // TODO: without knowing the length of the packet number?!

                // Read old packet number to store it in the translation map.
                uint32_t old_pn = read_packet_number(payload, pn_len, 1 /* Short header bits */ + CONN_ID_LEN);

                uint32_t *new_pn = bpf_map_lookup_elem(&connection_current_pn, &key); 
                uint32_t zero = 0;
                // If there is no packet number found it is the first request for that
                // connection so we create a new entry of zero in the map.
                if (new_pn == NULL) {
                        bpf_map_update_elem(&connection_current_pn, &key, &zero, BPF_ANY);
                        new_pn = &zero;
                }
                uint32_t pn_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 1 /* Short header flags */ + CONN_ID_LEN;
                uint16_t new_pn_net = htons(*new_pn);
                bpf_skb_store_bytes(skb, pn_off, &new_pn_net, sizeof(new_pn_net), 0);

                // Increment the packet number of the connection.
                *new_pn = *new_pn + 1;
                bpf_map_update_elem(&connection_current_pn, &key, new_pn, BPF_ANY);

                // Do not use bpf_ktime_get_ns() since that's only time since boot.
                // https://lore.kernel.org/netdev/CAEf4Bzb9KA=mzYo_x42ExRoZjm=dF6up1DxrUL_eqkDYs9+UUg@mail.gmail.com/T/
                // https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
                uint64_t time_ns = bpf_ktime_get_tai_ns();
                // bpf_printk("Current nanoseconds: %llu\n", time_ns);

                struct register_packet_t pack_to_reg = {
                        .packet_number = (uint64_t)(*new_pn - 1),
                        .timestamp = time_ns,
                        .length = payload_size,
                        .offset = data_offset,
                        .server_pn = old_pn,
                        .flags = VALID_FLAG,
                };
                store_packet_to_register(pack_to_reg);

                store_pn_and_ts(*new_pn - 1, time_ns, value->dst_ip_addr, value->dst_port);
        
        } else {

                // TODO: We cannot just write the packet number into the packet
                // TODO: without knowing the length of the packet number!

                // If we receive a long header packet and it is not from userspace
                // something went wrong since long header packets should not be
                // redirected from ingress. We can just drop the packet.
                if (!user_space) {
                        bpf_printk("Not a user space packet\n");
                        return TC_ACT_SHOT;
                }

                // Retry packets do not have a packet number
                // so we can just ignore them.
                if ((quic_flags & 0x30 >> 4) == 3) {
                        bpf_printk("Retry packet\n");
                        return TC_ACT_OK;
                }

                // Read dst ip and port.
                uint32_t dst_ip_addr;
                SAVE_BPF_PROBE_READ_KERNEL(&dst_ip_addr, sizeof(dst_ip_addr), &ip->daddr);
                uint16_t dst_port;
                SAVE_BPF_PROBE_READ_KERNEL(&dst_port, sizeof(dst_port), &udp->dest);

                // Now we have to update the packet number.
                struct client_info_key_t key = {
                        .ip_addr = dst_ip_addr,
                        .port = dst_port,
                };
                uint32_t *new_pn = bpf_map_lookup_elem(&connection_current_pn, &key); 
                uint32_t zero = 0;
                // If there is no packet number found it is the first request for that
                // connection so we create a new entry of zero in the map.
                if (new_pn == NULL) {
                        bpf_map_update_elem(&connection_current_pn, &key, &zero, BPF_ANY);
                        new_pn = &zero;
                }

                // We do not need to update the packet number in the long header
                // packets since they are only sent in the beginning and therefore
                // the packet number is staying the same. This is kind of hacky
                // and only works if the long headers are sent only in the beginning
                // without any short header packets in between.
                // For now this seems to be sufficient.

                // TODO: actually read the "real" old packet number (should be the same as new_pn).
                // Change the mapping for packet number translation
                struct client_pn_map_key_t pn_key = {
                        .key = key,
                        .packet_number = *new_pn,
                };
                bpf_map_update_elem(&connection_pn_translation, &pn_key, new_pn, BPF_ANY);

                *new_pn = *new_pn + 1;
                bpf_map_update_elem(&connection_current_pn, &key, new_pn, BPF_ANY);

                uint64_t time_ns = bpf_ktime_get_tai_ns();

                // Userspace packets do not need to be registered (in theory).
                // However somehow the userspace needs to know the translation of the
                // packet number so an easy way is to also register the packet.
                // TODO: other way to tell userspace the translation?
                struct register_packet_t pack_to_reg = {
                        .packet_number = pn_key.packet_number,
                        .timestamp = time_ns,
                        .length = payload_size,
                        .server_pn = -1, // -1 -> we don't care right now // TODO: what to do with long headers?
                        .flags = VALID_FLAG, // TODO: register_packet_t: long header can only be from userspace (verify)
                };
                // store_packet_to_register(pack_to_reg); // TODO: even needed for long headers?

                store_pn_and_ts(pn_key.packet_number, time_ns, dst_ip_addr, dst_port);

        }

        return TC_ACT_OK;
}
