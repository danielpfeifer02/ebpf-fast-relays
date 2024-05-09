#include "tc_common.c"

__section("egress")
int tc_egress(struct __sk_buff *skb)
{

        // Before redirecting we need to: 

        //      1) change src ethernet 
        //      2) change dst ethernet
        //      3) change src ip
        //      4) change dst ip
        //      5) change dst port (or set it in code)
        //      6) change connection id (setup maps for that)

        // TODO: also filter for direction so that connection establishment from client is not affected

        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
                bpf_printk("Not enough data\n");
                return TC_ACT_OK; // Not enough data
        }

        // Load ethernet header
        struct ethhdr *eth = (struct ethhdr *)data;

        // Load IP header
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        // Check if the packet is UDP
        if (ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_ICMP) {
                bpf_printk("Not UDP\n");
                return TC_ACT_OK;
        }

        // Load UDP header
        struct udphdr *udp = (struct udphdr *)(ip + 1);

        // Check if the packet is QUIC
        if (udp->source != RELAY_PORT) {
                bpf_printk("Not QUIC\n");
                return TC_ACT_OK;
        }

        uint8_t user_space = 0;

        // UDP checksum needs to be 0
        if (udp->check != 0) {
                bpf_printk("Checksum not 0 (%d)\n", udp->check);
                // return TC_ACT_OK;
                user_space = 1;
        }

        // check that the UDP dst port is the port marker
        if (udp->dest != PORT_MARKER) {
                bpf_printk("Not the correct port (%d)\n", udp->dest);
                // return TC_ACT_OK;
                user_space = 1;
        }

        // ! TODO: are there quic icmp packets? looks like it in wireshark
        if (ip->protocol == IPPROTO_ICMP) {
                bpf_printk("ICMP packet\n");
                user_space = 1;
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

        bpf_printk("Payload size notice: %d\n", payload_size);
        uint8_t limit = 23;
        uint8_t prio_notice = payload_size == limit; // TODO: how to find out the priority notice packets?
        if (prio_notice) {
                uint8_t tmp;
                bpf_probe_read_kernel(&tmp, sizeof(tmp), payload+limit-1);
                bpf_printk("Priority notice packet: %02x\n", tmp);
        }


        uint8_t quic_flags;
        long read_res = bpf_probe_read_kernel(&quic_flags, sizeof(quic_flags), payload);
        if (read_res < 0) {
                bpf_printk("ERROR: Could not read quic flags\n");
                return TC_ACT_OK;
        }
        uint8_t header_form = (quic_flags & 0x80) >> 7;

        // redirecting short header packets
        if (header_form == 0) {

                // When a short header packet arrives at the egress interface
                // which is sent from user space we update the packet number
                // ! TODO seems to have fixed the error after prio dropping
                if (user_space) {

                        // read dst ip and port
                        uint32_t dst_ip_addr;
                        bpf_probe_read_kernel(&dst_ip_addr, sizeof(dst_ip_addr), &ip->daddr);
                        uint16_t dst_port;
                        bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &udp->dest);

                        // now we have to update the packet number
                        struct client_info_key_t key = {
                                .ip_addr = dst_ip_addr,
                                .port = dst_port,
                        };

                        // // struct pn_value_t pn_value = {
                        // //         .packet_number = old_pn + 1,
                        // //         .changed = 0,
                        // // };
                        // // bpf_map_update_elem(&client_pn, &key, &pn_value, BPF_ANY);
                        
                        // Here we translate the packet number of the outgoing packet to 
                        // the packet number which will actually be sent out (the one in
                        // the bpf map)
                        uint32_t old_pn = 0;
                        uint8_t pn_len = (quic_flags & 0x03) + 1;
                        uint8_t byte;
                        uint32_t pn_off_from_quic = 1 /* Short header bits */ + CONN_ID_LEN;

                        // bpf_printk("zero: %02x\n", quic_flags); // ! TODO: sometimes 0x00????

                        // ^ TODO: turn into loop
                        if (pn_len >= 1) {
                                bpf_probe_read_kernel(&byte, sizeof(byte), payload + pn_off_from_quic);
                                old_pn = byte;
                                // bpf_printk("Old packet number (zero? 1): %08x %02x\n", old_pn, byte);
                        }
                        if (pn_len >= 2) {
                                old_pn = old_pn << 8;
                                bpf_probe_read_kernel(&byte, sizeof(byte), payload + pn_off_from_quic + 1);
                                old_pn = old_pn | byte;
                                // bpf_printk("Old packet number (zero? 2): %08x\n", old_pn);
                        }
                        if (pn_len >= 3) {
                                old_pn = old_pn << 8;
                                bpf_probe_read_kernel(&byte, sizeof(byte), payload + pn_off_from_quic + 2);
                                old_pn = old_pn | byte;
                                // bpf_printk("Old packet number (zero? 3): %08x\n", old_pn);
                        }
                        if (pn_len == 4) {
                                old_pn = old_pn << 8;
                                bpf_probe_read_kernel(&byte, sizeof(byte), payload + pn_off_from_quic + 3);
                                old_pn = old_pn | byte;
                                // bpf_printk("Old packet number (zero? 4): %08x\n", old_pn);
                        }
                        // ! TODO: why are there so many 0 pns???
                        if (old_pn == 0) {
                                bpf_printk("Packet number is zero (len %d)\n", pn_len);
                        }

                        // long res = bpf_probe_read_kernel(&old_pn, sizeof(old_pn), payload
                        //                                                 + 1 /* Short header bits */
                        //                                                 + CONN_ID_LEN /* Connection ID */);

                        // if (res != 0) {
                        //         bpf_printk("Could not read packet number\n");
                        //         return TC_ACT_OK;
                        // }

                        // old_pn = ntohs(old_pn);

                        // if (old_pn == 0) { // TODO: why does this happen?
                        //         uint16_t ipcheck;
                        //         bpf_probe_read_kernel(&ipcheck, sizeof(ipcheck), &ip->check);
                        //         bpf_printk("packet number is zero? ip check: %04x\n", ipcheck);
                        //         return TC_ACT_OK;
                        // }
                        // ^

                        // lookup the next packet number for a connection
                        uint32_t *new_pn = bpf_map_lookup_elem(&connection_current_pn, &key);
                        uint32_t zero = 0;
                        if (new_pn == NULL) {
                                bpf_map_update_elem(&connection_current_pn, &key, &zero, BPF_ANY);
                                new_pn = &zero;
                                bpf_printk("No packet number found. Setting to zero\n");
                        }
                        
                        // update the packet number in the packet
                        uint32_t pn_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 1 /* Short header flags */ + CONN_ID_LEN;
                        // uint16_t new_pn_net = htons(*new_pn); // TODO: correct htons?
                        // bpf_skb_store_bytes(skb, pn_off, &new_pn_net, sizeof(new_pn_net), 0); // heree
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
                        // ! TODO: why is the new pn SMALLER than the old one???? is it still?
                        bpf_skb_store_bytes(skb, pn_off, new_pn_bytes, pn_len, 0);
                        

                        // we also need to save the mapping for later
                        struct client_pn_map_key_t pn_key = {
                                .key = key,
                                .packet_number = *new_pn,
                        };
                        // bpf_printk("Old packet number: %08x\n", old_pn);
                        bpf_map_update_elem(&connection_pn_translation, &pn_key, &old_pn, BPF_ANY);

                        // bpf_printk("Short header (user space) pn mapping change: %d -> %d\n", old_pn, *new_pn);

                        // increment the packet number of the connection
                        *new_pn = *new_pn + 1;
                        bpf_map_update_elem(&connection_current_pn, &key, new_pn, BPF_ANY);

                        // bpf_printk("Let packet through from user space\n");
                        return TC_ACT_OK;
                }



                // ! JUST FOR TESTING
                // uint32_t tmepory = 0;
                // uint32_t *other_tempory = bpf_map_lookup_elem(&packet_counter, &tmepory);
                // if (other_tempory == NULL || *other_tempory != 1) {
                //         bpf_printk("Packet counter drop\n");
                //         return TC_ACT_SHOT;
                // }
                if (TURNOFF) {
                        bpf_printk("Dropping because of turn off\n");
                        return TC_ACT_OK;
                }


                // bpf_printk("Received redirected short header!\n");

                // // get packet_counter
                // uint32_t zero = 0;
                // uint32_t *pack_ctr = bpf_map_lookup_elem(&packet_counter, &zero);

                // if (pack_ctr == NULL) {
                //         bpf_printk("No packet counter found\n");
                //         return TC_ACT_OK;
                // }

                uint32_t pack_ctr;
                void *index_off = payload + 1 /* Short header flags */ + 1 /* Prio in conn id */;
                bpf_probe_read_kernel(&pack_ctr, sizeof(pack_ctr), index_off);
                // bpf_printk("Packet counter: %d\n", pack_ctr);

                // get pack_ctr-th client data
                struct client_info_t *value;

                // TODO this assumes that they are linear in the map (verify)
                // TODO remove dependency on packet_counter
                // TODO  is it made sure that the client ids are always sequential?
                value = bpf_map_lookup_elem(&client_data, &pack_ctr);
                if (value == NULL) {
                        bpf_printk("No client data found for packet ctr %d\n", pack_ctr);
                        return TC_ACT_SHOT;
                }


                // if the connection with this client is not yet established
                // drop the packet
                // load connection_established map                
                struct client_info_key_t key = {
                        .ip_addr = value->dst_ip_addr,
                        .port = value->dst_port,
                };

                // ! TODO: fix within go code
                // uint8_t *conn_est = bpf_map_lookup_elem(&connection_established, &key);
                // if (conn_est == NULL) {
                //         bpf_printk("No connection established found for %d %d\n", key.ip_addr, key.port);
                //         return TC_ACT_SHOT;
                // }
                // if (*conn_est == 0) {
                //         bpf_printk("Connection not established\n");
                //         return TC_ACT_SHOT;
                // }


                uint8_t client_prio_drop_limit = value->priority_drop_limit;
                uint8_t packet_prio; 
                bpf_probe_read_kernel(&packet_prio, sizeof(packet_prio), payload + 1 /* Short header flags */);

                // bpf_printk("Threshold: %02x - Packet prio: %02x\n", client_prio_drop_limit, packet_prio);

                // drop the packet if the prio is lower than the client prio drop limit
                // TODO: turn back on once prio is set correctly again for streams
                // if (packet_prio < 2) {//client_prio_drop_limit) {
                //         bpf_printk("Packet prio lower than client prio Threshold\n");
                //         return TC_ACT_SHOT;
                // }

                // ! Generally this would be the way to go but that seems to be too
                // ! complex for the bpf verifier.
                // ! For now this should work since the quic-go-prio-packs impl ensures
                // ! that stream frames are always send in a separate packet
                // void *stream_start;
                // get_stream_frame_start(payload, payload_size, &stream_start);
                // if (stream_start == NULL) {
                //         bpf_printk("No stream frame found\n");
                //         return TC_ACT_SHOT;
                // }
                // // set the payload to the start of the stream frame
                // // since we only care about the stream frame
                // payload = stream_start;

                // if the frame is a stream frame we need to update the stream offset
                /*
                STREAM Frame {
                  Type (i) = 0x08..0x0f,
                  Stream ID (i),
                  [Offset (i)],
                  [Length (i)],
                  Stream Data (..),
                }                        
                */
                uint8_t pn_len = (quic_flags & 0x03) + 1;
                uint8_t frame_type;
                uint16_t frame_off = 1 /* Short header bits */ + CONN_ID_LEN + pn_len;
                bpf_probe_read_kernel(&frame_type, sizeof(frame_type), payload + frame_off);

                // TODO: separation between single and multiple stream usage needed?
                // TODONEXT: why FLOW_CONTROL_ERROR?
                if (IS_STREAM_FRAME(frame_type) && SINGLE_STREAM_USAGE) {
                        // TODO: update stream offset
                        // TODO: for this add a map which stores the stream offset for each stream! 
                        // TODO: how to identify the stream? -> stream id in the packet

                        uint8_t off_bit_set = frame_type & 0x04;
                        uint8_t len_bit_set = frame_type & 0x02;
                        // uint8_t fin_bit_set = frame_type & 0x01;

                        uint8_t byte;

                        uint32_t stream_id_off = frame_off + 1 /* Frame type */;
                        struct var_int stream_id = {0};
                        // read_var_int(payload + stream_id_off, &stream_id_off, VALUE_NEEDED); // TODO: fix
                        bpf_probe_read_kernel(&byte, sizeof(byte), payload + stream_id_off);
                        stream_id.len = 1 << (byte >> 6);
                        stream_id.value = byte & 0x3f; 
                        for (int i=1; i<8; i++) {
                                if (i >= stream_id.len) {
                                        break;
                                }
                                stream_id.value = stream_id.value << 8;
                                bpf_probe_read_kernel(&byte, sizeof(byte), payload + stream_id_off + i);
                                stream_id.value = stream_id.value | byte;
                        }

                        if (off_bit_set) {

                                uint32_t stream_offset_off = stream_id_off + bounded_var_int_len(stream_id.len);
                                struct var_int stream_offset = {0};
                                // read_var_int(payload + stream_offset_off, &stream_offset, VALUE_NEEDED); // TODO: fix
                                bpf_probe_read_kernel(&byte, sizeof(byte), payload + stream_offset_off);
                                stream_offset.len = 1 << (byte >> 6);
                                stream_offset.value = byte & 0x3f; 
                                for (int i=1; i<8; i++) {
                                        if (i >= stream_offset.len) {
                                                break;
                                        }
                                        stream_offset.value = stream_offset.value << 8;
                                        bpf_probe_read_kernel(&byte, sizeof(byte), payload + stream_offset_off + i);
                                        stream_offset.value = stream_offset.value | byte;
                                }

                                struct client_stream_offset_key_t stream_key = {
                                        .key = key,
                                        .stream_id = stream_id.value,
                                };
                                
                                uint64_t data_length = 0;
                                if (len_bit_set) {

                                        struct var_int stream_len = {0};
                                        uint32_t stream_len_off = stream_offset_off + bounded_var_int_len(stream_offset.len);
                                        // read_var_int(payload + stream_len_off, &stream_len, VALUE_NEEDED); // TODO: fix
                                        bpf_probe_read_kernel(&byte, sizeof(byte), payload + stream_len_off);
                                        stream_len.len = 1 << (byte >> 6);
                                        stream_len.value = byte & 0x3f;
                                        for (int i=1; i<8; i++) {
                                                if (i >= stream_len.len) {
                                                        break;
                                                }
                                                stream_len.value = stream_len.value << 8;
                                                bpf_probe_read_kernel(&byte, sizeof(byte), payload + stream_len_off + i);
                                                stream_len.value = stream_len.value | byte;
                                        }
                                        data_length = stream_len.value;
                                        stream_offset_off += bounded_var_int_len(stream_len.len);

                                } else {
                                        data_length = payload_size - 1 /* 1-RTT Header Flags */
                                                                - CONN_ID_LEN
                                                                - pn_len
                                                                - 1 /* Frame Type */
                                                                - bounded_var_int_len(stream_id.len)
                                                                - bounded_var_int_len(stream_offset.len);
                                }

                                // bpf_printk("Stream data length: %d\n", data_length);

                                struct var_int *old_stream_offset = bpf_map_lookup_elem(&client_stream_offset, &stream_key);
                                struct var_int zero = {
                                        .value = 0,
                                        .len = 1,
                                };
                                if (old_stream_offset == NULL) {
                                        bpf_printk("[stream handling] No stream offset found\n"); // TODO should not happen?
                                        old_stream_offset = &zero;
                                }

                                uint64_t new_value = old_stream_offset->value + data_length;
                                uint8_t new_len_enc = determine_minimal_length_encoded(new_value);
                                if (new_len_enc > 0b11) {
                                        bpf_printk("[stream handling] Stream offset too large\n");
                                        return TC_ACT_OK;
                                }

                                // bpf_printk("[stream handling] New Stream Offset will be %08x\n", new_value);

                                struct var_int new_stream_offset = {
                                        .value = new_value,
                                        .len = 1 << (new_len_enc),
                                };

                                if (new_stream_offset.len > stream_offset.len) {
                                        bpf_printk("[stream handling] Stream offset length of the packet is too short\n");
                                        return TC_ACT_OK;
                                }

                                bpf_map_update_elem(&client_stream_offset, &stream_key, &new_stream_offset, BPF_ANY);

                                // bpf_printk("Stream off len: %d\n", new_stream_offset.len);
                                // TODO: write into packet
                                uint8_t new_stream_offset_bytes[8] = {0};

                                // add length encoding to the first byte
                                uint8_t len_enc;
                                if (stream_offset.len == 1) {
                                        len_enc = 0b00;
                                } else if (stream_offset.len == 2) {
                                        len_enc = 0b01;
                                } else if (stream_offset.len == 4) {
                                        len_enc = 0b10;
                                } else if (stream_offset.len == 8) {
                                        len_enc = 0b11;
                                } else {
                                        bpf_printk("[stream handling] Stream offset length of the packet is not valid\n");
                                        return TC_ACT_OK;
                                }

                                uint8_t bounded_len = bounded_var_int_len(stream_offset.len);
                                new_stream_offset_bytes[0] = 
                                        (len_enc << 6) | ((new_stream_offset.value >> (8 * (bounded_len - 1))) & 0x3f);
                                
                                uint8_t cur;
                                uint64_t tmp = new_stream_offset.value;
                                uint8_t ctr = 1;
                                for (int i=1; i<8; i++, ctr++) {
                                        if (i >= bounded_len) {
                                                break;
                                        }
                                        cur = tmp & 0xff;
                                        new_stream_offset_bytes[i] |= cur;
                                        tmp = tmp >> 8; 

                                }

                                // TODO: why is stream_offset.len not working but ctr is?
                                // until now the offset off was relative to the quic payload start
                                // add all the previous headers to the offset
                                stream_offset_off += sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                                bpf_skb_store_bytes(skb, stream_offset_off, new_stream_offset_bytes, ctr, 0);

                                // bpf_printk("[stream handling] Stream offset updated to %08x\n", new_stream_offset.value);


                        } 
                        // TODO: handle len bit not only inside off bit handling
                        else { // if no off bit is set then it's the first frame of the stream

                                // set an entry in client_stream_offset
                                struct client_stream_offset_key_t stream_key = {
                                        .key = key,
                                        .stream_id = stream_id.value,
                                };

                                struct var_int *check_empty = bpf_map_lookup_elem(&client_stream_offset, &stream_key);
                                if (check_empty != NULL) {
                                        bpf_printk("[stream handling] Stream offset already set but shouldn't be?\n");
                                        return TC_ACT_OK;
                                } 

                                struct var_int zero = {
                                        .value = 0,
                                        .len = 1,
                                };
                                bpf_map_update_elem(&client_stream_offset, &stream_key, &zero, BPF_ANY);

                                bpf_printk("[stream handling] Stream offset set to 0\n");

                        }

                        if (!prio_notice && MOQ_PAYLOAD) {

                                uint32_t stream_pl_off = frame_off;
                                
                                uint8_t stream_id_len = bounded_var_int_len(stream_id.len);
                                stream_pl_off += 1 << stream_id_len;

                                if (off_bit_set) {
                                        bpf_probe_read_kernel(&byte, sizeof(byte), payload + stream_pl_off);
                                        uint8_t stream_offset_len = 1 << (byte >> 6);
                                        stream_pl_off += bounded_var_int_len(stream_offset_len);
                                }
                                if (len_bit_set) {
                                        bpf_probe_read_kernel(&byte, sizeof(byte), payload + stream_pl_off);
                                        uint8_t stream_len_len = 1 << (byte >> 6);
                                        stream_pl_off += bounded_var_int_len(stream_len_len);
                                }

                                void *stream_pl = payload + stream_pl_off;


                                // ! TODO: is the payload of the moq stuff packet contained?
                                // !       based on wireshark it looks like one moq packet is 
                                // !       split into multiple packets
                                uint8_t mt;
                                bpf_probe_read_kernel(&mt, sizeof(mt), stream_pl);
                                stream_pl += 1;

                                if (mt != 0x00) {
                                        // invalid message type likely means
                                        // we're inside of a payload that
                                        // has been split into multiple packets
                                        // bpf_printk("Invalid message type (%02x)\n", mt);
                                        return TC_ACT_OK;
                                }

                                struct var_int stream_data_len = {0};
                                read_var_int(stream_pl, &stream_data_len, 1);
                                stream_pl += bounded_var_int_len(stream_data_len.len);

                                // bpf_printk("Stream data length: %d\n", stream_data_len.value);

                                // // ! TODO: start at a valid packet for client
                                // // ! NOT WORKING client still gets unknown type error?
                                // // load packet counter
                                // uint32_t zero = 0;
                                // uint32_t *pack_ctr = bpf_map_lookup_elem(&packet_counter, &zero);
                                // if (stream_data_len.value > 10 && stream_data_len.value < 100) {
                                //         if (pack_ctr == NULL || *pack_ctr != 1) {
                                //                 uint32_t one = 1;
                                //                 bpf_map_update_elem(&packet_counter, &zero, &one, BPF_ANY);
                                //         }
                                // }
                                // if (pack_ctr == NULL || *pack_ctr != 1) {
                                //         return TC_ACT_SHOT;
                                // }

                                
                                uint8_t id;
                                bpf_probe_read_kernel(&id, sizeof(id), stream_pl);

                                if (id != 0x00) {
                                        // invalid track id
                                        bpf_printk("Invalid track id\n");
                                        return TC_ACT_SHOT;
                                }

                                stream_pl += 1;

                                bpf_probe_read_kernel(&byte, sizeof(byte), stream_pl);
                                // bpf_printk("Stream data: %02x\n", byte);

                                // leave data length alone but
                                // adapt:
                                // group sequence ?
                                // object sequence ?
                                // object send order ?

                                struct var_int group_seq = {0};
                                read_var_int(stream_pl, &group_seq, 1);
                                stream_pl += bounded_var_int_len(group_seq.len);

                                struct var_int obj_seq = {0};
                                read_var_int(stream_pl, &obj_seq, 1);
                                stream_pl += bounded_var_int_len(obj_seq.len);

                                struct var_int obj_send_order = {0};
                                read_var_int(stream_pl, &obj_send_order, 1);
                                stream_pl += bounded_var_int_len(obj_send_order.len);


                                // bpf_printk("Stream data length: %d, gs: %08x, os: %08x, oso: %08x\n", 
                                // stream_data_len.value,
                                // group_seq.value,
                                // obj_seq.value,
                                // obj_send_order.value);

                                if (VP8_VIDEO_PAYLOAD) {

                                        // VP8 payload
                                        // first look at the payload descriptor
                                        // see: https://datatracker.ietf.org/doc/html/rfc7741#section-4.2
                                        uint8_t vp8_pd;
                                        bpf_probe_read_kernel(&vp8_pd, sizeof(vp8_pd), stream_pl);
                                        stream_pl += 1;

                                        uint8_t vp8_xb, vp8_nb, vp8_sb, vp8_pid;
                                        vp8_xb = (vp8_pd >> 7) & 0x01;
                                        vp8_nb = (vp8_pd >> 6) & 0x01;
                                        vp8_sb = (vp8_pd >> 4) & 0x01;
                                        vp8_pid = vp8_pd & 0x07;

                                        // The payload is the beginning of a new frame
                                        // iff the S bit is set and PID is 0
                                        // TODO: what to do with frames that are not the 
                                        // TODO: beginning of a new frame but should still 
                                        // TODO: be dropped?

                                        // TODO: always 0x00??? seems to be parsed wrongly
                                        // bpf_printk("[VP8] sb: %d, pid: %d\n", vp8_sb, vp8_pid);
                                        bpf_printk("VP8 payload descriptor: %02x\n", vp8_pd);

                                        if (vp8_sb && vp8_pid == 0) {
                                                bpf_printk("Beginning of a new VP8 frame\n");

                                                uint8_t num_optional_bytes = 0;
                                                if (vp8_xb) {
                                                        uint8_t vp8_options;
                                                        bpf_probe_read_kernel(&vp8_options, sizeof(vp8_options), stream_pl);
                                                        stream_pl += 1;
                                                        
                                                        uint8_t vp8_ib, vp8_lb, vp8_tb, vp8_kb;
                                                        vp8_ib = (vp8_options >> 7) & 0x01;
                                                        vp8_lb = (vp8_options >> 6) & 0x01;
                                                        vp8_tb = (vp8_options >> 5) & 0x01;
                                                        vp8_kb = (vp8_options >> 4) & 0x01;

                                                        num_optional_bytes += vp8_ib;
                                                        num_optional_bytes += vp8_lb;
                                                        num_optional_bytes += (vp8_tb || vp8_kb);

                                                        if (vp8_ib) { // case of dual-octet version
                                                                uint8_t vp8_ib_bytes;
                                                                bpf_probe_read_kernel(&vp8_ib_bytes, sizeof(vp8_ib_bytes), stream_pl);
                                                                uint8_t vp8_ib_mb;
                                                                vp8_ib_mb = (vp8_ib_bytes >> 7) & 0x01;
                                                                if (vp8_ib_mb) {
                                                                        num_optional_bytes += 1;
                                                                }
                                                        }
                                                }

                                                stream_pl += num_optional_bytes;

                                                // now we have the payload descriptor and the optional bytes
                                                // next is the payload header

                                                //  0 1 2 3 4 5 6 7
                                                // +-+-+-+-+-+-+-+-+
                                                // |Size0|H| VER |P|
                                                // +-+-+-+-+-+-+-+-+
                                                // |     ...       |
                                                // +-+-+-+-+-+-+-+-+

                                                uint8_t video_ft;
                                                bpf_probe_read_kernel(&video_ft, sizeof(video_ft), stream_pl);
                                                bpf_printk("Video frame type: %02x\n", video_ft);
                                                video_ft = video_ft & 0x01;

                                                if (video_ft == 0) {
                                                        bpf_printk("Intra-/Key-/I-frame\n");
                                                } else {
                                                        bpf_printk("Inter-/Predicition-/P-frame\n");
                                                }
                                        }

                                }
                        
                        }

                } else if (IS_STREAM_FRAME(frame_type) && !SINGLE_STREAM_USAGE) {
                        // TODO: anything to do for stream frames with individual
                        // TODO: stream per packet?
                        bpf_printk("Stream frame in individual packet (%d)\n", prio_notice);
                } else if (IS_DATAGRAM_FRAME(frame_type)) {
                        // TODO: anything to do for datagram frames?
                } else {
                        // For now we only pass on stream frames
                        // if other frames should be passed on as well
                        // just add another "else if" above with the 
                        // appropriate frame type check
                        bpf_printk("Non-stream frame and non-datagram frame\n");
                        return TC_ACT_SHOT;
                }


                // set src_mac to value->src_mac
                uint32_t src_mac_off = 6 /* DST MAC */;
                bpf_skb_store_bytes(skb, src_mac_off, value->src_mac, MAC_LEN, 0); // TODO &value->src_mac?

                // set dst_mac to value->dst_mac
                uint32_t dst_mac_off = 0;
                bpf_skb_store_bytes(skb, dst_mac_off, value->dst_mac, MAC_LEN, 0);

                // ^ TODO turn ip addr setting to function: https://elixir.bootlin.com/linux/v4.9/source/samples/bpf/tcbpf1_kern.c#L51
                // set src_ip to value->src_ip_addr
                uint32_t src_ip_off = sizeof(struct ethhdr) + 12 /* Everything before SRC IP */;
                uint32_t old_src_ip;
                bpf_probe_read_kernel(&old_src_ip, sizeof(old_src_ip), &ip->saddr);
                bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_src_ip, value->src_ip_addr, sizeof(value->src_ip_addr));
                bpf_skb_store_bytes(skb, src_ip_off, &value->src_ip_addr, sizeof(value->src_ip_addr), 0);

                // set dst_ip to value->dst_ip_addr
                uint32_t dst_ip_off = sizeof(struct ethhdr) + 12 /* Everything before SRC IP */ +  4 /* SRC IP */;
                uint32_t old_dst_ip;
                bpf_probe_read_kernel(&old_dst_ip, sizeof(old_dst_ip), &ip->daddr);
                bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_dst_ip, value->dst_ip_addr, sizeof(value->dst_ip_addr));
                bpf_skb_store_bytes(skb, dst_ip_off, &value->dst_ip_addr, sizeof(value->dst_ip_addr), 0);
                // ^

                // set src_port to value->src_port
                uint16_t src_port_tmp = value->src_port;
                uint32_t src_port_tmp_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
                bpf_skb_store_bytes(skb, src_port_tmp_off, &src_port_tmp, sizeof(src_port_tmp), 0);

                // set dst_port to value->dst_port
                uint16_t dst_port_tmp = value->dst_port;
                uint32_t dst_port_tmp_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + 2 /* SRC PORT */;
                bpf_skb_store_bytes(skb, dst_port_tmp_off, &dst_port_tmp, sizeof(dst_port_tmp), 0);

                // set connection_id to value->connection_id
                uint32_t conn_id_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 1 /* Short header flags */;
                bpf_skb_store_bytes(skb, conn_id_off, value->connection_id, CONN_ID_LEN, 0);

                // TODO get rid of packet_counter and store lut index in packet (possible bc of clone_redirect?)
                // set pack_ctr to pack_ctr + 1 and write it back
                // *pack_ctr = *pack_ctr + 1;
                // bpf_map_update_elem(&packet_counter, &zero, pack_ctr, BPF_ANY);


                // // setting the packet number so that user space can update it
                // struct client_info_key_t key = {
                //         .ip_addr = value->dst_ip_addr,
                //         .port = value->dst_port,
                // };
                // struct pn_value_t *old_pn = bpf_map_lookup_elem(&client_pn, &key);
                // if (old_pn == NULL) {
                //         bpf_printk("No packet number found\n");
                //         return TC_ACT_OK;
                // }
                // struct pn_value_t pn_value = {
                //         .packet_number = old_pn->packet_number + 1, // // TODO: this should not be +100
                //         .changed = 1,
                // };
                // bpf_map_update_elem(&client_pn, &key, &pn_value, BPF_ANY);

                // // // TODO: i thought this might fix the problem of not receiving at client but apparently it does not
                // // // set packet number in packet to old_pn->packet_number + 50
                // uint32_t pn_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 1 /* Short header flags */ + CONN_ID_LEN;
                // uint16_t new_pn = htons(old_pn->packet_number); // // TODO: this should not be +50
                // bpf_skb_store_bytes(skb, pn_off, &new_pn, sizeof(new_pn), 0);


                        
                // ! TODO: cannot just write the packet number into the packet
                // ! without knowing the length of the packet number???

                uint32_t *new_pn = bpf_map_lookup_elem(&connection_current_pn, &key); 
                uint32_t zero = 0;
                if (new_pn == NULL) {
                        bpf_map_update_elem(&connection_current_pn, &key, &zero, BPF_ANY);
                        new_pn = &zero;
                        bpf_printk("No packet number found. Setting to zero\n");
                }
                uint32_t pn_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 1 /* Short header flags */ + CONN_ID_LEN;
                uint16_t new_pn_net = htons(*new_pn); // TODO: correct htons?
                bpf_skb_store_bytes(skb, pn_off, &new_pn_net, sizeof(new_pn_net), 0); // heree

                // bpf_printk("Packet number: %d\n", *new_pn);

                // increment the packet number of the connection
                *new_pn = *new_pn + 1;
                bpf_map_update_elem(&connection_current_pn, &key, new_pn, BPF_ANY);

                // bpf_printk("Done editing packet\n");
        
        } else {
                // ! TODO: update packet number for long header packets

                // ! TODO: cannot just write the packet number into the packet
                // ! without knowing the length of the packet number???

                // ! UPDATE THE PN MAPPING FOR USER SPACE RETRANSLATION

                if (!user_space) { // TODO: actually needed?
                        bpf_printk("Not a user space packet\n");
                        return TC_ACT_SHOT;
                }

                // retry packets do not have a packet number
                if ((quic_flags & 0x30 >> 4) == 3) {
                        bpf_printk("Retry packet\n");
                        return TC_ACT_OK;
                }

                // Long headers will only be sent from userspace
                // bpf_printk("Long header\n");

                // TODO: is that sufficient?
                // increment the packet number of the connection
                // read dst ip and port
                uint32_t dst_ip_addr;
                bpf_probe_read_kernel(&dst_ip_addr, sizeof(dst_ip_addr), &ip->daddr);
                uint16_t dst_port;
                bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &udp->dest);

                // now we have to update the packet number
                struct client_info_key_t key = {
                        .ip_addr = dst_ip_addr,
                        .port = dst_port,
                };
                uint32_t *new_pn = bpf_map_lookup_elem(&connection_current_pn, &key); 
                uint32_t zero = 0;
                if (new_pn == NULL) {
                        bpf_map_update_elem(&connection_current_pn, &key, &zero, BPF_ANY);
                        new_pn = &zero;
                        bpf_printk("No packet number found. Setting to zero\n");
                }

                // We do not need to update the packet number in the long header
                // packets since they are only sent in the beginning and therefore
                // the packet number is staying the same

                // Change the mapping for packet number translation
                struct client_pn_map_key_t pn_key = {
                        .key = key,
                        .packet_number = *new_pn,
                };
                bpf_map_update_elem(&connection_pn_translation, &pn_key, new_pn, BPF_ANY);


                // bpf_printk("Long header pn mapping change: %d -> %d\n", *new_pn, *new_pn);

                *new_pn = *new_pn + 1;
                bpf_map_update_elem(&connection_current_pn, &key, new_pn, BPF_ANY);

        }

        return TC_ACT_OK;
}
