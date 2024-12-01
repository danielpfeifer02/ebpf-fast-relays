#include "../main/tc_common.c"
#include "tc_crypto_common.c"

__section("crypto_ingress")
int tc_egress(struct __sk_buff *skb)
{
    // return TC_ACT_OK; // TODO: remove
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
        bpf_printk("Short header packet\n");
        // We need to check that the packet actually contains a supported frame.
        // We only need to look at the first frame since the underlying QUIC library is
        // expected to handle supported frames with separate packets.
        uint8_t pn_len = (quic_flags & 0x03) + 1;
        uint32_t old_pn = read_packet_number(payload, pn_len, 1 /* Short header bits */ + CONN_ID_LEN); 

        void *quic_payload_start = payload + 1 /* Short header bits */ + CONN_ID_LEN + pn_len; 
        void *quic_payload_end = data_end;
        uint32_t decryption_size = quic_payload_end - quic_payload_start - POLY1305_TAG_SIZE;
        bpf_printk("Decryption size: %d\n", decryption_size);

        // Decrypt the payload
        decrypt_packet_payload(skb, payload + 1 /* Short header bits */ + CONN_ID_LEN + pn_len, data_end, old_pn, decryption_size);              
        
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
            // return TC_ACT_OK;
        }

        bpf_printk("Frame type: %02x\n", frame_type);
        
        // TODO: for now just for debugging
        bpf_printk("Redirecting to crypto_egress");
        bpf_clone_redirect(skb, veth2_egress_ifindex, 0);

        if (0) { // TODO: remove
        // After a clone redirect all the pointers are invalid
        data_end = (void *)(long)skb->data_end;
        data = (void *)(long)skb->data;
        eth = (struct ethhdr *)data;
        ip = (struct iphdr *)(eth + 1);
        udp = (struct udphdr *)(ip + 1);
        payload = (void *)(udp + 1);

        // Undo decryption for now (debugging)
        decrypt_packet_payload(skb, payload + 1 /* Short header bits */ + CONN_ID_LEN + pn_len, data_end, old_pn, decryption_size); // xor again to undo decryption
        }
    
    } else {
        bpf_printk("Long header packet\n");
    }
    
    return TC_ACT_OK;
}