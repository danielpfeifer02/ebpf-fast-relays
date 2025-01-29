#include "xdp_common.c"
#include "xdp_crypto_common.c"

__section("xdp_crypto")
int xdp_egress(struct xdp_md *skb)
{
    // bpf_printk("Ingress\n");
    // Get data pointers from the buffer.
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // bpf_printk("Data length: %d\n", skb->len);
    // return XDP_PASS; // TODO: remove

    // If the packet is too small to contain the headers we expect
    // we can directly pass it through.
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
            return XDP_PASS;
    }

    // Load ethernet header.
    struct ethhdr *eth = (struct ethhdr *)data;

    // Load IP header.
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // If the packet is not a UDP packet we can pass it through
    // since QUIC is built on top of UDP.
    if (ip->protocol != IPPROTO_UDP) {
            return XDP_PASS;
    }

    // Load UDP header.
    struct udphdr *udp = (struct udphdr *)(ip + 1);

    // If the packet is not sent from the port where the server is
    // listening we can pass it through since the packet is from a 
    // different program.
    if (udp->source != SERVER_PORT) {
            return XDP_PASS;
    }

    // Load UDP payload as well as UDP payload size.
    void *payload = (void *)(udp + 1);
    uint32_t payload_size = ntohs(udp->len) - sizeof(*udp);

    // TODO: not needed for XDP?
    // // If the payload is not in the buffer we need to pull it in.
    // if ((void *)payload + payload_size > data_end) {
    //      // We need to use bpf_skb_pull_data() to get the rest of the packet.
    //     // If the pull fails we can pass the packet through.
    //     if(bpf_skb_pull_data(skb, (data_end-data)+payload_size) < 0) {
    //         bpf_printk("[ingress startup xdp] failed to pull data");
    //         return XDP_PASS;
    //     }
            
    //     // Once we have pulled the data we need to update the pointers.
    //     data_end = (void *)(long)skb->data_end;
    //     data = (void *)(long)skb->data;
    //     eth = (struct ethhdr *)data;
    //     ip = (struct iphdr *)(eth + 1);
    //     udp = (struct udphdr *)(ip + 1);
    //     payload = (void *)(udp + 1);
    // }

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
        struct decryption_bundle_t decryption_bundle = {
            .key = NULL, // Key will be added in the decryption function
            .payload = payload + 1 /* Short header bits */ + CONN_ID_LEN + pn_len,
            .additional_data = payload,
            .tag = payload + 1 /* Short header bits */ + CONN_ID_LEN + pn_len + decryption_size,
            .decyption_size = decryption_size,
            .additional_data_size = 1 /* Short header bits */ + CONN_ID_LEN + pn_len, 
        };
        
        // void *payload = decryption_bundle.payload;
        // void *additional_data = decryption_bundle.additional_data;
        // uint32_t decryption_size = decryption_bundle.decyption_size;
        // uint32_t additional_data_size = decryption_bundle.additional_data_size;
        
        void *data = (void *)(long)skb->data;

        // Check poly1305 tag
        struct tls_chacha20_poly1305_bitstream_block_t poly_key;
        uint8_t block_index = 0;

        // Get the poly1305 key
        uint32_t ret = retreive_tls_chacha20_poly1305_bitstream(old_pn, block_index, &poly_key);
        if (ret != 0) {
            bpf_printk("Error: Could not retrieve tls secrets for packet number %llu and block %d\n", old_pn, block_index);
            return 1;
        }

        decryption_bundle.key = poly_key.bitstream_bytes;
        uint8_t tag_valid = validate_tag(decryption_bundle);
        if (!tag_valid) {
            return XDP_DROP;
        }
        
    
    } else {
        bpf_printk("Long header packet\n");
    }
    
    return XDP_PASS;
}