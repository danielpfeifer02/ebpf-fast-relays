#include "xdp_common.c"
#include "xdp_crypto_common.c"

__section("xdp_crypto")
int xdp_ingress(struct xdp_md *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Pass through packets that cannot hold eth/ip/icmp (or udp) headers.
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
            return XDP_PASS;
    }

    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // QUIC is UDP-only; ignore other protocols.
    if (ip->protocol != IPPROTO_UDP) {
            return XDP_PASS;
    }

    struct udphdr *udp = (struct udphdr *)(ip + 1);

    // Only handle traffic from the media server port.
    if (udp->source != SERVER_PORT) {
            return XDP_PASS;
    }

    void *payload = (void *)(udp + 1);

    // XDP has no skb_pull; assume the UDP payload is already in the linear data range.

    uint8_t quic_flags;
    SAVE_BPF_PROBE_READ_KERNEL(&quic_flags, sizeof(quic_flags), payload);
    uint8_t header_form = (quic_flags & 0x80) >> 7;

    // Short-header packets: fetch Poly1305 key and validate AEAD tag.
    if (header_form == 0) {
        bpf_printk("Short header packet\n");
        uint8_t pn_len = (quic_flags & 0x03) + 1;
        uint32_t old_pn = read_packet_number(payload, pn_len, 1 /* Short header bits */ + CONN_ID_LEN);

        void *quic_payload_start = payload + 1 /* Short header bits */ + CONN_ID_LEN + pn_len;
        void *quic_payload_end = data_end;
        uint32_t decryption_size = quic_payload_end - quic_payload_start - POLY1305_TAG_SIZE;
        bpf_printk("Decryption size: %d\n", decryption_size);

        struct decryption_bundle_t decryption_bundle = {
            .key = NULL, // filled below after bitstream lookup
            .payload = payload + 1 /* Short header bits */ + CONN_ID_LEN + pn_len,
            .additional_data = payload,
            .tag = payload + 1 /* Short header bits */ + CONN_ID_LEN + pn_len + decryption_size,
            .decyption_size = decryption_size,
            .additional_data_size = 1 /* Short header bits */ + CONN_ID_LEN + pn_len,
        };

        struct tls_chacha20_poly1305_bitstream_block_t poly_key;
        uint8_t block_index = 0;

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
