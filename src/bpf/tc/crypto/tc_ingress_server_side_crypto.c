#include "../main/tc_common.c"
#include "tc_crypto_common.c"

__section("crypto_ingress")
int tc_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Pass through packets that cannot hold eth/ip/icmp (or udp) headers.
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
            return TC_ACT_OK;
    }

    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // QUIC is UDP-only; ignore other protocols.
    if (ip->protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
    }

    struct udphdr *udp = (struct udphdr *)(ip + 1);

    // Only handle traffic from the media server port.
    if (udp->source != SERVER_PORT) {
            return TC_ACT_OK;
    }

    void *payload = (void *)(udp + 1);
    uint32_t payload_size = ntohs(udp->len) - sizeof(*udp);

    // Pull remaining UDP payload into the linear skb if needed.
    if ((void *)payload + payload_size > data_end) {
        if (bpf_skb_pull_data(skb, (data_end - data) + payload_size) < 0) {
            bpf_printk("[ingress startup tc] failed to pull data");
            return TC_ACT_OK;
        }

        data_end = (void *)(long)skb->data_end;
        data = (void *)(long)skb->data;
        eth = (struct ethhdr *)data;
        ip = (struct iphdr *)(eth + 1);
        udp = (struct udphdr *)(ip + 1);
        payload = (void *)(udp + 1);
    }

    uint8_t quic_flags;
    SAVE_BPF_PROBE_READ_KERNEL(&quic_flags, sizeof(quic_flags), payload);
    uint8_t header_form = (quic_flags & 0x80) >> 7;

    // Short-header packets: decrypt, check frame type, clone-redirect to egress.
    if (header_form == 0) {
        bpf_printk("Short header packet\n");
        // Expect supported frames in their own packets (library contract).
        uint8_t pn_len = (quic_flags & 0x03) + 1;
        uint32_t old_pn = read_packet_number(payload, pn_len, 1 /* Short header bits */ + CONN_ID_LEN);

        void *quic_payload_start = payload + 1 /* Short header bits */ + CONN_ID_LEN + pn_len;
        void *quic_payload_end = data_end;
        uint32_t decryption_size = quic_payload_end - quic_payload_start - POLY1305_TAG_SIZE;
        bpf_printk("Decryption size: %d\n", decryption_size);

        struct decryption_bundle_t decryption_bundle = {
            .key = NULL, // filled in decrypt_packet_payload
            .payload = payload + 1 /* Short header bits */ + CONN_ID_LEN + pn_len,
            .additional_data = payload,
            .tag = payload + 1 /* Short header bits */ + CONN_ID_LEN + pn_len + decryption_size,
            .decyption_size = decryption_size,
            .additional_data_size = 1 /* Short header bits */ + CONN_ID_LEN + pn_len,
        };
        uint32_t ret = decrypt_packet_payload(skb, decryption_bundle, data_end, old_pn);
        if (ret == INVALID_TAG) {
            bpf_printk("Invalid tag\n");
            return TC_ACT_OK;
        }

        uint8_t frame_type;
        // Frame starts after short-header bits, conn id, and packet number.
        uint16_t frame_off = 1 /* Short header bits */ + CONN_ID_LEN + pn_len;
        SAVE_BPF_PROBE_READ_KERNEL(&frame_type, sizeof(frame_type), payload + frame_off);

        if (!SUPPORTED_FRAME(frame_type)) {
            bpf_printk("Not a stream or datagram frame (%02x)\n", frame_type);
        } else {
            bpf_printk("Valid frame type: %02x\n", frame_type);
        }

        bpf_printk("Frame type: %02x\n", frame_type);

        // TODO: debugging redirect into crypto egress
        bpf_printk("Redirecting to crypto_egress");
        bpf_clone_redirect(skb, veth2_egress_ifindex, 0);

    } else {
        bpf_printk("Long header packet\n");
    }

    return TC_ACT_OK;
}
