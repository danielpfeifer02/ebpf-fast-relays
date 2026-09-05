// Crypto maps and helpers kept separate from tc_common.c during PoC development.
// Merge into tc_common.c once the crypto path is stable.

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include "tc_crypto_defines.c"
#include "tc_crypto_structs.c"
#include "tc_poly1305_mac.c"

// TLS ChaCha20-Poly1305 bitstream blocks handed down from userspace (server-relay path).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tls_chacha20_poly1305_bitstream_map_key_t);
    __type(value, struct tls_chacha20_poly1305_bitstream_block_t);
    __uint(max_entries, BITSTREAM_BLOCK_MAP_SIZE * MAX_BLOCKS_PER_PACKET);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tls_chacha20_poly1305_bitstream_server SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} last_decrypted_pn SEC(".maps");

// Poly1305 tag generation needs more than the 512-byte eBPF stack allows.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct poly1305buffer_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} poly1305_tag_gen_buffer SEC(".maps");

// Userspace sets this to request in-kernel payload decryption.
// TODO: race if userspace updates too late and an undecrypted packet is forwarded.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint8_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} decrypt_packet_payload_indicator SEC(".maps");

// Look up one ChaCha20 bitstream block for the given packet number.
__attribute__((always_inline)) int32_t retreive_tls_chacha20_poly1305_bitstream(uint64_t pn, uint8_t block_index, struct tls_chacha20_poly1305_bitstream_block_t *secret) {
    struct tls_chacha20_poly1305_bitstream_map_key_t key = {
        .pn = pn,
        .block_index = block_index,
        .padding = {0}
    };
    struct tls_chacha20_poly1305_bitstream_block_t *value = bpf_map_lookup_elem(&tls_chacha20_poly1305_bitstream_server, &key);
    if (value == NULL) {
        bpf_printk("No tls secrets found for packet number %llu and block %d\n", pn, block_index);
        return 1;
    }
    *secret = *value;

    return 0;
}

// Verify Poly1305 tag, then XOR-decrypt the ciphertext with the ChaCha20 bitstream.
__attribute__((always_inline)) int32_t decrypt_packet_payload(struct __sk_buff *skb, struct decryption_bundle_t decryption_bundle, void *data_end, uint64_t pn) { // ! TODO: fix the problem that multiple frames in same packet
    void *payload = decryption_bundle.payload;
    uint32_t decryption_size = decryption_bundle.decyption_size;

    void *data = (void *)(long)skb->data;

    struct tls_chacha20_poly1305_bitstream_block_t poly_key;
    uint8_t block_index = 0;

    uint32_t ret = retreive_tls_chacha20_poly1305_bitstream(pn, block_index, &poly_key);
    if (ret != 0) {
        bpf_printk("Error: Could not retrieve tls secrets for packet number %llu and block %d\n", pn, block_index);
        return 1;
    }

    decryption_bundle.key = poly_key.bitstream_bytes;
    uint8_t tag_valid = validate_tag(&decryption_bundle);
    if (!tag_valid) {
        return INVALID_TAG;
    }

    uint8_t byte;
    struct tls_chacha20_poly1305_bitstream_block_t bitstream;
    uint8_t cur_block_index = 1; // Start at 1 to skip the 0th block (poly1305 key block)
    ret = retreive_tls_chacha20_poly1305_bitstream(pn, cur_block_index, &bitstream);
    if (ret != 0) {
        bpf_printk("Error: Could not retrieve tls secrets for packet number %llu and block %d\n", pn, cur_block_index);
        return 1;
    }

    uint32_t last_decrypt_key = 0;
    uint32_t index = 0;
    uint32_t write_offset = 0;
    for (int i = 0; i < decryption_size; i++) { // TODO: make large enough to iterate over the whole payload
        SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), payload);

        byte = byte ^ bitstream.bitstream_bytes[index];
        write_offset = payload >= data ? ((size_t)payload - (size_t)data) : 0; // TODO: correct ptr arithmetic? void * arithmetic alone is not allowed

        SAVE_BPF_PROBE_WRITE_KERNEL(skb, write_offset, &byte, sizeof(byte), 0);
        bpf_map_update_elem(&last_decrypted_pn, &last_decrypt_key, &pn, BPF_ANY);

        payload++;
        index++;
        if (cur_block_index == MAX_BLOCKS_PER_PACKET || payload == data_end) {
            break;
        }
        if (index == BITSTREAM_BLOCK_SIZE) {
            index = 0;
            cur_block_index++;
            ret = retreive_tls_chacha20_poly1305_bitstream(pn, cur_block_index, &bitstream);
            if (ret != 0) {
                bpf_printk("Error: Could not retrieve tls secrets for packet number %llu and block %d\n", pn, cur_block_index);
                return 1;
            }
        }
    }

    return 0;
}
