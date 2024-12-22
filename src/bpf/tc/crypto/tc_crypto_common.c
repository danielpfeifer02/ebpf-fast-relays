// This file is just for ease of development to keep the newly added maps separate from tc_common.c.
// Once the poc is working this file can be merged with tc_common.c.

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

 
// This map will be used to hand down the tls secrets from the userspace to the eBPF program.
// This map is used for the server-relay connection.
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

// Since the stack size is limited to 512 bytes we need a separate ebpf map for generating the poly1305 tag.

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct poly1305buffer_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} poly1305_tag_gen_buffer SEC(".maps");

// This map is to tell the eBPF program that it should decrypt the payload of a packet.
// TODO: potential race conditions if the userspace tells this to late and an undecrypted packet is sent up to userspace
// TODO: or forwarded to the client? Potentially use different way of finding out what packets to decrypt.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint8_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} decrypt_packet_payload_indicator SEC(".maps");

// This function will read the tls secrets from the ring buffer and store them in the eBPF program.
__attribute__((always_inline)) int32_t retreive_tls_chacha20_poly1305_bitstream(uint64_t pn, uint8_t block_index, struct tls_chacha20_poly1305_bitstream_block_t *secret) {
    // return bpf_map_pop_elem(&tls_chacha20_poly1305_bitstream_server, secret);  // TODO: this would be for a queue

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

// This function will decrypt the packet using the tls bitsream.
__attribute__((always_inline)) int32_t decrypt_packet_payload(struct __sk_buff *skb, struct decryption_bundle_t decryption_bundle, void *data_end, uint64_t pn) { // ! TODO: fix the problem that multiple frames in same packet

    void *payload = decryption_bundle.payload;
    void *additional_data = decryption_bundle.additional_data;
    uint32_t decryption_size = decryption_bundle.decyption_size;
    uint32_t additional_data_size = decryption_bundle.additional_data_size;
    
    void *data = (void *)(long)skb->data;

    // Check poly1305 tag
    struct tls_chacha20_poly1305_bitstream_block_t poly_key;
    uint8_t block_index = 0;

    // Get the poly1305 key
    uint32_t ret = retreive_tls_chacha20_poly1305_bitstream(pn, block_index, &poly_key);
    if (ret != 0) {
        bpf_printk("Error: Could not retrieve tls secrets for packet number %llu and block %d\n", pn, block_index);
        return 1;
    }

    // // Get payload and additional data
    // struct poly1305buffer_t poly1305_buffer;
    // poly1305_buffer.payload_size = decryption_size;
    // poly1305_buffer.additional_data_size = additional_data_size;

    // struct mac_generic_t mac;
    // initialize_mac(&mac, poly_key.bitstream_bytes);

    // writeWithPadding(&mac, additional_data, additional_data_size);
    // writeWithPadding(&mac, payload, decryption_size); // TODO: ciphertext
    // writeUint64(&mac, additional_data_size);
    // writeUint64(&mac, decryption_size);

    // uint8_t tag_valid = verify(&mac, decryption_bundle.tag);

    decryption_bundle.key = poly_key.bitstream_bytes;
    uint8_t tag_valid = validate_tag(decryption_bundle);
    if (!tag_valid) {
        return INVALID_TAG;
    }


    uint8_t byte;
    struct tls_chacha20_poly1305_bitstream_block_t bitstream;
    uint8_t cur_block_index = 1; // Start at 1 to skip the 0th block (poly1305 block)
    ret = retreive_tls_chacha20_poly1305_bitstream(pn, cur_block_index, &bitstream);
    if (ret != 0) {
        bpf_printk("Error: Could not retrieve tls secrets for packet number %llu and block %d\n", pn, cur_block_index);
        return 1;
    }

    // Key for updating the last decrypted pn
    uint32_t last_decrypt_key = 0;

    // Decrypt the payload
    uint32_t index = 0;
    uint32_t write_offset = 0;
    for (int i=0; i<decryption_size; i++) { // TODO: make large enough to iterate over the whole payload
        SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), payload);
        // bpf_printk("Byte before: %02x\n", byte);
        // bpf_printk("%02x (%d) ^ %02x (%d) = %02x\n", byte, byte, bitstream.bitstream_bytes[index], bitstream.bitstream_bytes[index], byte^bitstream.bitstream_bytes[index]);
        
        // Decrypt the payload
        byte = byte ^ bitstream.bitstream_bytes[index];
        write_offset = payload >= data ? ((size_t)payload - (size_t)data) : 0; // TODO: correct ptr arithmetic? void * artihmetic allone is not allowed
        // bpf_printk("Writing %02x to offset %d\n", byte, write_offset);
        
        SAVE_BPF_PROBE_WRITE_KERNEL(skb, write_offset, &byte, sizeof(byte), 0); 
        bpf_map_update_elem(&last_decrypted_pn, &last_decrypt_key, &pn, BPF_ANY);


        SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), payload);
        // bpf_printk("Byte after: %02x\n", byte);
        
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
            // bpf_printk("Now using block %d of bitstream\n", cur_block_index);
        }
    }

    return 0;   
}