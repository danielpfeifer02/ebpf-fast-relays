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

#define SECRET_QUEUE_SIZE (1<<15)
#define BITSTREAM_BLOCK_SIZE 64
#define MAX_BLOCKS_PER_PACKET 24 // 24 * 64 = 1536 bytes which is large enough for a whole packet
#define BITSTREAM_BLOCK_MAP_SIZE 20 // TODO: make enough for continuous decryption
#define POLY1305_TAG_SIZE 16

struct tls_chacha20_poly1305_bitstream_block_t {
    uint8_t bitstream_bytes[BITSTREAM_BLOCK_SIZE]; // TODO
    // uint32_t offset; // gives the offset in the bitstream for the 64 byte block.
};

struct tls_chacha20_poly1305_bitstream_map_key_t {
    uint64_t pn;
    uint8_t block_index;
    uint8_t padding[7];
};
 
// This map will be used to hand down the tls secrets from the userspace to the eBPF program.
// This map is used for the server-relay connection.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tls_chacha20_poly1305_bitstream_map_key_t);
    __type(value, struct tls_chacha20_poly1305_bitstream_block_t);
    __uint(max_entries, BITSTREAM_BLOCK_MAP_SIZE * MAX_BLOCKS_PER_PACKET);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tls_chacha20_poly1305_bitstream_server SEC(".maps");

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
__attribute__((always_inline)) int32_t decrypt_packet_payload(struct __sk_buff *skb, void *payload, void *data_end, uint64_t pn, uint32_t decryption_size) { // ! TODO: fix the problem that multiple frames in same packet

    // // Get decryption indicator
    // uint32_t key = 0;
    // uint8_t *decrypt_indicator = bpf_map_lookup_elem(&decrypt_packet_payload_indicator, &key);
    // if (decrypt_indicator == NULL) {
    //     return 0;
    // }
    // if (*decrypt_indicator < 2) {
    //     uint8_t new_val = *decrypt_indicator;
    //     new_val++;
    //     bpf_map_update_elem(&decrypt_packet_payload_indicator, &key, &new_val, BPF_ANY);
    //     return 0;
    // }
    
    void *data = (void *)(long)skb->data;

    uint8_t byte;
    struct tls_chacha20_poly1305_bitstream_block_t bitstream;
    uint8_t cur_block_index = 1; // TODO: delibarately start at 1 to skip the 0th block (bc of some tls poly thing?)
    uint32_t ret = retreive_tls_chacha20_poly1305_bitstream(pn, cur_block_index, &bitstream);
    if (ret != 0) {
        return 1;
    }

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
        
        SAVE_BPF_PROBE_WRITE_KERNEL(skb, write_offset, &byte, sizeof(byte), 0); // ! TODO: in the end this should be turned on 

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
                return 1;
            }
            // bpf_printk("Now using block %d of bitstream\n", cur_block_index);
        }
    }

    return 0;   
}