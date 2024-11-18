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
#define BITSTREAM_LENGTH (64 * 3)

struct tls_chacha20_poly1305_bitstream_t {
    uint8_t bitstream_bytes[BITSTREAM_LENGTH]; // TODO
    // uint32_t offset; // gives the offset in the bitstream for the 64 byte block.
};
 
// This map will be used to hand down the tls secrets from the userspace to the eBPF program.
// This map is used for the server-relay connection.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, struct tls_chacha20_poly1305_bitstream_t);
    __uint(max_entries, SECRET_QUEUE_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tls_chacha20_poly1305_bitstream_server SEC(".maps");

// This function will read the tls secrets from the ring buffer and store them in the eBPF program.
__attribute__((always_inline)) int32_t retreive_tls_chacha20_poly1305_bitstream(uint64_t pn, struct tls_chacha20_poly1305_bitstream_t *secret) {
    // return bpf_map_pop_elem(&tls_chacha20_poly1305_bitstream_server, secret);  // TODO: this would be for a queue

    return 0;   
}