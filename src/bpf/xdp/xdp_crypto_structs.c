#pragma once

// #include <stdint.h>
#include "../vmlinux.h"

#include "xdp_crypto_defines.c"

// See: https://github.com/golang/crypto/blob/b4f1988a35dee11ec3e05d6bf3e90b695fbd8909/internal/poly1305/sum_generic.go#L45
struct mac_state_t {
    uint64_t h[3];
    uint64_t r[2];
    uint64_t s[2];
};

// See: https://github.com/golang/crypto/blob/b4f1988a35dee11ec3e05d6bf3e90b695fbd8909/internal/poly1305/sum_generic.go#L55
struct mac_generic_t {
    struct mac_state_t state;
    uint8_t buffer[POLY1305_TAG_SIZE];
    uint32_t offset;
};

// Struct for any operation that might give a carry out
struct result_carry_u64_t {
    uint64_t result;
    uint64_t carry;
};

struct result_u128_t {
    uint64_t lo;
    uint64_t hi;
};

struct decryption_bundle_t {
    void *key;
    void *payload;
    void *additional_data;
    void *tag;
    uint32_t decyption_size;
    uint32_t additional_data_size;
};

struct tls_chacha20_poly1305_bitstream_block_t {
    uint8_t bitstream_bytes[BITSTREAM_BLOCK_SIZE]; // TODO
    // uint32_t offset; // gives the offset in the bitstream for the 64 byte block.
};

struct tls_chacha20_poly1305_bitstream_map_key_t {
    uint64_t pn;
    uint8_t block_index;
    uint8_t padding[7];
};

struct poly1305buffer_t {
    uint8_t payload[MAX_PAYLOAD_SIZE];
    uint8_t additional_data[MAX_ADDITIONAL_DATA_SIZE];
    uint32_t payload_size;
    uint32_t additional_data_size;
};