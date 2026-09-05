#pragma once

#define SECRET_QUEUE_SIZE (1 << 15)
#define BITSTREAM_BLOCK_SIZE 64
#define MAX_BLOCKS_PER_PACKET 24 // 24 * 64 = 1536 bytes, enough for a full packet
#define BITSTREAM_BLOCK_MAP_SIZE (1 << 15) // TODO: size for continuous decryption
#define POLY1305_KEY_SIZE 32
#define POLY1305_TAG_SIZE 16
#define MAX_ADDITIONAL_DATA_SIZE 21 // 1 (short header) + 16 (conn id) + 4 (packet number)
#define MAX_PAYLOAD_SIZE 1500 // standard MTU is sufficient
#define INVALID_TAG 420

#define MIN(a, b) ((a) < (b) ? (a) : (b))
