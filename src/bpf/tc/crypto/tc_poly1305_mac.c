#include <stdint.h>

#include "tc_crypto_defines.c"
#include "tc_crypto_structs.c"
#include "tc_mac_update_from_asm.c"

const uint64_t rMask0 = 0x0FFFFFFC0FFFFFFF;
const uint64_t rMask1 = 0x0FFFFFFC0FFFFFFC;
const uint64_t mask_low_2_bits = 0x3;
const uint64_t mask_not_low_2_bits = ~0x3;

__attribute__((always_inline)) uint64_t to_little_endian(uint8_t *val, void *data_end) {
    if (val == NULL || val+8 > data_end) {
        return 0;
    }
    return (uint64_t)val[0] | 
           (uint64_t)val[1] << 8 | 
           (uint64_t)val[2] << 16 | 
           (uint64_t)val[3] << 24 | 
           (uint64_t)val[4] << 32 | 
           (uint64_t)val[5] << 40 | 
           (uint64_t)val[6] << 48 | 
           (uint64_t)val[7] << 56;
}

__attribute__((always_inline)) void initialize_mac_state(uint8_t *polykey, struct mac_state_t *mac_state, void *data_end) {

    uint64_t key_0_to_8_little_endian = to_little_endian(polykey, data_end);
    uint64_t key_8_to_16_little_endian = to_little_endian(polykey + 8, data_end);
    uint64_t key_16_to_24_little_endian = to_little_endian(polykey + 16, data_end);
    uint64_t key_24_to_32_little_endian = to_little_endian(polykey + 24, data_end);

    mac_state->r[0] = key_0_to_8_little_endian & rMask0;
    mac_state->r[1] = key_8_to_16_little_endian & rMask1;

    mac_state->s[1] = key_16_to_24_little_endian;
    mac_state->s[0] = key_24_to_32_little_endian;

    mac_state->h[0] = 0;
    mac_state->h[1] = 0;
    mac_state->h[2] = 0;
}

__attribute__((always_inline)) void initialize_mac(struct mac_generic_t *mac, uint8_t *polykey, void *data_end) {

    initialize_mac_state(polykey, &mac->state, data_end);
    mac->offset = 0;

}

__attribute__((always_inline)) void add64(uint64_t a, uint64_t b, uint64_t cin, struct result_carry_u64_t *result) {

    uint64_t addition = a + b + cin;
    uint64_t cout = ((a & b) | ((a | b) & ~addition)) >> 63;

    result->result = addition;
    result->carry = cout;

}

__attribute__((always_inline)) void mul64(uint64_t a, uint64_t b, struct result_u128_t *result) {

    const uint32_t mask32 = ~0;
	uint64_t x0 = a & mask32;
	uint64_t x1 = a >> 32;
	uint64_t y0 = b & mask32;
	uint64_t y1 = b >> 32;
	uint64_t w0 = x0 * y0;
	uint64_t t = x1*y0 + (w0>>32);
	uint64_t w1 = t & mask32;
	uint64_t w2 = t >> 32;
	w1 += x0 * y1;
	uint64_t hi = x1*y1 + w2 + (w1>>32);
	uint64_t lo = a * b;

    result->lo = lo;
    result->hi = hi;

}

__attribute__((always_inline)) void add128(struct result_u128_t a, struct result_u128_t b, struct result_u128_t *result) {

    struct result_carry_u64_t lo;
    add64(a.lo, b.lo, 0, &lo);
    struct result_carry_u64_t hi;
    add64(a.hi, b.hi, lo.carry, &hi);

    if (hi.carry) {
        bpf_printk("Overflow in add128\n");
    }

    result->lo = lo.result;
    result->hi = hi.result;

}

// See: https://github.com/golang/crypto/blob/b4f1988a35dee11ec3e05d6bf3e90b695fbd8909/internal/poly1305/sum_generic.go#L146
__attribute__((always_inline)) void update_generic(struct mac_state_t *state, uint8_t *msg, uint64_t msg_len, void *data_end) {

    uint64_t h0 = state->h[0];
    uint64_t h1 = state->h[1];
    uint64_t h2 = state->h[2];

    uint64_t r0 = state->r[0];
    uint64_t r1 = state->r[1];

    struct result_carry_u64_t res64;
    uint64_t c;

    while (msg_len > 0) { // TODO: prolly needs refactor due to verifier
        
        c = 0;

        if (msg_len >= POLY1305_TAG_SIZE) {

            add64(h0, to_little_endian(msg, data_end), 0, &res64);
            h0 = res64.result;
            c = res64.carry;

            add64(h1, to_little_endian(msg + 8, data_end), c, &res64);
            h1 = res64.result;
            c = res64.carry;

            h2 += c + 1;

            msg += POLY1305_TAG_SIZE;
            msg_len -= POLY1305_TAG_SIZE;

        } else {

            uint8_t buf[POLY1305_TAG_SIZE] = {0};
            for (uint64_t i = 0; i < msg_len; i++) {
                buf[i] = msg[i];
            }
            buf[msg_len] = 1;

            add64(h0, to_little_endian(buf, data_end), 0, &res64);
            h0 = res64.result;
            c = res64.carry;

            add64(h1, to_little_endian(buf + 8, data_end), c, &res64);
            h1 = res64.result;
            c = res64.carry;

            h2 += c;

            msg_len = 0;

        }

        struct result_u128_t h0r0;
        mul64(h0, r0, &h0r0);
		struct result_u128_t h1r0;
        mul64(h1, r0, &h1r0);
		struct result_u128_t h2r0;
        mul64(h2, r0, &h2r0);
		struct result_u128_t h0r1;
        mul64(h0, r1, &h0r1);
		struct result_u128_t h1r1;
        mul64(h1, r1, &h1r1);
		struct result_u128_t h2r1;
        mul64(h2, r1, &h2r1);

        if (h2r0.hi != 0 || h2r1.hi != 0) {
            bpf_printk("Overflow in update_generic\n");
        }

        struct result_u128_t m0 = h0r0;
		
        struct result_u128_t m1;
        add128(h1r0, h0r1, &m1);
        struct result_u128_t m2; 
        add128(h2r0, h1r1, &m2);
		struct result_u128_t m3 = h2r1;

        uint64_t t0 = m0.lo;
		add64(m1.lo, m0.hi, 0, &res64);
        uint64_t t1 = res64.result;
        c = res64.carry;

		add64(m2.lo, m1.hi, c, &res64);
        uint64_t t2 = res64.result;
        c = res64.carry;

		add64(m3.lo, m2.hi, c, &res64);
        uint64_t t3 = res64.result;

        h0 = t0;
        h1 = t1;
        h2 = t2&mask_low_2_bits;

        struct result_u128_t cc = (struct result_u128_t){t2 & mask_not_low_2_bits, t3};

        add64(h0, cc.lo, 0, &res64);
        h0 = res64.result;
        c = res64.carry;

        add64(h1, cc.hi, c, &res64);
        h1 = res64.result;
        c = res64.carry;

        h2 += c;

    }

    state->h[0] = h0;
    state->h[1] = h1;
    state->h[2] = h2;

}

__attribute__((always_inline)) void write(struct mac_generic_t *mac, uint8_t *data, uint64_t data_len, void *data_end) {

    if (mac->offset > 0) {
        uint32_t length = MIN(POLY1305_TAG_SIZE - mac->offset, data_len);
        for (uint32_t i = 0; i < length; i++) {
            mac->buffer[mac->offset + i] = data[i];
        }
        if (mac->offset + length < POLY1305_TAG_SIZE) {
            mac->offset += length;
            return;
        }
        data += length;
        data_len -= length;
        mac->offset = 0;
        update_generic(&mac->state, mac->buffer, POLY1305_TAG_SIZE, data_end);
    }

    uint64_t n = data_len - (data_len % POLY1305_TAG_SIZE);
    if (n > 0) {
        update_generic(&mac->state, data, n, data_end);
        data += n;
        data_len -= n;
    }

    if (data_len > 0) {
        uint32_t length = MIN(POLY1305_TAG_SIZE - mac->offset, data_len);
        for (uint32_t i = 0; i < length; i++) {
            mac->buffer[mac->offset + i] = data[i];
        }
        mac->offset += length;
    } 
    
}

__attribute__((always_inline)) void writeWithPadding(struct mac_generic_t *mac, uint8_t *data, uint64_t data_len) {

    void *data_end = (void *)(data) + data_len;

    write(mac, data, data_len, data_end);
    if (data_len % 16 != 0) {
        uint8_t padding[16] = {0};
        write(mac, padding, 16 - (data_len % 16), data_end);
    }

}

__attribute__((always_inline)) void writeUint64(struct mac_generic_t *mac, uint64_t val) {

    uint8_t val_bytes[8];
    val_bytes[0] = val & 0xFF;
    val_bytes[1] = (val >> 8) & 0xFF;
    val_bytes[2] = (val >> 16) & 0xFF;
    val_bytes[3] = (val >> 24) & 0xFF;
    val_bytes[4] = (val >> 32) & 0xFF;
    val_bytes[5] = (val >> 40) & 0xFF;
    val_bytes[6] = (val >> 48) & 0xFF;
    val_bytes[7] = (val >> 56) & 0xFF;

    write(mac, val_bytes, 8, val_bytes + 8);

}

__attribute__((always_inline)) uint8_t verify(struct mac_generic_t *mac, uint8_t *tag) {

    return 0;

}