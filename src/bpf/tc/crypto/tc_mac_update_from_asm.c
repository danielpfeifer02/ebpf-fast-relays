// This file is generated from the corresponding ASM (.s) file for amd64.
// Generated using: https://syntha.ai/converters/assembly-to-c
// from file: https://github.com/golang/crypto/blob/b4f1988a35dee11ec3e05d6bf3e90b695fbd8909/internal/poly1305/sum_amd64.s

#include <stdint.h>

#include "tc_crypto_structs.c"
/*
__attribute__((always_inline)) void update(struct mac_state_t *state, uint8_t *msg, uint64_t msg_len) {
    uint64_t r8 = state->h[0];
    uint64_t r9 = state->h[1];
    uint64_t r10 = state->h[2];
    uint64_t r11 = state->r[0];
    uint64_t r12 = state->r[1];
    uint64_t r15 = msg_len;
    uint8_t *si_var = msg;

    uint64_t ax_var=0;
    uint64_t bx_var=0;
    uint64_t cx_var=0;
    uint64_t dx_var=0;
    uint64_t r13=0; 
    uint64_t r14=0;

    if (r15 < 16) {
        goto bytes_between_0_and_15;
    }

loop:
    r8 += *(uint64_t *)si_var;
    r9 += *(uint64_t *)(si_var + 8);
    r10 += 1;
    si_var += 16;

multiply:
    ax_var = r11;
    bx_var = ax_var * r8;
    cx_var = dx_var;
    ax_var = r11;
    ax_var *= r9;
    cx_var += ax_var;
    dx_var += (cx_var < ax_var);
    r13 = r11 * r10 + dx_var;
    ax_var = r12;
    ax_var *= r8;
    cx_var += ax_var;
    dx_var += (cx_var < ax_var);
    r14 = r12 * r10;
    ax_var = r12;
    ax_var *= r9;
    r13 += ax_var;
    dx_var += (r13 < ax_var);
    r13 += dx_var;
    r8 = bx_var;
    r9 = cx_var;
    r10 = r13 & 3;
    bx_var &= ~3;
    r8 += bx_var;
    r9 += dx_var;
    r10 += 0;
    r13 >>= 2;
    r14 >>= 2;
    r8 += r13;
    r9 += r14;
    r10 += 0;
    r15 -= 16;
    if (r15 >= 16) {
        goto loop;
    }

bytes_between_0_and_15:
    if (r15 == 0) {
        goto done;
    }
    bx_var = 1;
    cx_var = 0;
    r13 = 0;
    si_var += r15;

flush_buffer:
    cx_var <<= 8;
    bx_var <<= 8;
    r13 = *(si_var - 1);
    bx_var ^= r13;
    si_var--;
    r15--;
    if (r15 != 0) {
        goto flush_buffer;
    }
    r8 += bx_var;
    r9 += cx_var;
    r10 += 0;
    r15 = 16;
    goto multiply;

done:
    state->h[0] = r8;
    state->h[1] = r9;
    state->h[2] = r10;
}

//*/