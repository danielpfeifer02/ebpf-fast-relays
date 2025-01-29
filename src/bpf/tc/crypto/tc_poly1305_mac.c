#include <stdint.h>

#include "tc_crypto_defines.c"
#include "tc_crypto_structs.c"
#include "tc_mac_update_from_asm.c"
#include "../main/tc_common.c"

#define DETERMINE_ADD_CARRY_PRESENCE(A, B, C) (((A) & (B)) | (((A) | (B)) & ~(C))) >> 63

// For debugging purposes
#define REPEAT_1(X) X
#define REPEAT_2(X) X X
#define REPEAT_4(X) X X X X
#define REPEAT_8(X) REPEAT_4(X) REPEAT_4(X)
#define REPEAT_16(X) REPEAT_8(X) REPEAT_8(X)
#define REPEAT_32(X) REPEAT_16(X) REPEAT_16(X)
#define REPEAT_64(X) REPEAT_32(X) REPEAT_32(X)

#define MAX_LINEARIZED_PADDED_DATA_SIZE (MAX_ADDITIONAL_DATA_SIZE + 15 + MAX_PAYLOAD_SIZE + 15 + 8 + 8)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, MAX_LINEARIZED_PADDED_DATA_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} linearized_padded_data SEC(".maps");

struct my_uint128_t {
    uint64_t lo;
    uint64_t hi;
};

struct my_uint192_t {
    uint64_t lo;
    uint64_t mid;
    uint64_t hi;
};

struct my_uint256_t {
    uint64_t lo;
    uint64_t mid_lo;
    uint64_t mid_hi;
    uint64_t hi;
};

const uint64_t mod_lut[768] = {
0x0000000000000000, 0x0000000000000000, 0x0000000000000001, // for for k = 1 << 0
0x0000000000000000, 0x0000000000000000, 0x0000000000000002, // for for k = 1 << 1
0x0000000000000000, 0x0000000000000000, 0x0000000000000004, // for for k = 1 << 2
0x0000000000000000, 0x0000000000000000, 0x0000000000000008, // for for k = 1 << 3
0x0000000000000000, 0x0000000000000000, 0x0000000000000010, // for for k = 1 << 4
0x0000000000000000, 0x0000000000000000, 0x0000000000000020, // for for k = 1 << 5
0x0000000000000000, 0x0000000000000000, 0x0000000000000040, // for for k = 1 << 6
0x0000000000000000, 0x0000000000000000, 0x0000000000000080, // for for k = 1 << 7
0x0000000000000000, 0x0000000000000000, 0x0000000000000100, // for for k = 1 << 8
0x0000000000000000, 0x0000000000000000, 0x0000000000000200, // for for k = 1 << 9
0x0000000000000000, 0x0000000000000000, 0x0000000000000400, // for for k = 1 << 10
0x0000000000000000, 0x0000000000000000, 0x0000000000000800, // for for k = 1 << 11
0x0000000000000000, 0x0000000000000000, 0x0000000000001000, // for for k = 1 << 12
0x0000000000000000, 0x0000000000000000, 0x0000000000002000, // for for k = 1 << 13
0x0000000000000000, 0x0000000000000000, 0x0000000000004000, // for for k = 1 << 14
0x0000000000000000, 0x0000000000000000, 0x0000000000008000, // for for k = 1 << 15
0x0000000000000000, 0x0000000000000000, 0x0000000000010000, // for for k = 1 << 16
0x0000000000000000, 0x0000000000000000, 0x0000000000020000, // for for k = 1 << 17
0x0000000000000000, 0x0000000000000000, 0x0000000000040000, // for for k = 1 << 18
0x0000000000000000, 0x0000000000000000, 0x0000000000080000, // for for k = 1 << 19
0x0000000000000000, 0x0000000000000000, 0x0000000000100000, // for for k = 1 << 20
0x0000000000000000, 0x0000000000000000, 0x0000000000200000, // for for k = 1 << 21
0x0000000000000000, 0x0000000000000000, 0x0000000000400000, // for for k = 1 << 22
0x0000000000000000, 0x0000000000000000, 0x0000000000800000, // for for k = 1 << 23
0x0000000000000000, 0x0000000000000000, 0x0000000001000000, // for for k = 1 << 24
0x0000000000000000, 0x0000000000000000, 0x0000000002000000, // for for k = 1 << 25
0x0000000000000000, 0x0000000000000000, 0x0000000004000000, // for for k = 1 << 26
0x0000000000000000, 0x0000000000000000, 0x0000000008000000, // for for k = 1 << 27
0x0000000000000000, 0x0000000000000000, 0x0000000010000000, // for for k = 1 << 28
0x0000000000000000, 0x0000000000000000, 0x0000000020000000, // for for k = 1 << 29
0x0000000000000000, 0x0000000000000000, 0x0000000040000000, // for for k = 1 << 30
0x0000000000000000, 0x0000000000000000, 0x0000000080000000, // for for k = 1 << 31
0x0000000000000000, 0x0000000000000000, 0x0000000100000000, // for for k = 1 << 32
0x0000000000000000, 0x0000000000000000, 0x0000000200000000, // for for k = 1 << 33
0x0000000000000000, 0x0000000000000000, 0x0000000400000000, // for for k = 1 << 34
0x0000000000000000, 0x0000000000000000, 0x0000000800000000, // for for k = 1 << 35
0x0000000000000000, 0x0000000000000000, 0x0000001000000000, // for for k = 1 << 36
0x0000000000000000, 0x0000000000000000, 0x0000002000000000, // for for k = 1 << 37
0x0000000000000000, 0x0000000000000000, 0x0000004000000000, // for for k = 1 << 38
0x0000000000000000, 0x0000000000000000, 0x0000008000000000, // for for k = 1 << 39
0x0000000000000000, 0x0000000000000000, 0x0000010000000000, // for for k = 1 << 40
0x0000000000000000, 0x0000000000000000, 0x0000020000000000, // for for k = 1 << 41
0x0000000000000000, 0x0000000000000000, 0x0000040000000000, // for for k = 1 << 42
0x0000000000000000, 0x0000000000000000, 0x0000080000000000, // for for k = 1 << 43
0x0000000000000000, 0x0000000000000000, 0x0000100000000000, // for for k = 1 << 44
0x0000000000000000, 0x0000000000000000, 0x0000200000000000, // for for k = 1 << 45
0x0000000000000000, 0x0000000000000000, 0x0000400000000000, // for for k = 1 << 46
0x0000000000000000, 0x0000000000000000, 0x0000800000000000, // for for k = 1 << 47
0x0000000000000000, 0x0000000000000000, 0x0001000000000000, // for for k = 1 << 48
0x0000000000000000, 0x0000000000000000, 0x0002000000000000, // for for k = 1 << 49
0x0000000000000000, 0x0000000000000000, 0x0004000000000000, // for for k = 1 << 50
0x0000000000000000, 0x0000000000000000, 0x0008000000000000, // for for k = 1 << 51
0x0000000000000000, 0x0000000000000000, 0x0010000000000000, // for for k = 1 << 52
0x0000000000000000, 0x0000000000000000, 0x0020000000000000, // for for k = 1 << 53
0x0000000000000000, 0x0000000000000000, 0x0040000000000000, // for for k = 1 << 54
0x0000000000000000, 0x0000000000000000, 0x0080000000000000, // for for k = 1 << 55
0x0000000000000000, 0x0000000000000000, 0x0100000000000000, // for for k = 1 << 56
0x0000000000000000, 0x0000000000000000, 0x0200000000000000, // for for k = 1 << 57
0x0000000000000000, 0x0000000000000000, 0x0400000000000000, // for for k = 1 << 58
0x0000000000000000, 0x0000000000000000, 0x0800000000000000, // for for k = 1 << 59
0x0000000000000000, 0x0000000000000000, 0x1000000000000000, // for for k = 1 << 60
0x0000000000000000, 0x0000000000000000, 0x2000000000000000, // for for k = 1 << 61
0x0000000000000000, 0x0000000000000000, 0x4000000000000000, // for for k = 1 << 62
0x0000000000000000, 0x0000000000000000, 0x8000000000000000, // for for k = 1 << 63
0x0000000000000000, 0x0000000000000001, 0x0000000000000000, // for for k = 1 << 64
0x0000000000000000, 0x0000000000000002, 0x0000000000000000, // for for k = 1 << 65
0x0000000000000000, 0x0000000000000004, 0x0000000000000000, // for for k = 1 << 66
0x0000000000000000, 0x0000000000000008, 0x0000000000000000, // for for k = 1 << 67
0x0000000000000000, 0x0000000000000010, 0x0000000000000000, // for for k = 1 << 68
0x0000000000000000, 0x0000000000000020, 0x0000000000000000, // for for k = 1 << 69
0x0000000000000000, 0x0000000000000040, 0x0000000000000000, // for for k = 1 << 70
0x0000000000000000, 0x0000000000000080, 0x0000000000000000, // for for k = 1 << 71
0x0000000000000000, 0x0000000000000100, 0x0000000000000000, // for for k = 1 << 72
0x0000000000000000, 0x0000000000000200, 0x0000000000000000, // for for k = 1 << 73
0x0000000000000000, 0x0000000000000400, 0x0000000000000000, // for for k = 1 << 74
0x0000000000000000, 0x0000000000000800, 0x0000000000000000, // for for k = 1 << 75
0x0000000000000000, 0x0000000000001000, 0x0000000000000000, // for for k = 1 << 76
0x0000000000000000, 0x0000000000002000, 0x0000000000000000, // for for k = 1 << 77
0x0000000000000000, 0x0000000000004000, 0x0000000000000000, // for for k = 1 << 78
0x0000000000000000, 0x0000000000008000, 0x0000000000000000, // for for k = 1 << 79
0x0000000000000000, 0x0000000000010000, 0x0000000000000000, // for for k = 1 << 80
0x0000000000000000, 0x0000000000020000, 0x0000000000000000, // for for k = 1 << 81
0x0000000000000000, 0x0000000000040000, 0x0000000000000000, // for for k = 1 << 82
0x0000000000000000, 0x0000000000080000, 0x0000000000000000, // for for k = 1 << 83
0x0000000000000000, 0x0000000000100000, 0x0000000000000000, // for for k = 1 << 84
0x0000000000000000, 0x0000000000200000, 0x0000000000000000, // for for k = 1 << 85
0x0000000000000000, 0x0000000000400000, 0x0000000000000000, // for for k = 1 << 86
0x0000000000000000, 0x0000000000800000, 0x0000000000000000, // for for k = 1 << 87
0x0000000000000000, 0x0000000001000000, 0x0000000000000000, // for for k = 1 << 88
0x0000000000000000, 0x0000000002000000, 0x0000000000000000, // for for k = 1 << 89
0x0000000000000000, 0x0000000004000000, 0x0000000000000000, // for for k = 1 << 90
0x0000000000000000, 0x0000000008000000, 0x0000000000000000, // for for k = 1 << 91
0x0000000000000000, 0x0000000010000000, 0x0000000000000000, // for for k = 1 << 92
0x0000000000000000, 0x0000000020000000, 0x0000000000000000, // for for k = 1 << 93
0x0000000000000000, 0x0000000040000000, 0x0000000000000000, // for for k = 1 << 94
0x0000000000000000, 0x0000000080000000, 0x0000000000000000, // for for k = 1 << 95
0x0000000000000000, 0x0000000100000000, 0x0000000000000000, // for for k = 1 << 96
0x0000000000000000, 0x0000000200000000, 0x0000000000000000, // for for k = 1 << 97
0x0000000000000000, 0x0000000400000000, 0x0000000000000000, // for for k = 1 << 98
0x0000000000000000, 0x0000000800000000, 0x0000000000000000, // for for k = 1 << 99
0x0000000000000000, 0x0000001000000000, 0x0000000000000000, // for for k = 1 << 100
0x0000000000000000, 0x0000002000000000, 0x0000000000000000, // for for k = 1 << 101
0x0000000000000000, 0x0000004000000000, 0x0000000000000000, // for for k = 1 << 102
0x0000000000000000, 0x0000008000000000, 0x0000000000000000, // for for k = 1 << 103
0x0000000000000000, 0x0000010000000000, 0x0000000000000000, // for for k = 1 << 104
0x0000000000000000, 0x0000020000000000, 0x0000000000000000, // for for k = 1 << 105
0x0000000000000000, 0x0000040000000000, 0x0000000000000000, // for for k = 1 << 106
0x0000000000000000, 0x0000080000000000, 0x0000000000000000, // for for k = 1 << 107
0x0000000000000000, 0x0000100000000000, 0x0000000000000000, // for for k = 1 << 108
0x0000000000000000, 0x0000200000000000, 0x0000000000000000, // for for k = 1 << 109
0x0000000000000000, 0x0000400000000000, 0x0000000000000000, // for for k = 1 << 110
0x0000000000000000, 0x0000800000000000, 0x0000000000000000, // for for k = 1 << 111
0x0000000000000000, 0x0001000000000000, 0x0000000000000000, // for for k = 1 << 112
0x0000000000000000, 0x0002000000000000, 0x0000000000000000, // for for k = 1 << 113
0x0000000000000000, 0x0004000000000000, 0x0000000000000000, // for for k = 1 << 114
0x0000000000000000, 0x0008000000000000, 0x0000000000000000, // for for k = 1 << 115
0x0000000000000000, 0x0010000000000000, 0x0000000000000000, // for for k = 1 << 116
0x0000000000000000, 0x0020000000000000, 0x0000000000000000, // for for k = 1 << 117
0x0000000000000000, 0x0040000000000000, 0x0000000000000000, // for for k = 1 << 118
0x0000000000000000, 0x0080000000000000, 0x0000000000000000, // for for k = 1 << 119
0x0000000000000000, 0x0100000000000000, 0x0000000000000000, // for for k = 1 << 120
0x0000000000000000, 0x0200000000000000, 0x0000000000000000, // for for k = 1 << 121
0x0000000000000000, 0x0400000000000000, 0x0000000000000000, // for for k = 1 << 122
0x0000000000000000, 0x0800000000000000, 0x0000000000000000, // for for k = 1 << 123
0x0000000000000000, 0x1000000000000000, 0x0000000000000000, // for for k = 1 << 124
0x0000000000000000, 0x2000000000000000, 0x0000000000000000, // for for k = 1 << 125
0x0000000000000000, 0x4000000000000000, 0x0000000000000000, // for for k = 1 << 126
0x0000000000000000, 0x8000000000000000, 0x0000000000000000, // for for k = 1 << 127
0x0000000000000001, 0x0000000000000000, 0x0000000000000000, // for for k = 1 << 128
0x0000000000000002, 0x0000000000000000, 0x0000000000000000, // for for k = 1 << 129
0x0000000000000000, 0x0000000000000000, 0x0000000000000005, // for for k = 1 << 130
0x0000000000000000, 0x0000000000000000, 0x000000000000000a, // for for k = 1 << 131
0x0000000000000000, 0x0000000000000000, 0x0000000000000014, // for for k = 1 << 132
0x0000000000000000, 0x0000000000000000, 0x0000000000000028, // for for k = 1 << 133
0x0000000000000000, 0x0000000000000000, 0x0000000000000050, // for for k = 1 << 134
0x0000000000000000, 0x0000000000000000, 0x00000000000000a0, // for for k = 1 << 135
0x0000000000000000, 0x0000000000000000, 0x0000000000000140, // for for k = 1 << 136
0x0000000000000000, 0x0000000000000000, 0x0000000000000280, // for for k = 1 << 137
0x0000000000000000, 0x0000000000000000, 0x0000000000000500, // for for k = 1 << 138
0x0000000000000000, 0x0000000000000000, 0x0000000000000a00, // for for k = 1 << 139
0x0000000000000000, 0x0000000000000000, 0x0000000000001400, // for for k = 1 << 140
0x0000000000000000, 0x0000000000000000, 0x0000000000002800, // for for k = 1 << 141
0x0000000000000000, 0x0000000000000000, 0x0000000000005000, // for for k = 1 << 142
0x0000000000000000, 0x0000000000000000, 0x000000000000a000, // for for k = 1 << 143
0x0000000000000000, 0x0000000000000000, 0x0000000000014000, // for for k = 1 << 144
0x0000000000000000, 0x0000000000000000, 0x0000000000028000, // for for k = 1 << 145
0x0000000000000000, 0x0000000000000000, 0x0000000000050000, // for for k = 1 << 146
0x0000000000000000, 0x0000000000000000, 0x00000000000a0000, // for for k = 1 << 147
0x0000000000000000, 0x0000000000000000, 0x0000000000140000, // for for k = 1 << 148
0x0000000000000000, 0x0000000000000000, 0x0000000000280000, // for for k = 1 << 149
0x0000000000000000, 0x0000000000000000, 0x0000000000500000, // for for k = 1 << 150
0x0000000000000000, 0x0000000000000000, 0x0000000000a00000, // for for k = 1 << 151
0x0000000000000000, 0x0000000000000000, 0x0000000001400000, // for for k = 1 << 152
0x0000000000000000, 0x0000000000000000, 0x0000000002800000, // for for k = 1 << 153
0x0000000000000000, 0x0000000000000000, 0x0000000005000000, // for for k = 1 << 154
0x0000000000000000, 0x0000000000000000, 0x000000000a000000, // for for k = 1 << 155
0x0000000000000000, 0x0000000000000000, 0x0000000014000000, // for for k = 1 << 156
0x0000000000000000, 0x0000000000000000, 0x0000000028000000, // for for k = 1 << 157
0x0000000000000000, 0x0000000000000000, 0x0000000050000000, // for for k = 1 << 158
0x0000000000000000, 0x0000000000000000, 0x00000000a0000000, // for for k = 1 << 159
0x0000000000000000, 0x0000000000000000, 0x0000000140000000, // for for k = 1 << 160
0x0000000000000000, 0x0000000000000000, 0x0000000280000000, // for for k = 1 << 161
0x0000000000000000, 0x0000000000000000, 0x0000000500000000, // for for k = 1 << 162
0x0000000000000000, 0x0000000000000000, 0x0000000a00000000, // for for k = 1 << 163
0x0000000000000000, 0x0000000000000000, 0x0000001400000000, // for for k = 1 << 164
0x0000000000000000, 0x0000000000000000, 0x0000002800000000, // for for k = 1 << 165
0x0000000000000000, 0x0000000000000000, 0x0000005000000000, // for for k = 1 << 166
0x0000000000000000, 0x0000000000000000, 0x000000a000000000, // for for k = 1 << 167
0x0000000000000000, 0x0000000000000000, 0x0000014000000000, // for for k = 1 << 168
0x0000000000000000, 0x0000000000000000, 0x0000028000000000, // for for k = 1 << 169
0x0000000000000000, 0x0000000000000000, 0x0000050000000000, // for for k = 1 << 170
0x0000000000000000, 0x0000000000000000, 0x00000a0000000000, // for for k = 1 << 171
0x0000000000000000, 0x0000000000000000, 0x0000140000000000, // for for k = 1 << 172
0x0000000000000000, 0x0000000000000000, 0x0000280000000000, // for for k = 1 << 173
0x0000000000000000, 0x0000000000000000, 0x0000500000000000, // for for k = 1 << 174
0x0000000000000000, 0x0000000000000000, 0x0000a00000000000, // for for k = 1 << 175
0x0000000000000000, 0x0000000000000000, 0x0001400000000000, // for for k = 1 << 176
0x0000000000000000, 0x0000000000000000, 0x0002800000000000, // for for k = 1 << 177
0x0000000000000000, 0x0000000000000000, 0x0005000000000000, // for for k = 1 << 178
0x0000000000000000, 0x0000000000000000, 0x000a000000000000, // for for k = 1 << 179
0x0000000000000000, 0x0000000000000000, 0x0014000000000000, // for for k = 1 << 180
0x0000000000000000, 0x0000000000000000, 0x0028000000000000, // for for k = 1 << 181
0x0000000000000000, 0x0000000000000000, 0x0050000000000000, // for for k = 1 << 182
0x0000000000000000, 0x0000000000000000, 0x00a0000000000000, // for for k = 1 << 183
0x0000000000000000, 0x0000000000000000, 0x0140000000000000, // for for k = 1 << 184
0x0000000000000000, 0x0000000000000000, 0x0280000000000000, // for for k = 1 << 185
0x0000000000000000, 0x0000000000000000, 0x0500000000000000, // for for k = 1 << 186
0x0000000000000000, 0x0000000000000000, 0x0a00000000000000, // for for k = 1 << 187
0x0000000000000000, 0x0000000000000000, 0x1400000000000000, // for for k = 1 << 188
0x0000000000000000, 0x0000000000000000, 0x2800000000000000, // for for k = 1 << 189
0x0000000000000000, 0x0000000000000000, 0x5000000000000000, // for for k = 1 << 190
0x0000000000000000, 0x0000000000000000, 0xa000000000000000, // for for k = 1 << 191
0x0000000000000000, 0x0000000000000001, 0x4000000000000000, // for for k = 1 << 192
0x0000000000000000, 0x0000000000000002, 0x8000000000000000, // for for k = 1 << 193
0x0000000000000000, 0x0000000000000005, 0x0000000000000000, // for for k = 1 << 194
0x0000000000000000, 0x000000000000000a, 0x0000000000000000, // for for k = 1 << 195
0x0000000000000000, 0x0000000000000014, 0x0000000000000000, // for for k = 1 << 196
0x0000000000000000, 0x0000000000000028, 0x0000000000000000, // for for k = 1 << 197
0x0000000000000000, 0x0000000000000050, 0x0000000000000000, // for for k = 1 << 198
0x0000000000000000, 0x00000000000000a0, 0x0000000000000000, // for for k = 1 << 199
0x0000000000000000, 0x0000000000000140, 0x0000000000000000, // for for k = 1 << 200
0x0000000000000000, 0x0000000000000280, 0x0000000000000000, // for for k = 1 << 201
0x0000000000000000, 0x0000000000000500, 0x0000000000000000, // for for k = 1 << 202
0x0000000000000000, 0x0000000000000a00, 0x0000000000000000, // for for k = 1 << 203
0x0000000000000000, 0x0000000000001400, 0x0000000000000000, // for for k = 1 << 204
0x0000000000000000, 0x0000000000002800, 0x0000000000000000, // for for k = 1 << 205
0x0000000000000000, 0x0000000000005000, 0x0000000000000000, // for for k = 1 << 206
0x0000000000000000, 0x000000000000a000, 0x0000000000000000, // for for k = 1 << 207
0x0000000000000000, 0x0000000000014000, 0x0000000000000000, // for for k = 1 << 208
0x0000000000000000, 0x0000000000028000, 0x0000000000000000, // for for k = 1 << 209
0x0000000000000000, 0x0000000000050000, 0x0000000000000000, // for for k = 1 << 210
0x0000000000000000, 0x00000000000a0000, 0x0000000000000000, // for for k = 1 << 211
0x0000000000000000, 0x0000000000140000, 0x0000000000000000, // for for k = 1 << 212
0x0000000000000000, 0x0000000000280000, 0x0000000000000000, // for for k = 1 << 213
0x0000000000000000, 0x0000000000500000, 0x0000000000000000, // for for k = 1 << 214
0x0000000000000000, 0x0000000000a00000, 0x0000000000000000, // for for k = 1 << 215
0x0000000000000000, 0x0000000001400000, 0x0000000000000000, // for for k = 1 << 216
0x0000000000000000, 0x0000000002800000, 0x0000000000000000, // for for k = 1 << 217
0x0000000000000000, 0x0000000005000000, 0x0000000000000000, // for for k = 1 << 218
0x0000000000000000, 0x000000000a000000, 0x0000000000000000, // for for k = 1 << 219
0x0000000000000000, 0x0000000014000000, 0x0000000000000000, // for for k = 1 << 220
0x0000000000000000, 0x0000000028000000, 0x0000000000000000, // for for k = 1 << 221
0x0000000000000000, 0x0000000050000000, 0x0000000000000000, // for for k = 1 << 222
0x0000000000000000, 0x00000000a0000000, 0x0000000000000000, // for for k = 1 << 223
0x0000000000000000, 0x0000000140000000, 0x0000000000000000, // for for k = 1 << 224
0x0000000000000000, 0x0000000280000000, 0x0000000000000000, // for for k = 1 << 225
0x0000000000000000, 0x0000000500000000, 0x0000000000000000, // for for k = 1 << 226
0x0000000000000000, 0x0000000a00000000, 0x0000000000000000, // for for k = 1 << 227
0x0000000000000000, 0x0000001400000000, 0x0000000000000000, // for for k = 1 << 228
0x0000000000000000, 0x0000002800000000, 0x0000000000000000, // for for k = 1 << 229
0x0000000000000000, 0x0000005000000000, 0x0000000000000000, // for for k = 1 << 230
0x0000000000000000, 0x000000a000000000, 0x0000000000000000, // for for k = 1 << 231
0x0000000000000000, 0x0000014000000000, 0x0000000000000000, // for for k = 1 << 232
0x0000000000000000, 0x0000028000000000, 0x0000000000000000, // for for k = 1 << 233
0x0000000000000000, 0x0000050000000000, 0x0000000000000000, // for for k = 1 << 234
0x0000000000000000, 0x00000a0000000000, 0x0000000000000000, // for for k = 1 << 235
0x0000000000000000, 0x0000140000000000, 0x0000000000000000, // for for k = 1 << 236
0x0000000000000000, 0x0000280000000000, 0x0000000000000000, // for for k = 1 << 237
0x0000000000000000, 0x0000500000000000, 0x0000000000000000, // for for k = 1 << 238
0x0000000000000000, 0x0000a00000000000, 0x0000000000000000, // for for k = 1 << 239
0x0000000000000000, 0x0001400000000000, 0x0000000000000000, // for for k = 1 << 240
0x0000000000000000, 0x0002800000000000, 0x0000000000000000, // for for k = 1 << 241
0x0000000000000000, 0x0005000000000000, 0x0000000000000000, // for for k = 1 << 242
0x0000000000000000, 0x000a000000000000, 0x0000000000000000, // for for k = 1 << 243
0x0000000000000000, 0x0014000000000000, 0x0000000000000000, // for for k = 1 << 244
0x0000000000000000, 0x0028000000000000, 0x0000000000000000, // for for k = 1 << 245
0x0000000000000000, 0x0050000000000000, 0x0000000000000000, // for for k = 1 << 246
0x0000000000000000, 0x00a0000000000000, 0x0000000000000000, // for for k = 1 << 247
0x0000000000000000, 0x0140000000000000, 0x0000000000000000, // for for k = 1 << 248
0x0000000000000000, 0x0280000000000000, 0x0000000000000000, // for for k = 1 << 249
0x0000000000000000, 0x0500000000000000, 0x0000000000000000, // for for k = 1 << 250
0x0000000000000000, 0x0a00000000000000, 0x0000000000000000, // for for k = 1 << 251
0x0000000000000000, 0x1400000000000000, 0x0000000000000000, // for for k = 1 << 252
0x0000000000000000, 0x2800000000000000, 0x0000000000000000, // for for k = 1 << 253
0x0000000000000000, 0x5000000000000000, 0x0000000000000000, // for for k = 1 << 254
0x0000000000000000, 0xa000000000000000, 0x0000000000000000, // for for k = 1 << 255
};

const uint64_t bit_lut[64] = {
    0x0000000000000001, 0x0000000000000002, 0x0000000000000004, 0x0000000000000008,
    0x0000000000000010, 0x0000000000000020, 0x0000000000000040, 0x0000000000000080,
    0x0000000000000100, 0x0000000000000200, 0x0000000000000400, 0x0000000000000800,
    0x0000000000001000, 0x0000000000002000, 0x0000000000004000, 0x0000000000008000,
    0x0000000000010000, 0x0000000000020000, 0x0000000000040000, 0x0000000000080000,
    0x0000000000100000, 0x0000000000200000, 0x0000000000400000, 0x0000000000800000,
    0x0000000001000000, 0x0000000002000000, 0x0000000004000000, 0x0000000008000000,
    0x0000000010000000, 0x0000000020000000, 0x0000000040000000, 0x0000000080000000,
    0x0000000100000000, 0x0000000200000000, 0x0000000400000000, 0x0000000800000000,
    0x0000001000000000, 0x0000002000000000, 0x0000004000000000, 0x0000008000000000,
    0x0000010000000000, 0x0000020000000000, 0x0000040000000000, 0x0000080000000000,
    0x0000100000000000, 0x0000200000000000, 0x0000400000000000, 0x0000800000000000,
    0x0001000000000000, 0x0002000000000000, 0x0004000000000000, 0x0008000000000000,
    0x0010000000000000, 0x0020000000000000, 0x0040000000000000, 0x0080000000000000,
    0x0100000000000000, 0x0200000000000000, 0x0400000000000000, 0x0800000000000000,
    0x1000000000000000, 0x2000000000000000, 0x4000000000000000, 0x8000000000000000
};

// clamp = 0x0ffffffc0ffffffc_0ffffffc0fffffff
const static uint64_t clamp_lo = 0x0ffffffc0fffffff;
const static uint64_t clamp_hi = 0x0ffffffc0ffffffc;
// const static struct my_uint128_t clamp = {
//     .lo = clamp_lo,
//     .hi = clamp_hi
// };

// p = 0x3_ffffffffffffffff_fffffffffffffffb
const uint64_t p_lo =   0xfffffffffffffffb;
const uint64_t p_mid =  0xffffffffffffffff;
const uint64_t p_hi =   0x3;
const struct my_uint192_t p = {
    .lo = p_lo,
    .mid = p_mid,
    .hi = p_hi
};

__attribute__((always_inline)) void add_my_uint128(struct my_uint128_t *a, struct my_uint128_t *b, struct my_uint128_t *result) {
    struct my_uint128_t res = {
        .lo = a->lo + b->lo,
        .hi = a->hi + b->hi + (a->lo + b->lo < a->lo)
    };
    *result = res;
}

__attribute__((always_inline)) void add_my_uint256(struct my_uint256_t *a, struct my_uint256_t *b, struct my_uint256_t *result) {

    result->lo = a->lo + b->lo;
    result->mid_lo = a->mid_lo + b->mid_lo + (a->lo + b->lo < a->lo);
    result->mid_hi = a->mid_hi + b->mid_hi + (a->mid_lo + b->mid_lo + (a->lo + b->lo < a->lo) < a->mid_lo);
    result->hi = a->hi + b->hi + (a->mid_hi + b->mid_hi + (a->mid_lo + b->mid_lo + (a->lo + b->lo < a->lo) < a->mid_lo) < a->mid_hi);
    
}

__attribute__((always_inline)) void mul_uint64(uint64_t a, uint64_t b, struct my_uint128_t *result) {

    uint64_t a_lo = a & 0xffffffff;
    uint64_t a_hi = a >> 32;
    uint64_t b_lo = b & 0xffffffff;
    uint64_t b_hi = b >> 32;

    uint64_t lo = a_lo * b_lo;
    uint64_t hi = ((a_hi * b_lo) + (a_lo * b_hi)) << 32;

    result->lo = lo;
    result->hi = hi;
}

__attribute__((always_inline)) void mul_my_uint128(struct my_uint128_t *a, struct my_uint128_t *b, struct my_uint128_t *result) {
    
    struct my_uint128_t res = {0, 0};
    mul_uint64(a->lo, b->lo, &res);

    uint64_t first_hi = a->hi * b->lo;
    uint64_t second_hi = a->lo * b->hi;

    // We can skip a->hi * b->hi since it would be multiplied by 2^128 i.e. 0

    res.hi += first_hi;
    res.hi += second_hi;
}

__attribute__((always_inline)) void mul_my_uint256_with_my_uint128(struct my_uint256_t *a, struct my_uint128_t *b, struct my_uint256_t *result) {

    struct my_uint128_t af, be, bf, ce, cf, de, df;
    uint64_t a_part, b_part, c_part, d_part, e_part, f_part;

    a_part = a->hi;
    b_part = a->mid_hi;
    c_part = a->mid_lo;
    d_part = a->lo;

    e_part = b->hi;
    f_part = b->lo;

    mul_uint64(a_part, f_part, &af);
    mul_uint64(b_part, e_part, &be);
    mul_uint64(b_part, f_part, &bf);
    mul_uint64(c_part, e_part, &ce);
    mul_uint64(c_part, f_part, &cf);
    mul_uint64(d_part, e_part, &de);
    mul_uint64(d_part, f_part, &df);

    result->lo = df.lo;
    result->mid_lo = cf.lo + de.lo + df.hi;
    result->mid_hi = bf.lo + ce.lo + cf.hi + de.hi;
    result->hi = af.lo + be.lo + ce.hi + bf.hi;

    result->mid_hi += DETERMINE_ADD_CARRY_PRESENCE(de.lo + cf.lo, df.hi, result->mid_lo);
    result->hi += DETERMINE_ADD_CARRY_PRESENCE(ce.lo + bf.lo, de.hi + cf.hi, result->mid_hi);    

}

int my_mod_p(struct my_uint256_t *a, struct my_uint256_t *result) {
    if (!a || !result) {
        return -1;
    }

    uint64_t carry_mid_lo = 0, carry_mid_hi = 0, carry_hi = 0, carry_tmp_1 = 0, carry_tmp_2 = 0;
    uint64_t res_hi = 0, res_mid_hi = 0, res_mid_lo = 0, res_lo = 0;
    uint64_t hi_lut = 0, mid_lut = 0, lo_lut = 0;

    uint32_t unroll_factor = 16;

    uint32_t i = 0;
    for (int j=0; j<64/unroll_factor; j++) { 

        REPEAT_16(
            if (a->lo & (1 << i)) {
                hi_lut = mod_lut[3*i];
                mid_lut = mod_lut[3*i + 1];
                lo_lut = mod_lut[3*i + 2];
                
                carry_tmp_1 = res_lo + lo_lut;
                carry_mid_lo = DETERMINE_ADD_CARRY_PRESENCE(res_lo, lo_lut, carry_tmp_1); // res_lo + lo_lut < res_lo;
                res_lo += lo_lut;

                // carry_tmp_1 = (mid_lut + carry_mid_lo); // this itself will never overflow since carry is at most 1
                carry_tmp_2 = res_mid_lo + (mid_lut + carry_mid_lo);
                carry_mid_hi = DETERMINE_ADD_CARRY_PRESENCE(res_mid_lo, mid_lut + carry_mid_lo, carry_tmp_2); // res_mid_lo + mid_lut + carry_mid_lo < res_mid_lo;
                
                // This alternative might be slightly better for verification but is incorrect if the carry causes overflow
                // carry_tmp_1 = mid_lut + res_mid_lo;
                // carry_mid_hi = ((mid_lut & res_mid_lo) | ((mid_lut | res_mid_lo) & ~carry_tmp_1)) >> 63;
                res_mid_lo += mid_lut + carry_mid_lo;


                carry_tmp_1 = res_mid_hi + (hi_lut + carry_mid_hi);
                carry_hi = DETERMINE_ADD_CARRY_PRESENCE(res_mid_hi, hi_lut + carry_mid_hi, carry_tmp_1); // res_hi + hi_lut + carry_mid_hi < res_hi;
                res_mid_hi += hi_lut + carry_mid_hi;

                res_hi += carry_hi;
            }
            i++;
        )
    }

    i = 0;
    for (int j=0; j<64/unroll_factor; j++) {

        REPEAT_16(
            if (a->mid_lo & (1 << i)) {
                hi_lut = mod_lut[192 + 3*i];
                mid_lut = mod_lut[192 + 3*i + 1];
                lo_lut = mod_lut[192 + 3*i + 2];
                
                carry_tmp_1 = res_lo + lo_lut;
                carry_mid_lo = DETERMINE_ADD_CARRY_PRESENCE(res_lo, lo_lut, carry_tmp_1); // res_lo + lo_lut < res_lo;
                res_lo += lo_lut;

                // carry_tmp_1 = (mid_lut + carry_mid_lo); // this itself will never overflow since carry is at most 1
                carry_tmp_2 = res_mid_lo + (mid_lut + carry_mid_lo);
                carry_mid_hi = DETERMINE_ADD_CARRY_PRESENCE(res_mid_lo, mid_lut + carry_mid_lo, carry_tmp_2); // res_mid_lo + mid_lut + carry_mid_lo < res_mid_lo;
                
                // This alternative might be slightly better for verification but is incorrect if the carry causes overflow
                // carry_tmp_1 = mid_lut + res_mid_lo;
                // carry_mid_hi = ((mid_lut & res_mid_lo) | ((mid_lut | res_mid_lo) & ~carry_tmp_1)) >> 63;
                res_mid_lo += mid_lut + carry_mid_lo;


                carry_tmp_1 = res_mid_hi + (hi_lut + carry_mid_hi);
                carry_hi = DETERMINE_ADD_CARRY_PRESENCE(res_mid_hi, hi_lut + carry_mid_hi, carry_tmp_1); // res_hi + hi_lut + carry_mid_hi < res_hi;
                res_mid_hi += hi_lut + carry_mid_hi;

                res_hi += carry_hi;
            }
            i++;
        )
    }

    i = 0;
    for (int j=0; j<64/unroll_factor; j++) {
        REPEAT_16(
            if (a->mid_hi & (1 << i)) {
                hi_lut = mod_lut[384 + 3*i];
                mid_lut = mod_lut[384 + 3*i + 1];
                lo_lut = mod_lut[384 + 3*i + 2];
                
                carry_tmp_1 = res_lo + lo_lut;
                carry_mid_lo = DETERMINE_ADD_CARRY_PRESENCE(res_lo, lo_lut, carry_tmp_1); // res_lo + lo_lut < res_lo;
                res_lo += lo_lut;

                // carry_tmp_1 = (mid_lut + carry_mid_lo); // this itself will never overflow since carry is at most 1
                carry_tmp_2 = res_mid_lo + (mid_lut + carry_mid_lo);
                carry_mid_hi = DETERMINE_ADD_CARRY_PRESENCE(res_mid_lo, mid_lut + carry_mid_lo, carry_tmp_2); // res_mid_lo + mid_lut + carry_mid_lo < res_mid_lo;
                
                // This alternative might be slightly better for verification but is incorrect if the carry causes overflow
                // carry_tmp_1 = mid_lut + res_mid_lo;
                // carry_mid_hi = ((mid_lut & res_mid_lo) | ((mid_lut | res_mid_lo) & ~carry_tmp_1)) >> 63;
                res_mid_lo += mid_lut + carry_mid_lo;


                carry_tmp_1 = res_mid_hi + (hi_lut + carry_mid_hi);
                carry_hi = DETERMINE_ADD_CARRY_PRESENCE(res_mid_hi, hi_lut + carry_mid_hi, carry_tmp_1); // res_hi + hi_lut + carry_mid_hi < res_hi;
                res_mid_hi += hi_lut + carry_mid_hi;

                res_hi += carry_hi;
            }
            i++;
        )
    }

    i = 0;
    for (int j=0; j<64/unroll_factor; j++) {
        REPEAT_16(
            if (a->hi & (1 << i)) {
                hi_lut = mod_lut[576 + 3*i];
                mid_lut = mod_lut[576 + 3*i + 1];
                lo_lut = mod_lut[576 + 3*i + 2];
                
                carry_tmp_1 = res_lo + lo_lut;
                carry_mid_lo = DETERMINE_ADD_CARRY_PRESENCE(res_lo, lo_lut, carry_tmp_1); // res_lo + lo_lut < res_lo;
                res_lo += lo_lut;

                // carry_tmp_1 = (mid_lut + carry_mid_lo); // this itself will never overflow since carry is at most 1
                carry_tmp_2 = res_mid_lo + (mid_lut + carry_mid_lo);
                carry_mid_hi = DETERMINE_ADD_CARRY_PRESENCE(res_mid_lo, mid_lut + carry_mid_lo, carry_tmp_2); // res_mid_lo + mid_lut + carry_mid_lo < res_mid_lo;
                
                // This alternative might be slightly better for verification but is incorrect if the carry causes overflow
                // carry_tmp_1 = mid_lut + res_mid_lo;
                // carry_mid_hi = ((mid_lut & res_mid_lo) | ((mid_lut | res_mid_lo) & ~carry_tmp_1)) >> 63;
                res_mid_lo += mid_lut + carry_mid_lo;


                carry_tmp_1 = res_mid_hi + (hi_lut + carry_mid_hi);
                carry_hi = DETERMINE_ADD_CARRY_PRESENCE(res_mid_hi, hi_lut + carry_mid_hi, carry_tmp_1); // res_hi + hi_lut + carry_mid_hi < res_hi;
                res_mid_hi += hi_lut + carry_mid_hi;

                res_hi += carry_hi;
            }
            i++;
        )
    }

    result->lo = res_lo;
    result->mid_lo = res_mid_lo;
    result->mid_hi = res_mid_hi;
    result->hi = res_hi;    
    return 0;
}

__attribute__((always_inline)) clamp(struct my_uint128_t *x) {
    x->lo &= clamp_lo;
    x->hi &= clamp_hi;
}

__attribute__((always_inline))
 int validate_tag(struct decryption_bundle_t *decryption_bundle) {

    if (!decryption_bundle) {
        return -1;
    }

    uint8_t byte;
    uint64_t qword;

    uint8_t *read_address_key = (uint8_t *)(decryption_bundle->key); // TODO: handling correct / needed?

    // r = int.from_bytes(key[:16], "little")
    // r = clamp(r)
    struct my_uint128_t r = {0, 0};
    for (int i=0; i<8; i++) { // TODO: correct endianess?
        SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), read_address_key + i);
        r.lo |= (uint64_t)byte << (i * 8);
        read_address_key++;
    }
    for (int i=0; i<8; i++) {
        SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), read_address_key + i);
        r.hi |= (uint64_t)byte << (i * 8);
        read_address_key++;      
    }
    clamp(&r);

    // s = int.from_bytes(key[16:], "little")
    struct my_uint128_t s = {0, 0};

    for (int i=0; i<8; i++) {
        SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), read_address_key + i);
        s.lo |= (uint64_t)byte << (i * 8);
        read_address_key++;
    }
    for (int i=0; i<8; i++) {
        SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), read_address_key + i);
        s.hi |= (uint64_t)byte << (i * 8);      
        read_address_key++;  
    }

    // a = 0
    struct my_uint256_t a = {0, 0, 0, 0};
    struct my_uint256_t a_old;

    // p = (1 << 130) - 5
    // p is static

    uint32_t additional_data_padding =  decryption_bundle->additional_data_size % 16 == 0 ?
                                        0 : 16 - (decryption_bundle->additional_data_size % 16);

    uint32_t payload_padding =  decryption_bundle->decyption_size % 16 == 0 ?
                                0 : 16 - (decryption_bundle->decyption_size % 16);

    uint32_t total_length = decryption_bundle->additional_data_size + additional_data_padding +
                            decryption_bundle->decyption_size + payload_padding +
                            8 + 8; // 8 bytes for additional_data_size and decryption_size as uint64_t each


    //! Write data into the linearized padded map
    uint32_t ctr = 0;

    uint32_t limit_add_data = decryption_bundle->additional_data_size;
    for (int i=0; i<MAX_ADDITIONAL_DATA_SIZE; i+=8) {
        if (i >= limit_add_data) {
            // TODO: potentially do semi read with padding
            break;
        }
        bpf_probe_read_kernel(&qword, sizeof(qword), decryption_bundle->additional_data + i);
        bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
        ctr++;
    }
    // TODO: wrong
    // for (int i=0; i<16; i++) { // Implicitly done since map has type uint64_t
    //     if (i >= additional_data_padding) {
    //         break;
    //     }
    //     byte = 0;
    //     bpf_map_update_elem(&linearized_padded_data, &ctr, &byte, BPF_ANY);
    //     ctr++;
    // }
    // TODO: right
    // 7 bytes and less will be done implicitly because of uint64_t.
    // If we need more then we add one more qword.
    // The padding is never >= 16.
    if (additional_data_padding > 7 && additional_data_padding < 16) { // TODO: fine like this or better do sthg with "even number of loop iterations"?
        qword = 0;
        bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
        ctr++;
    }

    uint32_t limit_payload = decryption_bundle->decyption_size;
    for (int i=0; i<MAX_PAYLOAD_SIZE/16; i+=0) { // TODO: due to REPEAT_16 i+=0 should be needed since manual i+=8 is in the loop
        REPEAT_16({
        if (i >= limit_payload) {
            // TODO: potentially do semi read with padding
            break;
        }
        bpf_probe_read_kernel(&qword, sizeof(qword), decryption_bundle->payload + i);
        bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
        ctr++;
        i += 8;
        });
    }
    // TODO: wrong
    // for (int i=0; i<16; i++) { // Implicitly done since map has type uint64_t
    //     if (i >= payload_padding) {
    //         break;
    //     }
    //     byte = 0;
    //     bpf_map_update_elem(&linearized_padded_data, &ctr, &byte, BPF_ANY);
    //     ctr++;
    // }
    // TODO: right
    // 7 bytes and less will be done implicitly because of uint64_t.
    // If we need more then we add one more qword.
    // The padding is never >= 16.
    if (payload_padding > 7 && payload_padding < 16) { // TODO: fine like this or better do sthg with "even number of loop iterations"?
        qword = 0;
        bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
        ctr++;
    }


    // TODO: wrong
    // for (int i=0; i<8; i++) {
    //     qword = (decryption_bundle->additional_data_size >> (8 * i)) & 0xff;
    //     bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
    //     ctr++;
    // }
    // for (int i=0; i<8; i++) {
    //     qword = (decryption_bundle->decyption_size >> (8 * i)) & 0xff;
    //     bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
    //     ctr++;
    // }

    // TODO: right
    qword = 0;
    qword |= (decryption_bundle->additional_data_size & 0x000000ff) << 56;
    qword |= (decryption_bundle->additional_data_size & 0x0000ff00) << 48;
    qword |= (decryption_bundle->additional_data_size & 0x00ff0000) << 40;
    qword |= (decryption_bundle->additional_data_size & 0xff000000) << 32;
    bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
    ctr++;

    qword = 0;
    qword |= (decryption_bundle->decyption_size & 0x000000ff) << 56;
    qword |= (decryption_bundle->decyption_size & 0x0000ff00) << 48;
    qword |= (decryption_bundle->decyption_size & 0x00ff0000) << 40;
    qword |= (decryption_bundle->decyption_size & 0xff000000) << 32;
    bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
    ctr++;
    

    uint32_t iterations = (total_length / 16) + (total_length % 16 == 0 ? 0 : 1);
    // iterations is maximally (MAX_ADDITIONAL_DATA_SIZE + MAX_PAYLOAD_SIZE + POLY1305_TAG_SIZE + 16) / 16 = ceil((1500 + 21 + 16 + 16) / 16) = 98
    // TODO: do with max iterations
    //*
    struct my_uint256_t block = {0, 0, 0, 0};
    uint64_t *lo;
    uint64_t*hi;
    for (uint32_t i=0; i<100; i++) {

        if (i >= iterations) {
            break;
        }

        block.lo = 1;
        block.mid_lo = 0;
        block.mid_hi = 0;
        block.hi = 0;

        uint32_t index = i;
        *hi = bpf_map_lookup_elem(&linearized_padded_data, &index);
        if (hi == NULL) {
            return 1;
        }
        index = i + 1;
        *lo = bpf_map_lookup_elem(&linearized_padded_data, &index);
        if (lo == NULL) {
            return 1;
        }

        // block.hi = 0;
        block.mid_hi = (*hi) >> 56;
        block.mid_lo = ((*lo) >> 56) | ((*hi) << 8);
        block.lo |= ((*lo) << 8); // The added 0x01 is already in the lo part

        // a += n
        a_old = a;
        add_my_uint256(&a_old, &block, &a);

        // a = (r * a) % p
        // TODO
        a_old = a;
        mul_my_uint256_with_my_uint128(&a_old, &r, &a);
        a_old = a;
        my_mod_p(&a_old, &a); // https://electronics.stackexchange.com/questions/608840/verilog-modulus-operator-for-non-power-of-two-synthetizable/608854#608854
    }
    //*/

    // a += s
    a_old = a;
    add_my_uint128(&a_old, &s, &a);

    // Now the 128 least significant bits of a should be equal to the tag
    // TODO: check this
    uint64_t created_tag_lo = a.lo;
    uint64_t created_tag_hi = a.hi;

    uint32_t dbg_i = 0;
    uint8_t expected_tag_byte;
    uint8_t tag_byte;
    REPEAT_8({
        tag_byte = (created_tag_lo >> (dbg_i * 8)) & 0xff;
        SAVE_BPF_PROBE_READ_KERNEL(&expected_tag_byte, sizeof(expected_tag_byte), decryption_bundle->tag + dbg_i);
        bpf_printk("Tag byte %d: %d, %d\n", dbg_i++, tag_byte, expected_tag_byte);
    });

    REPEAT_8({
        tag_byte = (created_tag_hi >> (dbg_i * 8)) & 0xff;
        SAVE_BPF_PROBE_READ_KERNEL(&expected_tag_byte, sizeof(expected_tag_byte), decryption_bundle->tag + dbg_i);
        bpf_printk("Tag byte %d: %d, %d\n", dbg_i++, tag_byte, expected_tag_byte);
    });
        
    return 0;
}
