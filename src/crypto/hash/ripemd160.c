//
// Created by M Lunkeit on 11.08.26.
//

#ifndef BASALT_RIPEMD160_H
#define BASALT_RIPEMD160_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "basalt/mem.h"

#define F1(x,y,z) ((x) ^ (y) ^ (z))
#define F2(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define F3(x,y,z) (((x) | ~(y)) ^ (z))
#define F4(x,y,z) (((x) & (z)) | ((y) & ~(z)))
#define F5(x,y,z) ((x) ^ ((y) | ~(z)))

static constexpr uint8_t r_left[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

static constexpr uint8_t r_right[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

static constexpr uint8_t shifts_left[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7,
    13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9,
    14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6,
    15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5
};

static constexpr uint8_t shifts_right[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

static constexpr uint32_t K_left[5] = {0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e};
static constexpr uint32_t K_right[5] = {0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000};

static constexpr uint32_t H0[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};

size_t ripemd160_pad(uint32_t *output, const uint8_t *input, const size_t len) {
    const size_t blocks = 1 + (len >> 6) + ((len & 0x3F) >= 56 ? 1 : 0);

    uint8_t buf[blocks * 64];
    memset(buf, 0, blocks * 64 * sizeof(uint8_t));
    memcpy(buf, input, len * sizeof(uint8_t));
    memset(buf + len, 0x80, sizeof(uint8_t));

    const size_t bitlen = len << 3;

    for (size_t i = 0; i < 8; i++) {
        buf[blocks * 64 - 8 + i] = (uint8_t) (bitlen >> (i * 8));
    }

    for (size_t i = 0; i < blocks * 16; i++) {
        output[i] = (buf[i * 4]
            | (buf[i * 4 + 1] << 8)
            | (buf[i * 4 + 2] << 16)
            | (buf[i * 4 + 3] << 24));
    }

    basalt_memzero(buf, blocks * 64);

    return blocks;
}

#endif //BASALT_RIPEMD160_H
