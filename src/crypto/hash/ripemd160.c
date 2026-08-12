//
// Created by M Lunkeit on 11.08.26.
//

#ifndef BASALT_RIPEMD160_H
#define BASALT_RIPEMD160_H

#include <stdint.h>
#include <string.h>

#include "basalt/mem.h"
#include "crypto/hash/ripemd160.h"

#define ROL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

typedef uint32_t (*ripemd_func)(uint32_t x, uint32_t y, uint32_t z);

static uint32_t F1(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static uint32_t F2(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static uint32_t F3(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
static uint32_t F4(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static uint32_t F5(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

static const ripemd_func F_left[5] = { F1, F2, F3, F4, F5 };
static const ripemd_func F_right[5] = { F5, F4, F3, F2, F1 };

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
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
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
    const size_t blocks = (len + 72) >> 6;

    uint8_t buf[blocks * 64];
    memset(buf, 0, blocks * 64 * sizeof(uint8_t));
    memcpy(buf, input, len * sizeof(uint8_t));
    memset(buf + len, 0x80, sizeof(uint8_t));

    const uint64_t bitlen = (uint64_t) len << 3;

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

void ripemd160(uint8_t output[20], const uint8_t *input, const size_t len) {
    const size_t blocks = (len + 72) >> 6;

    uint32_t buf[blocks * 16];
    memset(buf, 0, blocks * 16 * sizeof(uint32_t));
    ripemd160_pad(buf, input, len);

    uint32_t H[5];
    memcpy(H, H0, 5 * sizeof(uint32_t));

    for (size_t i = 0; i < blocks; i++) {
        uint32_t A_left = H[0];
        uint32_t B_left = H[1];
        uint32_t C_left = H[2];
        uint32_t D_left = H[3];
        uint32_t E_left = H[4];

        uint32_t A_right = H[0];
        uint32_t B_right = H[1];
        uint32_t C_right = H[2];
        uint32_t D_right = H[3];
        uint32_t E_right = H[4];

        for (size_t j = 0; j < 80; j++) {
            ripemd_func f_left = F_left[j / 16];
            uint32_t T = ROL(A_left + f_left(B_left, C_left, D_left) + buf[i * 16 + r_left[j]] + K_left[j / 16], shifts_left[j]) + E_left;
            A_left = E_left;
            E_left = D_left;
            D_left = ROL(C_left, 10);
            C_left = B_left;
            B_left = T;

            ripemd_func f_right = F_right[j / 16];
            T = ROL(A_right + f_right(B_right, C_right, D_right) + buf[i * 16 + r_right[j]] + K_right[j / 16], shifts_right[j]) + E_right;
            A_right = E_right;
            E_right = D_right;
            D_right = ROL(C_right, 10);
            C_right = B_right;
            B_right = T;
        }

        const uint32_t T = H[1] + C_left + D_right;
        H[1] = H[2] + D_left + E_right;
        H[2] = H[3] + E_left + A_right;
        H[3] = H[4] + A_left + B_right;
        H[4] = H[0] + B_left + C_right;
        H[0] = T;
    }

    for (size_t i = 0; i < 5; i++) {
        output[i * 4] = (uint8_t) H[i];
        output[i * 4 + 1] = (uint8_t) (H[i] >> 8);
        output[i * 4 + 2] = (uint8_t) (H[i] >> 16);
        output[i * 4 + 3] = (uint8_t) (H[i] >> 24);
    }
}

#endif //BASALT_RIPEMD160_H
