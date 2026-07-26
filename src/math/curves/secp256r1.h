//
// Created by M Lunkeit on 26.07.26.
//

#ifndef BASALT_SECP256R1_H
#define BASALT_SECP256R1_H

#include "../bigint.h"

typedef struct {
    uint256_t x;
    uint256_t y;
    bool infinity;
} secp256r1_point_t;

static constexpr uint256_t SECP256R1_P = {.limbs = {
    0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xffffffff
}};

static constexpr secp256r1_point_t SECP256R1_G = {
    .x = {.limbs = {
        0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81,
        0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2
    }},
    .y = {.limbs = {
        0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357,
        0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2
    }}
};

static constexpr uint256_t SECP256R1_N = {.limbs = {
    0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad,
    0xffffffff, 0xffffffff, 0x00000000, 0xffffffff
}};

static constexpr uint256_t SECP256R1_A = {.limbs = {
    0xfffffffc, 0xffffffff, 0xffffffff, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xffffffff
}};

static constexpr uint256_t SECP256R1_B = {.limbs = {
    0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0,
    0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8
}};

bool secp256r1_point_equal(const secp256r1_point_t *a, const secp256r1_point_t *b);

void secp256r1_point_add(secp256r1_point_t *result, const secp256r1_point_t *a, const secp256r1_point_t *b);

void secp256r1_point_scale(secp256r1_point_t *result, const secp256r1_point_t *point, const uint256_t *k);

#endif //BASALT_SECP256R1_H
