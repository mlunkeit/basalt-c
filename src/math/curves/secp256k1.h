//
// Created by M Lunkeit on 17.07.26.
//

#ifndef BASALT_SECP256K1_H
#define BASALT_SECP256K1_H

#include "../bigint.h"

typedef struct {
    uint256_t x;
    uint256_t y;
    bool infinity;
} secp256k1_point_t;

// The prime modulus of the field.
static constexpr uint256_t SECP256K1_P = {{
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
}};

// The point that generates the cyclic group.
static constexpr secp256k1_point_t SECP256K1_G = {
    .x = {{0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}},
    .y = {{0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}},
    .infinity = false
};

// The prime order of the cyclic group.
static constexpr uint256_t SECP256K1_N = {{
    0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
}};

void secp256k1_point_init(secp256k1_point_t *point);

bool secp256k1_point_equal(const secp256k1_point_t *a, const secp256k1_point_t *b);

void secp256k1_point_add(secp256k1_point_t *result, const secp256k1_point_t *a, const secp256k1_point_t *b);

void secp256k1_point_scale(secp256k1_point_t *result, const secp256k1_point_t *point, const uint256_t *k);

#endif //BASALT_SECP256K1_H
