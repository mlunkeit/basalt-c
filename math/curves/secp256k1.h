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

extern secp256k1_point_t SECP256K1_G;

void secp256k1_point_init(secp256k1_point_t *point);

bool secp256k1_point_equal(const secp256k1_point_t *a, const secp256k1_point_t *b);

void secp256k1_point_add(secp256k1_point_t *result, const secp256k1_point_t *a, const secp256k1_point_t *b);

#endif //BASALT_SECP256K1_H
