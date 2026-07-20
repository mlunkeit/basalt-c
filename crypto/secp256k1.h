//
// Created by M Lunkeit on 17.07.26.
//

#ifndef BASALT_SECP256K1_H
#define BASALT_SECP256K1_H

#include <stdint.h>

#include "../math/bigint.h"

typedef struct {
    uint256_t x;
    uint256_t y;
    bool infinity;
} secp256k1_point_t;

void secp256k1_point_init(secp256k1_point_t *point);

void secp256k1_point_add(secp256k1_point_t *result, const secp256k1_point_t *a, const secp256k1_point_t *b);

#endif //BASALT_SECP256K1_H
