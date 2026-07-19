//
// Created by M Lunkeit on 17.07.26.
//

#ifndef BASALT_MODULAR_H
#define BASALT_MODULAR_H

#include "bigint.h"

typedef struct modular_ctx {
    uint256_t modulus;
} modular_ctx;

void modular_init(modular_ctx *ctx, const uint256_t *modulus);

void modular_add_assign(modular_ctx *ctx, uint256_t *a, const uint256_t *b);

void modular_sub_assign(modular_ctx *ctx, uint256_t *a, const uint256_t *b);

void modular_neg_assign(modular_ctx *ctx, uint256_t *a);

#endif //BASALT_MODULAR_H
