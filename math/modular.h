//
// Created by M Lunkeit on 17.07.26.
//

#ifndef BASALT_MODULAR_H
#define BASALT_MODULAR_H

#include "bigint.h"

typedef struct modular_ctx {
    uint32_t *modulus;
    size_t len_modulus;
} modular_ctx;

void modular_init(modular_ctx *ctx, const uint32_t *modulus, size_t modulus_len);

void modular_add_raw(modular_ctx *ctx, uint32_t *result, const uint32_t *a, size_t len_a, const uint32_t *b, size_t len_b);

void modular_sub_raw(modular_ctx *ctx, uint32_t *result, const uint32_t *a, size_t len_a, const uint32_t *b, size_t len_b);

void modular_neg_raw(modular_ctx *ctx, uint32_t *result, const uint32_t *a, size_t len_a);

#endif //BASALT_MODULAR_H
