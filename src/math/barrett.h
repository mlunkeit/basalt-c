//
// Created by M Lunkeit on 22.07.26.
//

#ifndef BASALT_BARRETT_H
#define BASALT_BARRETT_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    // contains k 32-bit words
    const uint32_t *modulus;
    // contains k+1 32-bit words
    const uint32_t *mu;

    size_t k;
} barrett_ctx;

void barrett_reduce(const barrett_ctx *ctx, uint32_t *result, const uint32_t *input);

void barrett_mul(const barrett_ctx *ctx, uint32_t *result, const uint32_t *a, const uint32_t *b);

void barrett_pow(const barrett_ctx *ctx, uint32_t *result, const uint32_t *a, const uint32_t *b);

void barrett_inv(const barrett_ctx *ctx, uint32_t *result, const uint32_t *a);

#endif //BASALT_BARRETT_H
