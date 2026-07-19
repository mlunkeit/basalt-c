//
// Created by M Lunkeit on 17.07.26.
//

#include "modular.h"
#include "bigint.h"

void modular_init(modular_ctx *ctx, const uint256_t *modulus) {
    ctx->modulus = *modulus;
}

void modular_add_assign(modular_ctx *ctx, uint256_t *a, const uint256_t *b) {
    uint256_t tmp = ctx->modulus;
    uint256_sub_assign(&tmp, b);

    // if a > n - b
    if (uint256_cmp(a, &tmp) > 0) {
        // a - (n - b) = a + b - n
        uint256_sub_assign(a, &tmp);
        return;
    }

    uint256_add_assign(a, b);
}

void modular_neg_assign(modular_ctx *ctx, uint256_t *a) {
    uint256_t zero = {{0}};

    if (uint256_cmp(a, &zero) == 0) {
        return;
    }

    uint256_neg_assign(a);
    uint256_add_assign(a, &ctx->modulus);
}

void modular_sub_assign(modular_ctx *ctx, uint256_t *a, const uint256_t *b) {
    uint256_t tmp = *b;
    modular_neg_assign(ctx, &tmp);
    modular_add_assign(ctx, a, &tmp);
}

void modular_mul_assign(modular_ctx *ctx, uint256_t *a, const uint256_t *b) {
    uint256_t result;
}