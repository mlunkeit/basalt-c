//
// Created by M Lunkeit on 22.07.26.
//

#include <string.h>

#include "barrett.h"
#include "bigint.h"

void barrett_reduce(
    const barrett_ctx *ctx,
    uint32_t *result,
    const uint32_t *input)
{
    const size_t k = ctx->k;

    uint32_t q1[k + 1];
    memcpy(q1, input + k - 1, (k + 1) * sizeof(uint32_t));

    uint32_t q2[2 * k + 2];
    bigint_mul_raw(q2, q1, k + 1, ctx->mu, k + 1);

    uint32_t q3[k + 1];
    memcpy(q3, q2 + k + 1, (k + 1) * sizeof(uint32_t));

    uint32_t r1[k + 1];
    memcpy(r1, input, (k + 1) * sizeof(uint32_t));

    uint32_t r2[2 * k + 1];
    bigint_mul_raw(r2, q3, k + 1, ctx->modulus, k);

    uint32_t r[k + 2];
    bigint_sub_raw(r, r1, k + 1, r2, k + 1);

    result_t rmcmp = bigint_cmp_raw(r, k + 1, ctx->modulus, k);

    while (rmcmp >= 0) {
        bigint_sub_raw(r, r, k + 1, ctx->modulus, k);
        rmcmp = bigint_cmp_raw(r, k + 1, ctx->modulus, k);
    }

    memcpy(result, r, k * sizeof(uint32_t));
}

void barrett_mul(const barrett_ctx *ctx, uint32_t *result, const uint32_t *a, const uint32_t *b) {

    uint32_t buf[2 * ctx->k];
    memset(buf, 0, 2 * ctx->k * sizeof(uint32_t));
    bigint_mul_raw(buf, a, ctx->k, b, ctx->k);
    barrett_reduce(ctx, result, buf);
}

void barrett_pow(const barrett_ctx *ctx, uint32_t *result, const uint32_t *a, const uint32_t *b) {

    uint32_t acc[ctx->k];
    memset(acc, 0, ctx->k * sizeof(uint32_t));
    acc[0] = 1;

    uint32_t coeff[ctx->k];
    memcpy(coeff, a, ctx->k * sizeof(uint32_t));

    uint32_t exp[ctx->k];
    memcpy(exp, b, ctx->k * sizeof(uint32_t));

    while (bigint_cmp_raw(exp, ctx->k, nullptr, 0) > 0) {
        if (exp[0] & 0x1) {
            barrett_mul(ctx, acc, acc, coeff);
        }

        barrett_mul(ctx, coeff, coeff, coeff);
        bigint_shr_raw(exp, exp, ctx->k, 1);
    }

    memcpy(result, acc, ctx->k * sizeof(uint32_t));
}

void barrett_inv(const barrett_ctx *ctx, uint32_t *result, const uint32_t *a) {
    // Using Fermat's Little Theorem to invert an integer

    uint32_t p_minus_two[ctx->k];
    memcpy(p_minus_two, ctx->modulus, ctx->k * sizeof(uint32_t));

    static constexpr uint32_t two = 2;
    bigint_sub_raw(p_minus_two, p_minus_two, ctx->k, &two, 1);

    barrett_pow(ctx, result, a, p_minus_two);
}