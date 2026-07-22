//
// Created by M Lunkeit on 17.07.26.
//

#include <string.h>

#include "modular.h"
#include "bigint.h"

void modular_init(modular_ctx *ctx, const uint32_t *modulus, const size_t modulus_len) {
    ctx->modulus = (uint32_t*) modulus;
    ctx->len_modulus = modulus_len;
}

void modular_add_raw(const modular_ctx *ctx, uint32_t *result, const uint32_t *a, const size_t len_a, const uint32_t *b, const size_t len_b) {
    size_t maxsize = len_a > len_b ? len_a : len_b;

    uint32_t buf[maxsize + 1];
    memset(buf, 0, sizeof(uint32_t) * (maxsize + 1));
    bigint_add_raw(buf, a, len_a, b, len_b);

    if (bigint_cmp_raw(buf, maxsize + 1, ctx->modulus, ctx->len_modulus) >= 0) {
        uint32_t sub_buf[maxsize + 1];
        memset(sub_buf, 0, sizeof(uint32_t) * (maxsize + 1));
        bigint_sub_raw(sub_buf, buf, maxsize + 1, ctx->modulus, ctx->len_modulus);
        memcpy(result, sub_buf, sizeof(uint32_t) * ctx->len_modulus);
        return;
    }

    memcpy(result, buf, sizeof(uint32_t) * ctx->len_modulus);
}

void modular_sub_raw(const modular_ctx *ctx, uint32_t *result, const uint32_t *a, const size_t len_a, const uint32_t *b, const size_t len_b) {
    uint32_t buf[ctx->len_modulus];
    memcpy(buf, b, sizeof(uint32_t) * len_b);
    modular_neg_raw(ctx, buf, buf, len_b);
    modular_add_raw(ctx, result, buf, len_b, a, len_a);
}

void modular_neg_raw(const modular_ctx *ctx, uint32_t *result, const uint32_t *a, const size_t len_a) {
    if (bigint_cmp_raw(a, len_a, nullptr, 0) == 0) {
        memset(result, 0, sizeof(uint32_t) * ctx->len_modulus);
        return;
    }

    uint32_t buf[ctx->len_modulus];
    memcpy(buf, ctx->modulus, sizeof(uint32_t) * ctx->len_modulus);
    bigint_sub_raw(result, buf, ctx->len_modulus, a, len_a);
}