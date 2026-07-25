//
// Created by M Lunkeit on 17.07.26.
//

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "../bigint.h"
#include "../modular.h"
#include "../barrett.h"

#include "secp256k1.h"

static constexpr uint256_t modulus = {
    {
        0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    }};

static constexpr uint256_t p_minus_2 = {
    {
        0xFFFFFC2D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    }};

static constexpr uint32_t mu[9] = {
    0x000003D1, 0x00000001, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001
};

static const modular_ctx mod_ctx = {.modulus = (uint32_t*) modulus.limbs, .len_modulus = 8};

static const barrett_ctx bar_ctx = {.modulus = (uint32_t*) modulus.limbs, .mu = (uint32_t*) mu, .k = 8};

void secp256k1_reduce(uint256_t *result, uint32_t x[16]) {
    barrett_reduce(&bar_ctx, result->limbs, x);
}

void secp256k1_mul(uint256_t *result, const uint256_t *a, const uint256_t *b) {
    barrett_mul(&bar_ctx, result->limbs, a->limbs, b->limbs);
}

void secp256k1_pow(uint256_t *result, const uint256_t *a, const uint256_t *b) {
    barrett_pow(&bar_ctx, result->limbs, a->limbs, b->limbs);
}

void secp256k1_invert(uint256_t *result, const uint256_t *a) {
    barrett_inv(&bar_ctx, result->limbs, a->limbs);
}

bool secp256k1_point_equal(const secp256k1_point_t *a, const secp256k1_point_t *b) {
    if (a->infinity != b->infinity) {
        return false;
    }

    if (bigint_cmp_raw(a->x.limbs, 8, b->x.limbs, 8) != 0) {
        return false;
    }

    if (bigint_cmp_raw(a->y.limbs, 8, b->y.limbs, 8) != 0) {
        return false;
    }

    return true;
}

void secp256k1_tangent_slope(uint256_t *result, const secp256k1_point_t *a) {
    uint256_t x_squared;
    secp256k1_mul(&x_squared, &a->x, &a->x);

    // 2. dividend = 3 * x^2 = x^2 + x^2 + x^2 (mod p)
    uint256_t dividend;
    modular_add_raw(&mod_ctx, dividend.limbs, x_squared.limbs, 8, x_squared.limbs, 8); // 2x^2
    modular_add_raw(&mod_ctx, dividend.limbs, dividend.limbs, 8, x_squared.limbs, 8);

    // divisor = 2y
    uint256_t divisor;
    modular_add_raw(&mod_ctx, divisor.limbs, a->y.limbs, 8, a->y.limbs, 8);

    uint256_t inv_divisor;
    secp256k1_invert(&inv_divisor, &divisor);

    // result = 3x^2 / 2y
    secp256k1_mul(result, &dividend, &inv_divisor);
}

void secp256k1_points_slope(uint256_t *result, const secp256k1_point_t *a, const secp256k1_point_t *b) {
    if (secp256k1_point_equal(a, b)) {
        secp256k1_tangent_slope(result, a);
        return;
    }

    uint256_t dividend;
    modular_sub_raw(&mod_ctx, dividend.limbs, a->y.limbs, 8, b->y.limbs, 8);

    uint256_t divisor;
    modular_sub_raw(&mod_ctx, divisor.limbs, a->x.limbs, 8, b->x.limbs, 8);
    secp256k1_invert(&divisor, &divisor);

    secp256k1_mul(result, &dividend, &divisor);
}

bool secp256k1_test_slope_for_infinity(const secp256k1_point_t *a, const secp256k1_point_t *b) {
    if (secp256k1_point_equal(a, b)) {
        return bigint_cmp_raw(a->y.limbs, 8, nullptr, 0) == 0;
    }

    return bigint_cmp_raw(a->x.limbs, 8, b->x.limbs, 8) == 0;
}

void secp256k1_point_init(secp256k1_point_t *point) {
    memcpy(point, &SECP256K1_G, sizeof(secp256k1_point_t));
}

void secp256k1_point_add(secp256k1_point_t *result, const secp256k1_point_t *a, const secp256k1_point_t *b) {

    if (a->infinity) {
        memcpy(result, b, sizeof(secp256k1_point_t));
        return;
    }

    if (b->infinity) {
        memcpy(result, a, sizeof(secp256k1_point_t));
        return;
    }

    if (secp256k1_test_slope_for_infinity(a, b)) {
        result->infinity = true;
        return;
    }

    uint256_t slope;
    secp256k1_points_slope(&slope, a, b);

    // c = y - mx
    uint256_t offset;
    secp256k1_mul(&offset, &slope, &a->x);
    modular_neg_raw(&mod_ctx, offset.limbs, offset.limbs, 8);
    modular_add_raw(&mod_ctx, offset.limbs, a->y.limbs, 8, offset.limbs, 8);

    // x3 = m^2 - x2 - x1
    uint256_t m_squared;
    secp256k1_mul(&m_squared, &slope, &slope);

    uint256_t x3;
    modular_sub_raw(&mod_ctx, x3.limbs, m_squared.limbs, 8, b->x.limbs, 8);
    modular_sub_raw(&mod_ctx, x3.limbs, x3.limbs, 8, a->x.limbs, 8);

    // y3 = -m * x3 - c
    uint256_t y3;
    secp256k1_mul(&y3, &slope, &x3);
    modular_neg_raw(&mod_ctx, y3.limbs, y3.limbs, 8);
    modular_sub_raw(&mod_ctx, y3.limbs, y3.limbs, 8, offset.limbs, 8);

    result->infinity = false;
    result->x = x3;
    result->y = y3;
}

void secp256k1_point_scale(secp256k1_point_t *result, const secp256k1_point_t *point, const uint256_t *k) {
    secp256k1_point_t acc = {0};
    acc.infinity = true;

    uint256_t scalar;
    memcpy(&scalar, k, sizeof(uint256_t));

    secp256k1_point_t summand;
    memcpy(&summand, point, sizeof(secp256k1_point_t));

    while (bigint_cmp_raw(scalar.limbs, 8, nullptr, 0) > 0) {
        if (scalar.limbs[0] & 0x1) {
            secp256k1_point_add(&acc, &acc, &summand);
        }

        secp256k1_point_add(&summand, &summand, &summand);
        bigint_shr_raw(scalar.limbs, scalar.limbs, 8, 1);
    }

    memcpy(result, &acc, sizeof(secp256k1_point_t));
}