//
// Created by M Lunkeit on 17.07.26.
//

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "../math/bigint.h"
#include "../math/modular.h"

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

static const modular_ctx ctx = {.modulus = (uint32_t*) modulus.limbs, .len_modulus = 8};

static constexpr secp256k1_point_t SECP256K1_P = {
    .x = {{0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}},
    .y = {{0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}},
    .infinity = false
};

/*********************************************************
 *                  BARRETT REDUCTION
 *
 * This is an implementation of the special case of the
 * barrett reduction. It reduces the input to the modulus
 * required by the secp256k1 elliptic curve. It can
 * only handle this special case with 32-bit words.
 *********************************************************/

void secp256k1_reduce(uint256_t *result, uint32_t x[16]) {
    uint32_t q1[9] = {0};
    memcpy(q1, x + 7, sizeof(uint32_t) * 9);

    uint32_t q2[18] = {0};
    bigint_mul_raw(q2, q1, 9, mu, 9);

    uint32_t q3[9];
    memcpy(q3, q2 + 9, sizeof(q3));

    uint32_t r1[9];
    memcpy(r1, x, sizeof(r1));

    uint32_t r2[17] = {0};
    bigint_mul_raw(r2, q3, 9, modulus.limbs, 8);
    memset(r2 + 9, 0, sizeof(uint32_t) * 8);

    uint32_t r[10] = {0};
    bigint_sub_raw(r, r1, 9, r2, 9);

    result_t rmcmp = bigint_cmp_raw(r, 9, modulus.limbs, 8);

    while (rmcmp >= 0) {
        bigint_sub_raw(r, r, 9, modulus.limbs, 8);
        rmcmp = bigint_cmp_raw(r, 9, modulus.limbs, 8);
    }

    memcpy(result->limbs, r, sizeof(uint32_t) * 8);
}

void secp256k1_mul(uint256_t *result, const uint256_t *a, const uint256_t *b) {
    uint32_t buf[16];
    bigint_mul_raw(buf, a->limbs, 8, b->limbs, 8);
    secp256k1_reduce(result, buf);
}

/*********************************************************
 *                 SQUARE AND MULTIPLY
 *
 * This is an implementation of the square and multiply
 * algorithm that uses barrett reduction to efficiently
 * compute big multiplications.
 *********************************************************/

void secp256k1_pow(uint256_t *result, const uint256_t *a, const uint256_t *b) {
    uint256_t buf;
    memset(&buf, 0, sizeof(uint256_t));
    buf.limbs[0] = 1;

    uint256_t coeff;
    memcpy(&coeff, a, sizeof(uint256_t));

    uint256_t exp;
    memcpy(&exp, b, sizeof(uint256_t));

    result_t cmpresult = bigint_cmp_raw(exp.limbs, 8, nullptr, 0);
    while (cmpresult > 0) {

        if (exp.limbs[0] & 1) {
            secp256k1_mul(&buf, &buf, &coeff);
        }

        bigint_shr_raw(exp.limbs, exp.limbs, 8, 1);
        secp256k1_mul(&coeff, &coeff, &coeff);

        cmpresult = bigint_cmp_raw(exp.limbs, 8, nullptr, 0);
    }

    memcpy(result, &buf, sizeof(uint256_t));
}

void secp256k1_invert(uint256_t *result, const uint256_t *a) {
    // Using Fermats little theorem to find the multiplicative inverse element of a.
    secp256k1_pow(result, a, &p_minus_2);
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
    modular_add_raw(&ctx, dividend.limbs, x_squared.limbs, 8, x_squared.limbs, 8); // 2x^2
    modular_add_raw(&ctx, dividend.limbs, dividend.limbs, 8, x_squared.limbs, 8);

    // divisor = 2y
    uint256_t divisor;
    modular_add_raw(&ctx, divisor.limbs, a->y.limbs, 8, a->y.limbs, 8);

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
    modular_sub_raw(&ctx, dividend.limbs, a->y.limbs, 8, b->y.limbs, 8);

    uint256_t divisor;
    modular_sub_raw(&ctx, divisor.limbs, a->x.limbs, 8, b->x.limbs, 8);
    secp256k1_invert(&divisor, &divisor);

    secp256k1_mul(result, &dividend, &divisor);
}

bool secp256k1_test_slope_for_infinity(const secp256k1_point_t *a, const secp256k1_point_t *b) {
    if (secp256k1_point_equal(a, b)) {
        return bigint_cmp_raw(a->y.limbs, 8, nullptr, 0) == 0;
    }

    return bigint_cmp_raw(a->x.limbs, 8, b->x.limbs, 8) == 0;
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
    modular_neg_raw(&ctx, offset.limbs, offset.limbs, 8);
    modular_add_raw(&ctx, offset.limbs, a->y.limbs, 8, offset.limbs, 8);

    // x3 = m^2 - x2 - x1
    uint256_t m_squared;
    secp256k1_mul(&m_squared, &slope, &slope);

    uint256_t x3;
    modular_sub_raw(&ctx, x3.limbs, m_squared.limbs, 8, b->x.limbs, 8);
    modular_sub_raw(&ctx, x3.limbs, x3.limbs, 8, a->x.limbs, 8);

    // y3 = -m * x3 - c
    uint256_t y3;
    secp256k1_mul(&y3, &slope, &x3);
    modular_neg_raw(&ctx, y3.limbs, y3.limbs, 8);
    modular_sub_raw(&ctx, y3.limbs, y3.limbs, 8, offset.limbs, 8);

    result->infinity = false;
    result->x = x3;
    result->y = y3;
}