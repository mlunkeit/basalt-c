//
// Created by M Lunkeit on 17.07.26.
//

#include <stdint.h>
#include <string.h>

#include "../bigint.h"
#include "../modular.h"
#include "../barrett.h"

#include "secp256k1.h"

typedef struct {
    uint256_t x;
    uint256_t y;
    uint256_t z;

    bool infinity;
} secp256k1_point_jacobian_t;

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

void secp256k1_point_jacobian_double(secp256k1_point_jacobian_t *result, const secp256k1_point_jacobian_t *point) {
    static constexpr uint256_t three = {.limbs = {3, 0, 0, 0, 0, 0, 0, 0}};
    static constexpr uint256_t four = {.limbs = {4, 0, 0, 0, 0, 0, 0, 0}};
    static constexpr uint256_t eight = {.limbs = {8, 0, 0, 0, 0, 0, 0, 0}};

    if (point->infinity) {
        result->infinity = true;
        return;
    }

    if (bigint_cmp_raw(point->y.limbs, 8, nullptr, 0) == 0) {
        result->infinity = true;
        return;
    }

    // M = 3 * X^2
    uint256_t M;
    secp256k1_mul(&M, &three, &point->x);
    secp256k1_mul(&M, &M, &point->x);

    // S = 4 * X * Y^2
    uint256_t S;
    secp256k1_mul(&S, &four, &point->x);
    secp256k1_mul(&S, &S, &point->y);
    secp256k1_mul(&S, &S, &point->y);

    // T = 8 * Y^4
    uint256_t T;
    secp256k1_mul(&T, &eight, &point->y);
    secp256k1_mul(&T, &T, &point->y);
    secp256k1_mul(&T, &T, &point->y);
    secp256k1_mul(&T, &T, &point->y);

    // X3 = M^2 - 2 * S
    uint256_t X3;
    secp256k1_mul(&X3, &M, &M);
    modular_sub_raw(&mod_ctx, X3.limbs, X3.limbs, 8, S.limbs, 8);
    modular_sub_raw(&mod_ctx, X3.limbs, X3.limbs, 8, S.limbs, 8);

    uint256_t S_minus_X3;
    modular_sub_raw(&mod_ctx, S_minus_X3.limbs, S.limbs, 8, X3.limbs, 8);

    // Y3 = M * (S - X3) - T
    uint256_t Y3;
    secp256k1_mul(&Y3, &M, &S_minus_X3);
    modular_sub_raw(&mod_ctx, Y3.limbs, Y3.limbs, 8, T.limbs, 8);

    // Z3 = 2 * Y * Z
    uint256_t Z3;
    secp256k1_mul(&Z3, &point->y, &point->z);
    modular_add_raw(&mod_ctx, Z3.limbs, Z3.limbs, 8, Z3.limbs, 8);

    result->infinity = false;
    result->x = X3;
    result->y = Y3;
    result->z = Z3;
}

void secp256k1_point_jacobian_add(secp256k1_point_jacobian_t *result, const secp256k1_point_jacobian_t *a, const secp256k1_point_jacobian_t *b) {
    if (a->infinity) {
        memcpy(result, b, sizeof(secp256k1_point_jacobian_t));
        return;
    }

    if (b->infinity) {
        memcpy(result, a, sizeof(secp256k1_point_jacobian_t));
        return;
    }

    // U_1 = X_1 * Z_2^2
    uint256_t U1;
    secp256k1_mul(&U1, &a->x, &b->z);   // U1 <- X_1 * Z_2
    secp256k1_mul(&U1, &U1, &b->z);     // U1 <- U_1 * Z_2

    // U_2 = X_2 * Z_1^2
    uint256_t U2;
    secp256k1_mul(&U2, &b->x, &a->z);   // U2 <- X_2 * Z_1
    secp256k1_mul(&U2, &U2, &a->z);     // U2 <- U_2 * Z_1

    // S_1 = Y_1 * Z_2^3
    uint256_t S1;
    secp256k1_mul(&S1, &a->y, &b->z);   // S1 <- Y_1 * Z_2
    secp256k1_mul(&S1, &S1, &b->z);     // S1 <- S_1 * Z_2
    secp256k1_mul(&S1, &S1, &b->z);     // S1 <- S_1 * Z_2

    // S_2 = Y_2 * Z_1^3
    uint256_t S2;
    secp256k1_mul(&S2, &b->y, &a->z);   // S_2 <- Y_2 * Z_1
    secp256k1_mul(&S2, &S2, &a->z);     // S_2 <- S_2 * Z_1
    secp256k1_mul(&S2, &S2, &a->z);     // S_2 <- S_2 * Z_1

    // H = U2 - U1
    uint256_t H;
    modular_sub_raw(&mod_ctx, H.limbs, U2.limbs, 8, U1.limbs, 8);

    // R = S2 - S1
    uint256_t R;
    modular_sub_raw(&mod_ctx, R.limbs, S2.limbs, 8, S1.limbs, 8);

    if (bigint_cmp_raw(H.limbs, 8, nullptr, 0) == 0) {

        if (bigint_cmp_raw(R.limbs, 8, nullptr, 0) != 0) {
            result->infinity = true;
            return;
        }

        secp256k1_point_jacobian_double(result, a);
        return;
    }

    uint256_t H_squared;
    secp256k1_mul(&H_squared, &H, &H);

    uint256_t H_pow3;
    secp256k1_mul(&H_pow3, &H_squared, &H);

    // V = U1 * H^2
    uint256_t V;
    secp256k1_mul(&V, &U1, &H_squared);

    // W = S1 * H^3
    uint256_t W;
    secp256k1_mul(&W, &S1, &H_pow3);

    uint256_t R_squared;
    secp256k1_mul(&R_squared, &R, &R);

    uint256_t X3;
    modular_sub_raw(&mod_ctx, X3.limbs, R_squared.limbs, 8, H_pow3.limbs, 8); // X3 <- R^2 - H^3
    modular_sub_raw(&mod_ctx, X3.limbs, X3.limbs, 8, V.limbs, 8); // X3 <- X3 - U_1*H^2
    modular_sub_raw(&mod_ctx, X3.limbs, X3.limbs, 8, V.limbs, 8); // X3 <- X3 - U_1*H^2

    uint256_t Z3;
    secp256k1_mul(&Z3, &H, &a->z);
    secp256k1_mul(&Z3, &Z3, &b->z);

    uint256_t V_minus_X3;
    modular_sub_raw(&mod_ctx, V_minus_X3.limbs, V.limbs, 8, X3.limbs, 8);

    // Y3 = R * (V - X3) - W
    uint256_t Y3;
    secp256k1_mul(&Y3, &R, &V_minus_X3);
    modular_sub_raw(&mod_ctx, Y3.limbs, Y3.limbs, 8, W.limbs, 8);

    result->infinity = false;
    result->x = X3;
    result->y = Y3;
    result->z = Z3;
}

void secp256k1_point_scale(secp256k1_point_t *result, const secp256k1_point_t *point, const uint256_t *k) {
    secp256k1_point_jacobian_t acc = {0};
    acc.infinity = true;

    uint256_t scalar;
    memcpy(&scalar, k, sizeof(uint256_t));

    secp256k1_point_jacobian_t summand;
    memcpy(&summand.x, &point->x, sizeof(uint256_t));
    memcpy(&summand.y, &point->y, sizeof(uint256_t));
    memset(&summand.z, 0, sizeof(uint256_t));
    summand.z.limbs[0] = 1;
    summand.infinity = point->infinity;

    while (bigint_cmp_raw(scalar.limbs, 8, nullptr, 0) > 0) {
        if (scalar.limbs[0] & 0x1) {
            secp256k1_point_jacobian_add(&acc, &acc, &summand);
        }

        secp256k1_point_jacobian_add(&summand, &summand, &summand);
        bigint_shr_raw(scalar.limbs, scalar.limbs, 8, 1);
    }

    if (acc.infinity) {
        result->infinity = true;
        return;
    }

    result->infinity = false;

    uint256_t Z_squared;
    secp256k1_mul(&Z_squared, &acc.z, &acc.z);

    uint256_t Z_squared_inv;
    secp256k1_invert(&Z_squared_inv, &Z_squared);

    uint256_t Z_pow3;
    secp256k1_mul(&Z_pow3, &Z_squared, &acc.z);

    uint256_t Z_pow3_inv;
    secp256k1_invert(&Z_pow3_inv, &Z_pow3);

    secp256k1_mul(&result->x, &acc.x, &Z_squared_inv);
    secp256k1_mul(&result->y, &acc.y, &Z_pow3_inv);
}