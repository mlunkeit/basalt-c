//
// Created by M Lunkeit on 26.07.26.
//

#include <string.h>

#include "basalt/mem.h"
#include "math/bigint.h"
#include "math/modular.h"
#include "math/barrett.h"
#include "math/curves/wcurve.h"

void wcurve_point_add(
    const wcurve_spec_t *wcurve,
    wcurve_point_t *result,
    const wcurve_point_t *a,
    const wcurve_point_t *b)
{
    wcurve_point_jacobian_t ajac;
    wcurve_point_affin_to_jacobian(wcurve, &ajac, a);

    wcurve_point_jacobian_t bjac;
    wcurve_point_affin_to_jacobian(wcurve, &bjac, b);

    wcurve_point_jacobian_t sumjac;
    wcurve_point_jacobian_add(wcurve, &sumjac, &ajac, &bjac);

    wcurve_point_jacobian_to_affin(wcurve, result, &sumjac);
}

void wcurve_point_scale(
    const wcurve_spec_t *wcurve,
    wcurve_point_t *result,
    const wcurve_point_t *point,
    const uint32_t *k)
{
    wcurve_point_jacobian_t pjac;
    wcurve_point_affin_to_jacobian(wcurve, &pjac, point);

    wcurve_point_jacobian_t sjac;
    wcurve_point_jacobian_scale(wcurve, &sjac, &pjac, k);

    wcurve_point_jacobian_to_affin(wcurve, result, &sjac);
}

void wcurve_point_jacobian_double(
    const wcurve_spec_t *wcurve,
    wcurve_point_jacobian_t *result,
    const wcurve_point_jacobian_t *point)
{
    const modular_ctx mod_ctx = {.modulus = wcurve->p, .len_modulus = wcurve->len_p};
    const barrett_ctx bar_ctx = {.modulus = wcurve->p, .k = wcurve->len_p, .mu = wcurve->mu_p};

    uint32_t three[wcurve->len_p];
    memset(three, 0, sizeof(uint32_t) * wcurve->len_p);
    three[0] = 3;

    uint32_t four[wcurve->len_p];
    memset(four, 0, sizeof(uint32_t) * wcurve->len_p);
    four[0] = 4;

    uint32_t eight[wcurve->len_p];
    memset(eight, 0, sizeof(uint32_t) * wcurve->len_p);
    eight[0] = 8;

    if (point->infinity) {
        result->infinity = true;
        return;
    }

    if (bigint_cmp_raw(point->y, wcurve->len_p, nullptr, 0) == 0) {
        result->infinity = true;
        return;
    }

    // M = 3 * X^2 + aZ^4
    uint32_t M[wcurve->len_p];
    barrett_mul(&bar_ctx, M, three, point->x);
    barrett_mul(&bar_ctx, M, M, point->x);

    uint32_t aZ_pow4[wcurve->len_p];
    barrett_mul(&bar_ctx, aZ_pow4, wcurve->a, point->z);
    barrett_mul(&bar_ctx, aZ_pow4, aZ_pow4, point->z);
    barrett_mul(&bar_ctx, aZ_pow4, aZ_pow4, point->z);
    barrett_mul(&bar_ctx, aZ_pow4, aZ_pow4, point->z);

    // M <- M + aZ^4
    modular_add_raw(&mod_ctx, M, M, wcurve->len_p, aZ_pow4, wcurve->len_p);

    // S = 4 * X * Y^2
    uint32_t S[wcurve->len_p];
    barrett_mul(&bar_ctx, S, four, point->x);
    barrett_mul(&bar_ctx, S, S, point->y);
    barrett_mul(&bar_ctx, S, S, point->y);

    // T = 8 * Y^4
    uint32_t T[wcurve->len_p];
    barrett_mul(&bar_ctx, T, eight, point->y);
    barrett_mul(&bar_ctx, T, T, point->y);
    barrett_mul(&bar_ctx, T, T, point->y);
    barrett_mul(&bar_ctx, T, T, point->y);

    // X3 = M^2 - 2 * S
    uint32_t X3[wcurve->len_p];
    barrett_mul(&bar_ctx, X3, M, M);
    modular_sub_raw(&mod_ctx, X3, X3, wcurve->len_p, S, wcurve->len_p);
    modular_sub_raw(&mod_ctx, X3, X3, wcurve->len_p, S, wcurve->len_p);

    uint32_t S_minus_X3[wcurve->len_p];
    modular_sub_raw(&mod_ctx, S_minus_X3, S, wcurve->len_p, X3, wcurve->len_p);

    // Y3 = M * (S - X3) - T
    uint32_t Y3[wcurve->len_p];
    barrett_mul(&bar_ctx, Y3, M, S_minus_X3);
    modular_sub_raw(&mod_ctx, Y3, Y3, wcurve->len_p, T, wcurve->len_p);

    // Z3 = 2 * Y * Z
    uint32_t Z3[wcurve->len_p];
    barrett_mul(&bar_ctx, Z3, point->y, point->z);
    modular_add_raw(&mod_ctx, Z3, Z3, wcurve->len_p, Z3, wcurve->len_p);

    result->infinity = false;
    memcpy(result->x, X3, sizeof(uint32_t) * wcurve->len_p);
    memcpy(result->y, Y3, sizeof(uint32_t) * wcurve->len_p);
    memcpy(result->z, Z3, sizeof(uint32_t) * wcurve->len_p);
}

void wcurve_point_jacobian_add(
    const wcurve_spec_t *wcurve,
    wcurve_point_jacobian_t *result,
    const wcurve_point_jacobian_t *a,
    const wcurve_point_jacobian_t *b)
{
    const modular_ctx mod_ctx = {.modulus = wcurve->p, .len_modulus = wcurve->len_p};
    const barrett_ctx bar_ctx = {.modulus = wcurve->p, .k = wcurve->len_p, .mu = wcurve->mu_p};

    if (a->infinity) {
        memcpy(result, b, sizeof(wcurve_point_jacobian_t));
        return;
    }

    if (b->infinity) {
        memcpy(result, a, sizeof(wcurve_point_jacobian_t));
        return;
    }

    // U_1 = X_1 * Z_2^2
    uint32_t U1[wcurve->len_p];
    barrett_mul(&bar_ctx, U1, a->x, b->z);  // U1 <- X_1 * Z_2
    barrett_mul(&bar_ctx, U1, U1, b->z);    // U1 <- U_1 * Z_2

    // U_2 = X_2 * Z_1^2
    uint32_t U2[wcurve->len_p];
    barrett_mul(&bar_ctx, U2, b->x, a->z);  // U2 <- X_2 * Z_1
    barrett_mul(&bar_ctx, U2, U2, a->z);    // U2 <- U_2 * Z_1

    // S_1 = Y_1 * Z_2^3
    uint32_t S1[wcurve->len_p];
    barrett_mul(&bar_ctx, S1, a->y, b->z);  // S1 <- Y_1 * Z_2
    barrett_mul(&bar_ctx, S1, S1, b->z);    // S1 <- S_1 * Z_2
    barrett_mul(&bar_ctx, S1, S1, b->z);    // S1 <- S_1 * Z_2

    // S_2 = Y_2 * Z_1^3
    uint32_t S2[wcurve->len_p];
    barrett_mul(&bar_ctx, S2, b->y, a->z);   // S_2 <- Y_2 * Z_1
    barrett_mul(&bar_ctx, S2, S2, a->z);     // S_2 <- S_2 * Z_1
    barrett_mul(&bar_ctx, S2, S2, a->z);     // S_2 <- S_2 * Z_1

    // H = U2 - U1
    uint32_t H[wcurve->len_p];
    modular_sub_raw(&mod_ctx, H, U2, wcurve->len_p, U1, wcurve->len_p);

    // R = S2 - S1
    uint32_t R[wcurve->len_p];
    modular_sub_raw(&mod_ctx, R, S2, wcurve->len_p, S1, wcurve->len_p);

    if (bigint_cmp_raw(H, wcurve->len_p, nullptr, 0) == 0) {
        if (bigint_cmp_raw(R, wcurve->len_p, nullptr, 0) != 0) {
            result->infinity = true;
            return;
        }

        wcurve_point_jacobian_double(wcurve, result, a);
        return;
    }

    uint32_t H_squared[wcurve->len_p];
    barrett_mul(&bar_ctx, H_squared, H, H);

    uint32_t H_pow3[wcurve->len_p];
    barrett_mul(&bar_ctx, H_pow3, H_squared, H);

    // V = U1 * H^2
    uint32_t V[wcurve->len_p];
    barrett_mul(&bar_ctx, V, U1, H_squared);

    // W = S1 * H^3
    uint32_t W[wcurve->len_p];
    barrett_mul(&bar_ctx, W, S1, H_pow3);

    uint32_t R_squared[wcurve->len_p];
    barrett_mul(&bar_ctx, R_squared, R, R);

    uint32_t X3[wcurve->len_p];
    modular_sub_raw(&mod_ctx, X3, R_squared, wcurve->len_p, H_pow3, wcurve->len_p);   // X3 <- R^2 - H^3
    modular_sub_raw(&mod_ctx, X3, X3, wcurve->len_p, V, wcurve->len_p);               // X3 <- X3 - U_1*H^2
    modular_sub_raw(&mod_ctx, X3, X3, wcurve->len_p, V, wcurve->len_p);               // X3 <- X3 - U_1*H^2

    // Z_3 = H * Z_1 * Z_2
    uint32_t Z3[wcurve->len_p];
    barrett_mul(&bar_ctx, Z3, H, a->z);
    barrett_mul(&bar_ctx, Z3, Z3, b->z);

    uint32_t V_minus_X3[wcurve->len_p];
    modular_sub_raw(&mod_ctx, V_minus_X3, V, wcurve->len_p, X3, wcurve->len_p);

    // Y3 = R * (V - X3) - W
    uint32_t Y3[wcurve->len_p];
    barrett_mul(&bar_ctx, Y3, R, V_minus_X3);
    modular_sub_raw(&mod_ctx, Y3, Y3, wcurve->len_p, W, wcurve->len_p);

    result->infinity = false;
    memcpy(result->x, X3, wcurve->len_p * sizeof(uint32_t));
    memcpy(result->y, Y3, wcurve->len_p * sizeof(uint32_t));
    memcpy(result->z, Z3, wcurve->len_p * sizeof(uint32_t));
}

void wcurve_point_jacobian_scale(
    const wcurve_spec_t *wcurve,
    wcurve_point_jacobian_t *result,
    const wcurve_point_jacobian_t *point,
    const uint32_t *k)
{
    wcurve_point_jacobian_t acc = {0};
    acc.infinity = true;

    uint32_t scalar[wcurve->len_n];
    memcpy(scalar, k, sizeof(uint32_t) * wcurve->len_n);

    wcurve_point_jacobian_t summand;
    memcpy(&summand, point, sizeof(wcurve_point_jacobian_t));

    while (bigint_cmp_raw(scalar, wcurve->len_n, nullptr, 0) > 0) {
        if (scalar[0] & 0x1) {
            wcurve_point_jacobian_add(wcurve, &acc, &acc, &summand);
        }

        wcurve_point_jacobian_add(wcurve, &summand, &summand, &summand);
        bigint_shr_raw(scalar, scalar, wcurve->len_n, 1);
    }

    memcpy(result, &acc, sizeof(wcurve_point_jacobian_t));

    // clear sensible data from memory
    basalt_memzero(scalar, sizeof(uint32_t) * wcurve->len_n);
}

void wcurve_point_affin_to_jacobian(
    const wcurve_spec_t *wcurve,
    wcurve_point_jacobian_t *jacobian,
    const wcurve_point_t *affin)
{
    if (affin->infinity) {
        jacobian->infinity = true;
        return;
    }

    memset(jacobian, 0, sizeof(wcurve_point_jacobian_t));

    memcpy(jacobian->x, affin->x, sizeof(uint32_t) * wcurve->len_p);
    memcpy(jacobian->y, affin->y, sizeof(uint32_t) * wcurve->len_p);

    jacobian->z[0] = 1;
    jacobian->infinity = false;
}

void wcurve_point_jacobian_to_affin(
    const wcurve_spec_t *wcurve,
    wcurve_point_t *affin,
    const wcurve_point_jacobian_t *jacobian)
{
    if (jacobian->infinity) {
        affin->infinity = true;
        return;
    }

    const barrett_ctx bar_ctx = {.modulus = wcurve->p, .k = wcurve->len_p, .mu = wcurve->mu_p};

    memset(affin, 0, sizeof(wcurve_point_t));

    uint32_t Z_squared[wcurve->len_p];
    barrett_mul(&bar_ctx, Z_squared, jacobian->z, jacobian->z);

    uint32_t Z_pow3[wcurve->len_p];
    barrett_mul(&bar_ctx, Z_pow3, Z_squared, jacobian->z);

    uint32_t Z_squared_inv[wcurve->len_p];
    barrett_inv(&bar_ctx, Z_squared_inv, Z_squared);

    uint32_t Z_pow3_inv[wcurve->len_p];
    barrett_inv(&bar_ctx, Z_pow3_inv, Z_pow3);

    barrett_mul(&bar_ctx, affin->x, jacobian->x, Z_squared_inv);
    barrett_mul(&bar_ctx, affin->y, jacobian->y, Z_pow3_inv);
    affin->infinity = false;
}
