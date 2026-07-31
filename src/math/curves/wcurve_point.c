//
// Created by M Lunkeit on 31.07.26.
//

#include <string.h>

#include "math/curves/wcurve_point.h"
#include "math/bigint.h"
#include "math/barrett.h"
#include "math/modular.h"

basalt_err_t wcurve_point_compress(
    const wcurve_spec_t *wcurve,
    uint8_t out[33],
    const wcurve_point_t *point)
{
    if (!wcurve || !out || !point) {
        return BASALT_ERR_NULL_POINTER;
    }

    if (point->infinity) {
        return BASALT_ERR_INVALID_PARAM;
    }

    if (point->y[0] & 0x1) {
        // y is odd
        out[0] = 0x3;
    } else {
        // y is even
        out[0] = 0x2;
    }

    bigint_to_bytes(out + 1, point->x, wcurve->len_p);
    return BASALT_OK;
}

basalt_err_t wcurve_point_decompress(
    const wcurve_spec_t *wcurve,
    wcurve_point_t *point,
    const uint8_t input[33])
{
    if (!wcurve || !point || !input) {
        return BASALT_ERR_NULL_POINTER;
    }

    if (input[0] != 0x02 && input[0] != 0x03) {
        return BASALT_ERR_INVALID_PARAM;
    }

    point->infinity = false;
    bytes_to_bigint(point->x, input + 1, 32);

    // y^2 = x^3 + ax + b

    const barrett_ctx bar_ctx = {.modulus = wcurve->p, .k = wcurve->len_p, .mu = wcurve->mu_p};
    const modular_ctx mod_ctx = {.modulus = wcurve->p, .len_modulus = wcurve->len_p};

    // we first calculate c, such that c = x^3 + ax + b
    uint32_t c[wcurve->len_p];
    // c <- x^3
    barrett_mul(&bar_ctx, c, point->x, point->x);   // c <- x^2
    barrett_mul(&bar_ctx, c, c, point->x);          // c <- c * x

    // c <- c + ax
    uint32_t ax[wcurve->len_p];
    barrett_mul(&bar_ctx, ax, wcurve->a, point->x);
    modular_add_raw(&mod_ctx, c, c, wcurve->len_p, ax, wcurve->len_p);

    // c <- c + b
    modular_add_raw(&mod_ctx, c, c, wcurve->len_p, wcurve->b, wcurve->len_p);

    // we now must find y such that y^2 = c
    // we will use fermat's little theorem and the fact that p mod 4 = 3

    // p = 4m + 3 <=> m = p >> 2
    // y = c^(m + 1) mod p
    uint32_t m[wcurve->len_p];
    bigint_shr_raw(m, wcurve->p, wcurve->len_p, 2);

    // y <- c^(m + 1)
    uint32_t y[wcurve->len_p];
    barrett_pow(&bar_ctx, y, c, m); // y <- c^m
    barrett_mul(&bar_ctx, y, y, c); // y <- y * c

    if ((y[0] & 0x1 && input[0] == 0x02) // y is odd but must be even
        || (!(y[0] & 0x1) && input[0] == 0x03) // y is even but must be odd
        ) {
        // y <- -y
        barrett_inv(&bar_ctx, y, y);
    }

    memcpy(point->y, y, wcurve->len_p * sizeof(uint32_t));

    return BASALT_OK;
}