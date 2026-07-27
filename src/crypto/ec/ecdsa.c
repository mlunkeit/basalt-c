//
// Created by M Lunkeit on 24.07.26.
//

#include "math/bigint.h"
#include "math/barrett.h"
#include "math/modular.h"
#include "crypto/ec/rfc6979.h"
#include "crypto/ec/ecdsa.h"

#include <string.h>

void ecdsa_sign(
    const wcurve_spec_t *wcurve,
    uint32_t *r,
    uint32_t *s,
    const uint32_t *d,
    const uint8_t *hash, const size_t len_hash)
{
    const barrett_ctx bar_ctx = {.modulus = wcurve->n, .mu = wcurve->mu_n, .k = wcurve->len_n};
    const modular_ctx mod_ctx = {.modulus = wcurve->n, .len_modulus = wcurve->len_n};

    uint32_t half_n[wcurve->len_n];
    memcpy(half_n, wcurve->n, wcurve->len_n * sizeof(uint32_t));
    bigint_shr_raw(half_n, half_n, wcurve->len_n, 1);

    uint32_t h[wcurve->len_n];
    bytes_to_bigint(h, hash, len_hash);

    uint32_t k[wcurve->len_n];
    rfc6979(wcurve, k, d, hash, len_hash);

    wcurve_point_t R;
    wcurve_point_scale(wcurve, &R, &wcurve->g, k);

    uint32_t dr[wcurve->len_n];
    barrett_mul(&bar_ctx, dr, d, R.x);

    uint32_t dividend[wcurve->len_n];
    modular_add_raw(&mod_ctx, dividend, h, wcurve->len_n, dr, wcurve->len_n);

    barrett_inv(&bar_ctx, k, k);

    barrett_mul(&bar_ctx, s, dividend, k);

    if (bigint_cmp_raw(s, wcurve->len_n, half_n, wcurve->len_n) >= 0) {
        modular_neg_raw(&mod_ctx, s, s, wcurve->len_n);
    }

    uint32_t rbuf[2 * wcurve->len_n];
    memset(rbuf, 0, 2 * wcurve->len_n * sizeof(uint32_t));
    memcpy(rbuf, R.x, wcurve->len_p * sizeof(uint32_t));
    barrett_reduce(&bar_ctx, r, rbuf);
}

bool ecdsa_verify(
    const wcurve_spec_t *wcurve,
    const wcurve_point_t *e,
    const uint8_t *hash, const size_t len_hash,
    const uint32_t *r,
    const uint32_t *s)
{
    const barrett_ctx bar_ctx = {.modulus = wcurve->n, .mu = wcurve->mu_n, .k = wcurve->len_n};

    uint32_t half_n[wcurve->len_n];
    memcpy(half_n, wcurve->n, wcurve->len_n * sizeof(uint32_t));
    bigint_shr_raw(half_n, half_n, wcurve->len_n, 1);

    if (bigint_cmp_raw(s, wcurve->len_n, half_n, wcurve->len_n) >= 0) {
        // s has to be less than floor(n/2)
        return false;
    }

    uint32_t h[wcurve->len_n];
    bytes_to_bigint(h, hash, len_hash);

    // w = s^(-1) mod n
    uint32_t w[wcurve->len_n];
    barrett_inv(&bar_ctx, w, s);

    // u1 = w * h(x) mod n
    uint32_t u1[wcurve->len_n];
    barrett_mul(&bar_ctx, u1, w, h);

    // u2 = w * r mod n
    uint32_t u2[wcurve->len_n];
    barrett_mul(&bar_ctx, u2, w, r);

    wcurve_point_t A = {0};
    wcurve_point_t B = {0};

    // P = u1 * G + u2 * E
    wcurve_point_t P = {0};

    wcurve_point_scale(wcurve, &A, &wcurve->g, u1);
    wcurve_point_scale(wcurve, &B, e, u2);

    wcurve_point_add(wcurve, &P, &A, &B);

    if (P.infinity) {
        return false;
    }

    uint32_t Pxbuf[16] = {0};
    memcpy(Pxbuf, &P.x, wcurve->len_p * sizeof(uint32_t));

    uint256_t xp;
    barrett_reduce(&bar_ctx, xp.limbs, Pxbuf);

    return bigint_cmp_raw(xp.limbs, wcurve->len_n, r, wcurve->len_n) == 0;
}
