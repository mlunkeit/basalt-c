//
// Created by M Lunkeit on 24.07.26.
//

#include "../../math/bigint.h"
#include "../../math/barrett.h"
#include "../../math/modular.h"
#include "rfc6979.h"
#include "ecdsa.h"

#include <stdio.h>
#include <string.h>

void ecdsa_sign(
    const wcurve_spec_t *wcurve,
    ecdsa_signature_t *sig,
    const ecdsa_private_key_t *key,
    const uint8_t *hash, const size_t len_hash)
{
    const barrett_ctx bar_ctx = {.modulus = wcurve->n, .mu = wcurve->mu_n, .k = wcurve->len_n};
    const modular_ctx mod_ctx = {.modulus = wcurve->n, .len_modulus = wcurve->len_n};

    uint32_t half_n[wcurve->len_n];
    memcpy(half_n, wcurve->n, wcurve->len_n * sizeof(uint32_t));
    bigint_shr_raw(half_n, half_n, wcurve->len_n, 1);

    uint32_t h[wcurve->len_n];
    bytes_to_bigint(h, hash, len_hash);

    uint8_t privkey_bytes[32];
    bigint_to_bytes(privkey_bytes, key->d, 32);

    uint32_t k[wcurve->len_n];
    rfc6979(k, privkey_bytes, hash, wcurve->n);

    wcurve_point_t R;
    wcurve_point_scale(wcurve, &R, &wcurve->g, k);

    uint32_t dr[wcurve->len_n];
    barrett_mul(&bar_ctx, dr, key->d, R.x);

    uint32_t dividend[wcurve->len_n];
    modular_add_raw(&mod_ctx, dividend, h, wcurve->len_n, dr, wcurve->len_n);

    barrett_inv(&bar_ctx, k, k);

    uint32_t s[wcurve->len_n];
    barrett_mul(&bar_ctx, s, dividend, k);

    if (bigint_cmp_raw(s, wcurve->len_n, half_n, wcurve->len_n) >= 0) {
        modular_neg_raw(&mod_ctx, s, s, wcurve->len_n);
    }

    uint32_t rbuf[2 * wcurve->len_n];
    memset(rbuf, 0, 2 * wcurve->len_n * sizeof(uint32_t));
    memcpy(rbuf, R.x, wcurve->len_p * sizeof(uint32_t));

    barrett_reduce(&bar_ctx, sig->r, rbuf);
    memcpy(sig->s, s, sizeof(uint32_t) * wcurve->len_n);
}

bool ecdsa_verify(
    const wcurve_spec_t *wcurve,
    const ecdsa_public_key_t *key,
    const uint8_t *hash, size_t len_hash,
    const ecdsa_signature_t *sig)
{
    const barrett_ctx bar_ctx = {.modulus = wcurve->n, .mu = wcurve->mu_n, .k = wcurve->len_n};
    const modular_ctx mod_ctx = {.modulus = wcurve->n, .len_modulus = wcurve->len_n};

    uint32_t half_n[wcurve->len_n];
    memcpy(half_n, wcurve->n, wcurve->len_n * sizeof(uint32_t));
    bigint_shr_raw(half_n, half_n, wcurve->len_n, 1);

    if (bigint_cmp_raw(sig->s, wcurve->len_n, half_n, wcurve->len_n) >= 0) {
        // s has to be less than floor(n/2)
        return false;
    }

    uint32_t h[wcurve->len_n];
    bytes_to_bigint(h, hash, len_hash);

    // w = s^(-1) mod n
    uint32_t w[wcurve->len_n];
    barrett_inv(&bar_ctx, w, sig->s);

    // u1 = w * h(x) mod n
    uint32_t u1[wcurve->len_n];
    barrett_mul(&bar_ctx, u1, w, h);

    // u2 = w * r mod n
    uint32_t u2[wcurve->len_n];
    barrett_mul(&bar_ctx, u2, w, sig->r);

    wcurve_point_t A = wcurve->g;

    wcurve_point_t B = {0};

    // P = u1 * A + u2 * B
    wcurve_point_t P = {0};

    wcurve_point_scale(wcurve, &A, &A, u1);

    wcurve_point_scale(wcurve, &B, &key->point, u2);

    wcurve_point_add(wcurve, &P, &A, &B);

    if (P.infinity) {
        return false;
    }

    uint32_t Pxbuf[16] = {0};
    memcpy(Pxbuf, &P.x, 8 * sizeof(uint32_t));

    uint256_t xp;
    barrett_reduce(&bar_ctx, xp.limbs, Pxbuf);

    return bigint_cmp_raw(xp.limbs, wcurve->len_n, sig->r, wcurve->len_n) == 0;
}