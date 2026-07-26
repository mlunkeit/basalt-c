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

    memcpy(sig->r, R.x, sizeof(uint32_t) * wcurve->len_p);
    memcpy(sig->s, s, sizeof(uint32_t) * wcurve->len_n);
}

bool ecdsa_verify(
    const wcurve_spec_t *curve,
    const uint8_t *pubkey,
    const uint8_t *hash, size_t len_hash,
    const ecdsa_signature_t *sig)
{
    if (pubkey[0] != 0x04) {
        // public key is not in a valid uncompressed format
        return false;
    }

    static constexpr uint32_t MU[9] = {0x2FC9BEC0, 0x402DA173, 0x50B75FC4, 0x45512319, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001};
    static const barrett_ctx BAR_CTX = {.modulus = SECP256K1_N.limbs, .mu = MU, .k = 8};

    static constexpr uint32_t HALF_N[8] = {0x681B20A0, 0xDFE92F46, 0x57A4501D, 0x5D576E73, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF};

    uint256_t r;
    bytes_to_bigint(r.limbs, input, 32);

    uint256_t s;
    bytes_to_bigint(s.limbs, input + 32, 32);

    if (bigint_cmp_raw(s.limbs, 8, HALF_N, 8) >= 0) {
        // s has to be less than floor(n/2)
        return false;
    }

    uint256_t h;
    bytes_to_bigint(h.limbs, hash, 32);

    // w = s^(-1) mod n
    uint256_t w;
    barrett_inv(&BAR_CTX, w.limbs, s.limbs);

    // u1 = w * h(x) mod n
    uint256_t u1;
    barrett_mul(&BAR_CTX, u1.limbs, w.limbs, h.limbs);

    // u2 = w * r mod n
    uint256_t u2;
    barrett_mul(&BAR_CTX, u2.limbs, w.limbs, r.limbs);

    secp256k1_point_t A = SECP256K1_G;

    secp256k1_point_t B;
    B.infinity = false;
    bytes_to_bigint(B.x.limbs, pubkey + 1, 32);
    bytes_to_bigint(B.y.limbs, pubkey + 33, 32);

    // P = u1 * A + u2 * B
    secp256k1_point_t P = {0};

    secp256k1_point_scale(&A, &SECP256K1_G, &u1);

    secp256k1_point_scale(&B, &B, &u2);

    secp256k1_point_add(&P, &A, &B);

    if (P.infinity) {
        return false;
    }

    uint32_t Pxbuf[16] = {0};
    memcpy(Pxbuf, &P.x.limbs, 8 * sizeof(uint32_t));

    uint256_t xp;
    barrett_reduce(&BAR_CTX, xp.limbs, Pxbuf);

    return bigint_cmp_raw(xp.limbs, 8, r.limbs, 8) == 0;
}