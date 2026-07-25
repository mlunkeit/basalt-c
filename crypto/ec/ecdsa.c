//
// Created by M Lunkeit on 24.07.26.
//

#include "../../math/bigint.h"
#include "../../math/barrett.h"
#include "../../math/modular.h"
#include "../../math/curves/secp256k1.h"
#include "rfc6979.h"
#include "ecdsa.h"

#include <stdio.h>
#include <string.h>

void ecdsa_sign_secp256k1(uint8_t output[64], const uint8_t privkey[32], const uint8_t hash[32]) {
    static constexpr uint32_t MU[9] = {0x2FC9BEC0, 0x402DA173, 0x50B75FC4, 0x45512319, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001};
    static const barrett_ctx BAR_CTX = {.modulus = SECP256K1_N.limbs, .mu = MU, .k = 8};
    static const modular_ctx MOD_CTX = {.modulus = SECP256K1_N.limbs, .len_modulus = 8};

    static constexpr uint32_t HALF_N[8] = {0x681B20A0, 0xDFE92F46, 0x57A4501D, 0x5D576E73, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF};

    uint256_t h;
    bytes_to_bigint(h.limbs, hash, 32);

    uint256_t d;
    bytes_to_bigint(d.limbs, privkey, 32);

    uint256_t k;
    rfc6979(&k, privkey, hash, &SECP256K1_N);

    secp256k1_point_t R;
    secp256k1_point_scale(&R, &SECP256K1_G, &k);

    uint256_t dr;
    barrett_mul(&BAR_CTX, dr.limbs, d.limbs, R.x.limbs);

    uint256_t dividend = {0};
    modular_add_raw(&MOD_CTX, dividend.limbs, h.limbs, 8, dr.limbs, 8);

    barrett_inv(&BAR_CTX, k.limbs, k.limbs);

    uint256_t s;
    barrett_mul(&BAR_CTX, s.limbs, dividend.limbs, k.limbs);

    if (bigint_cmp_raw(s.limbs, 8, HALF_N, 8) >= 0) {
        modular_neg_raw(&MOD_CTX, s.limbs, s.limbs, 8);
    }

    bigint_to_bytes(output, R.x.limbs, 8);
    bigint_to_bytes(output + 32, s.limbs, 8);
}

bool ecdsa_verify_secp256k1(uint8_t input[64], const uint8_t pubkey[65], const uint8_t hash[32]) {
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