//
// Created by M Lunkeit on 24.07.26.
//

#include <string.h>

#include "../../math/bigint.h"
#include "../../math/barrett.h"
#include "../../math/modular.h"
#include "../../math/curves/secp256k1.h"
#include "../mac/hmac.h"
#include "ecdsa.h"

void rfc6979(uint256_t *result, const uint8_t privkey[32], const uint8_t hash[32], const uint256_t *order) {
    uint8_t V[32];
    memset(V, 0x01, sizeof(V));

    uint8_t K[32];
    memset(K, 0x00, sizeof(K));

    uint8_t buf[97];
    memcpy(buf, V, 32 * sizeof(uint8_t));
    memset(buf + 32, 0x00, 1);
    memcpy(buf + 33, privkey, 32 * sizeof(uint8_t));
    memcpy(buf + 65, hash, 32 * sizeof(uint8_t));

    // K = HMAC_K(V || 0x00 || privkey || hash)
    hmac_sha256(K, K, 32, buf, 97);

    // V = HMAC_K(V)
    hmac_sha256(V, K, 32, V, 32);

    // K = HMAC_K(V || 0x01 || privkey || hash)
    memcpy(buf, V, 32 * sizeof(uint8_t));
    memset(buf + 32, 0x01, 1);
    hmac_sha256(K, K, 32, buf, 97);

    // V = HMAC_K(V)
    hmac_sha256(V, K, 32, V, 32);

    while (1) {
        uint8_t T[32];
        // V = HMAC_K(V)
        hmac_sha256(V, K, 32, V, 32);
        memcpy(T, V, 32 * sizeof(uint8_t));

        bytes_to_bigint(result->limbs, T, 32);

        const result_t kncmp = bigint_cmp_raw(result->limbs, 8, order->limbs, 8);
        const result_t k0cmp = bigint_cmp_raw(result->limbs, 8, nullptr, 0);

        if (kncmp < 0 && k0cmp > 0) {
            return;
        }

        // K = HMAC_K(V || 0x00)
        uint8_t bufV[33];
        memcpy(bufV, V, 32 * sizeof(uint8_t));
        memset(bufV + 32, 0x00, sizeof(uint8_t));
        hmac_sha256(K, K, 32, bufV, 33);

        // V = HMAC_K(V)
        hmac_sha256(V, K, 32, V, 32);
    }
}

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

    if (bigint_cmp_raw(s.limbs, 8, HALF_N, 8) > 0) {
        modular_neg_raw(&MOD_CTX, s.limbs, s.limbs, 8);
    }

    bigint_to_bytes(output, R.x.limbs, 8);
    bigint_to_bytes(output + 32, s.limbs, 8);
}