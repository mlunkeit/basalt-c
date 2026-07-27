//
// Created by M Lunkeit on 25.07.26.
//

#include <string.h>

#include "crypto/mac/hmac.h"
#include "math/bigint.h"
#include "rfc6979.h"

void rfc6979(
    const wcurve_spec_t *wcurve,
    uint32_t *result,
    const uint32_t *d,
    const uint8_t *hash, const size_t len_hash)
{
    uint8_t V[len_hash];
    memset(V, 0x01, sizeof(V));

    uint8_t K[len_hash];
    memset(K, 0x00, sizeof(K));

    size_t len_privkey = 4 * wcurve->len_n;
    uint8_t privkey[len_privkey];
    bigint_to_bytes(privkey, d, wcurve->len_n);

    uint8_t buf[2 * len_hash + len_privkey + 1];
    memcpy(buf, V, len_hash * sizeof(uint8_t));
    memset(buf + len_hash, 0x00, 1);
    memcpy(buf + len_hash + 1, privkey, len_privkey * sizeof(uint8_t));
    memcpy(buf + len_hash + len_privkey + 1, hash, len_hash * sizeof(uint8_t));

    // K = HMAC_K(V || 0x00 || privkey || hash)
    hmac_sha256(K, K, len_hash, buf, 2 * len_hash + len_privkey + 1);

    // V = HMAC_K(V)
    hmac_sha256(V, K, 32, V, 32);

    // K = HMAC_K(V || 0x01 || privkey || hash)
    memcpy(buf, V, 32 * sizeof(uint8_t));
    memset(buf + 32, 0x01, 1);
    memcpy(buf + 33, privkey, len_privkey * sizeof(uint8_t));
    memcpy(buf + len_privkey + 33, hash, len_hash * sizeof(uint8_t));
    hmac_sha256(K, K, 32, buf, len_privkey + len_hash + 33);

    // V = HMAC_K(V)
    hmac_sha256(V, K, 32, V, 32);

    while (1) {
        const size_t len_t = 32 * ((wcurve->len_n + 7) >> 3);
        uint8_t T[len_t];

        for (size_t ptr_t = 0; ptr_t < wcurve->len_n; ptr_t += 32) {
            // V = HMAC_K(V)
            hmac_sha256(V, K, 32, V, 32);
            // T = T || V
            memcpy(T + ptr_t, V, 32 * sizeof(uint8_t));
        }

        bytes_to_bigint(result, T, wcurve->len_n * 4);

        const result_t kncmp = bigint_cmp_raw(result, wcurve->len_n, wcurve->n, wcurve->len_n);
        const result_t k0cmp = bigint_cmp_raw(result, wcurve->len_n, nullptr, 0);

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
