//
// Created by M Lunkeit on 25.07.26.
//

#include <string.h>

#include "../mac/hmac.h"
#include "rfc6979.h"

void rfc6979(uint32_t result[8], const uint8_t privkey[32], const uint8_t hash[32], const uint32_t order[8]) {
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

        bytes_to_bigint(result, T, 32);

        const result_t kncmp = bigint_cmp_raw(result, 8, order, 8);
        const result_t k0cmp = bigint_cmp_raw(result, 8, nullptr, 0);

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
