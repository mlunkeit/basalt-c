//
// Created by M Lunkeit on 17.07.26.
//

#include <stdint.h>
#include <string.h>

#include "../math/bigint.h"
#include "../math/modular.h"

static const uint256_t modulus = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFC2F}};

static const uint32_t mu[9] = {1, 0x000003D1, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};

static const modular_ctx ctx = {modulus};

void secp256k1_wshiftr(uint32_t* limbs, const size_t len, const size_t num_words) {
    for (size_t i = 0; i < (len - num_words); i++) {
        limbs[i] = limbs[i + num_words];
        limbs[i + num_words] = 0;
    }
}

void secp256k1_wmod(uint32_t* limbs, const size_t len, const size_t num_words) {
    for (size_t i = num_words; i < len; i++) {
        limbs[i] = 0;
    }
}

void secp256k1_reduce(uint32_t limbs[16]) {
    // k is the amount of 32-bit words in an uint256_t integer. therefore k = 8

    uint32_t q1[16];
    memcpy(q1, limbs, sizeof(uint32_t) * 16);

    // shifting 7 to the right <=> dividing by 32^7
    secp256k1_wshiftr(q1, 16, 7);

    uint32_t q2[18];
    bigint_mul_raw(q2, q1, 9, mu, 9);

    secp256k1_wshiftr(q2, 18, 9);

    // r1 = x mod b^(k+1)
    secp256k1_wmod(limbs, 16, 9);

    uint32_t r2[17] = {0};
    bigint_mul_raw(r2, q2, 9, modulus.limbs, 8);
    secp256k1_wmod(r2, 17, 9);

    uint32_t r[10] = {0};
    bigint_sub_raw(r, limbs, 9, r2, 10);

    // if r < 0
    if ((r[9] & 1) != 0) {
        // r = r + b^(k+1)
        r[9] += 1;
    }

    result_t cmp_result = bigint_cmp_raw(r, 10, modulus.limbs, 8);
    while (cmp_result >= 0) {
        bigint_sub_raw(r, r, 10, modulus.limbs, 8);
        cmp_result = bigint_cmp_raw(r, 10, modulus.limbs, 8);
    }

    memcpy(limbs, r, sizeof(uint32_t) * 8);

    for (size_t i = 8; i < 16; i++) {
        limbs[i] = 0;
    }
}