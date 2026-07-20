//
// Created by M Lunkeit on 17.07.26.
//

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "../math/bigint.h"
#include "../math/modular.h"

typedef struct {
    uint256_t x;
    uint256_t y;
    bool infinity;
} secp256k1_point_t;

static const uint256_t modulus = {{0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};

static const uint32_t mu[9] = {0x000003D1, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 1};

static const modular_ctx ctx = {.modulus = (uint32_t*) modulus.limbs, .len_modulus = 8};

/*********************************************************
 *                  BARRETT REDUCTION
 *
 * This is an implementation of the special case of the
 * barrett reduction. It reduces the input to the modulus
 * required by the secp256k1 elliptic curve. It can
 * only handle this special case with 32-bit words.
 *********************************************************/

void secp256k1_reduce(uint256_t *result, uint32_t x[16]) {
    uint32_t q1[9] = {0};
    memcpy(q1, x + 7, sizeof(uint32_t) * 9);

    uint32_t q2[18] = {0};
    bigint_mul_raw(q2, q1, 9, mu, 9);

    uint32_t q3[9];
    memcpy(q3, q2 + 9, sizeof(q3));

    uint32_t r1[9];
    memcpy(r1, x, sizeof(r1));

    uint32_t r2[17] = {0};
    bigint_mul_raw(r2, q3, 9, modulus.limbs, 8);
    memset(r2 + 9, 0, sizeof(uint32_t) * 8);

    uint32_t r[10] = {0};
    bigint_sub_raw(r, r1, 9, r2, 9);

    result_t rmcmp = bigint_cmp_raw(r, 9, modulus.limbs, 8);

    while (rmcmp >= 0) {
        bigint_sub_raw(r, r, 9, modulus.limbs, 8);
        rmcmp = bigint_cmp_raw(r, 9, modulus.limbs, 8);
    }

    memcpy(result->limbs, r, sizeof(uint32_t) * 8);
}

void secp256k1_mul(uint256_t *result, const uint256_t *a, const uint256_t *b) {
    uint32_t buf[16];
    bigint_mul_raw(buf, a->limbs, 8, b->limbs, 8);
    secp256k1_reduce(result, buf);
}

void secp256k1_pow(uint256_t *result, const uint256_t *a, const uint256_t *b) {
    uint256_t exp;
    memcpy(&exp, b, sizeof(uint256_t));

    constexpr uint32_t one = 1;

    memset(result->limbs, 0, sizeof(uint32_t) * 8);
    result->limbs[0] = 1;

    result_t cmpresult = bigint_cmp_raw(exp.limbs, 8, nullptr, 0);
    while (cmpresult > 0) {
        if ((exp.limbs[0] & 1) != 0) {
            bigint_sub_raw(exp.limbs, exp.limbs, 8, &one, 1);
            secp256k1_mul(result, result, a);
        } else {

        }
    }
}

void secp256k1_point_add(secp256k1_point_t *result, const secp256k1_point_t *a, const secp256k1_point_t *b) {

    if (a->infinity) {
        memcpy(result, b, sizeof(secp256k1_point_t));
        return;
    }

    if (b->infinity) {
        memcpy(result, a, sizeof(secp256k1_point_t));
        return;
    }

    uint256_t m;
}