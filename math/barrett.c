//
// Created by M Lunkeit on 22.07.26.
//

#include <string.h>

#include "barrett.h"
#include "bigint.h"

void barrett_reduce(
    uint32_t *result,
    const uint32_t *input,
    const uint32_t *modulus, const size_t len_modulus,
    const uint32_t *mu)
{
    const size_t k = len_modulus;

    uint32_t q1[k + 1];
    memcpy(q1, input + k - 1, (k + 1) * sizeof(uint32_t));

    uint32_t q2[2 * k + 2];
    bigint_mul_raw(q2, q1, k + 1, mu, k + 1);

    uint32_t q3[k + 1];
    memcpy(q3, q2 + k + 1, (k + 1) * sizeof(uint32_t));

    uint32_t r1[k + 1];
    memcpy(r1, input, (k + 1) * sizeof(uint32_t));

    uint32_t r2[2 * k + 1];
    bigint_mul_raw(r2, q3, k + 1, modulus, k);

    uint32_t r[k + 2];
    bigint_sub_raw(r, r1, k + 1, r2, k + 1);

    result_t rmcmp = bigint_cmp_raw(r, k + 1, modulus, k);

    while (rmcmp >= 0) {
        bigint_sub_raw(r, r, k + 1, modulus, k);
        rmcmp = bigint_cmp_raw(r, k + 1, modulus, k);
    }

    memcpy(result, r, k * sizeof(uint32_t));
}

void barrett_mul(uint32_t *result, const uint32_t *a, const size_t len_a, const uint32_t *b, const size_t len_b, const uint32_t *modulus, const size_t len_modulus, const uint32_t *mu) {
    uint32_t buf[2 * len_modulus];
    memset(buf, 0, 2 * len_modulus * sizeof(uint32_t));
    bigint_mul_raw(buf, a, len_a, b, len_b);
    barrett_reduce(result, buf, modulus, len_modulus, mu);
}

void barrett_pow(uint32_t *result,
    const uint32_t *a, const size_t len_a,
    const uint32_t *b, const size_t len_b,
    const uint32_t *modulus, const size_t len_modulus,
    const uint32_t *mu) {

    uint32_t acc[len_modulus];
    memset(acc, 0, len_modulus * sizeof(uint32_t));
    acc[0] = 1;

    uint32_t coeff[len_modulus];
    memset(coeff, 0, len_modulus * sizeof(uint32_t));
    memcpy(coeff, a, len_a * sizeof(uint32_t));

    uint32_t exp[len_b];
    memcpy(exp, b, len_b * sizeof(uint32_t));

    while (bigint_cmp_raw(exp, len_b, nullptr, 0) > 0) {
        if (exp[0] & 0x1) {
            barrett_mul(acc, acc, len_modulus, coeff, len_modulus, modulus, len_modulus, mu);
        }

        barrett_mul(coeff, coeff, len_modulus, coeff, len_modulus, modulus, len_modulus, mu);
        bigint_shr_raw(exp, exp, len_b, 1);
    }

    memcpy(result, acc, len_modulus * sizeof(uint32_t));
}