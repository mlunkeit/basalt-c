//
// Created by M Lunkeit on 22.07.26.
//

#include <string.h>
#include <stdio.h>

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
    memset(q1, 0, (k + 1) * sizeof(uint32_t));
    memcpy(q1, input + k - 1, (k + 1) * sizeof(uint32_t));

    uint32_t q2[2 * k + 2];
    memset(q2, 0, (2 * k + 2) * sizeof(uint32_t));
    bigint_mul_raw(q2, q1, k + 1, mu, k + 1);

    uint32_t q3[k + 1];
    memcpy(q3, q2 + k + 1, (k + 1) * sizeof(uint32_t));

    uint32_t r1[k + 1];
    memcpy(r1, input, (k + 1) * sizeof(uint32_t));

    uint32_t r2[2 * k + 1];
    memset(r2, 0, (2 * k + 1) * sizeof(uint32_t));
    bigint_mul_raw(r2, q3, k + 1, modulus, k);
    memset(r2 + k + 1, 0, sizeof(uint32_t) * k);

    uint32_t r[k + 2];
    memset(r, 0, (k + 2) * sizeof(uint32_t));
    bigint_sub_raw(r, r1, k + 1, r2, k + 1);

    result_t rmcmp = bigint_cmp_raw(r, k + 1, modulus, k);

    while (rmcmp >= 0) {
        bigint_sub_raw(r, r, k + 1, modulus, k);
        rmcmp = bigint_cmp_raw(r, k + 1, modulus, k);
    }

    memcpy(result, r, k * sizeof(uint32_t));
}
