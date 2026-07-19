//
// Created by M Lunkeit on 17.07.26.
//

#include <stddef.h>

#include "bigint.h"

void uint256_add_assign(uint256_t *a, const uint256_t *b)
{
    uint64_t carry = 0;

    for (int i = 0; i < 8; i++) {

        uint64_t tmp = carry;
        tmp += a->limbs[i];
        tmp += b->limbs[i];

        a->limbs[i] = (uint32_t) tmp;
        carry = tmp >> 32;
    }
}

static void uint256_one_complement(uint256_t *a) {
    for (size_t i = 0; i < 8; i++) {
        a->limbs[i] = ~a->limbs[i];
    }
}

static void uint256_two_complement(uint256_t *a) {

    uint256_one_complement(a);

    uint64_t carry = 1;

    for (size_t i = 0; i < 8; i++) {

        uint64_t tmp = carry;
        tmp += a->limbs[i];

        a->limbs[i] = (uint32_t) tmp;
        carry = tmp >> 32;
    }
}

void uint256_neg_assign(uint256_t *a) {
    uint256_two_complement(a);
}

void uint256_sub_assign(uint256_t *a, const uint256_t *b) {
    uint256_t tmp = *b;
    uint256_two_complement(&tmp);
    uint256_add_assign(a, &tmp);
}

result_t uint256_cmp(const uint256_t *a, const uint256_t *b)
{
    result_t result = 0;

    for (int i = 0; i < 8; i++) {

        if (a->limbs[i] == b->limbs[i]) {
            continue;
        }

        if (a->limbs[i] > b->limbs[i]) {
            result = 1;
        } else {
            result = -1;
        }
    }

    return result;
}

void uint256_mul_raw(uint32_t result[16], const uint256_t *a, const uint256_t *b) {
    for (size_t i = 0; i < 8; i++) {
        const uint64_t limb_a = a->limbs[i];
        uint64_t carry = 0;

        for (size_t j = 0; j < 8; j++) {
            const uint64_t limb_b = b->limbs[j];

            const uint64_t full = limb_a * limb_b;
            const uint32_t low = (uint32_t) full;
            const uint32_t high = full >> 32;

            const size_t slot = i + j;
            const uint64_t sum = result[slot] + carry + low;
            result[slot] = (uint32_t) sum;

            carry = high + (sum >> 32);
        }

        result[i + 8] = carry;
    }
}