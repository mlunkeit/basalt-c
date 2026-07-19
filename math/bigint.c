//
// Created by M Lunkeit on 17.07.26.
//

#include <stddef.h>

#include "bigint.h"

void uint256_add_assign(uint256_t *a, const uint256_t *b)
{
    bigint_add_raw(a->limbs, a->limbs, 8, b->limbs, 8);
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
    /*uint256_t tmp = *b;
    uint256_two_complement(&tmp);
    uint256_add_assign(a, &tmp);*/
    bigint_sub_raw(a->limbs, a->limbs, 8, b->limbs, 8);
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
    /*for (size_t i = 0; i < 8; i++) {
        const uint32_t limb_a = a->limbs[i];
        uint64_t carry = 0;

        for (size_t j = 0; j < 8; j++) {
            const uint32_t limb_b = b->limbs[j];

            const uint64_t full = (uint64_t) limb_a * limb_b;
            const uint32_t low = (uint32_t) full;
            const uint32_t high = full >> 32;

            const size_t slot = i + j;
            const uint64_t sum = result[slot] + carry + low;
            result[slot] = (uint32_t) sum;

            carry = high + (sum >> 32);
        }

        result[i + 8] = carry;
    }*/

    bigint_mul_raw(result, a->limbs, 8, b->limbs, 8);
}

void bigint_add_raw(uint32_t *result, const uint32_t *a, const size_t len_a, const uint32_t *b, const size_t len_b) {
    size_t max_len;

    if (len_a < len_b) {
        max_len = len_b;
    } else {
        max_len = len_a;
    }

    uint64_t carry = 0;

    for (size_t i = 0; i < max_len; i++) {
        const uint64_t limb_a = i < len_a ? a[i] : 0;
        const uint64_t limb_b = i < len_b ? b[i] : 0;

        carry += limb_a + limb_b;
        result[i] = (uint32_t) carry;
        carry >>= 32;
    }
}

void bigint_sub_raw(uint32_t *result, const uint32_t *a, const size_t len_a, const uint32_t *b, const size_t len_b) {
    size_t max_len;

    if (len_a < len_b) {
        max_len = len_b;
    } else {
        max_len = len_a;
    }

    uint64_t borrow = 0;

    for (size_t i = 0; i < max_len; i++) {
        const uint64_t limb_a = i < len_a ? a[i] : 0;
        const uint64_t limb_b = i < len_b ? b[i] : 0;
        const uint64_t diff = limb_a - limb_b - borrow;

        result[i] = diff;
        borrow = (diff >> 32) & 1;
    }
}

void bigint_mul_raw(uint32_t *result, const uint32_t *a, const size_t len_a, const uint32_t *b, const size_t len_b) {
    for (size_t i = 0; i < len_a; i++) {
        const uint32_t limb_a = a[i];
        uint64_t carry = 0;

        for (size_t j = 0; j < len_b; j++) {
            const uint32_t limb_b = b[j];

            const uint64_t full = (uint64_t) limb_a * limb_b;
            const uint32_t low = (uint32_t) full;
            const uint32_t high = full >> 32;

            const size_t slot = i + j;
            const uint64_t sum = result[slot] + carry + low;
            result[slot] = (uint32_t) sum;

            carry = high + (sum >> 32);
        }

        result[i + len_b] = carry;
    }
}

result_t bigint_cmp_raw(const uint32_t *a, const size_t len_a, const uint32_t *b, const size_t len_b) {
    size_t max_len;

    if (len_a < len_b) {
        max_len = len_b;
    } else {
        max_len = len_a;
    }

    result_t result = 0;

    for (size_t i = 0; i < max_len; i++) {
        const uint32_t limb_a = i < len_a ? a[i] : 0;
        const uint32_t limb_b = i < len_b ? b[i] : 0;

        const uint32_t diff = limb_a - limb_b;

        if (diff == 0) {
            continue;
        }

        result = (result_t) (diff < 0 ? -1 : 1);
    }

    return result;
}