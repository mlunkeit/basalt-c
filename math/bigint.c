//
// Created by M Lunkeit on 17.07.26.
//

#include <string.h>

#include "bigint.h"

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

    if (carry != 0) {
        result[max_len] = carry;
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

    if (borrow != 0) {
        result[max_len] = 0 - borrow;
    }
}

void bigint_mul_raw(uint32_t *result, const uint32_t *a, const size_t len_a, const uint32_t *b, const size_t len_b) {
    uint32_t buf[len_a + len_b];
    memset(buf, 0, (len_a + len_b) * sizeof(uint32_t));

    for (size_t i = 0; i < len_a; i++) {
        const uint32_t limb_a = a[i];
        uint64_t carry = 0;

        for (size_t j = 0; j < len_b; j++) {
            const uint32_t limb_b = b[j];

            const uint64_t full = (uint64_t) limb_a * limb_b;
            const uint32_t low = (uint32_t) full;
            const uint32_t high = full >> 32;

            const size_t slot = i + j;
            const uint64_t sum = buf[slot] + carry + low;
            buf[slot] = (uint32_t) sum;

            carry = high + (sum >> 32);
        }

        buf[i + len_b] = carry;
    }

    memcpy(result, buf, (len_a + len_b) * sizeof(uint32_t));
}

void bigint_shl_raw(uint32_t *result, const uint32_t *a, const size_t len_a, size_t bits) {
    uint32_t buf[len_a];

    if (bits >= 32) {
        const size_t words = bits / 32;
        bits %= 32;

        memcpy(buf + words, a, (len_a - words) * sizeof(uint32_t));
        memset(buf, 0, words * sizeof(uint32_t));
    } else {
        memcpy(buf, a, len_a * sizeof(uint32_t));
    }

    uint64_t overflow = 0;

    for (size_t i = 0; i < len_a; i++) {
        overflow |= (uint64_t) buf[i] << bits;
        result[i] = (uint32_t) overflow;
        overflow >>= 32;
    }
}

void bigint_shr_raw(uint32_t *result, const uint32_t *a, const size_t len_a, size_t bits) {
    uint32_t buf[len_a];

    if (bits >= 32) {
        const size_t words = bits / 32;
        bits %= 32;
        memcpy(buf, a + words, (len_a - words) * sizeof(uint32_t));
        memset(buf + (len_a - words), 0, words * sizeof(uint32_t));
    } else {
        memcpy(buf, a, len_a * sizeof(uint32_t));
    }

    uint32_t underflow = 0;

    for (size_t i = len_a; i > 0; i--) {
        const size_t idx = i - 1;
        const uint64_t limb = (uint64_t) buf[idx] << (32 - bits);
        result[idx] = (limb >> 32) | underflow;
        underflow = limb;
    }
}

result_t bigint_cmp_raw(const uint32_t *a, const size_t len_a, const uint32_t *b, const size_t len_b) {
    size_t max_len = len_a > len_b ? len_a : len_b;

    for (size_t i = max_len; i > 0; i--) {
        size_t idx = i - 1;

        const uint32_t limb_a = (idx < len_a) ? a[idx] : 0;
        const uint32_t limb_b = (idx < len_b) ? b[idx] : 0;

        if (limb_a > limb_b) {
            return 1;
        }

        if (limb_a < limb_b) {
            return -1;
        }
    }

    return 0;
}