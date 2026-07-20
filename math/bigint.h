//
// Created by M Lunkeit on 17.07.26.
//

#ifndef BASALT_BIGUINT256_H
#define BASALT_BIGUINT256_H

#include <stdint.h>
#include <stddef.h>

typedef struct uint256_t {
    uint32_t limbs[8];
} uint256_t;

typedef int8_t result_t;

void bigint_add_raw(uint32_t *result, const uint32_t *a, size_t len_a, const uint32_t *b, size_t len_b);

void bigint_sub_raw(uint32_t *result, const uint32_t *a, size_t len_a, const uint32_t *b, size_t len_b);

void bigint_mul_raw(uint32_t *result, const uint32_t *a, size_t len_a, const uint32_t *b, size_t len_b);

result_t bigint_cmp_raw(const uint32_t *a, size_t len_a, const uint32_t *b, size_t len_b);

#endif //BASALT_BIGUINT256_H
