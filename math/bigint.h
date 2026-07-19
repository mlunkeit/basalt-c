//
// Created by M Lunkeit on 17.07.26.
//

#ifndef BASALT_BIGUINT256_H
#define BASALT_BIGUINT256_H

#include <stdint.h>

typedef struct uint256_t {
    uint32_t limbs[8];
} uint256_t;

typedef int8_t result_t;

void uint256_add_assign(uint256_t *a, const uint256_t *b);

void uint256_neg_assign(uint256_t *a);

void uint256_sub_assign(uint256_t *a, const uint256_t *b);

result_t uint256_cmp(const uint256_t *a, const uint256_t *b);

void uint256_mul_raw(uint32_t result[16], const uint256_t *a, const uint256_t *b);

#endif //BASALT_BIGUINT256_H
