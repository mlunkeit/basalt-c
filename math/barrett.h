//
// Created by M Lunkeit on 22.07.26.
//

#ifndef BASALT_BARRETT_H
#define BASALT_BARRETT_H

#include <stdint.h>

void barrett_reduce(uint32_t *result, const uint32_t *input, const uint32_t *modulus, size_t len_modulus, const uint32_t *mu);

void barrett_pow(uint32_t *result, const uint32_t *a, size_t len_a, const uint32_t *b, size_t len_b, const uint32_t *modulus, size_t len_modulus, const uint32_t *mu);

#endif //BASALT_BARRETT_H
