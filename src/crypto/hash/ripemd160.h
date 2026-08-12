//
// Created by M Lunkeit on 13.08.26.
//

#ifndef BASALT_RIPEMD160_H
#define BASALT_RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

void ripemd160(uint8_t output[20], const uint8_t *input, const size_t len);

#endif //BASALT_RIPEMD160_H
