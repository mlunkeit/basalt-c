//
// Created by M Lunkeit on 27.07.26.
//

#ifndef BASALT_SHA512_H
#define BASALT_SHA512_H

#include <stdint.h>
#include <stddef.h>

void sha512(uint8_t output[64], const uint8_t *input, size_t len);

#endif //BASALT_SHA512_H
