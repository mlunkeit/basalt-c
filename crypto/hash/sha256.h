//
// Created by M Lunkeit on 23.07.26.
//

#ifndef BASALT_SHA256_H
#define BASALT_SHA256_H

#include <stdint.h>
#include <stddef.h>

void sha256(uint8_t output[32], const uint8_t *input, size_t len);

#endif //BASALT_SHA256_H
