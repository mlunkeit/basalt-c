//
// Created by M Lunkeit on 17.07.26.
//

#ifndef BASALT_SECP256K1_H
#define BASALT_SECP256K1_H

#include <stddef.h>
#include <stdint.h>

size_t secp256k1_sign(uint8_t* result, const uint8_t* content, size_t len, const uint32_t private_key[8]);

bool secp256k1_verify(const uint8_t* content, size_t len, const uint32_t public_key[8]);

#endif //BASALT_SECP256K1_H
