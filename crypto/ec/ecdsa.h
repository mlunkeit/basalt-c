//
// Created by M Lunkeit on 24.07.26.
//

#ifndef BASALT_ECDSA_H
#define BASALT_ECDSA_H

#include <stdint.h>
#include <stddef.h>

void ecdsa_sign_secp256k1(uint8_t output[64], const uint8_t privkey[32], const uint8_t hash[32]);

#endif //BASALT_ECDSA_H
