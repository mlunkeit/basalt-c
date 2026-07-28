//
// Created by M Lunkeit on 24.07.26.
//

#ifndef BASALT_INTERNAL_HMAC_H
#define BASALT_INTERNAL_HMAC_H

#include <stdint.h>
#include <stddef.h>

void hmac_sha256(uint8_t output[32], const uint8_t *key, size_t len_key, const uint8_t *message, size_t len_message);

void hmac_sha512(uint8_t output[64], const uint8_t *key, size_t len_key, const uint8_t *message, size_t len_message);

#endif //BASALT_INTERNAL_HMAC_H
