//
// Created by M Lunkeit on 27.07.26.
//

#ifndef BASALT_HMAC_H
#define BASALT_HMAC_H

#include <stdint.h>
#include <stddef.h>

#include "basalt/error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BASALT_HS256_DIGEST_SIZE 32

basalt_err_t basalt_hmac_sha256(
    uint8_t output[BASALT_HS256_DIGEST_SIZE],
    const uint8_t *key, size_t len_key,
    const uint8_t *message, size_t len_message);

#ifdef __cplusplus
}
#endif

#endif //BASALT_HMAC_H
