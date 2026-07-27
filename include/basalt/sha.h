//
// Created by M Lunkeit on 27.07.26.
//

#ifndef BASALT_SHA_H
#define BASALT_SHA_H

#include <stdint.h>
#include <stddef.h>

#include "basalt/error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BASALT_SHA256_DIGEST_SIZE 32
#define BASALT_SHA512_DIGEST_SIZE 64

basalt_err_t basalt_sha256(
    uint8_t output[BASALT_SHA256_DIGEST_SIZE],
    const uint8_t *input, size_t len);

basalt_err_t basalt_sha512(
    uint8_t output[BASALT_SHA512_DIGEST_SIZE],
    const uint8_t *input, size_t len);

#ifdef __cplusplus
}
#endif

#endif //BASALT_SHA_H
