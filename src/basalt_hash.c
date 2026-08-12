//
// Created by M Lunkeit on 27.07.26.
//

#include "basalt/hash.h"
#include "crypto/hash/sha256.h"
#include "crypto/hash/sha512.h"
#include "crypto/hash/ripemd160.h"

basalt_err_t basalt_sha256(
    uint8_t output[BASALT_SHA256_DIGEST_SIZE],
    const uint8_t *input, const size_t len)
{
    if (!output || !input) {
        return BASALT_ERR_NULL_POINTER;
    }

    sha256(output, input, len);

    return BASALT_OK;
}

basalt_err_t basalt_sha512(
    uint8_t output[BASALT_SHA512_DIGEST_SIZE],
    const uint8_t *input, const size_t len)
{
    if (!output || !input) {
        return BASALT_ERR_NULL_POINTER;
    }

    sha512(output, input, len);

    return BASALT_OK;
}

basalt_err_t basalt_ripemd160(
    uint8_t output[BASALT_RIPEMD160_DIGEST_SIZE],
    const uint8_t *input, const size_t len)
{
    if (!output || !input) {
        return BASALT_ERR_NULL_POINTER;
    }

    ripemd160(output, input, len);

    return BASALT_OK;
}
