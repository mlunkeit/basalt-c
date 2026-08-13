//
// Created by M Lunkeit on 27.07.26.
//

#include "basalt/hmac.h"
#include "crypto/mac/hmac.h"

basalt_err_t basalt_hmac_sha256(
    uint8_t output[BASALT_HS256_DIGEST_SIZE],
    const uint8_t *key, const size_t len_key,
    const uint8_t *message, const size_t len_message)
{
    if (!output || !key || !message) {
        return BASALT_ERR_NULL_POINTER;
    }

    hmac_sha256(output, key, len_key, message, len_message);

    return BASALT_OK;
}

basalt_err_t basalt_hmac_sha512(
    uint8_t output[BASALT_HS512_DIGEST_SIZE],
    const uint8_t *key, const size_t len_key,
    const uint8_t *message, const size_t len_message)
{
    if (!output || !key || !message) {
        return BASALT_ERR_NULL_POINTER;
    }

    hmac_sha512(output, key, len_key, message, len_message);

    return BASALT_OK;
}