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
#define BASALT_HS512_DIGEST_SIZE 64

/**
 * @brief Generates a Hash-based Message Authentication Code (HMAC-SHA-256).
 *
 * Calculates a 256-bit authentication tag according to RFC 2104 using
 * SHA-256 as the underlying cryptographic hash function.
 *
 * If the key exceeds the SHA-256 block size (64 bytes), it is automatically
 * hashed using SHA-256 first. Keys shorter than 64 bytes are zero-padded.
 *
 * @param[out] output      buffer (32 bytes) where the resulting HMAC tag will be stored.
 * @param[in]  key         pointer to the secret key buffer.
 * @param[in]  len_key     length of the secret key in bytes.
 * @param[in]  message     pointer to the message buffer to be authenticated.
 * @param[in]  len_message length of the message in bytes.
 *
 * @return the error code, 0 otherwise
 */
basalt_err_t basalt_hmac_sha256(
    uint8_t output[BASALT_HS256_DIGEST_SIZE],
    const uint8_t *key, size_t len_key,
    const uint8_t *message, size_t len_message);

/**
 * @brief Generates a Hash-based Message Authentication Code (HMAC-SHA-512).
 *
 * Calculates a 512 bit authentication tag according to RFC 2104 using
 * SHA-512 as the underlying cryptographic hash function.
 *
 * If the key exceeds the SHA-512 block size (128 bytes), it is automatically
 * hashed using SHA-512 first. Keys shorter than 128 bytes are zero-padded.
 *
 * @param[out] output       buffer (64 bytes) where the resulting HMAC tag will be stored
 * @param[in]  key          a pointer to the secret key buffer
 * @param[in]  len_key      the length of the secret key in bytes
 * @param[in]  message      pointer to the message buffer to be authenticated
 * @param[in]  len_message  length of message in bytes
 *
 * @return the error code, 0 otherwise
 */
basalt_err_t basalt_hmac_sha512(
    uint8_t output[BASALT_HS512_DIGEST_SIZE],
    const uint8_t *key, size_t len_key,
    const uint8_t *message, size_t len_message);

#ifdef __cplusplus
}
#endif

#endif //BASALT_HMAC_H
