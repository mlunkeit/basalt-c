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
#define BASALT_RIPEMD160_DIGEST_SIZE 20

/**
 * @brief Generates SHA-256 hash values for a given message.
 *
 * This is a deterministic one-way-function. Meaning that for a
 * given message it will always produce the same 256-bit value,
 * but is computationally impossible to reconstruct the message
 * by its hash value.
 *
 * @param[out]  output  the output byte array. This function generates
 *                      an 256-bit output and therefore writes 32
 *                      bytes into the output array.
 * @param[in]   input   the input byte array. May be of any length.
 * @param[in]   len     the length of the input array in bytes.
 *
 * @return      the error code, 0 otherwise
 */
basalt_err_t basalt_sha256(
    uint8_t output[BASALT_SHA256_DIGEST_SIZE],
    const uint8_t *input, size_t len);

/**
 * @brief Generates SHA-512 hash values for a given message.
 *
 * This is a deterministic one-way-function. Meaning that for a
 * given message it will always produce the same 512-bit value,
 * but is computationally impossible to reconstruct the message
 * by its hash value.
 *
 * @param[out]  output  the output byte array. This function generates
 *                      an 512-bit output and therefore writes 64
 *                      bytes into the output array.
 * @param[in]   input   the input byte array. May be of any length.
 * @param[in]   len     the length of the input array in bytes.
 *
 * @return      the error code, 0 otherwise
 */
basalt_err_t basalt_sha512(
    uint8_t output[BASALT_SHA512_DIGEST_SIZE],
    const uint8_t *input, size_t len);

/**
 * @brief Generates RIPEMD-160 hash values for a given message.
 *
 * This is a deterministic one-way-function. Meaning that for a
 * given message it will always produce the same 160-bit value,
 * but is computationally impossible to reconstruct the message
 * by its hash value.
 *
 * @param[out]  output  the output byte array. This function generates
 *                      an 160-bit output and therefore writes 20 bytes
 *                      into the output array.
 * @param[in]   input   the input byte array. May be of any length.
 * @param[in]   len     the length of the input array in bytes.
 *
 * @return the error code, 0 otherwise
 */
basalt_err_t basalt_ripemd160(
    uint8_t output[BASALT_RIPEMD160_DIGEST_SIZE],
    const uint8_t *input, size_t len);

#ifdef __cplusplus
}
#endif

#endif //BASALT_SHA_H
