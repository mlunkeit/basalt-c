//
// Created by M Lunkeit on 27.07.26.
//

#ifndef BASALT_ECDSA_H
#define BASALT_ECDSA_H

#include <stdint.h>
#include <stddef.h>

#include "basalt/error.h"
#include "basalt/ec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BASALT_ECDSA_MAX_BYTES 32

/**
 * @brief Holds an ECDSA signature.
 *
 * The signature consists of two parts.
 *
 * The first part (r) is the x-coordinate of a calculated point on a
 * specified elliptic curve. It is represented as a byte array in big endian.
 *
 * The second part (s) is a calculated value from the hash value of
 * the message, the private key and r (the x-coordinate). It is also
 * represented as a byte array in big endian.
 *
 * This structure does not necessarily have the same size as the real
 * signature. There may be bytes reserved to hold signatures for
 * elliptic curves whose signatures take up more space.
 *
 * Nevertheless, the r and s values start at index 0. The amount of bytes
 * that need to be read are dependent on the elliptic curve you are using.
 */
typedef struct {
    uint8_t r[BASALT_ECDSA_MAX_BYTES];
    uint8_t s[BASALT_ECDSA_MAX_BYTES];
} basalt_ecdsa_signature_t;

/**
 * @brief Creates a deterministic ECDSA signature according to RFC-6979.
 *
 * Please note that the size of the signature is entirely dependent
 * on the curve used. As an example, the secp256k1 and secp256r1 both
 * create 512-bit signatures. Although the size may changed based
 * on the curve passed as a parameter.
 *
 * Furthermore, please note, that this library can only calculate
 * ECDSA signatures on elliptic curves in the Weierstraß form.
 *
 * The signatures created by this algorithm are deterministic.
 * This means, there is no ephemeral key chosen by any random number
 * generator. The procedure used to find a secure ephemeral key
 * is described in the RFC-6979 document.
 *
 * @warning             The RFC-6979 implementation of this algorithm works
 *                      with HMAC-SHA-256. Therefore, any elliptic curve with
 *                      more than 256-bit can be used, BUT IT IS NOT RECOMMENDED,
 *                      as the random ephemeral key loses security with more
 *                      than 256 bits.
 *
 * @param[in] curve     the curve that will be used to create the signature.
 *                      Please note that only secp256k1 and secp256r1 are
 *                      supported at this time.
 * @param[out] sig      the calculated signature.
 * @param[in] key       the private key.
 * @param[in] hash      the hash value of the message, generated with any
 *                      secure hash function, such as SHA-256.
 * @param[in] len_hash  the length of the hash value in bytes.
 *                      (such as 32 for SHA-256)
 *
 * @return              the error code, 0 otherwise
 */
basalt_err_t basalt_ecdsa_sign(
    basalt_ec_curve_t curve,
    basalt_ecdsa_signature_t *sig,
    const basalt_ec_private_key_t *key,
    const uint8_t *hash, size_t len_hash);

/**
 * @brief Verifies an ECDSA signature.
 *
 * @param[in] curve     the elliptic curve that was used to create the
 *                      signature.
 * @param[in] key       the matching public key to the private key that
 *                      was used for the signature creation.
 * @param[in] hash      the hash value of the message.
 * @param[in] len_hash  the length of the hash value in bytes.
 *                      (such as 32 for SHA-256)
 * @param[in] sig       the signature of the message.
 *
 * @return              the error code, 0 when the signature is valid
 *                      and no error occurred.
 */
basalt_err_t basalt_ecdsa_verify(
    basalt_ec_curve_t curve,
    const basalt_ec_public_key_t *key,
    const uint8_t *hash, size_t len_hash,
    const basalt_ecdsa_signature_t *sig);

#ifdef __cplusplus
}
#endif

#endif //BASALT_ECDSA_H
