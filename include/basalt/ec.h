//
// Created by M Lunkeit on 10.08.26.
//

#ifndef BASALT_EC_H
#define BASALT_EC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BASALT_EC_MAX_BYTES 32

/**
 * @brief Holds a private key that can be used with a specific elliptic curve.
 *
 * This key can be used to create signatures on an elliptic curve with any
 * supported signature algorithm, such as ECDSA.
 *
 * It only consists of one field (d) which holds a number in big endian format.
 * This number may be used for point multiplication on the given elliptic curve,
 * therefore it has to be smaller than the order of the curve used.
 *
 * Please note that d * G = P where G is the generator point of the given curve
 * and P is the public key bound to this private key.
 *
 * @warning     This private key has to be kept – as the name suggests –
 *              strictly private as anyone with this key can create
 *              signatures in the name of the owner of this key.
 */
typedef struct {
    uint8_t d[BASALT_EC_MAX_BYTES];
} basalt_ec_private_key_t;

/**
 * @brief Holds a public key that can be used with a specific elliptic curve.
 *
 * This key can be used to verify signatures on an elliptic curve with any
 * supported signature algorithm, such as ECDSA.
 *
 * It consists of two fields (x and y) which represent a coordinate pair on
 * the given elliptic curve. Both are integers in big endian format.
 * Both coordinates must be less than the characteristic of the curve used.
 */
typedef struct {
    uint8_t x[BASALT_EC_MAX_BYTES];
    uint8_t y[BASALT_EC_MAX_BYTES];
} basalt_ec_public_key_t;

/**
 * @brief   Holds a public key in compressed form that can be used with a
 *          specific elliptic curve.
 *
 * This key can be used to verify signatures on an elliptic curve with any
 * supported signature algorithm, such as ECDSA.
 *
 * It consists only of a byte containing the information if y is even (0x02)
 * or odd (0x03) and the x coordinate in big endian format.
 * The x coordinate must be less than the characteristic of the curve used.
 * The very first byte may not contain any other value than 0x02 or 0x03.
 */
typedef struct {
    uint8_t data[BASALT_EC_MAX_BYTES + 1];
} basalt_ec_compressed_public_key_t;

/**
 * @brief The list of elliptic curves supported by all implemented signature
 * algorithms.
 *
 * Please note that not all curves can be used with all signature algorithms.
 *
 * Also note that due to the use of RFC-6979 with HMAC-SHA256 it is not safe
 * to use curves greater than 256 bit with the ECDSA signature algorithm.
 *
 * Please be careful and do not confuse the curves secp256k1 and secp256r1.
 * While secp256k1 is used mostly in bitcoin context, the curve secp256r1
 * appears in protocols such as FIDO2.
 */
typedef enum {
    BASALT_CURVE_SECP256K1 = 0,
    BASALT_CURVE_SECP256R1 = 1,
} basalt_ec_curve_t;

#ifdef __cplusplus
}
#endif

#endif //BASALT_EC_H
