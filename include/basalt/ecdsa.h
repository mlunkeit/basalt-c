//
// Created by M Lunkeit on 27.07.26.
//

#ifndef BASALT_ECDSA_H
#define BASALT_ECDSA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "basalt/error.h"

#define BASALT_ECDSA_MAX_BYTES 32

typedef struct {
    uint8_t r[BASALT_ECDSA_MAX_BYTES];
    uint8_t s[BASALT_ECDSA_MAX_BYTES];
} basalt_ecdsa_signature_t;

typedef struct {
    uint8_t d[BASALT_ECDSA_MAX_BYTES];
} basalt_ecdsa_private_key_t;

typedef struct {
    uint8_t x[BASALT_ECDSA_MAX_BYTES];
    uint8_t y[BASALT_ECDSA_MAX_BYTES];
} basalt_ecdsa_public_key_t;

typedef enum {
    BASALT_CURVE_SECP256K1 = 0,
    BASALT_CURVE_SECP256R1 = 1,
} basalt_ecdsa_curve_t;

basalt_err_t basalt_ecdsa_sign(
    basalt_ecdsa_curve_t curve,
    basalt_ecdsa_signature_t *sig,
    const basalt_ecdsa_private_key_t *key,
    const uint8_t *hash, size_t len_hash);

basalt_err_t basalt_ecdsa_verify(
    basalt_ecdsa_curve_t curve,
    const basalt_ecdsa_public_key_t *key,
    const uint8_t *hash, size_t len_hash,
    const basalt_ecdsa_signature_t *sig);

#ifdef __cplusplus
}
#endif

#endif //BASALT_ECDSA_H
