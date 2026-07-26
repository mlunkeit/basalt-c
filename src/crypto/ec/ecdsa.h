//
// Created by M Lunkeit on 24.07.26.
//

#ifndef BASALT_ECDSA_H
#define BASALT_ECDSA_H

#include <stdint.h>

#include "../../math/curves/wcurve.h"

typedef struct {
    uint32_t r[WCURVE_MAX_LIMBS];
    uint32_t s[WCURVE_MAX_LIMBS];
} ecdsa_signature_t;

typedef struct {
    uint32_t d[WCURVE_MAX_LIMBS];
} ecdsa_private_key_t;

typedef struct {
    wcurve_point_t point;
} ecdsa_public_key_t;

void ecdsa_sign(
    const wcurve_spec_t *wcurve,
    ecdsa_signature_t *sig,
    const ecdsa_private_key_t *key,
    const uint8_t *hash, size_t len_hash);

bool ecdsa_verify(
    const wcurve_spec_t *curve,
    const uint8_t *pubkey,
    const uint8_t *hash, size_t len_hash,
    const ecdsa_signature_t *sig);

#endif //BASALT_ECDSA_H
