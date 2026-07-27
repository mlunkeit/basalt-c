//
// Created by M Lunkeit on 24.07.26.
//

#ifndef BASALT_INTERNAL_ECDSA_H
#define BASALT_INTERNAL_ECDSA_H

#include <stdint.h>

#include "math/curves/wcurve.h"

void ecdsa_sign(
    const wcurve_spec_t *wcurve,
    uint32_t *r,
    uint32_t *s,
    const uint32_t *d,
    const uint8_t *hash, size_t len_hash);

bool ecdsa_verify(
    const wcurve_spec_t *wcurve,
    const wcurve_point_t *e,
    const uint8_t *hash, size_t len_hash,
    const uint32_t *r,
    const uint32_t *s);

#endif //BASALT_INTERNAL_ECDSA_H
