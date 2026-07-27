//
// Created by M Lunkeit on 25.07.26.
//

#ifndef BASALT_RFC6979_H
#define BASALT_RFC6979_H

#include <stdint.h>

#include "math/curves/wcurve.h"

void rfc6979(
    const wcurve_spec_t *wcurve,
    uint32_t *result,
    const uint32_t *d,
    const uint8_t *hash, size_t len_hash);

#endif //BASALT_RFC6979_H
