//
// Created by M Lunkeit on 31.07.26.
//

#ifndef BASALT_WCURVE_POINT_H
#define BASALT_WCURVE_POINT_H

#include <stdint.h>

#include "basalt/error.h"
#include "math/curves/wcurve.h"

// Compresses a point on a weierstraß curve (0x02/0x03 + X)
basalt_err_t wcurve_point_compress(
    const wcurve_spec_t *curve,
    uint8_t out[33],
    const wcurve_point_t *point
);

// Decompresses a point on a weierstraß curve using Fermat's little theorem
basalt_err_t wcurve_point_decompress(
    const wcurve_spec_t *curve,
    wcurve_point_t *point,
    const uint8_t input[33]
);

#endif //BASALT_WCURVE_POINT_H
