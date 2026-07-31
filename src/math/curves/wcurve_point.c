//
// Created by M Lunkeit on 31.07.26.
//

#include "math/curves/wcurve_point.h"
#include "math/bigint.h"

basalt_err_t wcurve_point_compress(
    const wcurve_spec_t *curve,
    uint8_t out[33],
    const wcurve_point_t *point)
{
    if (!curve || !out || !point) {
        return BASALT_ERR_NULL_POINTER;
    }

    if (point->infinity) {
        return BASALT_ERR_INVALID_PARAM;
    }

    if (point->y[0] & 0x1) {
        // y is odd
        out[0] = 0x3;
    } else {
        // y is even
        out[0] = 0x2;
    }

    bigint_to_bytes(out + 1, point->x, curve->len_p);
    return BASALT_OK;
}