//
// Created by M Lunkeit on 10.08.26.
//

#include "basalt_ec.h"

#include "math/curves/secp256k1.h"
#include "math/curves/secp256r1.h"

basalt_err_t find_wcurve(const wcurve_spec_t **out_curve, const basalt_ec_curve_t ec) {
    if (!out_curve) {
        return BASALT_ERR_NULL_POINTER;
    }

    switch (ec) {
        case BASALT_CURVE_SECP256K1:
            *out_curve = &SECP256K1;
            break;
        case BASALT_CURVE_SECP256R1:
            *out_curve = &SECP256R1;
            break;
        default:
            return BASALT_ERR_UNSUPPORTED_CURVE;
    }

    return BASALT_OK;
}