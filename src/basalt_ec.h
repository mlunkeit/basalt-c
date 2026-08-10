//
// Created by M Lunkeit on 10.08.26.
//

#ifndef BASALT_INTERNAL_EC_H
#define BASALT_INTERNAL_EC_H

#include "basalt/error.h"
#include "basalt/ec.h"
#include "math/curves/wcurve.h"

// finds the matching weierstraß curve to the input enum value
basalt_err_t find_wcurve(const wcurve_spec_t **out_curve, basalt_ec_curve_t ec);

#endif //BASALT_INTERNAL_EC_H
