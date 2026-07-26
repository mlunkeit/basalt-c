//
// Created by M Lunkeit on 17.07.26.
//

#ifndef BASALT_SECP256K1_H
#define BASALT_SECP256K1_H

#include "wcurve.h"

static constexpr uint32_t SECP256K1_P[8] = {
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

static constexpr uint32_t SECP256K1_N[8] = {
    0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

static constexpr uint32_t SECP256K1_A[8] = {0};

static constexpr uint32_t SECP256K1_B[8] = {7, 0, 0, 0, 0, 0, 0, 0};

static constexpr wcurve_point_t SECP256K1_G = {
    .x = {
        0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
        0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E
    },
    .y = {
        0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
        0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77
    }
};

static constexpr uint32_t SECP256K1_MU_P[9] = {
    0x000003D1, 0x00000001, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001
};

static constexpr uint32_t SECP256K1_MU_N[9] = {
    0x2FC9BEC0, 0x402DA173, 0x50B75FC4, 0x45512319,
    0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001
};

static const wcurve_spec_t SECP256K1 = {
    .p = SECP256K1_P,
    .len_p = 8,

    .n = SECP256K1_N,
    .len_n = 8,

    .a = SECP256K1_A,
    .b = SECP256K1_B,

    .g = SECP256K1_G,

    .mu_p = SECP256K1_MU_P,
    .mu_n = SECP256K1_MU_N
};

#endif //BASALT_SECP256K1_H
