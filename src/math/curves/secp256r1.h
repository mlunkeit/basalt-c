//
// Created by M Lunkeit on 26.07.26.
//

#ifndef BASALT_SECP256R1_H
#define BASALT_SECP256R1_H

#include <stdint.h>
#include "math/curves/wcurve.h"

static constexpr uint32_t SECP256R1_P[8] = {
    0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xffffffff
};

static constexpr wcurve_point_t SECP256R1_G = {
    .x = {
        0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81,
        0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2
    },
    .y = {
        0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357,
        0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2
    }
};

static constexpr uint32_t SECP256R1_N[8] = {
    0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad,
    0xffffffff, 0xffffffff, 0x00000000, 0xffffffff
};

static constexpr uint32_t SECP256R1_A[8] = {
    0xfffffffc, 0xffffffff, 0xffffffff, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xffffffff
};

static constexpr uint32_t SECP256R1_B[8] = {
    0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0,
    0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8
};

static constexpr uint32_t SECP256R1_MU_P[9] = {
    0x00000003, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE,
    0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000000,
    0x00000001
};

static constexpr uint32_t SECP256R1_MU_N[9] = {
    0xEEDF9BFE, 0x012FFD85, 0xDF1A6C21, 0x43190552,
    0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000000,
    0x00000001
};

static const wcurve_spec_t SECP256R1 = {
    .p = SECP256R1_P,
    .len_p = 8,

    .n = SECP256R1_N,
    .len_n = 8,

    .a = SECP256R1_A,
    .b = SECP256R1_B,

    .g = SECP256R1_G,

    .mu_p = SECP256R1_MU_P,
    .mu_n = SECP256R1_MU_N
};

#endif //BASALT_SECP256R1_H
