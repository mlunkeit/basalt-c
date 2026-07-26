//
// Created by M Lunkeit on 20.07.26.
//

#include <stdio.h>
#include <stdint.h>

#include "../../../src/math/bigint.h"
#include "../../../src/math/modular.h"
#include "../../../src/math/curves/secp256k1.h"

#define ASSERT_UINT256_EQ(actual, expected, msg) \
    for (size_t i = 0; i < 8; i++) { \
        if ((actual)[i] != (expected)[i]) { \
            printf("[FAIL] %s at limb [%zu]: expected 0x%08X, got 0x%08X (Line %d)\n", \
                   msg, i, (expected)[i], (actual)[i], __LINE__); \
            return 1; \
        } \
    }

#define ASSERT_POINT_EQ(actual, expected, msg) \
    if ((actual).infinity != (expected).infinity) { \
        printf("[FAIL] %s: infinity flag mismatch (Line %d)\n", msg, __LINE__); \
        return 1; \
    } \
    if (!(actual).infinity) { \
        ASSERT_UINT256_EQ((actual).x, (expected).x, msg " (X-Coordinate)"); \
        ASSERT_UINT256_EQ((actual).y, (expected).y, msg " (Y-Coordinate)"); \
    }

static const wcurve_point_t G = {
    .x = {0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E},
    .y = {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77},
    .infinity = false
};

// Erwartetes 2G = G + G
static const wcurve_point_t EXPECTED_2G = {
    .x = {0x5C709EE5, 0xABAC09B9, 0x8CEF3CA7, 0x5C778E4B, 0x95C07CD8, 0x3045406E, 0x41ED7D6D, 0xC6047F94},
    .y = {0x50CFE52A, 0x236431A9, 0x3266D0E1, 0xF7F63265, 0x466CEAEE, 0xA3C58419, 0xA63DC339, 0x1AE168FE},
    .infinity = false
};

// Erwartetes 3G = G + 2G
static const wcurve_point_t EXPECTED_3G = {
    .x = {0xBCE036F9, 0x8601F113, 0x836F99B0, 0xB531C845, 0xF89D5229, 0x49344F85, 0x9258C310, 0xF9308A01},
    .y = {0x84B8E672, 0x6CB9FD75, 0x34C2231B, 0x6500A999, 0x2A37F356, 0x0FE337E6, 0x632DE814, 0x388F7B0F},
    .infinity = false
};

static uint256_t uint256_from_u64(uint64_t val) {
    uint256_t res = {{0}};
    res.limbs[0] = (uint32_t)(val & 0xFFFFFFFF);
    res.limbs[1] = (uint32_t)(val >> 32);
    return res;
}

static uint8_t test_point_add_doubling() {
    wcurve_point_t res;
    wcurve_point_add(&SECP256K1, &res, &G, &G);

    ASSERT_POINT_EQ(res, EXPECTED_2G, "G + G failed (Doubling)");
    return 0;
}

static uint8_t test_point_add_different_points() {
    wcurve_point_t res;
    wcurve_point_add(&SECP256K1, &res, &G, &EXPECTED_2G);

    ASSERT_POINT_EQ(res, EXPECTED_3G, "G + 2G failed");
    return 0;
}

static uint8_t test_point_add_identity() {
    wcurve_point_t inf = {.infinity = true};
    wcurve_point_t res_left, res_right;

    // G + O = G
    wcurve_point_add(&SECP256K1, &res_left, &G, &inf);
    ASSERT_POINT_EQ(res_left, G, "G + Infinity must equal G");

    // O + G = G
    wcurve_point_add(&SECP256K1, &res_right, &inf, &G);
    ASSERT_POINT_EQ(res_right, G, "Infinity + G must equal G");

    return 0;
}

static uint8_t test_point_add_inverse() {
    uint256_t p = {{
        0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    }};

    const modular_ctx ctx = {.modulus = p.limbs, .len_modulus = 8};

    wcurve_point_t neg_G = G;
    modular_neg_raw(&ctx, neg_G.y, G.y, 8);

    wcurve_point_t res;
    wcurve_point_add(&SECP256K1, &res, &G, &neg_G);

    if (!res.infinity) {
        printf("[FAIL] G + (-G) must yield Point at Infinity (Line %d)\n", __LINE__);
        return 1;
    }
    return 0;
}

static uint8_t test_point_add_in_place() {
    wcurve_point_t p = SECP256K1_G;
    wcurve_point_add(&SECP256K1, &p, &p, &EXPECTED_2G); // p = G + 2G = 3G

    ASSERT_POINT_EQ(p, EXPECTED_3G, "In-place point addition failed");
    return 0;
}

static uint8_t test_point_scale_in_place() {
    uint32_t scalar[8] = {3, 0, 0, 0, 0, 0, 0, 0};

    wcurve_point_t p = SECP256K1_G;
    wcurve_point_scale(&SECP256K1, &p, &p, scalar);

    ASSERT_POINT_EQ(p, EXPECTED_3G, "In-place point scaling failed");

    return 0;
}

int run_secp256k1_tests() {
    printf("Running tests for secp256k1 elliptic curve...\n");

    uint8_t status = 0;

    status |= test_point_add_doubling();
    status |= test_point_add_different_points();
    status |= test_point_add_identity();
    status |= test_point_add_inverse();
    status |= test_point_add_in_place();

    status |= test_point_scale_in_place();

    if (status != 0) {
        printf("[FAIL] Tests failed\n");
    } else {
        printf("[SUCCESS] All secp256k1 tests passed!\n");
    }

    return status;
}