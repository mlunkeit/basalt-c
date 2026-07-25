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
        if ((actual).limbs[i] != (expected).limbs[i]) { \
            printf("[FAIL] %s at limb [%zu]: expected 0x%08X, got 0x%08X (Line %d)\n", \
                   msg, i, (expected).limbs[i], (actual).limbs[i], __LINE__); \
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

static const secp256k1_point_t G = {
    .x = {{0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}},
    .y = {{0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}},
    .infinity = false
};

// Erwartetes 2G = G + G
static const secp256k1_point_t EXPECTED_2G = {
    .x = {{0x5C709EE5, 0xABAC09B9, 0x8CEF3CA7, 0x5C778E4B, 0x95C07CD8, 0x3045406E, 0x41ED7D6D, 0xC6047F94}},
    .y = {{0x50CFE52A, 0x236431A9, 0x3266D0E1, 0xF7F63265, 0x466CEAEE, 0xA3C58419, 0xA63DC339, 0x1AE168FE}},
    .infinity = false
};

// Erwartetes 3G = G + 2G
static const secp256k1_point_t EXPECTED_3G = {
    .x = {{0xBCE036F9, 0x8601F113, 0x836F99B0, 0xB531C845, 0xF89D5229, 0x49344F85, 0x9258C310, 0xF9308A01}},
    .y = {{0x84B8E672, 0x6CB9FD75, 0x34C2231B, 0x6500A999, 0x2A37F356, 0x0FE337E6, 0x632DE814, 0x388F7B0F}},
    .infinity = false
};

void secp256k1_reduce(uint256_t* result, uint32_t limbs[16]);
void secp256k1_mul(uint256_t* result, const uint256_t *a, const uint256_t *b);
void secp256k1_pow(uint256_t *result, const uint256_t *a, const uint256_t *b);
void secp256k1_invert(uint256_t *result, const uint256_t *a);

static uint256_t uint256_from_u64(uint64_t val) {
    uint256_t res = {{0}};
    res.limbs[0] = (uint32_t)(val & 0xFFFFFFFF);
    res.limbs[1] = (uint32_t)(val >> 32);
    return res;
}

static uint8_t test_barrett_underflow_reduction() {
    uint32_t limbs[16] = {
        0x000E90A0, 0x000007A2, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFF85E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    uint256_t result;

    uint256_t expected = {{
        0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    }};

    secp256k1_reduce(&result, limbs);

    ASSERT_UINT256_EQ(result, expected, "Barrett reduction failed on p^2 - 1 boundary condition");

    return 0;
}

// 1. a^0 = 1
static uint8_t test_pow_zero_exponent() {
    uint256_t base = uint256_from_u64(123456789);
    uint256_t exp = uint256_from_u64(0);
    uint256_t result;
    uint256_t expected = uint256_from_u64(1);

    secp256k1_pow(&result, &base, &exp);

    ASSERT_UINT256_EQ(result, expected, "a^0 must be 1");
    return 0;
}

// 2. a^1 = a
static uint8_t test_pow_one_exponent() {
    uint256_t base = uint256_from_u64(987654321);
    uint256_t exp = uint256_from_u64(1);
    uint256_t result;

    secp256k1_pow(&result, &base, &exp);

    ASSERT_UINT256_EQ(result, base, "a^1 must be a");
    return 0;
}

// 3. 0^b = 0 (für b > 0)
static uint8_t test_pow_zero_base() {
    uint256_t base = uint256_from_u64(0);
    uint256_t exp = uint256_from_u64(42);
    uint256_t result;
    uint256_t expected = uint256_from_u64(0);

    secp256k1_pow(&result, &base, &exp);

    ASSERT_UINT256_EQ(result, expected, "0^b must be 0");
    return 0;
}

// 4. 1^b = 1
static uint8_t test_pow_one_base() {
    uint256_t base = uint256_from_u64(1);
    uint256_t exp = uint256_from_u64(0xDEADBEEF);
    uint256_t result;
    uint256_t expected = uint256_from_u64(1);

    secp256k1_pow(&result, &base, &exp);

    ASSERT_UINT256_EQ(result, expected, "1^b must be 1");
    return 0;
}

static uint8_t test_pow_small_known_values() {
    uint256_t base = uint256_from_u64(3);
    uint256_t exp = uint256_from_u64(5);
    uint256_t result;
    uint256_t expected = uint256_from_u64(243);

    secp256k1_pow(&result, &base, &exp);

    ASSERT_UINT256_EQ(result, expected, "3^5 must be 243");
    return 0;
}

static uint8_t test_pow_fermat_little_theorem() {
    uint256_t p_minus_1 = {{
        0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    }};

    uint256_t base = uint256_from_u64(2);
    uint256_t result;
    uint256_t expected = uint256_from_u64(1);

    secp256k1_pow(&result, &base, &p_minus_1);

    ASSERT_UINT256_EQ(result, expected, "Fermat's Little Theorem (a^(p-1) mod p = 1) failed");
    return 0;
}

static uint8_t test_pow_in_place_aliasing() {
    uint256_t a = uint256_from_u64(3);
    uint256_t exp = uint256_from_u64(5);
    uint256_t expected = uint256_from_u64(243);

    secp256k1_pow(&a, &a, &exp);

    ASSERT_UINT256_EQ(a, expected, "In-place calculation failed (result == base)");
    return 0;
}

static uint8_t test_invert_one() {
    uint256_t a = uint256_from_u64(1);
    uint256_t result;
    uint256_t expected = uint256_from_u64(1);

    secp256k1_invert(&result, &a);

    ASSERT_UINT256_EQ(result, expected, "1^-1 must be 1");
    return 0;
}

// 2. (p - 1)^-1 = p - 1
static uint8_t test_invert_p_minus_one() {
    uint256_t p_minus_1 = {{
        0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    }};
    uint256_t result;

    secp256k1_invert(&result, &p_minus_1);

    ASSERT_UINT256_EQ(result, p_minus_1, "(p - 1)^-1 must be p - 1");
    return 0;
}

static uint8_t test_double_inversion() {
    uint256_t a = uint256_from_u64(0xDEADBEEF12345678ULL);
    uint256_t inv;
    uint256_t double_inv;

    secp256k1_invert(&inv, &a);
    secp256k1_invert(&double_inv, &inv);

    ASSERT_UINT256_EQ(double_inv, a, "((a)^-1)^-1 must equal a");
    return 0;
}

static uint8_t test_invert_in_place_aliasing() {
    uint256_t a = uint256_from_u64(0x123456789ABCDEF0ULL);
    uint256_t original_a = a;
    uint256_t expected_inv;

    secp256k1_invert(&expected_inv, &original_a);

    secp256k1_invert(&a, &a);

    ASSERT_UINT256_EQ(a, expected_inv, "In-place inversion failed (result == a)");
    return 0;
}

static uint8_t test_invert_full_256bit_value() {
    uint256_t a = {{
        0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210,
        0x55555555, 0xAAAAAAAA, 0x12093487, 0x43218765
    }};

    uint256_t inv;
    secp256k1_invert(&inv, &a);

    uint256_t check;
    secp256k1_mul(&check, &a, &inv);

    uint256_t expected_one = uint256_from_u64(1);

    ASSERT_UINT256_EQ(check, expected_one, "a * a^-1 for full 256-bit value must be 1!");
    return 0;
}

static uint8_t test_point_add_doubling() {
    secp256k1_point_t res;
    secp256k1_point_add(&res, &G, &G);

    ASSERT_POINT_EQ(res, EXPECTED_2G, "G + G failed (Doubling)");
    return 0;
}

static uint8_t test_point_add_different_points() {
    secp256k1_point_t res;
    secp256k1_point_add(&res, &G, &EXPECTED_2G);

    ASSERT_POINT_EQ(res, EXPECTED_3G, "G + 2G failed");
    return 0;
}

static uint8_t test_point_add_identity() {
    secp256k1_point_t inf = {.infinity = true};
    secp256k1_point_t res_left, res_right;

    // G + O = G
    secp256k1_point_add(&res_left, &G, &inf);
    ASSERT_POINT_EQ(res_left, G, "G + Infinity must equal G");

    // O + G = G
    secp256k1_point_add(&res_right, &inf, &G);
    ASSERT_POINT_EQ(res_right, G, "Infinity + G must equal G");

    return 0;
}

static uint8_t test_point_add_inverse() {
    uint256_t p = {{
        0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    }};

    const modular_ctx ctx = {.modulus = p.limbs, .len_modulus = 8};

    secp256k1_point_t neg_G = G;
    modular_neg_raw(&ctx, neg_G.y.limbs, G.y.limbs, 8);

    secp256k1_point_t res;
    secp256k1_point_add(&res, &G, &neg_G);

    if (!res.infinity) {
        printf("[FAIL] G + (-G) must yield Point at Infinity (Line %d)\n", __LINE__);
        return 1;
    }
    return 0;
}

static uint8_t test_point_add_in_place() {
    secp256k1_point_t p;
    secp256k1_point_init(&p);
    secp256k1_point_add(&p, &p, &EXPECTED_2G); // p = G + 2G = 3G

    ASSERT_POINT_EQ(p, EXPECTED_3G, "In-place point addition failed");
    return 0;
}

static uint8_t test_point_scale_in_place() {
    uint256_t scalar = {{3, 0, 0, 0, 0, 0, 0, 0}};

    secp256k1_point_t p;
    secp256k1_point_init(&p);
    secp256k1_point_scale(&p, &p, &scalar);

    ASSERT_POINT_EQ(p, EXPECTED_3G, "In-place point scaling failed");

    return 0;
}

int run_secp256k1_tests() {
    printf("Running tests for secp256k1 elliptic curve...\n");

    uint8_t status = 0;

    status |= test_barrett_underflow_reduction();
    status |= test_pow_zero_exponent();
    status |= test_pow_one_exponent();
    status |= test_pow_zero_base();
    status |= test_pow_one_base();
    status |= test_pow_small_known_values();
    status |= test_pow_fermat_little_theorem();
    status |= test_pow_in_place_aliasing();

    status |= test_invert_one();
    status |= test_invert_p_minus_one();
    status |= test_double_inversion();
    status |= test_invert_in_place_aliasing();
    status |= test_invert_full_256bit_value();

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