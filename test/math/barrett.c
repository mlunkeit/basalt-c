//
// Created by M Lunkeit on 23.07.26.
//

#include <stdint.h>

#include "../../src/math/barrett.h"
#include "unittest.h"

// ===========================================================================
// BARRETT REDUCTION TESTS
// ===========================================================================

// 1. Basic reduction: 0x123456789ABCDEF0 % 13 = 10 (0xA)
DEFINE_TEST(barrett_reduce_basic)
    // Input: 0x123456789ABCDEF0 (2 limbs, Little-Endian)
    uint32_t input[2] = { 0x9ABCDEF0, 0x12345678 };
    uint32_t modulus[1] = { 13 };

    // mu = floor(4^1 / 13) = floor(16 / 13) = 1 (for len_modulus = 1)
    uint32_t mu[2] = { 0xb13b13b1, 0x13b13b13 };

    uint32_t result[1] = { 0 };
    uint32_t expected[1] = { 0xA };

    const barrett_ctx ctx = {.modulus = modulus, .mu = mu, .k = 1};

    barrett_reduce(&ctx, result, input);

    ASSERT_RAW_GENERIC_EQ(result, expected, 1);
END_TEST

// 2. Reduction of 0 (0 % m = 0)
DEFINE_TEST(barrett_reduce_zero)
    uint32_t input[16] = { 0 };
    uint32_t modulus[8] = {
        0xFFFFFC2F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    uint32_t mu[9] = {
        0x000003D1, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001
    };

    uint32_t result[8] = { 0xFFFFFFFF };
    uint32_t expected[8] = { 0 };

    const barrett_ctx ctx = {.modulus = modulus, .mu = mu, .k = 8};

    barrett_reduce(&ctx, result, input);

    ASSERT_RAW_GENERIC_EQ(result, expected, 8);
END_TEST

// 3. Input smaller than modulus (a < m => a % m = a)
DEFINE_TEST(barrett_reduce_smaller_than_modulus)
    // Input: 0x12345678 (smaller than 256-bit prime)
    uint32_t input[16] = { 0x12345678 };
    uint32_t modulus[8] = {
        0xFFFFFC2F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    uint32_t mu[9] = {
        0x000003D1, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001
    };

    uint32_t result[8] = { 0 };
    uint32_t expected[8] = { 0x12345678 };

    const barrett_ctx ctx = {.modulus = modulus, .mu = mu, .k = 8};

    barrett_reduce(&ctx, result, input);

    ASSERT_RAW_GENERIC_EQ(result, expected, 8);
END_TEST

// 4. Exact modulus boundary (m % m = 0)
DEFINE_TEST(barrett_reduce_exact_modulus)
    uint32_t input[16] = {
        0xFFFFFC2F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0, 0, 0, 0, 0, 0, 0, 0
    };

    uint32_t modulus[8] = {
        0xFFFFFC2F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    uint32_t mu[9] = {
        0x000003D1, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001
    };

    uint32_t result[8] = { 0xFFFFFFFF };
    uint32_t expected[8] = { 0 };

    const barrett_ctx ctx = {.modulus = modulus, .mu = mu, .k = 8};

    barrett_reduce(&ctx, result, input);

    ASSERT_RAW_GENERIC_EQ(result, expected, 8);
END_TEST

// 5. Upper boundary condition: (p^2 - 1) % p = p - 1
DEFINE_TEST(barrett_reduce_secp256k1_p_squared_minus_one)
    // Modulus p (8 Limbs, Little-Endian)
    static const uint32_t p[8] = {
        0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    // Precomputed mu for secp256k1 Field Prime p (9 Limbs)
    static const uint32_t mu[9] = {
        0x000003D1, 0x00000001, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001
    };

    // Input: (p^2 - 1)
    static const uint32_t input[16] = {
        0x000E90A0, 0x000007A2, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0xFFFFF85E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    // Expected result: p - 1
    static const uint32_t expected[8] = {
        0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    uint32_t result[8] = { 0 };

    const barrett_ctx ctx = {.modulus = (uint32_t*) p, .mu = (uint32_t*) mu, .k = 8};

    barrett_reduce(&ctx, result, input);

    ASSERT_RAW_GENERIC_EQ(result, expected, 8);
END_TEST

// 6. In-place reduction (result memory buffers overlaying input limbs)
DEFINE_TEST(barrett_reduce_in_place_aliasing)
    uint32_t buffer[16] = {
        0x000E90A0, 0x000007A2, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0xFFFFF85E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    static const uint32_t p[8] = {
        0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    static const uint32_t mu[9] = {
        0x000003D1, 0x00000001, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001
    };

    static const uint32_t expected[8] = {
        0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    // Reduce directly into the lower 8 limbs of the input buffer
    const barrett_ctx ctx = {.modulus = (uint32_t*) p, .mu = (uint32_t*) mu, .k = 8};

    barrett_reduce(&ctx, buffer, buffer);

    ASSERT_RAW_GENERIC_EQ(buffer, expected, 8);
END_TEST

// ===========================================================================
// MAIN RUNNER
// ===========================================================================

DEFINE_TEST_SUITE(barrett)

    RUN_TEST(barrett_reduce_basic, "basic Barrett reduction (64-bit to 32-bit mod 13)");
    RUN_TEST(barrett_reduce_zero, "Barrett reduction of zero");
    RUN_TEST(barrett_reduce_smaller_than_modulus, "Barrett reduction for value < modulus");
    RUN_TEST(barrett_reduce_exact_modulus, "Barrett reduction of exact modulus");
    RUN_TEST(barrett_reduce_secp256k1_p_squared_minus_one, "Barrett reduction on (p^2 - 1) boundary");
    RUN_TEST(barrett_reduce_in_place_aliasing, "in-place Barrett reduction");

END_TEST_SUITE