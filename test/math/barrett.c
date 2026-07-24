//
// Created by M Lunkeit on 23.07.26.
//

#include <stdio.h>
#include <stdint.h>

#include "../../math/barrett.h"

#define ASSERT_UINT32_ARRAY_EQ(actual, expected, len, msg) \
    for (size_t i = 0; i < (len); i++) { \
        if ((actual)[i] != (expected)[i]) { \
            printf("[FAIL] %s at limb [%zu]: expected 0x%08X, got 0x%08X (Line %d)\n", \
                   msg, i, (expected)[i], (actual)[i], __LINE__); \
            return 1; \
        } \
    }

// 1. Basic reduction: 0x123456789ABCDEF0 % 13 = 3
static uint8_t test_barrett_reduce_basic() {
    // Input: 0x123456789ABCDEF0 (2 limbs, Little-Endian)
    uint32_t input[2] = { 0x9ABCDEF0, 0x12345678 };
    uint32_t modulus[1] = { 13 };

    // mu = floor(4^1 / 13) = floor(16 / 13) = 1 (for len_modulus = 1)
    uint32_t mu[2] = { 0xb13b13b1, 0x13b13b13 };

    uint32_t result[1] = { 0 };
    uint32_t expected[1] = { 0xA };

    const barrett_ctx ctx = {.modulus = modulus, .mu = mu, .k = 1};

    barrett_reduce(&ctx, result, input);

    ASSERT_UINT32_ARRAY_EQ(result, expected, 1, "Basic Barrett reduction (64-bit to 32-bit mod 13) failed");
    return 0;
}

// 2. Reduction of 0 (0 % m = 0)
static uint8_t test_barrett_reduce_zero() {
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

    ASSERT_UINT32_ARRAY_EQ(result, expected, 8, "Barrett reduction of zero failed");
    return 0;
}

// 3. Input smaller than modulus (a < m => a % m = a)
static uint8_t test_barrett_reduce_smaller_than_modulus() {
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

    ASSERT_UINT32_ARRAY_EQ(result, expected, 8, "Barrett reduction for value < modulus failed");
    return 0;
}

// 4. Exact modulus boundary (m % m = 0)
static uint8_t test_barrett_reduce_exact_modulus() {
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

    ASSERT_UINT32_ARRAY_EQ(result, expected, 8, "Barrett reduction of exact modulus failed");
    return 0;
}

// 5. Upper boundary condition: (p^2 - 1) % p = p - 1
static uint8_t test_barrett_reduce_secp256k1_p_squared_minus_one() {
    // Modulus p (8 Limbs, Little-Endian)
    static constexpr uint32_t p[8] = {
        0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    // Precomputed mu for secp256k1 Field Prime p (9 Limbs)
    static constexpr uint32_t mu[9] = {
        0x000003D1, 0x00000001, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001
    };

    // Input: (p^2 - 1)
    static constexpr uint32_t input[16] = {
        0x000E90A0, 0x000007A2, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0xFFFFF85E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    // Expected result: p - 1
    static constexpr uint32_t expected[8] = {
        0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    uint32_t result[8] = { 0 };

    const barrett_ctx ctx = {.modulus = (uint32_t*) p, .mu = (uint32_t*) mu, .k = 8};

    barrett_reduce(&ctx, result, input);

    ASSERT_UINT32_ARRAY_EQ(result, expected, 8, "Barrett reduction on (p^2 - 1) boundary failed");
    return 0;
}

// 6. In-place reduction (result memory buffers overlaying input limbs)
static uint8_t test_barrett_reduce_in_place_aliasing() {
    uint32_t buffer[16] = {
        0x000E90A0, 0x000007A2, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0xFFFFF85E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    static constexpr uint32_t p[8] = {
        0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    static constexpr uint32_t mu[9] = {
        0x000003D1, 0x00000001, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001
    };

    static constexpr uint32_t expected[8] = {
        0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    // Reduce directly into the lower 8 limbs of the input buffer
    const barrett_ctx ctx = {.modulus = (uint32_t*) p, .mu = (uint32_t*) mu, .k = 8};

    barrett_reduce(&ctx, buffer, buffer);

    ASSERT_UINT32_ARRAY_EQ(buffer, expected, 8, "In-place Barrett reduction failed");
    return 0;
}

int run_barrett_tests() {
    printf("Running tests for Barrett reduction...\n");

    uint8_t status = 0;

    status |= test_barrett_reduce_basic();
    status |= test_barrett_reduce_zero();
    status |= test_barrett_reduce_smaller_than_modulus();
    status |= test_barrett_reduce_exact_modulus();
    status |= test_barrett_reduce_secp256k1_p_squared_minus_one();
    status |= test_barrett_reduce_in_place_aliasing();

    if (status != 0) {
        printf("[FAIL] Barrett reduction tests failed\n");
    } else {
        printf("[SUCCESS] All Barrett reduction tests passed!\n");
    }

    return status;
}