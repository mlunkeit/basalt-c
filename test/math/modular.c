
#include <stdio.h>
#include <stdint.h>
#include "../../math/bigint.h"
#include "../../math/modular.h"

// Re-use your helper macro for assertion
#define ASSERT_UINT256_EQ(actual, expected, msg) \
    for (size_t i = 0; i < 8; i++) { \
        if ((actual).limbs[i] != (expected).limbs[i]) { \
            printf("[FAIL] %s at limb [%zu]: expected 0x%08X, got 0x%08X (Line %d)\n", \
                   msg, i, (expected).limbs[i], (actual).limbs[i], __LINE__); \
            return 1; \
        } \
    }

// The official secp256k1 prime modulus: 2^256 - 2^32 - 977
// In hex: FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFCF
static const uint256_t SECP256K1_P = {{
    0xFFFFFCF1, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
}};

// Test 1: Modular addition without exceeding the modulus (Standard Add)
static uint8_t test_mod_add_no_reduction() {
    modular_ctx ctx;
    modular_init(&ctx, &SECP256K1_P);

    uint256_t a = {{5, 0, 0, 0, 0, 0, 0, 0}};
    const uint256_t b = {{10, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t expected = {{15, 0, 0, 0, 0, 0, 0, 0}};

    modular_add_assign(&ctx, &a, &b);

    ASSERT_UINT256_EQ(a, expected, "Simple modular addition failed");
    return 0;
}

// Test 2: Modular addition that triggers a reduction (a + b >= p)
static uint8_t test_mod_add_with_reduction() {
    modular_ctx ctx;
    modular_init(&ctx, &SECP256K1_P);

    // a = p - 3
    uint256_t a = {{0xFFFFFCF1 - 3, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    // b = 5
    const uint256_t b = {{5, 0, 0, 0, 0, 0, 0, 0}};

    // (p - 3) + 5 = p + 2 = 2 (mod p)
    uint256_t expected = {{2, 0, 0, 0, 0, 0, 0, 0}};

    modular_add_assign(&ctx, &a, &b);

    ASSERT_UINT256_EQ(a, expected, "Modular addition reduction failed to wrap around p");
    return 0;
}

// Test 3: Modular subtraction without underflow (Standard Sub)
static uint8_t test_mod_sub_no_borrow() {
    modular_ctx ctx;
    modular_init(&ctx, &SECP256K1_P);

    uint256_t a = {{15, 0, 0, 0, 0, 0, 0, 0}};
    const uint256_t b = {{5, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t expected = {{10, 0, 0, 0, 0, 0, 0, 0}};

    modular_sub_assign(&ctx, &a, &b);

    ASSERT_UINT256_EQ(a, expected, "Simple modular subtraction failed");
    return 0;
}

// Test 4: Modular subtraction with underflow (a < b, needs to add p)
static uint8_t test_mod_sub_with_underflow() {
    modular_ctx ctx;
    modular_init(&ctx, &SECP256K1_P);

    uint256_t a = {{2, 0, 0, 0, 0, 0, 0, 0}};
    const uint256_t b = {{5, 0, 0, 0, 0, 0, 0, 0}};

    // 2 - 5 = -3 = p - 3 (mod p)
    uint256_t expected = {{0xFFFFFCF1 - 3, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};

    modular_sub_assign(&ctx, &a, &b);

    ASSERT_UINT256_EQ(a, expected, "Modular subtraction underflow failed to add p");
    return 0;
}

// Test 5: Modular negation of zero (-0 = 0 mod p)
static uint8_t test_mod_neg_zero() {
    modular_ctx ctx;
    modular_init(&ctx, &SECP256K1_P);

    uint256_t a = {{0}};
    uint256_t expected = {{0}};

    modular_neg_assign(&ctx, &a);

    ASSERT_UINT256_EQ(a, expected, "Negating zero should result in zero");
    return 0;
}

// Test 6: Modular negation of a regular value (-a = p - a mod p)
static uint8_t test_mod_neg_value() {
    modular_ctx ctx;
    modular_init(&ctx, &SECP256K1_P);

    uint256_t a = {{5, 0, 0, 0, 0, 0, 0, 0}};

    // -5 = p - 5
    uint256_t expected = {{0xFFFFFCF1 - 5, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};

    modular_neg_assign(&ctx, &a);

    ASSERT_UINT256_EQ(a, expected, "Modular negation failed");
    return 0;
}

int run_modular_tests() {
    printf("Starting modular arithmetic tests (secp256k1 modulus)...\n\n");

    uint8_t failed = 0;

    failed |= test_mod_add_no_reduction();
    failed |= test_mod_add_with_reduction();
    failed |= test_mod_sub_no_borrow();
    failed |= test_mod_sub_with_underflow();
    failed |= test_mod_neg_zero();
    failed |= test_mod_neg_value();

    if (failed == 0) {
        printf("\n[SUCCESS] Passed all modular arithmetic tests!\n");
    } else {
        printf("\n[FAIL] One or more modular tests failed.\n");
    }

    return failed;
}