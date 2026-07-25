#include <stdio.h>
#include <stdint.h>
#include "../../src/math/modular.h"

#define ASSERT_UINT256_EQ(actual, expected, msg) \
    for (size_t i = 0; i < 8; i++) { \
        if ((actual).limbs[i] != (expected).limbs[i]) { \
            printf("[FAIL] %s at limb [%zu]: expected 0x%08X, got 0x%08X (Line %d)\n", \
                   msg, i, (expected).limbs[i], (actual).limbs[i], __LINE__); \
            return 1; \
        } \
    }

#define ASSERT_RAW_GENERIC_EQ(actual, expected, len, msg) \
    for (size_t i = 0; i < (len); i++) { \
        if ((actual)[i] != (expected)[i]) { \
            printf("[FAIL] %s at limb [%zu]: expected 0x%08X, got 0x%08X (Line %d)\n", \
                   msg, i, (expected)[i], (actual)[i], __LINE__); \
            return 1; \
        } \
    }

// ===========================================================================
// MODULAR ADDITION TESTS
// ===========================================================================

static uint8_t test_mod_add_simple() {
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}}; // Modulus = 100
    uint256_t a   = {{40, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t b   = {{35, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{75, 0, 0, 0, 0, 0, 0, 0}}; // 40 + 35 = 75 < 100

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_add_raw(&ctx, res.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(res, exp, "Simple modular addition failed");
    return 0;
}

static uint8_t test_mod_add_overflow() {
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{60, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t b   = {{55, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{15, 0, 0, 0, 0, 0, 0, 0}}; // (60 + 55) - 100 = 15

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_add_raw(&ctx, res.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(res, exp, "Modular addition overflow reduction failed");
    return 0;
}

static uint8_t test_mod_add_exact_modulus() {
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{40, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t b   = {{60, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{0}}; // 40 + 60 = 100 -> 0 mod 100

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_add_raw(&ctx, res.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(res, exp, "Addition resulting exactly in modulus failed to wrap to 0");
    return 0;
}

// ===========================================================================
// MODULAR SUBTRACTION TESTS
// ===========================================================================

static uint8_t test_mod_sub_simple() {
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{75, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t b   = {{30, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{45, 0, 0, 0, 0, 0, 0, 0}}; // 75 - 30 = 45

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_sub_raw(&ctx, res.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(res, exp, "Simple modular subtraction failed");
    return 0;
}

static uint8_t test_mod_sub_underflow() {
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{30, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t b   = {{45, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{85, 0, 0, 0, 0, 0, 0, 0}}; // (30 - 45) + 100 = 85

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_sub_raw(&ctx, res.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(res, exp, "Modular subtraction underflow correction failed");
    return 0;
}

// ===========================================================================
// MODULAR NEGATION TESTS
// ===========================================================================

static uint8_t test_mod_neg_normal() {
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{15, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{85, 0, 0, 0, 0, 0, 0, 0}}; // 100 - 15 = 85

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_neg_raw(&ctx, res.limbs, a.limbs, 8);

    ASSERT_UINT256_EQ(res, exp, "Modular negation of positive value failed");
    return 0;
}

static uint8_t test_mod_neg_zero() {
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{0}};
    uint256_t res = {{0}};
    uint256_t exp = {{0}}; // -0 mod 100 = 0

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_neg_raw(&ctx, res.limbs, a.limbs, 8);

    ASSERT_UINT256_EQ(res, exp, "Modular negation of zero must remain zero");
    return 0;
}

// ===========================================================================
// MISMATCHED LENGTHS & EDGE CASES
// ===========================================================================

static uint8_t test_mod_mismatched_lengths() {
    uint32_t mod[4] = {0, 0, 0, 1}; // Modulus über 4 Limbs gestreckt
    uint32_t a[2]   = {0xFFFFFFFF, 0x00000000};
    uint32_t b[3]   = {1, 0, 0};
    uint32_t res[4] = {0};
    uint32_t exp[4] = {0, 1, 0, 0}; // Übertrag schiebt 1 in das zweite Limb

    modular_ctx ctx = { .modulus = mod, .len_modulus = 4 };

    // a (len 2) + b (len 3), Ergebnis geschrieben in res (len des Modulus = 4)
    modular_add_raw(&ctx, res, a, 2, b, 3);

    ASSERT_RAW_GENERIC_EQ(res, exp, 4, "Modular addition with mismatched array lengths failed");
    return 0;
}

// ===========================================================================
// MAIN RUNNER
// ===========================================================================

int run_modular_tests() {
    printf("Starting raw Modular Arithmetic tests...\n\n");

    uint8_t failed = 0;

    // Addition

    failed |= test_mod_add_simple();
    failed |= test_mod_add_overflow();
    failed |= test_mod_add_exact_modulus();

    if (failed == 0) {
        printf("[SUCCESS] Passed all modular addition tests!\n\n");
    } else {
        printf("[FAIL] At least one modular addition test failed\n");
        return 1;
    }

    // Negation
    failed = 0;
    failed |= test_mod_neg_normal();
    failed |= test_mod_neg_zero();

    if (failed == 0) {
        printf("[SUCCESS] Passed all modular negation tests!\n\n");
    } else {
        printf("[FAIL] At least one modular negation test failed\n");
        return 1;
    }

    // Subtraction
    failed = 0;
    failed |= test_mod_sub_simple();
    failed |= test_mod_sub_underflow();

    if (failed == 0) {
        printf("[SUCCESS] Passed all modular subtraction tests!\n\n");
    } else {
        printf("[FAIL] At least one modular subtraction test failed\n");
        return 1;
    }

    // Mismatched lengths
    failed = 0;
    failed |= test_mod_mismatched_lengths();

    if (failed == 0) {
        printf("[SUCCESS] Passed all dynamic length modular tests!\n");
    } else {
        printf("[FAIL] Mismatched length modular test failed\n");
        return 1;
    }

    return 0;
}