#include <stdint.h>
#include "math/modular.h"
#include "unittest.h"

// ===========================================================================
// MODULAR ADDITION TESTS
// ===========================================================================

DEFINE_TEST(mod_add_simple)
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}}; // Modulus = 100
    uint256_t a   = {{40, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t b   = {{35, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{75, 0, 0, 0, 0, 0, 0, 0}}; // 40 + 35 = 75 < 100

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_add_raw(&ctx, res.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(res, exp);
END_TEST

DEFINE_TEST(mod_add_overflow)
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{60, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t b   = {{55, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{15, 0, 0, 0, 0, 0, 0, 0}}; // (60 + 55) - 100 = 15

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_add_raw(&ctx, res.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(res, exp);
END_TEST

DEFINE_TEST(mod_add_exact_modulus)
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{40, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t b   = {{60, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{0}}; // 40 + 60 = 100 -> 0 mod 100

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_add_raw(&ctx, res.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(res, exp);
END_TEST

// ===========================================================================
// MODULAR SUBTRACTION TESTS
// ===========================================================================

DEFINE_TEST(mod_sub_simple)
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{75, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t b   = {{30, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{45, 0, 0, 0, 0, 0, 0, 0}}; // 75 - 30 = 45

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_sub_raw(&ctx, res.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(res, exp);
END_TEST

DEFINE_TEST(mod_sub_underflow)
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{30, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t b   = {{45, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{85, 0, 0, 0, 0, 0, 0, 0}}; // (30 - 45) + 100 = 85

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_sub_raw(&ctx, res.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(res, exp);
END_TEST

// ===========================================================================
// MODULAR NEGATION TESTS
// ===========================================================================

DEFINE_TEST(mod_neg_normal)
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{15, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t res = {{0}};
    uint256_t exp = {{85, 0, 0, 0, 0, 0, 0, 0}}; // 100 - 15 = 85

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_neg_raw(&ctx, res.limbs, a.limbs, 8);

    ASSERT_UINT256_EQ(res, exp);
END_TEST

DEFINE_TEST(mod_neg_zero)
    uint256_t mod = {{100, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t a   = {{0}};
    uint256_t res = {{0}};
    uint256_t exp = {{0}}; // -0 mod 100 = 0

    modular_ctx ctx = { .modulus = mod.limbs, .len_modulus = 8 };

    modular_neg_raw(&ctx, res.limbs, a.limbs, 8);

    ASSERT_UINT256_EQ(res, exp);
END_TEST

// ===========================================================================
// MISMATCHED LENGTHS & EDGE CASES
// ===========================================================================

DEFINE_TEST(mod_mismatched_lengths)
    uint32_t mod[4] = {0, 0, 0, 1};
    uint32_t a[2]   = {0xFFFFFFFF, 0x00000000};
    uint32_t b[3]   = {1, 0, 0};
    uint32_t res[4] = {0};
    uint32_t exp[4] = {0, 1, 0, 0};

    modular_ctx ctx = { .modulus = mod, .len_modulus = 4 };

    modular_add_raw(&ctx, res, a, 2, b, 3);

    ASSERT_RAW_GENERIC_EQ(res, exp, 4);
END_TEST

// ===========================================================================
// MAIN RUNNER
// ===========================================================================

DEFINE_TEST_SUITE(modular)

    // MODULAR ADDITION TESTS

    RUN_TEST(mod_add_simple, "simple modular addition");
    RUN_TEST(mod_add_overflow, "modular addition with overflow reduction");
    RUN_TEST(mod_add_exact_modulus, "modular addition resulting exactly in modulus");

    // MODULAR SUBTRACTION TESTS

    RUN_TEST(mod_sub_simple, "simple modular subtraction");
    RUN_TEST(mod_sub_underflow, "modular subtraction with underflow correction");

    // MODULAR NEGATION TESTS

    RUN_TEST(mod_neg_normal, "modular negation of positive value");
    RUN_TEST(mod_neg_zero, "modular negation of zero");

    // MISMATCHED LENGTHS & EDGE CASES

    RUN_TEST(mod_mismatched_lengths, "modular addition with mismatched array lengths");

END_TEST_SUITE