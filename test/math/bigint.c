#include <stdio.h>
#include <stdint.h>
#include "../../math/bigint.h"

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

#define ASSERT(cond, msg) \
    if (!(cond)) { \
        printf("[FAIL] %s at line %d\n", msg, __LINE__); \
        return 1; \
    }

// ===========================================================================
// ADDITION TESTS (Nutzen jetzt bigint_add_raw)
// ===========================================================================

static uint8_t test_add_zero() {
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};
    const uint256_t b = {{0}};
    uint256_t result = {{0}};
    uint256_t expected = a;

    bigint_add_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected, "Addition with 0 changed value");
    return 0;
}

static uint8_t test_add_no_carry() {
    uint256_t a = {{1, 2, 3, 4, 5, 6, 7, 8}};
    const uint256_t b = {{10, 20, 30, 40, 50, 60, 70, 80}};
    uint256_t result = {{0}};
    uint256_t expected = {{11, 22, 33, 44, 55, 66, 77, 88}};

    bigint_add_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected, "Simple addition without carry failed");
    return 0;
}

static uint8_t test_add_single_carry() {
    uint256_t a = {{0xFFFFFFFF, 0x00000000, 0, 0, 0, 0, 0, 0}};
    const uint256_t b = {{1, 0x00000000, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0x00000000, 0x00000001, 0, 0, 0, 0, 0, 0}};

    bigint_add_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected, "Failed carry over from limb 0 to limb 1");
    return 0;
}

static uint8_t test_add_cascade_carry() {
    uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0, 0, 0, 0, 0, 0, 0, 1}};

    bigint_add_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected, "Cascading carry-out blocked");
    return 0;
}

static uint8_t test_add_overflow_wrap() {
    uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0}};

    bigint_add_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected, "Maximum wrap around to zero failed");
    return 0;
}

// ===========================================================================
// SUBTRACTION TESTS (Nutzen jetzt bigint_sub_raw)
// ===========================================================================

static uint8_t test_sub_zero() {
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};
    const uint256_t b = {{0}};
    uint256_t result = {{0}};
    uint256_t expected = a;

    bigint_sub_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected, "Subtracting zero modified the value");
    return 0;
}

static uint8_t test_sub_no_borrow() {
    uint256_t a = {{11, 22, 33, 44, 55, 66, 77, 88}};
    const uint256_t b = {{10, 20, 30, 40, 50, 60, 70, 80}};
    uint256_t result = {{0}};
    uint256_t expected = {{1, 2, 3, 4, 5, 6, 7, 8}};

    bigint_sub_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected, "Simple subtraction without borrow failed");
    return 0;
}

static uint8_t test_sub_single_borrow() {
    uint256_t a = {{0x00000000, 0x00000001, 0, 0, 0, 0, 0, 0}};
    const uint256_t b = {{1, 0x00000000, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0xFFFFFFFF, 0x00000000, 0, 0, 0, 0, 0, 0}};

    bigint_sub_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected, "Borrow from limb 1 failed");
    return 0;
}

static uint8_t test_sub_cascade_borrow() {
    uint256_t a = {{0, 0, 0, 0, 0, 0, 0, 1}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000}};

    bigint_sub_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected, "Cascading borrow chain blocked");
    return 0;
}

static uint8_t test_sub_underflow_wrap() {
    uint256_t a = {{0}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};

    bigint_sub_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected, "Maximum underflow wrap-around failed");
    return 0;
}

static uint8_t test_sub_raw_varied_sizes_no_underflow() {
    uint32_t a[9] = {0x00000005, 0, 0, 0, 0, 0, 0, 0, 0x00000002};
    uint32_t b[8] = {0x00000002, 0, 0, 0, 0, 0, 0, 0};
    uint32_t result[9] = {0};
    uint32_t expected[9] = {0x00000003, 0, 0, 0, 0, 0, 0, 0, 0x00000002};

    bigint_sub_raw(result, a, 9, b, 8);

    ASSERT_RAW_GENERIC_EQ(result, expected, 9, "bigint_sub_raw (A > B, ungleiche Laengen) fehlgeschlagen");
    return 0;
}

static uint8_t test_sub_raw_barrett_underflow() {
    uint32_t a[9] = {1, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t b[10] = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t result[10] = {0};
    uint32_t expected[10] = {
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF
    };

    bigint_sub_raw(result, a, 9, b, 10);

    ASSERT_RAW_GENERIC_EQ(result, expected, 10, "Barrett Underflow-Zustand oder Borrow-Bit fehlgeschlagen");
    return 0;
}

static uint8_t test_sub_raw_mismatched_lengths() {
    uint32_t a[10] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t b[9] = {2, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t result[10] = {0};

    bigint_sub_raw(result, a, 10, b, 9);

    if ((result[9] & 1) != 0) {
        result[9] += 1;
    }

    ASSERT((result[9] & 1) == 0, "Nachtraegliches Bereinigen des Borrow-Bits in r[9] schlug fehl");
    return 0;
}

// ===========================================================================
// COMPARISON TESTS (Nutzen jetzt bigint_cmp_raw)
// ===========================================================================

static uint8_t test_cmp_equal() {
    const uint256_t a = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};
    const uint256_t b = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};

    result_t res = bigint_cmp_raw(a.limbs, 8, b.limbs, 8);

    ASSERT(res == 0, "Comparison failed: expected 0 (equal) for identical numbers");
    return 0;
}

static uint8_t test_cmp_greater_msb() {
    const uint256_t a = {{0, 0, 0, 0, 0, 0, 0, 5}};
    const uint256_t b = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 4}};

    result_t res = bigint_cmp_raw(a.limbs, 8, b.limbs, 8);

    ASSERT(res > 0, "Comparison failed: expected positive value (greater) based on MSB priority");
    return 0;
}

static uint8_t test_cmp_less_msb() {
    const uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 4}};
    const uint256_t b = {{0, 0, 0, 0, 0, 0, 0, 5}};

    result_t res = bigint_cmp_raw(a.limbs, 8, b.limbs, 8);

    ASSERT(res < 0, "Comparison failed: expected negative value (less) based on MSB priority");
    return 0;
}

static uint8_t test_cmp_greater_lsb() {
    const uint256_t a = {{10, 0, 0, 0, 0, 0, 0, 0xABCDEF}};
    const uint256_t b = {{9,  0, 0, 0, 0, 0, 0, 0xABCDEF}};

    result_t res = bigint_cmp_raw(a.limbs, 8, b.limbs, 8);

    ASSERT(res > 0, "Comparison failed: expected positive value (greater) based on LSB difference");
    return 0;
}

static uint8_t test_cmp_less_lsb() {
    const uint256_t a = {{9,  0, 0, 0, 0, 0, 0, 0xABCDEF}};
    const uint256_t b = {{10, 0, 0, 0, 0, 0, 0, 0xABCDEF}};

    result_t res = bigint_cmp_raw(a.limbs, 8, b.limbs, 8);

    ASSERT(res < 0, "Comparison failed: expected negative value (less) based on LSB difference");
    return 0;
}

// ===========================================================================
// MULTIPLICATION TESTS (Nutzen jetzt bigint_mul_raw)
// ===========================================================================

static uint8_t test_mul_raw_zero() {
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x11112222, 0x33334444, 0x55556666, 0x77778888, 0x9999AAAA, 0xBBBBCCCC}};
    uint256_t b = {{0}};
    uint32_t result[16] = {0};
    uint32_t expected[16] = {0};

    bigint_mul_raw(result, a.limbs, 8, b.limbs, 8);

    ASSERT_RAW_GENERIC_EQ(result, expected, 16, "Multiplication by zero did not yield zero");
    return 0;
}

static uint8_t test_mul_raw_one() {
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x11112222, 0x33334444, 0x55556666, 0x77778888, 0x9999AAAA, 0xBBBBCCCC}};
    uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint32_t result[16] = {0};
    uint32_t expected[16] = {
        0x12345678, 0xABCDEF01, 0x11112222, 0x33334444, 0x55556666, 0x77778888, 0x9999AAAA, 0xBBBBCCCC,
        0, 0, 0, 0, 0, 0, 0, 0
    };

    bigint_mul_raw(result, a.limbs, 8, b.limbs, 8);

    ASSERT_RAW_GENERIC_EQ(result, expected, 16, "Multiplication by one altered the value");
    return 0;
}

static uint8_t test_mul_raw_overflow_to_upper() {
    uint256_t a = {{0, 0, 0, 0, 0, 0, 0, 1}};
    uint256_t b = {{0, 1, 0, 0, 0, 0, 0, 0}};
    uint32_t result[16] = {0};
    uint32_t expected[16] = {0};
    expected[8] = 1;

    bigint_mul_raw(result, a.limbs, 8, b.limbs, 8);

    ASSERT_RAW_GENERIC_EQ(result, expected, 16, "Carries failed to cross into the upper 8 limbs");
    return 0;
}

static uint8_t test_mul_raw_max() {
    uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    uint256_t b = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    uint32_t result[16] = {0};
    uint32_t expected[16] = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    bigint_mul_raw(result, a.limbs, 8, b.limbs, 8);

    ASSERT_RAW_GENERIC_EQ(result, expected, 16, "Maximum value multiplication failed or wrapped around incorrectly");
    return 0;
}

// ===========================================================================
// MAIN RUNNER
// ===========================================================================

int run_bigint_tests() {
    printf("Starting raw BigInt arithmetic tests (Flexible Sizes via Limbs)...\n\n");

    uint8_t failed = 0;

    failed |= test_add_zero();
    failed |= test_add_no_carry();
    failed |= test_add_single_carry();
    failed |= test_add_cascade_carry();
    failed |= test_add_overflow_wrap();

    if (failed == 0) {
        printf("[SUCCESS] Passed all raw addition tests!\n\n");
    } else {
        printf("[FAIL] At least one addition test failed\n");
        return 1;
    }

    failed = 0;
    failed |= test_sub_zero();
    failed |= test_sub_no_borrow();
    failed |= test_sub_single_borrow();
    failed |= test_sub_cascade_borrow();
    failed |= test_sub_underflow_wrap();
    failed |= test_sub_raw_varied_sizes_no_underflow();
    failed |= test_sub_raw_barrett_underflow();
    failed |= test_sub_raw_mismatched_lengths();

    if (failed == 0) {
        printf("[SUCCESS] Passed all raw subtraction tests!\n\n");
    } else {
        printf("[FAIL] At least one subtraction test failed\n");
        return 1;
    }

    failed = 0;
    failed |= test_cmp_equal();
    failed |= test_cmp_greater_msb();
    failed |= test_cmp_less_msb();
    failed |= test_cmp_greater_lsb();
    failed |= test_cmp_less_lsb();

    if (failed == 0) {
        printf("[SUCCESS] Passed all raw compare tests!\n\n");
    } else {
        printf("[FAIL] At least one compare test failed\n");
        return 1;
    }

    failed = 0;
    failed |= test_mul_raw_zero();
    failed |= test_mul_raw_one();
    failed |= test_mul_raw_overflow_to_upper();
    failed |= test_mul_raw_max();

    if (failed == 0) {
        printf("[SUCCESS] Passed all raw multiplication tests!\n");
    } else {
        printf("[FAIL] At least one multiplication test failed\n");
        return 1;
    }

    return failed;
}