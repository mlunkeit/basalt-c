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

#define ASSERT_RAW_512_EQ(actual, expected, msg) \
    for (size_t i = 0; i < 16; i++) { \
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

static uint8_t test_add_zero() {
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};
    const uint256_t b = {{0}};
    uint256_t expected = a;

    uint256_add_assign(&a, &b);

    ASSERT_UINT256_EQ(a, expected, "Addition with 0 changed value");
    return 0;
}

static uint8_t test_add_no_carry() {
    uint256_t a = {{1, 2, 3, 4, 5, 6, 7, 8}};
    const uint256_t b = {{10, 20, 30, 40, 50, 60, 70, 80}};
    uint256_t expected = {{11, 22, 33, 44, 55, 66, 77, 88}};

    uint256_add_assign(&a, &b);

    ASSERT_UINT256_EQ(a, expected, "Simple addition without carry failed");
    return 0;
}

static uint8_t test_add_single_carry() {
    uint256_t a = {{0xFFFFFFFF, 0x00000000, 0, 0, 0, 0, 0, 0}};
    const uint256_t b = {{1, 0x00000000, 0, 0, 0, 0, 0, 0}};
    uint256_t expected = {{0x00000000, 0x00000001, 0, 0, 0, 0, 0, 0}};

    uint256_add_assign(&a, &b);

    ASSERT_UINT256_EQ(a, expected, "Failed carry over from limb 0 to limb 1");
    return 0;
}

static uint8_t test_add_cascade_carry() {
    uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t expected = {{0, 0, 0, 0, 0, 0, 0, 1}};

    uint256_add_assign(&a, &b);

    ASSERT_UINT256_EQ(a, expected, "Cascading carry-out blocked");
    return 0;
}

static uint8_t test_add_overflow_wrap() {
    uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t expected = {{0}};

    uint256_add_assign(&a, &b);

    ASSERT_UINT256_EQ(a, expected, "Maximum wrap around to zero failed");
    return 0;
}

// Test 1: Identity Element (A - 0 = A)
static uint8_t test_sub_zero() {
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};
    const uint256_t b = {{0}}; // All limbs initialized to 0
    uint256_t expected = a;

    uint256_sub_assign(&a, &b);

    ASSERT_UINT256_EQ(a, expected, "Subtracting zero modified the value");
    return 0;
}

// Test 2: Standard Subtraction without borrowing (No Borrow)
static uint8_t test_sub_no_borrow() {
    uint256_t a = {{11, 22, 33, 44, 55, 66, 77, 88}};
    const uint256_t b = {{10, 20, 30, 40, 50, 60, 70, 80}};
    uint256_t expected = {{1, 2, 3, 4, 5, 6, 7, 8}};

    uint256_sub_assign(&a, &b);

    ASSERT_UINT256_EQ(a, expected, "Simple subtraction without borrow failed");
    return 0;
}

// Test 3: Simple borrow operation from Limb 1 (Single Borrow)
static uint8_t test_sub_single_borrow() {
    // 0x00000000 - 1 requires a borrow from the next limb (0x01 -> 0x00)
    uint256_t a = {{0x00000000, 0x00000001, 0, 0, 0, 0, 0, 0}};
    const uint256_t b = {{1, 0x00000000, 0, 0, 0, 0, 0, 0}};
    uint256_t expected = {{0xFFFFFFFF, 0x00000000, 0, 0, 0, 0, 0, 0}};

    uint256_sub_assign(&a, &b);

    ASSERT_UINT256_EQ(a, expected, "Borrow from limb 1 failed");
    return 0;
}

// Test 4: Cascading borrow across all limbs (Cascade Borrow)
static uint8_t test_sub_cascade_borrow() {
    // The chain of zeros must pass the borrow all the way to the last limb
    uint256_t a = {{0, 0, 0, 0, 0, 0, 0, 1}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t expected = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000}};

    uint256_sub_assign(&a, &b);

    ASSERT_UINT256_EQ(a, expected, "Cascading borrow chain blocked");
    return 0;
}

// Test 5: Global Underflow / Underflow Wrap-Around
static uint8_t test_sub_underflow_wrap() {
    // Subtracting 1 from 0 must wrap around to the maximum possible 256-bit value
    uint256_t a = {{0}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t expected = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};

    uint256_sub_assign(&a, &b);

    ASSERT_UINT256_EQ(a, expected, "Maximum underflow wrap-around failed");
    return 0;
}

// Test 1: Both numbers are completely identical
static uint8_t test_cmp_equal() {
    const uint256_t a = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};
    const uint256_t b = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};

    int8_t res = uint256_cmp(&a, &b);

    ASSERT(res == 0, "Comparison failed: expected 0 (equal) for identical numbers");
    return 0;
}

// Test 2: 'a' is greater than 'b' at the highest limb (MSB priority)
static uint8_t test_cmp_greater_msb() {
    const uint256_t a = {{0, 0, 0, 0, 0, 0, 0, 5}};
    const uint256_t b = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 4}};

    int8_t res = uint256_cmp(&a, &b);

    ASSERT(res > 0, "Comparison failed: expected positive value (greater) based on MSB priority");
    return 0;
}

// Test 3: 'a' is less than 'b' at the highest limb
static uint8_t test_cmp_less_msb() {
    const uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 4}};
    const uint256_t b = {{0, 0, 0, 0, 0, 0, 0, 5}};

    int8_t res = uint256_cmp(&a, &b);

    ASSERT(res < 0, "Comparison failed: expected negative value (less) based on MSB priority");
    return 0;
}

// Test 4: All high limbs are equal, but 'a' is greater at the lowest limb (LSB)
static uint8_t test_cmp_greater_lsb() {
    const uint256_t a = {{10, 0, 0, 0, 0, 0, 0, 0xABCDEF}};
    const uint256_t b = {{9,  0, 0, 0, 0, 0, 0, 0xABCDEF}};

    int8_t res = uint256_cmp(&a, &b);

    ASSERT(res > 0, "Comparison failed: expected positive value (greater) based on LSB difference");
    return 0;
}

// Test 5: All high limbs are equal, but 'a' is less at the lowest limb (LSB)
static uint8_t test_cmp_less_lsb() {
    const uint256_t a = {{9,  0, 0, 0, 0, 0, 0, 0xABCDEF}};
    const uint256_t b = {{10, 0, 0, 0, 0, 0, 0, 0xABCDEF}};

    int8_t res = uint256_cmp(&a, &b);

    ASSERT(res < 0, "Comparison failed: expected negative value (less) based on LSB difference");
    return 0;
}

// Test 1: Multiplication by Zero (A * 0 = 0)
static uint8_t test_mul_raw_zero() {
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x11112222, 0x33334444, 0x55556666, 0x77778888, 0x9999AAAA, 0xBBBBCCCC}};
    uint256_t b = {{0}};
    uint32_t result[16] = {0};
    uint32_t expected[16] = {0};

    uint256_mul_raw(result, &a, &b);

    ASSERT_RAW_512_EQ(result, expected, "Multiplication by zero did not yield zero");
    return 0;
}

// Test 2: Multiplication by One (Identity Element: A * 1 = A)
static uint8_t test_mul_raw_one() {
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x11112222, 0x33334444, 0x55556666, 0x77778888, 0x9999AAAA, 0xBBBBCCCC}};
    uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint32_t result[16] = {0};
    uint32_t expected[16] = {
        0x12345678, 0xABCDEF01, 0x11112222, 0x33334444, 0x55556666, 0x77778888, 0x9999AAAA, 0xBBBBCCCC,
        0, 0, 0, 0, 0, 0, 0, 0
    };

    uint256_mul_raw(result, &a, &b);

    ASSERT_RAW_512_EQ(result, expected, "Multiplication by one altered the value");
    return 0;
}

// Test 3: Crossing the 256-Bit Boundary (Carries must flow into the upper 8 limbs)
static uint8_t test_mul_raw_overflow_to_upper() {
    // a = 2^224 (only the highest limb of the 256-bit struct is set)
    uint256_t a = {{0, 0, 0, 0, 0, 0, 0, 1}};
    // b = 2^32 (the second limb is set)
    uint256_t b = {{0, 1, 0, 0, 0, 0, 0, 0}};

    // 2^224 * 2^32 = 2^256 -> This must land exactly in result[8] (the 9th limb)
    uint32_t result[16] = {0};
    uint32_t expected[16] = {0};
    expected[8] = 1;

    uint256_mul_raw(result, &a, &b);

    ASSERT_RAW_512_EQ(result, expected, "Carries failed to cross into the upper 8 limbs");
    return 0;
}

// Test 4: Maximum possible multiplication (MAX_256 * MAX_256)
static uint8_t test_mul_raw_max() {
    uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    uint256_t b = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    uint32_t result[16] = {0};

    // (2^256 - 1) * (2^256 - 1) = 2^512 - 2^257 + 1
    // Lower 8 limbs: 0x00000001 followed by zeros
    // Upper 8 limbs: 0xFFFFFFFE followed by 0xFFFFFFFF's
    uint32_t expected[16] = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    uint256_mul_raw(result, &a, &b);

    ASSERT_RAW_512_EQ(result, expected, "Maximum value multiplication failed or wrapped around incorrectly");
    return 0;
}

int run_bigint_tests() {
    printf("Starting uint256_add_assign tests (32-Bit Limbs)...\n\n");

    uint8_t failed = 0;

    failed |= test_add_zero();
    failed |= test_add_no_carry();
    failed |= test_add_single_carry();
    failed |= test_add_cascade_carry();
    failed |= test_add_overflow_wrap();

    if (failed == 0) {
        printf("\n[SUCCESS] Passed all addition tests!\n");
    } else {
        printf("\n[FAIL] At least one addition test failed\n");
        return 1;
    }

    failed = 0;

    failed |= test_sub_zero();
    failed |= test_sub_no_borrow();
    failed |= test_sub_single_borrow();
    failed |= test_sub_cascade_borrow();
    failed |= test_sub_underflow_wrap();

    if (failed == 0) {
        printf("\n[SUCCESS] Passed all subtraction tests!\n");
    } else {
        printf("\n[FAIL] At least one subtraction test failed\n");
        return 1;
    }

    failed = 0;
    failed |= test_cmp_equal();
    failed |= test_cmp_greater_msb();
    failed |= test_cmp_less_msb();
    failed |= test_cmp_greater_lsb();
    failed |= test_cmp_less_lsb();

    if (failed == 0) {
        printf("\n[SUCCESS] Passed all compare tests!\n");
    } else {
        printf("\n[FAIL] At least one compare test failed\n");
        return 1;
    }

    failed = 0;
    failed |= test_mul_raw_zero();
    failed |= test_mul_raw_one();
    failed |= test_mul_raw_overflow_to_upper();
    failed |= test_mul_raw_max();

    if (failed == 0) {
        printf("\n[SUCCESS] Passed all raw multiplication tests!\n");
    }

    return failed;
}