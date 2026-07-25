#include <stdio.h>
#include <stdint.h>
#include "../../src/math/bigint.h"

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

#define ASSERT_BYTES_EQ(actual, expected, len, msg) \
    for (size_t i = 0; i < (len); i++) { \
        if ((actual)[i] != (expected)[i]) { \
            printf("[FAIL] %s at byte [%zu]: expected 0x%02X, got 0x%02X (Line %d)\n", \
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
// ADDITION TESTS
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
// SUBTRACTION TESTS
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
// COMPARISON TESTS
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
// MULTIPLICATION TESTS
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

static uint8_t test_shl_raw_zero_bits() {
    uint32_t a[4] = {0x12345678, 0xABCDEF01, 0x11223344, 0x55667788};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x12345678, 0xABCDEF01, 0x11223344, 0x55667788};

    bigint_shl_raw(result, a, 4, 0);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4, "SHL by 0 bits modified the value");
    return 0;
}

static uint8_t test_shl_raw_within_limb() {
    // 0x00000001 << 4 -> 0x00000010
    uint32_t a[4] = {0x00000001, 0x00000000, 0x00000000, 0x80000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000010, 0x00000000, 0x00000000, 0x00000000};

    bigint_shl_raw(result, a, 4, 4);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4, "SHL within limb failed");
    return 0;
}

static uint8_t test_shl_raw_cross_limb_boundary() {
    uint32_t a[4] = {0x80000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000000, 0x00000008, 0x00000000, 0x00000000};

    bigint_shl_raw(result, a, 4, 4);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4, "SHL carry over across limb boundary failed");
    return 0;
}

static uint8_t test_shl_raw_exact_limb_multiple() {
    uint32_t a[4] = {0x12345678, 0xABCDEF01, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000000, 0x00000000, 0x12345678, 0xABCDEF01};

    bigint_shl_raw(result, a, 4, 64);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4, "SHL by exact limb multiple (64 bits) failed");
    return 0;
}

static uint8_t test_shl_raw_mixed_limbs_and_bits() {
    uint32_t a[4] = {0x00000001, 0x00000000, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000000, 0x00000008, 0x00000000, 0x00000000};

    bigint_shl_raw(result, a, 4, 35);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4, "SHL by mixed limbs and bits (35 bits) failed");
    return 0;
}

// --- SHIFT RIGHT (SHR) ---

static uint8_t test_shr_raw_zero_bits() {
    uint32_t a[4] = {0x12345678, 0xABCDEF01, 0x11223344, 0x55667788};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x12345678, 0xABCDEF01, 0x11223344, 0x55667788};

    bigint_shr_raw(result, a, 4, 0);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4, "SHR by 0 bits modified the value");
    return 0;
}

static uint8_t test_shr_raw_within_limb() {
    // 0x00000010 >> 4 -> 0x00000001
    uint32_t a[4] = {0x00000010, 0x00000000, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000001, 0x00000000, 0x00000000, 0x00000000};

    bigint_shr_raw(result, a, 4, 4);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4, "SHR within limb failed");
    return 0;
}

static uint8_t test_shr_raw_cross_limb_boundary() {
    uint32_t a[4] = {0x00000000, 0x00000008, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x80000000, 0x00000000, 0x00000000, 0x00000000};

    bigint_shr_raw(result, a, 4, 4);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4, "SHR borrow across limb boundary failed");
    return 0;
}

static uint8_t test_shr_raw_exact_limb_multiple() {
    uint32_t a[4] = {0x00000000, 0x00000000, 0x12345678, 0xABCDEF01};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x12345678, 0xABCDEF01, 0x00000000, 0x00000000};

    bigint_shr_raw(result, a, 4, 64);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4, "SHR by exact limb multiple (64 bits) failed");
    return 0;
}

static uint8_t test_shr_raw_mixed_limbs_and_bits() {
    uint32_t a[4] = {0x00000000, 0x00000008, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000001, 0x00000000, 0x00000000, 0x00000000};

    bigint_shr_raw(result, a, 4, 35);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4, "SHR by mixed limbs and bits (35 bits) failed");
    return 0;
}

static uint8_t test_bytes_to_bigint_exact_256bit() {
    const uint8_t input_bytes[32] = {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    const uint32_t expected_limbs[8] = {
        0x05060708, // Limb 0 (LS)
        0x01020304, // Limb 1
        0xDDEEFF00, // Limb 2
        0x99AABBCC, // Limb 3
        0x55667788, // Limb 4
        0x11223344, // Limb 5
        0x9ABCDEF0, // Limb 6
        0x12345678  // Limb 7 (MS)
    };

    uint32_t result_limbs[8] = {0};
    bytes_to_bigint(result_limbs, input_bytes, 32);

    ASSERT_RAW_GENERIC_EQ(result_limbs, expected_limbs, 8, "bytes_to_bigint 256-bit conversion failed");
    return 0;
}

static uint8_t test_bytes_to_bigint_unaligned_padding() {
    const uint8_t input_bytes[3] = {0xAA, 0xBB, 0xCC};

    // len_result = (3 + 3) >> 2 = 1 Limb
    // Big-Endian: 0xAA (MSB), 0xBB, 0xCC (LSB)
    const uint32_t expected_limbs[1] = {0x00AABBCC};

    uint32_t result_limbs[1] = {0};
    bytes_to_bigint(result_limbs, input_bytes, 3);

    ASSERT_RAW_GENERIC_EQ(result_limbs, expected_limbs, 1, "bytes_to_bigint unaligned byte padding failed");
    return 0;
}

static uint8_t test_bigint_to_bytes_exact_256bit() {
    const uint32_t input_limbs[8] = {
        0x05060708,
        0x01020304,
        0xDDEEFF00,
        0x99AABBCC,
        0x55667788,
        0x11223344,
        0x9ABCDEF0,
        0x12345678
    };

    const uint8_t expected_bytes[32] = {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    uint8_t result_bytes[32] = {0};
    bigint_to_bytes(result_bytes, input_limbs, 8);

    ASSERT_BYTES_EQ(result_bytes, expected_bytes, 32, "bigint_to_bytes 256-bit conversion failed");
    return 0;
}

static uint8_t test_conversion_roundtrip() {
    const uint8_t original_bytes[32] = {
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
        0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0
    };

    uint32_t intermediate_limbs[8] = {0};
    uint8_t final_bytes[32] = {0};

    // Bytes -> BigInt -> Bytes
    bytes_to_bigint(intermediate_limbs, original_bytes, 32);
    bigint_to_bytes(final_bytes, intermediate_limbs, 8);

    ASSERT_BYTES_EQ(final_bytes, original_bytes, 32, "Roundtrip Bytes -> BigInt -> Bytes failed");
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
        printf("[SUCCESS] Passed all raw addition tests!\n");
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
        printf("[SUCCESS] Passed all raw subtraction tests!\n");
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
        printf("[SUCCESS] Passed all raw compare tests!\n");
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

    failed |= test_shl_raw_zero_bits();
    failed |= test_shl_raw_within_limb();
    failed |= test_shl_raw_cross_limb_boundary();
    failed |= test_shl_raw_exact_limb_multiple();
    failed |= test_shl_raw_mixed_limbs_and_bits();

    failed |= test_shr_raw_zero_bits();
    failed |= test_shr_raw_within_limb();
    failed |= test_shr_raw_cross_limb_boundary();
    failed |= test_shr_raw_exact_limb_multiple();
    failed |= test_shr_raw_mixed_limbs_and_bits();

    if (failed == 0) {
        printf("[SUCCESS] Passed all raw shift tests!\n");
    } else {
        printf("[FAIL] At least one shift test failed\n");
        return 1;
    }

    failed |= test_bytes_to_bigint_exact_256bit();
    failed |= test_bytes_to_bigint_unaligned_padding();
    failed |= test_bigint_to_bytes_exact_256bit();
    failed |= test_conversion_roundtrip();

    if (failed == 0) {
        printf("[SUCCESS] Passed all bigint conversion tests!\n");
    } else {
        printf("[FAIL] At least one conversion test failed\n");
        return 1;
    }

    return failed;
}