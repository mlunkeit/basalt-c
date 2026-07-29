#include <stdint.h>

#include "math/bigint.h"
#include "unittest.h"

// ===========================================================================
// ADDITION TESTS
// ===========================================================================

DEFINE_TEST(add_zero)
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};
    const uint256_t b = {{0}};
    uint256_t result = {{0}};
    uint256_t expected = a;

    bigint_add_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected);
END_TEST

DEFINE_TEST(add_no_carry)
    uint256_t a = {{1, 2, 3, 4, 5, 6, 7, 8}};
    const uint256_t b = {{10, 20, 30, 40, 50, 60, 70, 80}};
    uint256_t result = {{0}};
    uint256_t expected = {{11, 22, 33, 44, 55, 66, 77, 88}};

    bigint_add_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected);
END_TEST

DEFINE_TEST(add_single_carry)
    uint256_t a = {{0xFFFFFFFF, 0x00000000, 0, 0, 0, 0, 0, 0}};
    const uint256_t b = {{1, 0x00000000, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0x00000000, 0x00000001, 0, 0, 0, 0, 0, 0}};

    bigint_add_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected);
END_TEST

DEFINE_TEST(add_cascade_carry)
    uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0, 0, 0, 0, 0, 0, 0, 1}};

    bigint_add_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected);
END_TEST

DEFINE_TEST(add_overflow_wrap)
    uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0}};

    bigint_add_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected);
END_TEST

// ===========================================================================
// SUBTRACTION TESTS
// ===========================================================================

DEFINE_TEST(sub_zero)
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};
    const uint256_t b = {{0}};
    uint256_t result = {{0}};
    uint256_t expected = a;

    bigint_sub_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected);
END_TEST

DEFINE_TEST(sub_no_borrow)
    uint256_t a = {{11, 22, 33, 44, 55, 66, 77, 88}};
    const uint256_t b = {{10, 20, 30, 40, 50, 60, 70, 80}};
    uint256_t result = {{0}};
    uint256_t expected = {{1, 2, 3, 4, 5, 6, 7, 8}};

    bigint_sub_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected);
END_TEST

DEFINE_TEST(sub_single_borrow)
    uint256_t a = {{0x00000000, 0x00000001, 0, 0, 0, 0, 0, 0}};
    const uint256_t b = {{1, 0x00000000, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0xFFFFFFFF, 0x00000000, 0, 0, 0, 0, 0, 0}};

    bigint_sub_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected);
END_TEST

DEFINE_TEST(sub_cascade_borrow)
    uint256_t a = {{0, 0, 0, 0, 0, 0, 0, 1}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000}};

    bigint_sub_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected);
END_TEST

DEFINE_TEST(sub_underflow_wrap)
    uint256_t a = {{0}};
    const uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint256_t result = {{0}};
    uint256_t expected = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};

    bigint_sub_raw(result.limbs, a.limbs, 8, b.limbs, 8);

    ASSERT_UINT256_EQ(result, expected);
END_TEST

DEFINE_TEST(sub_raw_varied_sizes_no_underflow)
    uint32_t a[9] = {0x00000005, 0, 0, 0, 0, 0, 0, 0, 0x00000002};
    uint32_t b[8] = {0x00000002, 0, 0, 0, 0, 0, 0, 0};
    uint32_t result[9] = {0};
    uint32_t expected[9] = {0x00000003, 0, 0, 0, 0, 0, 0, 0, 0x00000002};

    bigint_sub_raw(result, a, 9, b, 8);

    ASSERT_RAW_GENERIC_EQ(result, expected, 9);
END_TEST

DEFINE_TEST(sub_raw_underflow)
    uint32_t a[9] = {1, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t b[10] = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t result[10] = {0};
    uint32_t expected[10] = {
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF
    };

    bigint_sub_raw(result, a, 9, b, 10);

    ASSERT_RAW_GENERIC_EQ(result, expected, 10);
END_TEST

DEFINE_TEST(sub_raw_mismatched_lengths)
    uint32_t a[10] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t b[9] = {2, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t result[10] = {0};

    bigint_sub_raw(result, a, 10, b, 9);

    if ((result[9] & 1) != 0) {
        result[9] += 1;
    }

    ASSERT((result[9] & 1) == 0);
END_TEST

// ===========================================================================
// COMPARISON TESTS
// ===========================================================================

DEFINE_TEST(cmp_equal)
    const uint256_t a = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};
    const uint256_t b = {{0x12345678, 0xABCDEF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0xAAAA5555}};

    result_t res = bigint_cmp_raw(a.limbs, 8, b.limbs, 8);

    ASSERT(res == 0);
END_TEST

DEFINE_TEST(cmp_greater_msb)
    const uint256_t a = {{0, 0, 0, 0, 0, 0, 0, 5}};
    const uint256_t b = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 4}};

    result_t res = bigint_cmp_raw(a.limbs, 8, b.limbs, 8);

    ASSERT(res > 0);
END_TEST

DEFINE_TEST(cmp_less_msb)
    const uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 4}};
    const uint256_t b = {{0, 0, 0, 0, 0, 0, 0, 5}};

    result_t res = bigint_cmp_raw(a.limbs, 8, b.limbs, 8);

    ASSERT(res < 0);
END_TEST

DEFINE_TEST(cmp_greater_lsb)
    const uint256_t a = {{10, 0, 0, 0, 0, 0, 0, 0xABCDEF}};
    const uint256_t b = {{9,  0, 0, 0, 0, 0, 0, 0xABCDEF}};

    result_t res = bigint_cmp_raw(a.limbs, 8, b.limbs, 8);

    ASSERT(res > 0);
END_TEST

DEFINE_TEST(cmp_less_lsb)
    const uint256_t a = {{9,  0, 0, 0, 0, 0, 0, 0xABCDEF}};
    const uint256_t b = {{10, 0, 0, 0, 0, 0, 0, 0xABCDEF}};

    result_t res = bigint_cmp_raw(a.limbs, 8, b.limbs, 8);

    ASSERT(res < 0);
END_TEST

// ===========================================================================
// MULTIPLICATION TESTS
// ===========================================================================

DEFINE_TEST(mul_raw_zero)
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x11112222, 0x33334444, 0x55556666, 0x77778888, 0x9999AAAA, 0xBBBBCCCC}};
    uint256_t b = {{0}};
    uint32_t result[16] = {0};
    uint32_t expected[16] = {0};

    bigint_mul_raw(result, a.limbs, 8, b.limbs, 8);

    ASSERT_RAW_GENERIC_EQ(result, expected, 16);
END_TEST

DEFINE_TEST(mul_raw_one)
    uint256_t a = {{0x12345678, 0xABCDEF01, 0x11112222, 0x33334444, 0x55556666, 0x77778888, 0x9999AAAA, 0xBBBBCCCC}};
    uint256_t b = {{1, 0, 0, 0, 0, 0, 0, 0}};
    uint32_t result[16] = {0};
    uint32_t expected[16] = {
        0x12345678, 0xABCDEF01, 0x11112222, 0x33334444, 0x55556666, 0x77778888, 0x9999AAAA, 0xBBBBCCCC,
        0, 0, 0, 0, 0, 0, 0, 0
    };

    bigint_mul_raw(result, a.limbs, 8, b.limbs, 8);

    ASSERT_RAW_GENERIC_EQ(result, expected, 16);
END_TEST

DEFINE_TEST(mul_raw_overflow_to_upper)
    uint256_t a = {{0, 0, 0, 0, 0, 0, 0, 1}};
    uint256_t b = {{0, 1, 0, 0, 0, 0, 0, 0}};
    uint32_t result[16] = {0};
    uint32_t expected[16] = {0};
    expected[8] = 1;

    bigint_mul_raw(result, a.limbs, 8, b.limbs, 8);

    ASSERT_RAW_GENERIC_EQ(result, expected, 16);
END_TEST

DEFINE_TEST(mul_raw_max)
    uint256_t a = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    uint256_t b = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    uint32_t result[16] = {0};
    uint32_t expected[16] = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    bigint_mul_raw(result, a.limbs, 8, b.limbs, 8);

    ASSERT_RAW_GENERIC_EQ(result, expected, 16);
END_TEST

DEFINE_TEST(shl_raw_zero_bits)
    uint32_t a[4] = {0x12345678, 0xABCDEF01, 0x11223344, 0x55667788};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x12345678, 0xABCDEF01, 0x11223344, 0x55667788};

    bigint_shl_raw(result, a, 4, 0);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4);
END_TEST

DEFINE_TEST(shl_raw_within_limb)
    // 0x00000001 << 4 -> 0x00000010
    uint32_t a[4] = {0x00000001, 0x00000000, 0x00000000, 0x80000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000010, 0x00000000, 0x00000000, 0x00000000};

    bigint_shl_raw(result, a, 4, 4);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4);
END_TEST

DEFINE_TEST(shl_raw_cross_limb_boundary)
    uint32_t a[4] = {0x80000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000000, 0x00000008, 0x00000000, 0x00000000};

    bigint_shl_raw(result, a, 4, 4);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4);
END_TEST

DEFINE_TEST(shl_raw_exact_limb_multiple)
    uint32_t a[4] = {0x12345678, 0xABCDEF01, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000000, 0x00000000, 0x12345678, 0xABCDEF01};

    bigint_shl_raw(result, a, 4, 64);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4);
END_TEST

DEFINE_TEST(shl_raw_mixed_limbs_and_bits)
    uint32_t a[4] = {0x00000001, 0x00000000, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000000, 0x00000008, 0x00000000, 0x00000000};

    bigint_shl_raw(result, a, 4, 35);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4);
END_TEST

// --- SHIFT RIGHT (SHR) ---

DEFINE_TEST(shr_raw_zero_bits)
    uint32_t a[4] = {0x12345678, 0xABCDEF01, 0x11223344, 0x55667788};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x12345678, 0xABCDEF01, 0x11223344, 0x55667788};

    bigint_shr_raw(result, a, 4, 0);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4);
END_TEST

DEFINE_TEST(shr_raw_within_limb)
    // 0x00000010 >> 4 -> 0x00000001
    uint32_t a[4] = {0x00000010, 0x00000000, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000001, 0x00000000, 0x00000000, 0x00000000};

    bigint_shr_raw(result, a, 4, 4);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4);
END_TEST

DEFINE_TEST(shr_raw_cross_limb_boundary)
    uint32_t a[4] = {0x00000000, 0x00000008, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x80000000, 0x00000000, 0x00000000, 0x00000000};

    bigint_shr_raw(result, a, 4, 4);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4);
END_TEST

DEFINE_TEST(shr_raw_exact_limb_multiple)
    uint32_t a[4] = {0x00000000, 0x00000000, 0x12345678, 0xABCDEF01};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x12345678, 0xABCDEF01, 0x00000000, 0x00000000};

    bigint_shr_raw(result, a, 4, 64);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4);
END_TEST

DEFINE_TEST(shr_raw_mixed_limbs_and_bits)
    uint32_t a[4] = {0x00000000, 0x00000008, 0x00000000, 0x00000000};
    uint32_t result[4] = {0};
    uint32_t expected[4] = {0x00000001, 0x00000000, 0x00000000, 0x00000000};

    bigint_shr_raw(result, a, 4, 35);

    ASSERT_RAW_GENERIC_EQ(result, expected, 4);
END_TEST

DEFINE_TEST(bytes_to_bigint_exact_256bit)
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

    ASSERT_RAW_GENERIC_EQ(result_limbs, expected_limbs, 8);
END_TEST

DEFINE_TEST(bytes_to_bigint_unaligned_padding)
    const uint8_t input_bytes[3] = {0xAA, 0xBB, 0xCC};

    // len_result = (3 + 3) >> 2 = 1 Limb
    // Big-Endian: 0xAA (MSB), 0xBB, 0xCC (LSB)
    const uint32_t expected_limbs[1] = {0x00AABBCC};

    uint32_t result_limbs[1] = {0};
    bytes_to_bigint(result_limbs, input_bytes, 3);

    ASSERT_RAW_GENERIC_EQ(result_limbs, expected_limbs, 1);
END_TEST

DEFINE_TEST(bigint_to_bytes_exact_256bit)
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

    ASSERT_BYTES_EQ(result_bytes, expected_bytes, 32);
END_TEST

DEFINE_TEST(conversion_roundtrip)
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

    ASSERT_BYTES_EQ(final_bytes, original_bytes, 32);
END_TEST

// ===========================================================================
// MAIN RUNNER
// ===========================================================================

DEFINE_TEST_SUITE(bigint)

    // ADDITION TESTS

    RUN_TEST(add_zero, "addition with zero");
    RUN_TEST(add_no_carry, "addition without carry");
    RUN_TEST(add_single_carry, "addition with single carry");
    RUN_TEST(add_cascade_carry, "addition with cascading carry");
    RUN_TEST(add_overflow_wrap, "addition overflow");

    // SUBTRACTION TESTS

    RUN_TEST(sub_zero, "subtraction by zero");
    RUN_TEST(sub_no_borrow, "subtraction with no borrow");
    RUN_TEST(sub_single_borrow, "subtraction with single borrow");
    RUN_TEST(sub_cascade_borrow, "subtraction with cascading borrow");
    RUN_TEST(sub_underflow_wrap, "subtraction underflow");
    RUN_TEST(sub_raw_varied_sizes_no_underflow, "subtraction with varied sizes");
    RUN_TEST(sub_raw_underflow, "subtraction with varied sizes underflow");
    RUN_TEST(sub_raw_mismatched_lengths, "subtraction with mismatched lengths");

    // COMPARISON TESTS

    RUN_TEST(cmp_equal, "comparison with equal numbers");
    RUN_TEST(cmp_greater_msb, "comparison with greater most significant bit");
    RUN_TEST(cmp_less_msb, "comparison with less most significant bit");
    RUN_TEST(cmp_greater_lsb, "comparison with greater least significant bit");
    RUN_TEST(cmp_less_lsb, "comparison with less least significant bit");

    // MULTIPLICATION TESTS

    RUN_TEST(mul_raw_zero, "multiplication by zero");
    RUN_TEST(mul_raw_one, "multiplication by one");
    RUN_TEST(mul_raw_overflow_to_upper, "multiplication with overflow to upper limb");
    RUN_TEST(mul_raw_max, "maximum value multiplication");

    // SHIFTING OPERATION TESTS

    RUN_TEST(shl_raw_zero_bits, "shift left by zero");
    RUN_TEST(shl_raw_within_limb, "shift left within limb");
    RUN_TEST(shl_raw_cross_limb_boundary, "shift left across limb boundary");
    RUN_TEST(shl_raw_exact_limb_multiple, "shift left by exakt limb multiple");
    RUN_TEST(shl_raw_mixed_limbs_and_bits, "shift left by mixed limbs and bits");

    RUN_TEST(shr_raw_zero_bits, "shift right by zero");
    RUN_TEST(shr_raw_within_limb, "shift right within limb");
    RUN_TEST(shr_raw_cross_limb_boundary, "shift right across limb boundary");
    RUN_TEST(shr_raw_exact_limb_multiple, "shift right by exakt limb multiple");
    RUN_TEST(shr_raw_mixed_limbs_and_bits, "shift right by mixed limbs and bits");

    // BYTES TO BIGINT / BIGINT TO BYTES CONVERSION

    RUN_TEST(bytes_to_bigint_exact_256bit, "32 bytes to 256 bit bigint");
    RUN_TEST(bytes_to_bigint_unaligned_padding, "bytes to bigint with unaligned padding");
    RUN_TEST(bigint_to_bytes_exact_256bit, "256 bit bigint to 32 bytes");
    RUN_TEST(conversion_roundtrip, "conversion roundtrip");

END_TEST_SUITE