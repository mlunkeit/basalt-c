//
// Created by M Lunkeit on 24.07.26.
//

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "crypto/hash/sha256.h"
#include "unittest.h"

static void hex_to_bytes(const char *hex, uint8_t *bytes) {
    for (size_t i = 0; i < 32; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
}

size_t sha256_pad(uint32_t *output, const uint8_t *input, size_t len);

// ===========================================================================
// SHA-256 PADDING TESTS
// ===========================================================================

// 1. Pad empty input (len = 0) -> 1 Block, 0x80 Byte, 0x00 Padding, 0 Length
DEFINE_TEST(sha256_pad_empty_input)
    const uint8_t input[1] = { 0 };
    uint32_t output[16] = { 0 };

    // Expected: 0x80000000 at word 0, zero padded, last word length = 0
    uint32_t expected[16] = {
        0x80000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000
    };

    size_t blocks = sha256_pad(output, input, 0);

    if (blocks != 1) {
        FAIL("Expected 1 block, got %zu (Line %d)", blocks, __LINE__);
    }

    ASSERT_RAW_GENERIC_EQ(output, expected, 16);
END_TEST

// 2. Pad NIST Standard String "abc" (3 Bytes) -> 1 Block (24 bits)
DEFINE_TEST(sha256_pad_abc_standard)
    const uint8_t input[3] = { 'a', 'b', 'c' }; // 0x61, 0x62, 0x63
    uint32_t output[16] = { 0 };

    // "abc" (0x616263) + 0x80 -> Word 0: 0x61626380
    // Bit-Length = 3 * 8 = 24 (0x18) in last word
    uint32_t expected[16] = {
        0x61626380, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000018
    };

    size_t blocks = sha256_pad(output, input, 3);

    if (blocks != 1) {
        printf("[FAIL] %s: expected 1 block, got %zu (Line %d)\n", __func__, blocks, __LINE__);
        return 1;
    }

    ASSERT_RAW_GENERIC_EQ(output, expected, 16);
END_TEST

// 3. Exact boundary: len = 55 Bytes -> Fits in exactly 1 Block (55 data + 1 pad + 8 length = 64 Bytes)
DEFINE_TEST(sha256_pad_exact_55_bytes)
    uint8_t input[55];
    memset(input, 'A', 55); // 0x41
    uint32_t output[16] = { 0 };

    uint32_t expected[16];
    for (int i = 0; i < 13; i++) {
        expected[i] = 0x41414141; // "AAAA"
    }
    expected[13] = 0x41414180;   // "AAA" + 0x80
    expected[14] = 0x00000000;   // High 32-bit length
    expected[15] = 55 * 8;       // Low 32-bit length = 440 (0x000001B8)

    size_t blocks = sha256_pad(output, input, 55);

    if (blocks != 1) {
        printf("[FAIL] %s: expected 1 block, got %zu (Line %d)\n", __func__, blocks, __LINE__);
        return 1;
    }

    ASSERT_RAW_GENERIC_EQ(output, expected, 16);
END_TEST

// 4. Overflow boundary: len = 56 Bytes -> Requires 2 Blocks
DEFINE_TEST(sha256_pad_overflow_56_bytes)
    uint8_t input[56];
    memset(input, 'B', 56); // 0x42
    uint32_t output[32] = { 0 };

    uint32_t expected[32] = { 0 };
    for (int i = 0; i < 14; i++) {
        expected[i] = 0x42424242; // First 56 Bytes filled
    }
    expected[14] = 0x80000000;   // 0x80 appended at start of word 14
    // Words 15..30 are zeros
    expected[31] = 56 * 8;       // Length 448 (0x000001C0) in final word

    size_t blocks = sha256_pad(output, input, 56);

    if (blocks != 2) {
        printf("[FAIL] %s: expected 2 blocks, got %zu (Line %d)\n", __func__, blocks, __LINE__);
        return 1;
    }

    ASSERT_RAW_GENERIC_EQ(output, expected, 32);
END_TEST

// 5. Full 64-Byte Block -> Requires 2 Blocks
DEFINE_TEST(sha256_pad_exact_64_bytes)
    uint8_t input[64];
    memset(input, 'C', 64); // 0x43
    uint32_t output[32] = { 0 };

    uint32_t expected[32] = { 0 };
    for (int i = 0; i < 16; i++) {
        expected[i] = 0x43434343; // Block 1 entirely full with data
    }
    expected[16] = 0x80000000;   // 0x80 at start of Block 2
    expected[31] = 64 * 8;       // Length 512 (0x00000200) in final word

    size_t blocks = sha256_pad(output, input, 64);

    if (blocks != 2) {
        printf("[FAIL] %s: expected 2 blocks, got %zu (Line %d)\n", __func__, blocks, __LINE__);
        return 1;
    }

    ASSERT_RAW_GENERIC_EQ(output, expected, 32);
END_TEST

// ===========================================================================
// SHA-256 HASH EXECUTION TESTS
// ===========================================================================

DEFINE_TEST(sha256_hash_empty_message)
    uint8_t input[1] = { 0 };
    uint8_t output[32] = { 0 };

    const uint8_t expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    sha256(output, input, 0);

    ASSERT_BYTES_EQ(output, expected, 32);
END_TEST

DEFINE_TEST(sha256_hash_abc_standard)
    uint8_t input[3] = { 'a', 'b', 'c' };
    uint8_t output[32] = { 0 };
    uint8_t expected[32];

    hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", expected);

    sha256(output, input, 3);

    ASSERT_BYTES_EQ(output, expected, 32);
END_TEST

DEFINE_TEST(sha256_hash_overflow)
    const uint8_t input[] = "Hello World! dofjsoidfjsodjfoisdjfoisdjfoisjofijsoidjfkjalasewjlsjf";
    size_t len = sizeof(input) - 1;

    uint8_t output[32] = { 0 };
    uint8_t expected[32];

    hex_to_bytes("c8e6be7108a179d60f717839c0db1052c883e8baf742fd39240e43fd3ee83f07", expected);

    sha256(output, input, len);

    ASSERT_BYTES_EQ(output, expected, 32);
END_TEST

// ===========================================================================
// MAIN RUNNER
// ===========================================================================

DEFINE_TEST_SUITE(sha256)

    // PADDING TESTS

    RUN_TEST(sha256_pad_empty_input, "padding empty input");
    RUN_TEST(sha256_pad_abc_standard, "padding NIST standard 'abc'");
    RUN_TEST(sha256_pad_exact_55_bytes, "padding exact 55-byte boundary");
    RUN_TEST(sha256_pad_overflow_56_bytes, "padding overflow 56-byte boundary");
    RUN_TEST(sha256_pad_exact_64_bytes, "padding exact 64-byte block");

    // HASHING TESTS

    RUN_TEST(sha256_hash_empty_message, "hashing empty message");
    RUN_TEST(sha256_hash_abc_standard, "hashing 'abc'");
    RUN_TEST(sha256_hash_overflow, "hashing multi-block overflow message");

END_TEST_SUITE