//
// Created by M Lunkeit on 24.07.26.
//

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "../../../src/crypto/hash/sha256.h"

#define ASSERT_UINT32_ARRAY_EQ(actual, expected, len, msg) \
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

static void hex_to_bytes(const char *hex, uint8_t *bytes) {
    for (size_t i = 0; i < 32; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
}

size_t sha256_pad(uint32_t *output, const uint8_t *input, const size_t len);

// 1. Pad empty input (len = 0) -> 1 Block, 0x80 Byte, 0x00 Padding, 0 Length
static uint8_t test_pad_empty_input() {
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
        printf("[FAIL] test_pad_empty_input: expected 1 block, got %zu (Line %d)\n", blocks, __LINE__);
        return 1;
    }

    ASSERT_UINT32_ARRAY_EQ(output, expected, 16, "Padding empty input failed");
    return 0;
}

// 2. Pad NIST Standard String "abc" (3 Bytes) -> 1 Block (24 bits)
static uint8_t test_pad_abc_standard() {
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
        printf("[FAIL] test_pad_abc_standard: expected 1 block, got %zu (Line %d)\n", blocks, __LINE__);
        return 1;
    }

    ASSERT_UINT32_ARRAY_EQ(output, expected, 16, "Padding 'abc' failed");
    return 0;
}

// 3. Exact boundary: len = 55 Bytes -> Fits in exactly 1 Block (55 data + 1 pad + 8 length = 64 Bytes)
static uint8_t test_pad_exact_55_bytes() {
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
        printf("[FAIL] test_pad_exact_55_bytes: expected 1 block, got %zu (Line %d)\n", blocks, __LINE__);
        return 1;
    }

    ASSERT_UINT32_ARRAY_EQ(output, expected, 16, "Padding 55-byte input failed");
    return 0;
}

// 4. Overflow boundary: len = 56 Bytes -> Requires 2 Blocks
static uint8_t test_pad_overflow_56_bytes() {
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
        printf("[FAIL] test_pad_overflow_56_bytes: expected 2 blocks, got %zu (Line %d)\n", blocks, __LINE__);
        return 1;
    }

    ASSERT_UINT32_ARRAY_EQ(output, expected, 32, "Padding 56-byte input overflow failed");
    return 0;
}

// 5. Full 64-Byte Block -> Requires 2 Blocks
static uint8_t test_pad_exact_64_bytes() {
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
        printf("[FAIL] test_pad_exact_64_bytes: expected 2 blocks, got %zu (Line %d)\n", blocks, __LINE__);
        return 1;
    }

    ASSERT_UINT32_ARRAY_EQ(output, expected, 32, "Padding 64-byte input failed");
    return 0;
}

static uint8_t test_empty_message() {
    uint8_t input[1] = { 0 };
    uint8_t output[32] = { 0 };

    const uint8_t expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    sha256(output, input, 0);

    for (size_t i = 0; i < 32; i++) {
        if (output[i] != expected[i]) {
            printf("[FAIL] test_empty_message at byte [%zu]: expected 0x%02X, got 0x%02X (Line %d)\n",
                   i, expected[i], output[i], __LINE__);
            return 1;
        }
    }

    return 0; // PASS
}

static uint8_t test_abc_standard() {
    uint8_t input[3] = { 'a', 'b', 'c' };
    uint8_t output[32] = { 0 };
    uint8_t expected[32];

    hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", expected);

    sha256(output, input, 3);

    ASSERT_BYTES_EQ(output, expected, 32, "SHA-256 for 'abc' failed");
    return 0;
}

static uint8_t test_overflow() {
    const uint8_t input[] = "Hello World! dofjsoidfjsodjfoisdjfoisdjfoisjofijsoidjfkjalasewjlsjf";
    size_t len = sizeof(input) - 1;

    uint8_t output[32] = { 0 };
    uint8_t expected[32];

    hex_to_bytes("c8e6be7108a179d60f717839c0db1052c883e8baf742fd39240e43fd3ee83f07", expected);

    sha256(output, input, len);

    ASSERT_BYTES_EQ(output, expected, 32, "SHA-256 for overflow string failed");
    return 0;
}

int run_sha256_tests() {
    printf("Running tests for SHA-256...\n");

    uint8_t status = 0;

    status |= test_pad_empty_input();
    status |= test_pad_abc_standard();
    status |= test_pad_exact_55_bytes();
    status |= test_pad_overflow_56_bytes();
    status |= test_pad_exact_64_bytes();

    if (status != 0) {
        printf("[FAIL] SHA-256 padding tests failed\n");
    } else {
        printf("[SUCCESS] All SHA-256 padding tests passed!\n");
    }

    status |= test_empty_message();
    status |= test_abc_standard();
    status |= test_overflow();

    if (status != 0) {
        printf("[FAIL] SHA-256 tests failed\n");
    } else {
        printf("[SUCCESS] SHA-256 tests passed!\n");
    }

    return status;
}