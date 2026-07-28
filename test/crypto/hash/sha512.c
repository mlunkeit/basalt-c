//
// Created by M Lunkeit on 28.07.26.
//

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "crypto/hash/sha512.h"

#define ASSERT_UINT64_ARRAY_EQ(actual, expected, len, msg) \
    for (size_t i = 0; i < (len); i++) { \
        if ((actual)[i] != (expected)[i]) { \
            printf("[FAIL] %s at limb [%zu]: expected 0x%016llx, got 0x%016llx (Line %d)\n", \
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

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
}

size_t sha512_pad(uint64_t *output, const uint8_t *input, size_t len);

// 1. Pad empty input (len = 0) -> 1 Block (128 Bytes / 16 x uint64_t)
static uint8_t test_pad512_empty_input() {
    const uint8_t input[1] = { 0 };
    uint64_t output[16] = { 0 };

    // Expected: 0x8000000000000000ULL at word 0, zero padded, last word length = 0
    uint64_t expected[16] = {
        0x8000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL
    };

    size_t blocks = sha512_pad(output, input, 0);

    if (blocks != 1) {
        printf("[FAIL] test_pad512_empty_input: expected 1 block, got %zu (Line %d)\n", blocks, __LINE__);
        return 1;
    }

    ASSERT_UINT64_ARRAY_EQ(output, expected, 16, "Padding empty input failed for SHA-512");
    return 0;
}

// 2. Pad Standard String "abc" (3 Bytes) -> 1 Block (24 bits)
static uint8_t test_pad512_abc_standard() {
    const uint8_t input[3] = { 'a', 'b', 'c' }; // 0x61, 0x62, 0x63
    uint64_t output[16] = { 0 };

    // "abc" (0x616263) + 0x80 -> Word 0: 0x6162638000000000ULL
    // Bit-Length = 3 * 8 = 24 (0x18) in final word
    uint64_t expected[16] = {
        0x6162638000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
        0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000018ULL
    };

    size_t blocks = sha512_pad(output, input, 3);

    if (blocks != 1) {
        printf("[FAIL] test_pad512_abc_standard: expected 1 block, got %zu (Line %d)\n", blocks, __LINE__);
        return 1;
    }

    ASSERT_UINT64_ARRAY_EQ(output, expected, 16, "Padding 'abc' failed for SHA-512");
    return 0;
}

// 3. Exact boundary: len = 111 Bytes -> Fits in exactly 1 Block (111 data + 1 pad + 16 length = 128 Bytes)
static uint8_t test_pad512_exact_111_bytes() {
    uint8_t input[111];
    memset(input, 'A', 111); // 0x41
    uint64_t output[16] = { 0 };

    uint64_t expected[16];
    for (int i = 0; i < 13; i++) {
        expected[i] = 0x4141414141414141ULL; // 8x "A"
    }
    // 111 Bytes = 13 volle uint64_t (104 Bytes) + 7 Bytes im 14. Word
    expected[13] = 0x4141414141414180ULL;   // 7x "A" + 0x80
    expected[14] = 0x0000000000000000ULL;   // High 64-bit length
    expected[15] = (uint64_t)111 * 8;       // Low 64-bit length = 888 (0x0000000000000378ULL)

    size_t blocks = sha512_pad(output, input, 111);

    if (blocks != 1) {
        printf("[FAIL] test_pad512_exact_111_bytes: expected 1 block, got %zu (Line %d)\n", blocks, __LINE__);
        return 1;
    }

    ASSERT_UINT64_ARRAY_EQ(output, expected, 16, "Padding 111-byte input failed for SHA-512");
    return 0;
}

// 4. Overflow boundary: len = 112 Bytes -> Requires 2 Blocks (128 uint64_t entries = 256 Bytes space)
static uint8_t test_pad512_overflow_112_bytes() {
    uint8_t input[112];
    memset(input, 'B', 112); // 0x42
    uint64_t output[32] = { 0 };

    uint64_t expected[32] = { 0 };
    for (int i = 0; i < 14; i++) {
        expected[i] = 0x4242424242424242ULL; // 112 Bytes fill exactly 14 uint64_t words
    }
    expected[14] = 0x8000000000000000ULL;   // 0x80 appended at start of word 14
    // Words 15..30 are zeros
    expected[31] = (uint64_t)112 * 8;       // Length 896 (0x0000000000000380ULL) in final word

    size_t blocks = sha512_pad(output, input, 112);

    if (blocks != 2) {
        printf("[FAIL] test_pad512_overflow_112_bytes: expected 2 blocks, got %zu (Line %d)\n", blocks, __LINE__);
        return 1;
    }

    ASSERT_UINT64_ARRAY_EQ(output, expected, 32, "Padding 112-byte input overflow failed for SHA-512");
    return 0;
}

// 5. Full 128-Byte Block -> Requires 2 Blocks
static uint8_t test_pad512_exact_128_bytes() {
    uint8_t input[128];
    memset(input, 'C', 128); // 0x43
    uint64_t output[32] = { 0 };

    uint64_t expected[32] = { 0 };
    for (int i = 0; i < 16; i++) {
        expected[i] = 0x4343434343434343ULL; // Block 1 entirely full with data
    }
    expected[16] = 0x8000000000000000ULL;   // 0x80 at start of Block 2
    expected[31] = (uint64_t)128 * 8;       // Length 1024 (0x0000000000000400ULL) in final word

    size_t blocks = sha512_pad(output, input, 128);

    if (blocks != 2) {
        printf("[FAIL] test_pad512_exact_128_bytes: expected 2 blocks, got %zu (Line %d)\n", blocks, __LINE__);
        return 1;
    }

    ASSERT_UINT64_ARRAY_EQ(output, expected, 32, "Padding 128-byte input failed for SHA-512");
    return 0;
}

static uint8_t test_empty_message_512() {
    uint8_t input[1] = { 0 };
    uint8_t output[64] = { 0 };

    const uint8_t expected[64] = {
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
        0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
        0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
        0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
    };

    sha512(output, input, 0);

    for (size_t i = 0; i < 64; i++) {
        if (output[i] != expected[i]) {
            printf("[FAIL] test_empty_message_512 at byte [%zu]: expected 0x%02X, got 0x%02X (Line %d)\n",
                   i, expected[i], output[i], __LINE__);
            return 1;
        }
    }

    return 0; // PASS
}

static uint8_t test_abc_standard_512() {
    uint8_t input[3] = { 'a', 'b', 'c' };
    uint8_t output[64] = { 0 };
    uint8_t expected[64];

    hex_to_bytes(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        expected, 64
    );

    sha512(output, input, 3);

    ASSERT_BYTES_EQ(output, expected, 64, "SHA-512 for 'abc' failed");
    return 0;
}

static uint8_t test_overflow_512() {
    const uint8_t input[] = "Hello World! dofjsoidfjsodjfoisdjfoisdjfoisjofijsoidjfkjalasewjlsjf";
    size_t len = sizeof(input) - 1;

    uint8_t output[64] = { 0 };
    uint8_t expected[64];

    hex_to_bytes(
        "5c06dccb93948682b053258a1ab8f5319a75ed867a04798cdcef5f5abbd2691a987806e198591f2090b83c4e87cbb233bc76c9bde40b8f02cd9d101546792ff7",
        expected, 64
    );

    sha512(output, input, len);

    ASSERT_BYTES_EQ(output, expected, 64, "SHA-512 for overflow string failed");
    return 0;
}

int run_sha512_tests() {
    printf("Running tests for SHA-512...\n");

    uint8_t status = 0;

    status |= test_pad512_abc_standard();
    status |= test_pad512_exact_111_bytes();
    status |= test_pad512_overflow_112_bytes();
    status |= test_pad512_exact_128_bytes();
    status |= test_pad512_empty_input();

    if (status != 0) {
        printf("[FAIL] SHA-512 padding tests failed\n");
        return 1;
    } else {
        printf("[SUCCESS] All SHA-512 padding tests passed!\n");
    }

    status |= test_empty_message_512();
    status |= test_abc_standard_512();
    status |= test_overflow_512();

    if (status != 0) {
        printf("[FAIL] SHA-512 tests failed\n");
        return 1;
    } else {
        printf("[SUCCESS] SHA-512 tests passed!\n");
    }

    return status;
}