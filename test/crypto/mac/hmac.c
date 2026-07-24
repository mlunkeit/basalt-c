//
// Created by M Lunkeit on 24.07.26.
//

#include <stdlib.h>
#include <stdio.h>

#include "../../../crypto/mac/hmac.h"

#include <string.h>

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

uint8_t test_hmac_sha256_hithere() {
    uint8_t key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };

    uint8_t data[8] = {
        0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 // Hi There
    };

    uint8_t expected[32];
    hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", expected);

    uint8_t result[32];
    hmac_sha256(result, data, 8, key, 20);

    ASSERT_BYTES_EQ(result, expected, 32, "HMAC SHA256 for \"Hi There\" failed!");

    return 0;
}

uint8_t test_hmac_sha256_key_shorter() {
    uint8_t key[] = "Jefe";
    uint8_t data[] = "what do ya want for nothing?";

    uint8_t expected[32];
    hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", expected);

    uint8_t result[32];
    hmac_sha256(result, data, 28, key, 4);

    ASSERT_BYTES_EQ(result, expected, 32, "HMAC SHA256 for \"Jefe\" failed!");

    return 0;
}

uint8_t test_hmac_sha256_large_key() {
    uint8_t key[131];
    memset(key, 0xAA, sizeof(key));

    uint8_t data[] = "Test Using Larger Than Block-Size Key - Hash Key First";

    uint8_t expected[32];
    hex_to_bytes("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", expected);

    uint8_t result[32];
    hmac_sha256(result, data, 54, key, 131);

    ASSERT_BYTES_EQ(result, expected, 32, "HMAC SHA256 for large key failed!");

    return 0;
}

int run_hmac_tests() {
    uint8_t status = 0;

    printf("Running tests for HMAC...\n");

    // Running RFC 4231

    status |= test_hmac_sha256_hithere();
    status |= test_hmac_sha256_key_shorter();
    status |= test_hmac_sha256_large_key();

    if (status == 0) {
        printf("[SUCCESS] All HMAC-SHA-256 tests passed!\n");
    } else {
        printf("[FAIL] At least one HMAC-SHA-256 test failed!\n");
    }

    return status;
}