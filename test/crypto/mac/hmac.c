//
// Created by M Lunkeit on 24.07.26.
//

#include <stdlib.h>
#include <stdio.h>

#include "../../../src/crypto/mac/hmac.h"

#include <string.h>

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

uint8_t test_hmac_hithere() {
    uint8_t key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };

    uint8_t data[8] = {
        0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 // Hi There
    };

    uint8_t expected256[32];
    hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", expected256, 32);

    uint8_t expected512[64];
    hex_to_bytes("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", expected512, 64);

    uint8_t result256[32];
    hmac_sha256(result256, key, 20, data, 8);

    ASSERT_BYTES_EQ(result256, expected256, 32, "HMAC SHA256 for \"Hi There\" failed!");

    uint8_t result512[64];
    hmac_sha512(result512, key, 20, data, 8);

    ASSERT_BYTES_EQ(result512, expected512, 64, "HMAC SHA512 for \"Hi There\" failed!");

    return 0;
}

uint8_t test_hmac_key_shorter() {
    uint8_t key[] = "Jefe";
    uint8_t data[] = "what do ya want for nothing?";

    uint8_t expected256[32];
    hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", expected256, 32);

    uint8_t expected512[64];
    hex_to_bytes("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", expected512, 64);

    uint8_t result256[32];
    hmac_sha256(result256, key, 4, data, 28);

    ASSERT_BYTES_EQ(result256, expected256, 32, "HMAC SHA256 for \"Jefe\" failed!");

    uint8_t result512[64];
    hmac_sha512(result512, key, 4, data, 28);

    ASSERT_BYTES_EQ(result512, expected512, 64, "HMAC SHA512 for \"Jefe\" failed!");

    return 0;
}

uint8_t test_hmac_sha256_large_key() {
    uint8_t key[131];
    memset(key, 0xAA, sizeof(key));

    uint8_t data[] = "Test Using Larger Than Block-Size Key - Hash Key First";

    uint8_t expected256[32];
    hex_to_bytes("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", expected256, 32);

    uint8_t expected512[64];
    hex_to_bytes("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598", expected512, 64);

    uint8_t result256[32];
    hmac_sha256(result256, key, 131, data, 54);

    ASSERT_BYTES_EQ(result256, expected256, 32, "HMAC SHA256 for large key failed!");

    uint8_t result512[64];
    hmac_sha512(result512, key, 131, data, 54);

    ASSERT_BYTES_EQ(result512, expected512, 64, "HMAC SHA512 for large key failed!");

    return 0;
}

int run_hmac_tests() {
    uint8_t status = 0;

    printf("Running tests for HMAC...\n");

    // Running RFC 4231

    status |= test_hmac_hithere();
    status |= test_hmac_key_shorter();
    status |= test_hmac_sha256_large_key();

    if (status == 0) {
        printf("[SUCCESS] All HMAC tests passed!\n");
    } else {
        printf("[FAIL] At least one HMAC test failed!\n");
    }

    return status;
}