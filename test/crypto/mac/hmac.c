//
// Created by M Lunkeit on 24.07.26.
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/mac/hmac.h"
#include "unittest.h"

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
}

// ===========================================================================
// RFC 4231 HMAC TESTS (SHA-256 & SHA-512)
// ===========================================================================

// Test Case 1: Standard Key (20 Bytes) & "Hi There" (8 Bytes)
DEFINE_TEST(hmac_rfc4231_hi_there)
    uint8_t key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };

    uint8_t data[8] = {
        0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 // "Hi There"
    };

    // --- HMAC SHA-256 ---
    uint8_t expected256[32];
    hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", expected256, 32);

    uint8_t result256[32] = { 0 };
    hmac_sha256(result256, key, 20, data, 8);

    ASSERT_BYTES_EQ(result256, expected256, 32);

    // --- HMAC SHA-512 ---
    uint8_t expected512[64];
    hex_to_bytes("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", expected512, 64);

    uint8_t result512[64] = { 0 };
    hmac_sha512(result512, key, 20, data, 8);

    ASSERT_BYTES_EQ(result512, expected512, 64);
END_TEST

// Test Case 2: Key shorter than block size ("Jefe")
DEFINE_TEST(hmac_rfc4231_key_shorter)
    const uint8_t key[] = "Jefe";
    const uint8_t data[] = "what do ya want for nothing?";
    size_t key_len = 4;
    size_t data_len = 28;

    // --- HMAC SHA-256 ---
    uint8_t expected256[32];
    hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", expected256, 32);

    uint8_t result256[32] = { 0 };
    hmac_sha256(result256, key, key_len, data, data_len);

    ASSERT_BYTES_EQ(result256, expected256, 32);

    // --- HMAC SHA-512 ---
    uint8_t expected512[64];
    hex_to_bytes("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", expected512, 64);

    uint8_t result512[64] = { 0 };
    hmac_sha512(result512, key, key_len, data, data_len);

    ASSERT_BYTES_EQ(result512, expected512, 64);
END_TEST

// Test Case 6/7: Key larger than Block Size (131 Bytes > 64/128 Bytes)
DEFINE_TEST(hmac_rfc4231_large_key)
    uint8_t key[131];
    memset(key, 0xAA, sizeof(key));

    const uint8_t data[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    size_t data_len = 54;

    // --- HMAC SHA-256 ---
    uint8_t expected256[32];
    hex_to_bytes("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", expected256, 32);

    uint8_t result256[32] = { 0 };
    hmac_sha256(result256, key, 131, data, data_len);

    ASSERT_BYTES_EQ(result256, expected256, 32);

    // --- HMAC SHA-512 ---
    uint8_t expected512[64];
    hex_to_bytes("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598", expected512, 64);

    uint8_t result512[64] = { 0 };
    hmac_sha512(result512, key, 131, data, data_len);

    ASSERT_BYTES_EQ(result512, expected512, 64);
END_TEST

// ===========================================================================
// MAIN RUNNER
// ===========================================================================

DEFINE_TEST_SUITE(hmac)

    // RFC 4231 TEST VECTORS

    RUN_TEST(hmac_rfc4231_hi_there, "RFC 4231 Test Case 1 ('Hi There')");
    RUN_TEST(hmac_rfc4231_key_shorter, "RFC 4231 Test Case 2 ('Jefe')");
    RUN_TEST(hmac_rfc4231_large_key, "RFC 4231 Test Case 6/7 (Large Key > Block Size)");

END_TEST_SUITE