//
// Created by M Lunkeit on 24.07.26.
//

#include <stdio.h>

#include "math/bigint.h"
#include "crypto/hash/sha256.h"
#include "crypto/ec/ecdsa.h"
#include "crypto/ec/rfc6979.h"

#include "math/curves/secp256k1.h"
#include "math/curves/secp256r1.h"

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

static void hex_to_bytes(const char *hex, uint8_t *bytes, const size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%02x", &byte);
        bytes[i] = (uint8_t)byte;
    }
}

uint8_t test_rfc6979() {
    uint8_t privkey[32];
    hex_to_bytes("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", privkey, 32);

    uint32_t d[8];
    bytes_to_bigint(d, privkey, 32);

    uint8_t order_bytes[32];
    hex_to_bytes("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", order_bytes, 32);

    uint256_t order;
    bytes_to_bigint(order.limbs, order_bytes, 32);

    const uint8_t message[] = "sample";

    uint8_t hash[32];
    sha256(hash, message, 6);

    uint32_t result[8];
    rfc6979(&SECP256R1, result, d, hash, 32);

    uint8_t expected_bytes[32];
    hex_to_bytes("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60", expected_bytes, 32);

    uint32_t expected[8];
    bytes_to_bigint(expected, expected_bytes, 32);

    ASSERT_UINT32_ARRAY_EQ(result, expected, 8, "Failed generation of ephemeral deterministic key by RFC-6979 standard.");

    return 0;
}

uint8_t test_ecdsa_secp256k1_sign() {
    uint32_t d[8] = {0};
    d[0] = 1;

    const uint8_t message[] = "sample";

    uint8_t hash[32];
    sha256(hash, message, 6);

    uint32_t r[8];
    uint32_t s[8];
    ecdsa_sign(&SECP256K1, r, s, d, hash, 32);

    uint8_t r_expected[32];
    hex_to_bytes("58db657bcd631038bea07b4941172f0167aca98f12b55e3176bd1c35435d6501", r_expected, 32);

    uint8_t s_expected[32];
    hex_to_bytes("3a78e73d8ff8ab554e13c10f6390d81a882f91945d6275493882676170b53a57", s_expected, 32);

    uint8_t r_bytes[32];
    bigint_to_bytes(r_bytes, r, 8);

    uint8_t s_bytes[32];
    bigint_to_bytes(s_bytes, s, 8);

    ASSERT_BYTES_EQ(r_bytes, r_expected, 32, "ECDSA signature failed: invalid r");
    ASSERT_BYTES_EQ(s_bytes, s_expected, 32, "ECDSA signature failed: invalid s");

    return 0;
}

uint8_t test_ecdsa_secp256k1_verify() {
    uint8_t pubkey[65];
    hex_to_bytes("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", pubkey, 65);

    uint8_t r_bytes[32];
    hex_to_bytes("58db657bcd631038bea07b4941172f0167aca98f12b55e3176bd1c35435d6501", r_bytes, 32);

    uint8_t s_bytes[32];
    hex_to_bytes("3a78e73d8ff8ab554e13c10f6390d81a882f91945d6275493882676170b53a57", s_bytes, 32);

    uint32_t r[8];
    bytes_to_bigint(r, r_bytes, 32);

    uint32_t s[8];
    bytes_to_bigint(s, s_bytes, 32);

    wcurve_point_t public_key;
    bytes_to_bigint(public_key.x, pubkey + 1, 32);
    bytes_to_bigint(public_key.y, pubkey + 33, 32);
    public_key.infinity = false;

    const uint8_t message[] = "sample";

    uint8_t hash[32];
    sha256(hash, message, 6);

    const bool verified = ecdsa_verify(&SECP256K1, &public_key, hash, 32, r, s);

    if (!verified) {
        printf("[FAIL] Verification test with d = 1 failed.\n");
        return 1;
    }

    return 0;
}

int run_ecdsa_tests() {
    printf("Running ECDSA tests...\n\n");

    uint8_t failed = 0;
    failed |= test_rfc6979();

    if (!failed) {
        printf("[SUCCESS] All RFC-6979 tests passed.\n");
    } else {
        printf("[FAIL] At least one RFC-6979 test failed.\n");
        return failed;
    }

    failed |= test_ecdsa_secp256k1_sign();
    failed |= test_ecdsa_secp256k1_verify();

    if (!failed) {
        printf("[SUCCESS] All ECDSA tests passed.\n");
    } else {
        printf("[FAIL] At least one ECDSA test failed.\n");
    }

    return failed;
}