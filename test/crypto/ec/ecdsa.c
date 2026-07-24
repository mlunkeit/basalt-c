//
// Created by M Lunkeit on 24.07.26.
//

#include <stdio.h>

#include "../../../math/bigint.h"
#include "../../../crypto/hash/sha256.h"

#define ASSERT_UINT32_ARRAY_EQ(actual, expected, len, msg) \
    for (size_t i = 0; i < (len); i++) { \
        if ((actual)[i] != (expected)[i]) { \
            printf("[FAIL] %s at limb [%zu]: expected 0x%08X, got 0x%08X (Line %d)\n", \
                   msg, i, (expected)[i], (actual)[i], __LINE__); \
            return 1; \
        } \
    }

void rfc6979(uint256_t *result, const uint8_t privkey[32], const uint8_t hash[32], uint256_t *order);

static void hex_to_bytes(const char *hex, uint8_t *bytes) {
    for (size_t i = 0; i < 32; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
}

uint8_t test_rfc6979() {
    uint8_t privkey[32];
    hex_to_bytes("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", privkey);

    uint8_t order_bytes[32];
    hex_to_bytes("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", order_bytes);

    uint256_t order;
    bytes_to_bigint(order.limbs, order_bytes, 32);

    const uint8_t message[] = "sample";

    uint8_t hash[32];
    sha256(hash, message, 6);

    uint256_t result;
    rfc6979(&result, privkey, hash, &order);

    uint8_t expected_bytes[32];
    hex_to_bytes("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60", expected_bytes);

    uint256_t expected;
    bytes_to_bigint(expected.limbs, expected_bytes, 32);

    ASSERT_UINT32_ARRAY_EQ(result.limbs, expected.limbs, 8, "Failed generation of ephemeral deterministic key by RFC-6979 standard.");

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

    return failed;
}