//
// Created by M Lunkeit on 20.07.26.
//

#include <stdio.h>
#include <stdint.h>

#include "../../math/bigint.h"

#define ASSERT_UINT256_EQ(actual, expected, msg) \
    for (size_t i = 0; i < 8; i++) { \
        if ((actual).limbs[i] != (expected).limbs[i]) { \
            printf("[FAIL] %s at limb [%zu]: expected 0x%08X, got 0x%08X (Line %d)\n", \
                   msg, i, (expected).limbs[i], (actual).limbs[i], __LINE__); \
            return 1; \
        } \
    }

void secp256k1_reduce(uint256_t* result, uint32_t limbs[16]);

static uint8_t test_barrett_underflow_reduction() {
    uint32_t limbs[16] = {
        0x000E90A0, 0x000007A2, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFF85E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    uint256_t result;

    uint256_t expected = {{
        0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    }};

    secp256k1_reduce(&result, limbs);

    ASSERT_UINT256_EQ(result, expected, "Barrett reduction failed on p^2 - 1 boundary condition");

    return 0;
}

int run_secp256k1_tests() {
    printf("Running tests for secp256k1 elliptic curve...\n");

    const uint8_t status = test_barrett_underflow_reduction();

    if (status != 0) {
        printf("[FAIL] Tests failed\n");
    } else {
        printf("[SUCCESS] Tests passed\n");
    }

    return status;
}