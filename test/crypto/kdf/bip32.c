//
// Created by M Lunkeit on 09.08.26.
//

#include "crypto/kdf/bip32.h"

#include "math/curves/secp256k1.h"

#include "unittest.h"

DEFINE_TEST(bip32_vector1)
    bip32_extended_private_key_t private = {
        .k = {1, 0, 0, 0, 0, 0, 0, 0},
        .c = {0},
    };

    bip32_extended_private_key_t child = {0};

    bip32_derive_private(&SECP256K1, &child, &private, 0x80000000);

    printf("\nchild k =");
    for (size_t i = 0; i < 8; i++) {
        printf(" %08x", child.k[7 - i]);
    }
    printf("\n");

    printf("child c =");
    for (size_t i = 0; i < 32; i++) {
        printf(" %02x", child.c[31 - i]);
    }
    printf("\n");
END_TEST

DEFINE_TEST_SUITE(bip32)
    RUN_TEST(bip32_vector1, "BIP-32 vector 1");
END_TEST_SUITE