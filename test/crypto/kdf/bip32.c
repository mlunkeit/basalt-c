//
// Created by M Lunkeit on 09.08.26.
//

#include "crypto/kdf/bip32.h"

#include "math/curves/secp256k1.h"

#include "unittest.h"

DEFINE_TEST(bip32_private)
    static constexpr bip32_extended_private_key_t private = {
        .k = {1, 0, 0, 0, 0, 0, 0, 0},
        .c = {0},
    };

    bip32_extended_private_key_t child;

    bip32_derive_private(&SECP256K1, &child, &private, 0x00000123);

    static constexpr uint32_t k_expected[8] = {
        0x8a1282eb, 0x609415ef, 0x22228f6a, 0x7823ce7a,
        0x74e78084, 0xfa1e7e01, 0xdbee22d1, 0x9294a095
    };

    static constexpr uint8_t c_expected[32] = {
        0xb8, 0xc0, 0x35, 0x01, 0x53, 0xc5, 0x2f, 0x8c,
        0x29, 0x26, 0x77, 0xdf, 0x41, 0x18, 0x36, 0x96,
        0xb1, 0x96, 0xa8, 0x45, 0x8a, 0x04, 0xfe, 0xbf,
        0x22, 0xd1, 0x9b, 0xfe, 0x3a, 0x0a, 0x3e, 0x81
    };

    ASSERT_RAW_GENERIC_EQ(child.k, k_expected, 8);
    ASSERT_BYTES_EQ(child.c, c_expected, 32);
END_TEST

DEFINE_TEST(bip32_private_hardened)
    static constexpr bip32_extended_private_key_t private = {
        .k = {1, 0, 0, 0, 0, 0, 0, 0},
        .c = {0},
    };

    bip32_extended_private_key_t child;

    bip32_derive_private(&SECP256K1, &child, &private, 0x80000123);

    static constexpr uint32_t k_expected[8] = {
        0x3384f9bd, 0x030872b9, 0xf46cd129, 0x998a02b1,
        0x71092526, 0x6f8c2735, 0xff8cf5ad, 0xe7974706
    };

    static constexpr uint8_t c_expected[32] = {
        0xe8, 0x5d, 0xb7, 0x07, 0xdb, 0xb2, 0xa7, 0x1c,
        0xcc, 0xcc, 0xa3, 0x0f, 0xde, 0xec, 0x40, 0xf2,
        0xc0, 0x8a, 0x41, 0xfa, 0x6e, 0x62, 0xbd, 0xab,
        0xaf, 0xce, 0x4b, 0x8a, 0x10, 0x0e, 0x8d, 0x8d
    };

    ASSERT_RAW_GENERIC_EQ(child.k, k_expected, 8);
    ASSERT_BYTES_EQ(child.c, c_expected, 32);
END_TEST

DEFINE_TEST_SUITE(bip32)
    RUN_TEST(bip32_private, "BIP-32 private not hardened");
    RUN_TEST(bip32_private_hardened, "BIP-32 private hardened");
END_TEST_SUITE