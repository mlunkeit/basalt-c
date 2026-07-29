//
// Created by M Lunkeit on 19.07.26.
//

#include "unittest.h"

INCLUDE_TEST_SUITE(bigint)
INCLUDE_TEST_SUITE(modular)
INCLUDE_TEST_SUITE(barrett)
INCLUDE_TEST_SUITE(secp256k1)
INCLUDE_TEST_SUITE(sha256)
INCLUDE_TEST_SUITE(sha512)
INCLUDE_TEST_SUITE(hmac)
INCLUDE_TEST_SUITE(ecdsa)
INCLUDE_TEST_SUITE(bip39)

int main() {
    setbuf(stdout, nullptr);

    RUN_TEST_SUITE(bigint, "big integer arithmetic");
    RUN_TEST_SUITE(modular, "modular arithmetic");
    RUN_TEST_SUITE(barrett, "barrett reduction");
    RUN_TEST_SUITE(secp256k1, "secp256k1 elliptic curve arithmetic");
    RUN_TEST_SUITE(sha256, "SHA-256");
    RUN_TEST_SUITE(sha512, "SHA-512");
    RUN_TEST_SUITE(hmac, "HMAC");
    RUN_TEST_SUITE(ecdsa, "ECDSA");
    RUN_TEST_SUITE(bip39, "BIP-39");

    printf("%s%ssuccess%s All test suites passed successfully!\n", COLOR_GREEN, COLOR_BOLD, COLOR_RESET);

    return 0;
}