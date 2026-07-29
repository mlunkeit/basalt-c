//
// Created by M Lunkeit on 28.07.26.
//

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "crypto/kdf/bip39.h"

#include "unittest.h"

DEFINE_TEST(low_entropy)

    uint8_t entropy[16];
    memset(entropy, 0x7f, sizeof(entropy));

    char mnemonic[120] = {0};
    bip39_generate_mnemonic(mnemonic, entropy);

    const char *expected = "legal winner thank year wave sausage worth useful legal winner thank yellow ";

    ASSERT_STR_EQ(expected, mnemonic);

END_TEST

DEFINE_TEST_SUITE(bip39)

    RUN_TEST(low_entropy, "low entropy");

END_TEST_SUITE