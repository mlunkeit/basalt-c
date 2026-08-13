//
// Created by M Lunkeit on 28.07.26.
//

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "basalt/keyder.h"
#include "crypto/kdf/bip39.h"

#include "unittest.h"

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
}

DEFINE_TEST(low_entropy_mnemonic_generation)

    uint8_t entropy[16];
    memset(entropy, 0x7f, sizeof(entropy));

    char mnemonic[120] = {0};
    bip39_generate_mnemonic(mnemonic, entropy, 16);

    const char *expected = "legal winner thank year wave sausage worth useful legal winner thank yellow";

    ASSERT_STR_EQ(mnemonic, expected);

END_TEST

DEFINE_TEST(low_entropy_seed_generation)
    const char *mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const char *passphrase = "TREZOR";

    uint8_t seed[64];
    ASSERT(basalt_keyder_derive_seed(seed, mnemonic, passphrase) == BASALT_OK);

    uint8_t expected[64];
    hex_to_bytes("2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607", expected, 64);

    ASSERT_BYTES_EQ(seed, expected, 64);
END_TEST

DEFINE_TEST_SUITE(bip39)

    RUN_TEST(low_entropy_mnemonic_generation, "low entropy mnemonic generation");
    RUN_TEST(low_entropy_seed_generation, "low entropy seed generation");

END_TEST_SUITE