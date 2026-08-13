//
// Created by M Lunkeit on 13.08.26.
//

#include "basalt/keyder.h"
#include "basalt/serial.h"

#include "unittest.h"

static void dumpkey(const basalt_keyder_extended_private_key_t *key) {
    printf("\nversion = %08x\ndepth = %02x\nfingerprint = %08x\nchild number = %08x\n", key->version, key->depth, key->parent_fingerprint, key->child_number);

    printf("chain code = ");

    for (size_t i = 0; i < 32; i++) {
        printf("%02x", key->c[i]);
    }

    printf("\nkey = ");

    for (size_t i = 0; i < 32; i++) {
        printf("%02x", key->key.d[i]);
    }

    printf("\n");
}

static void dumppubkey(const basalt_keyder_extended_public_key_t *key) {
    printf("\nversion = %08x\ndepth = %02x\nfingerprint = %08x\nchild number = %08x\n", key->version, key->depth, key->parent_fingerprint, key->child_number);

    printf("chain code = ");

    for (size_t i = 0; i < 32; i++) {
        printf("%02x", key->c[i]);
    }

    printf("\nkey =\nx ");

    for (size_t i = 0; i < 32; i++) {
        printf("%02x", key->key.x[i]);
    }

    printf("\ny ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", key->key.y[i]);
    }

    printf("\n");
}

DEFINE_TEST(bip32_derive_master)
    const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char *passphrase = "TREZOR";

    uint8_t seed[64];
    basalt_keyder_derive_seed(seed, mnemonic, passphrase);

    printf("\nseed = ");
    for (size_t i = 0; i < 64; i++) {
        printf("%02x", seed[i]);
    }
    printf("\n");

    basalt_keyder_extended_private_key_t master;
    basalt_keyder_derive_master(BASALT_CURVE_SECP256K1, &master, seed, BASALT_MAINNET_PRIVATE);

    dumpkey(&master);
END_TEST

DEFINE_TEST(bip32_vector_1)
    static constexpr char seed_hex[128] = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    uint8_t seed[64];
    for (size_t i = 0; i < 64; i++) {
        sscanf(seed_hex + 2 * i, "%02hhx", &seed[i]);
    }

    basalt_keyder_extended_private_key_t master;
    basalt_keyder_derive_master(BASALT_CURVE_SECP256K1, &master, seed, BASALT_MAINNET_PRIVATE);

    uint32_t path[2] = {0, 2147483647 | (1 << 31)};

    basalt_keyder_extended_private_key_t child;
    basalt_keyder_derive_private(BASALT_CURVE_SECP256K1, &child, &master, path, 2);

    char base58[150];
    basalt_serialize_b58_private(base58, &child);
    ASSERT_STR_EQ(base58, "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9");

    basalt_keyder_extended_public_key_t childpub;
    childpub.version = BASALT_MAINNET_PUBLIC;
    childpub.depth = child.depth;
    childpub.parent_fingerprint = child.parent_fingerprint;
    childpub.child_number = child.child_number;
    memcpy(childpub.c, child.c, 32);

    ASSERT(basalt_ec_calculate_public_key(BASALT_CURVE_SECP256K1, &childpub.key, &child.key) == BASALT_OK);
    basalt_serialize_b58_public(BASALT_CURVE_SECP256K1, base58, &childpub);

    ASSERT_STR_EQ(base58, "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");
END_TEST

DEFINE_TEST_SUITE(keyder)
    RUN_TEST(bip32_derive_master, "BIP-32 deriving master key");
    RUN_TEST(bip32_vector_1, "BIP-32 derivation vector 1");
END_TEST_SUITE