//
// Created by M Lunkeit on 30.07.26.
//

#include "crypto/kdf/pbkdf2.h"

#include "unittest.h"

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
}

DEFINE_TEST(hs512_one_iteration)
    constexpr uint8_t password[8] = "password";
    constexpr uint8_t salt[4] = "salt";

    size_t iterations = 1;
    uint8_t dk[64];
    status_t status = pbkdf2_hmac_sha512(dk, 64, password, 8, salt, 4, iterations);

    if (status != 0) {
        FAIL("status is %d", status);
    }

    uint8_t expected[64];
    hex_to_bytes("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce", expected, 64);

    ASSERT_BYTES_EQ(dk, expected, 64);
END_TEST

DEFINE_TEST(hs512_1000_iterations)
    constexpr uint8_t password[8] = "password";
    constexpr uint8_t salt[4] = "salt";

    size_t iterations = 1000;
    uint8_t dk[64];
    status_t status = pbkdf2_hmac_sha512(dk, 64, password, 8, salt, 4, iterations);

    if (status != 0) {
        FAIL("status is %d", status);
    }

    uint8_t expected[64];
    hex_to_bytes("afe6c5530785b6cc6b1c6453384731bd5ee432ee549fd42fb6695779ad8a1c5bf59de69c48f774efc4007d5298f9033c0241d5ab69305e7b64eceeb8d834cfec", expected, 64);

    ASSERT_BYTES_EQ(dk, expected, 64);
END_TEST

DEFINE_TEST_SUITE(pbkdf2)
    RUN_TEST(hs512_one_iteration, "PBKDF2 HMAC-SHA-512 one iteration");
    RUN_TEST(hs512_1000_iterations, "PBKDF2 HMAC-SHA-512 thousand iterations");
END_TEST_SUITE