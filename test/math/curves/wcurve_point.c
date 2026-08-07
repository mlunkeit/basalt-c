//
// Created by M Lunkeit on 31.07.26.
//

#include "math/curves/wcurve_point.h"
#include "math/curves/secp256k1.h"
#include "math/bigint.h"

#include "unittest.h"

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
}

DEFINE_TEST(wcurve_point_decompress)
    uint8_t compressed[33];
    hex_to_bytes("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", compressed, 33);

    wcurve_point_t decompressed;
    wcurve_point_decompress(&SECP256K1, &decompressed, compressed);

    uint8_t x_expected[32];
    hex_to_bytes("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", x_expected, 32);

    uint8_t y_expected[32];
    hex_to_bytes("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", y_expected, 32);

    uint8_t x_actual[32];
    bigint_to_bytes(x_actual, decompressed.x, 8);

    uint8_t y_actual[32];
    bigint_to_bytes(y_actual, decompressed.y, 8);

    ASSERT_BYTES_EQ(x_actual, x_expected, 32);
    ASSERT_BYTES_EQ(y_actual, y_expected, 32);
END_TEST

DEFINE_TEST_SUITE(wcurve_point)
    RUN_TEST(wcurve_point_decompress, "point decompression on secp256k1");
END_TEST_SUITE