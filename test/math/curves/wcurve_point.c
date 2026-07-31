//
// Created by M Lunkeit on 31.07.26.
//

#include "math/curves/wcurve_point.h"
#include "math/curves/secp256k1.h"

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

    printf("\nx =");

    for (size_t i = 0; i < 8; i++) {
        printf(" %08x", decompressed.x[7 - i]);
    }

    printf("\ny =");

    for (size_t i = 0; i < 8; i++) {
        printf(" %08x", decompressed.y[7 - i]);
    }

    printf("\n");
END_TEST

DEFINE_TEST_SUITE(wcurve_point)
    RUN_TEST(wcurve_point_decompress, "point decompression on secp256k1");
END_TEST_SUITE