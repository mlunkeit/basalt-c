#include "unittest.h"
#include "crypto/hash/ripemd160.h"

size_t ripemd160_pad(uint32_t *output, const uint8_t *input, size_t len);

DEFINE_TEST(ripemd160_pad_empty)
    uint32_t output[16] = {0};
    const uint8_t input[] = "";
    size_t len = 0;

    size_t blocks = ripemd160_pad(output, input, len);

    ASSERT(blocks == 1);

    ASSERT(output[0] == 0x00000080);

    for (size_t i = 1; i < 14; i++) {
        ASSERT(output[i] == 0x00000000);
    }

    ASSERT(output[14] == 0x00000000);
    ASSERT(output[15] == 0x00000000);
END_TEST

DEFINE_TEST(ripemd160_pad_abc)
    uint32_t output[16] = {0};
    const uint8_t input[] = "abc"; // 'a'=0x61, 'b'=0x62, 'c'=0x63
    size_t len = 3;

    size_t blocks = ripemd160_pad(output, input, len);

    ASSERT(blocks == 1);

    ASSERT(output[0] == 0x80636261);

    for (size_t i = 1; i < 14; i++) {
        ASSERT(output[i] == 0x00000000);
    }

    ASSERT(output[14] == 24);
    ASSERT(output[15] == 0);
END_TEST

DEFINE_TEST(ripemd160_pad_boundary_55_bytes)
    uint32_t output[16] = {0};
    uint8_t input[55];
    memset(input, 'A', 55);

    size_t blocks = ripemd160_pad(output, input, 55);

    ASSERT(blocks == 1);

    ASSERT(output[13] == 0x80414141);

    ASSERT(output[14] == 440);
    ASSERT(output[15] == 0);
END_TEST

DEFINE_TEST(ripemd160_pad_boundary_56_bytes)
    uint32_t output[32] = {0};
    uint8_t input[56];
    memset(input, 'B', 56);

    size_t blocks = ripemd160_pad(output, input, 56);

    ASSERT(blocks == 2);

    ASSERT(output[14] == 0x00000080);

    ASSERT(output[16] == 0x00000000);

    ASSERT(output[30] == 448);
    ASSERT(output[31] == 0);
END_TEST

DEFINE_TEST(ripemd160_vector_1)
    uint8_t output[20] = {0};
    ripemd160(output, nullptr, 0);

    char out_hex[41] = {0};
    for (size_t i = 0; i < 20; i++) {
        sprintf(out_hex + i * 2, "%02x", output[i]);
    }

    ASSERT_STR_EQ(out_hex, "9c1185a5c5e9fc54612808977ee8f548b2258d31");
END_TEST

DEFINE_TEST(ripemd160_vector_2)
    uint8_t output[20] = {0};
    ripemd160(output, (uint8_t*) "a", 1);

    char out_hex[41] = {0};
    for (size_t i = 0; i < 20; i++) {
        sprintf(out_hex + i * 2, "%02x", output[i]);
    }

    ASSERT_STR_EQ(out_hex, "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
END_TEST

DEFINE_TEST(ripemd160_vector_3)
    uint8_t output[20] = {0};
    ripemd160(output, (uint8_t*) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62);

    char out_hex[41] = {0};
    for (size_t i = 0; i < 20; i++) {
        sprintf(out_hex + i * 2, "%02x", output[i]);
    }

    ASSERT_STR_EQ(out_hex, "b0e20b6e3116640286ed3a87a5713079b21f5189");
END_TEST

DEFINE_TEST_SUITE(ripemd160)
    RUN_TEST(ripemd160_pad_empty, "RIPEMD160 Pad: Empty String");
    RUN_TEST(ripemd160_pad_abc, "RIPEMD160 Pad: 'abc'");
    RUN_TEST(ripemd160_pad_boundary_55_bytes, "RIPEMD160 Pad: Boundary 55 Bytes (1 Block)");
    RUN_TEST(ripemd160_pad_boundary_56_bytes, "RIPEMD160 Pad: Boundary 56 Bytes (2 Blocks)");
    RUN_TEST(ripemd160_vector_1, "RIPEMD160 vector 1");
    RUN_TEST(ripemd160_vector_2, "RIPEMD160 vector 2");
    RUN_TEST(ripemd160_vector_3, "RIPEMD160 vector 3");
END_TEST_SUITE