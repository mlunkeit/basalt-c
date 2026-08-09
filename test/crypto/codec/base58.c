//
// Created by M Lunkeit on 05.08.26.
//

#include "crypto/codec/base58.h"

#include "unittest.h"

size_t div58(uint8_t *quotient, uint8_t *remainder, const uint8_t *in, size_t len);

DEFINE_TEST(div58_simple)
    static constexpr uint8_t dividend[] = {1, 0};

    uint8_t quotient[2];
    uint8_t remainder;

    div58(quotient, &remainder, dividend, 2);

    static constexpr uint8_t expected_quotient[] = {0, 4};
    ASSERT_BYTES_EQ(quotient, expected_quotient, 2);
    ASSERT(remainder == 24);
END_TEST

DEFINE_TEST(encode_base58)
    static constexpr uint8_t raw_data[] = "my name is retep and i am evil";

    char out[100];
    base58_encode(out, raw_data, strlen((const char*) raw_data));

    static constexpr char expected[] = "NwFuhTR7rE9hhyqqEo4k3rbo8iQDrtzazWh2xR8vX";

    ASSERT_STR_EQ(out, expected);
END_TEST

DEFINE_TEST(encode_base58_padding)
    constexpr uint8_t raw_data[4] = {0, 0, 0, 0xff};

    char out[100];
    base58_encode(out, raw_data, 4);

    static constexpr char expected[] = "1115Q";

    ASSERT_STR_EQ(out, expected);
END_TEST

DEFINE_TEST(decode_base58)
    static constexpr char input[] = "NwFuhTR7rE9hhyqqEo4k3rbo8iQDrtzazWh2xR8vX";

    uint8_t out[100] = {0};
    size_t written;
    base58_decode(out, &written, input);

    static constexpr char expected[] = "my name is retep and i am evil";

    ASSERT_STR_EQ((char*) out, expected);
END_TEST

DEFINE_TEST_SUITE(base58)
    RUN_TEST(div58_simple, "simple dividing by 58");
    RUN_TEST(encode_base58, "encode base58");
    RUN_TEST(encode_base58_padding, "encode base58 padding");
    RUN_TEST(decode_base58, "decode base58");
END_TEST_SUITE