//
// Created by M Lunkeit on 07.08.26.
//

#include "utils/strutil.h"

#include "unittest.h"

DEFINE_TEST(reverse)
    char str[] = "peter";
    strrev(str);

    static constexpr char expected[] = "retep";
    ASSERT_STR_EQ(str, expected);
END_TEST

DEFINE_TEST_SUITE(strutil)
    RUN_TEST(reverse, "reversing string");
END_TEST_SUITE