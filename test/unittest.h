//
// Created by M Lunkeit on 29.07.26.
//

#ifndef BASALT_UNITTEST_H
#define BASALT_UNITTEST_H

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

typedef uint8_t status_t;

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

#define DEFINE_TEST(name) \
    static status_t test_ ## name(void) {

#define END_TEST \
    OK; \
    }

#define FAIL(msg, ...) \
    do {\
        printf("%s%sfail%s\n", COLOR_RED, COLOR_BOLD, COLOR_RESET); \
        printf(msg, __VA_ARGS__); \
        return 1;\
    } while(0)

#define OK \
    do {\
        printf("%s%sok%s\n", COLOR_GREEN, COLOR_BOLD, COLOR_RESET); \
        return 0;\
    } while (0)

#define RUN_TEST(test, name) \
    do {\
        printf("testing %s...", name); \
        status_t status = test_ ## test(); \
        if (status != 0) { \
            return 1;\
        }\
    } while (0)

#define DEFINE_TEST_SUITE(suite) \
    status_t run_ ## suite ##_tests(void) {

#define END_TEST_SUITE \
    return 0; \
    }

#define INCLUDE_TEST_SUITE(suite) \
    status_t run_ ## suite ##_tests(void);

#define RUN_TEST_SUITE(suite, name) \
    do { \
        printf(COLOR_YELLOW COLOR_BOLD "testing" COLOR_RESET " %s...\n\n", name); \
        status_t status = run_ ## suite ##_tests(); \
        if (status != 0) {\
            printf("\n" COLOR_RED COLOR_BOLD "failure" COLOR_RESET " test suite %s failed", name); \
            return status; \
        }\
        printf("\n");\
    } while(0)

// ASSERTIONS

#define ASSERT(cond) \
    if (!(cond)) { \
        FAIL("\n  " COLOR_RED "-> Assertion failed"\
             "\n     File: %s, Line: %d\n  ", __FILE__, __LINE__ \
        );\
    }

#define ASSERT_STR_EQ(actual, expected) \
    do { \
        const char *_e = (expected); \
        const char *_a = (actual); \
        if (strcmp(_e, _a) != 0) { \
            FAIL("\n  " COLOR_RED "-> Expected \"%s\", but got \"%s\"" COLOR_RESET \
                 "\n     File: %s, Line: %d\n  ", _e, _a, __FILE__, __LINE__); \
        } \
    } while(0)


#define ASSERT_UINT256_EQ(actual, expected) \
    for (size_t i = 0; i < 8; i++) { \
        if ((actual).limbs[i] != (expected).limbs[i]) { \
            FAIL("\n  " COLOR_RED "-> Expected 0x%08X, got 0x%08X" COLOR_RESET \
                 "\n     File: %s, Line: %d\n  ", (expected).limbs[i], (actual).limbs[i], __FILE__, __LINE__ \
            ); \
        } \
    }

#define ASSERT_RAW_GENERIC_EQ(actual, expected, len) \
    for (size_t i = 0; i < (len); i++) { \
        if ((actual)[i] != (expected)[i]) { \
            FAIL("\n  " COLOR_RED "-> Expected 0x%08X, got 0x%08X" COLOR_RESET \
                 "\n     File: %s, Line: %d\n  ", (expected)[i], (actual)[i], __FILE__, __LINE__ \
            ); \
        } \
    }

#define ASSERT_BYTES_EQ(actual, expected, len) \
    for (size_t i = 0; i < (len); i++) { \
        if ((actual)[i] != (expected)[i]) { \
            FAIL("\n  " COLOR_RED "-> Expected 0x%08X, got 0x%08X" COLOR_RESET \
                 "\n     File: %s, Line: %d\n  ", (expected)[i], (actual)[i], __FILE__, __LINE__ \
            ); \
        } \
    }

#define ASSERT_UINT64ARR_EQ(actual, expected, len) \
    for (size_t i = 0; i < (len); i++) { \
        if ((actual)[i] != (expected)[i]) { \
            FAIL("\n  " COLOR_RED "-> Expected 0x%016llX, got 0x%016llX" COLOR_RESET \
                 "\n     File: %s, Line: %d\n  ", (expected)[i], (actual)[i], __FILE__, __LINE__ \
            ); \
        } \
    }

#endif //BASALT_UNITTEST_H
