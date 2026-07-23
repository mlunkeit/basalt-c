cmake_minimum_required(VERSION 4.3)
project(basalt C)

set(CMAKE_C_STANDARD 23)

add_library(basalt STATIC
        math/curves/secp256k1.h
        math/curves/secp256k1.c
        math/bigint.h
        math/bigint.c
        math/modular.h
        math/modular.c
        math/barrett.h
        math/barrett.c
        crypto/hash/sha256.c
        crypto/hash/sha256.h
        test/crypto/hash/sha256.c)

add_executable(run_tests
        test/math/bigint.c
        test/math/modular.c
        test/math/curves/secp256k1.c
        test/runner.c
        test/math/barrett.c)

target_link_libraries(run_tests PRIVATE basalt)