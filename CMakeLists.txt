cmake_minimum_required(VERSION 4.3)
project(basalt C)

set(CMAKE_C_STANDARD 23)

add_library(basalt STATIC
        crypto/secp256k1.h
        crypto/secp256k1.c
        math/bigint.h
        math/bigint.c
        math/modular.h
        math/modular.c)

add_executable(run_tests
        test/math/bigint.c
        test/math/modular.c
        test/crypto/secp256k1.c
        test/runner.c)

target_link_libraries(run_tests PRIVATE basalt)