cmake_minimum_required(VERSION 4.3)
project(basalt C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(basalt STATIC
        src/math/bigint.c
        src/math/modular.c
        src/math/barrett.c
        src/crypto/hash/sha256.c
        src/crypto/mac/hmac.c
        src/crypto/ec/ecdsa.c
        src/crypto/ec/rfc6979.c
        src/math/curves/wcurve.c
        src/basalt_ecdsa.c
        src/basalt_hmac.c
        src/basalt_sha.c
        src/crypto/hash/sha512.c
        src/crypto/kdf/bip39words.h
        src/crypto/kdf/bip39.c
)

target_include_directories(basalt
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(MSVC)
    target_compile_options(basalt PRIVATE /W4)
else()
    target_compile_options(basalt PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(run_tests
        test/runner.c
        test/math/bigint.c
        test/math/modular.c
        test/math/curves/secp256k1.c
        test/math/barrett.c
        test/crypto/hash/sha256.c
        test/crypto/mac/hmac.c
        test/crypto/ec/ecdsa.c
        test/crypto/hash/sha512.c
        test/crypto/kdf/bip39.c)

target_include_directories(run_tests
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(run_tests PRIVATE basalt)