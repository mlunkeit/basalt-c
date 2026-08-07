cmake_minimum_required(VERSION 3.25)
project(basalt C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(basalt STATIC
        src/basalt_ecdsa.c
        src/basalt_hmac.c
        src/basalt_sha.c
        src/math/bigint.c
        src/math/modular.c
        src/math/barrett.c
        src/math/curves/wcurve.c
        src/math/curves/wcurve_point.c
        src/crypto/codec/base58.c
        src/crypto/ec/ecdsa.c
        src/crypto/ec/rfc6979.c
        src/crypto/hash/sha256.c
        src/crypto/hash/sha512.c
        src/crypto/kdf/bip39.c
        src/crypto/kdf/pbkdf2.c
        src/crypto/kdf/bip32.c
        src/crypto/mac/hmac.c
        src/utils/strutil.c
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
        test/crypto/kdf/bip39.c
        test/crypto/kdf/pbkdf2.c
        test/math/curves/wcurve_point.c
        test/crypto/codec/base58.c
        test/utils/strutil.c)

target_include_directories(run_tests
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test
)

target_link_libraries(run_tests PRIVATE basalt)