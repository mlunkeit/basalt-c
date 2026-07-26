cmake_minimum_required(VERSION 4.3)
project(basalt C)

set(CMAKE_C_STANDARD 23)

add_library(basalt STATIC
        src/math/curves/secp256k1.h
        src/math/bigint.h
        src/math/bigint.c
        src/math/modular.h
        src/math/modular.c
        src/math/barrett.h
        src/math/barrett.c
        src/crypto/hash/sha256.c
        src/crypto/hash/sha256.h
        src/crypto/mac/hmac.h
        src/crypto/mac/hmac.c
        src/crypto/ec/ecdsa.h
        src/crypto/ec/ecdsa.c
        src/crypto/ec/rfc6979.h
        src/crypto/ec/rfc6979.c
        src/math/curves/secp256r1.h
        src/math/curves/secp256r1.c
        src/math/curves/wcurve.h
        src/math/curves/wcurve.c)

add_executable(run_tests
        test/runner.c
        test/math/bigint.c
        test/math/modular.c
        test/math/curves/secp256k1.c
        test/math/barrett.c
        test/crypto/hash/sha256.c
        test/crypto/mac/hmac.c
        #test/crypto/ec/ecdsa.c
)

target_link_libraries(run_tests PRIVATE basalt)