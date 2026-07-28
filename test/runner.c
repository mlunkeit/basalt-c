//
// Created by M Lunkeit on 19.07.26.
//

#include <stdio.h>

int run_bigint_tests();
int run_modular_tests();
int run_barrett_tests();
int run_secp256k1_tests();
int run_sha256_tests();
int run_sha512_tests();
int run_hmac_tests();
int run_ecdsa_tests();
int run_bip39_tests();

int main() {
    setbuf(stdout, nullptr);
    int total_failed = 0;

    printf("=== RUNNING ALL UNIT TESTS ===\n\n");

    total_failed += run_bigint_tests();
    printf("\n-------------------------------\n\n");

    total_failed += run_modular_tests();
    printf("\n-------------------------------\n\n");

    total_failed += run_barrett_tests();
    printf("\n-------------------------------\n\n");

    total_failed += run_secp256k1_tests();
    printf("\n-------------------------------\n\n");

    total_failed += run_sha256_tests();
    printf("\n-------------------------------\n\n");

    total_failed += run_sha512_tests();
    printf("\n-------------------------------\n\n");

    total_failed += run_hmac_tests();
    printf("\n-------------------------------\n\n");

    total_failed += run_ecdsa_tests();
    printf("\n-------------------------------\n\n");

    total_failed += run_bip39_tests();
    printf("\n-------------------------------\n\n");

    if (total_failed == 0) {
        printf("\033[32m[SUCCESS]\033[0m ALL TEST SUITES PASSED SUCCESSFULLY!\n");
    } else {
        printf("\033[31m[FAIL]\033[0m System check failed. Total errors found: %d\n", total_failed);
    }

    return total_failed;
}