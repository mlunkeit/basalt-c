//
// Created by M Lunkeit on 19.07.26.
//

#include <stdio.h>

int run_bigint_tests();
int run_modular_tests();
int run_barrett_tests();
int run_secp256k1_tests();

int main() {
    int total_failed = 0;

    printf("=== RUNNING ALL UNIT TESTS ===\n\n");

    // 1. BigInt Tests ausführen
    total_failed += run_bigint_tests();
    printf("\n-------------------------------\n\n");

    // 2. Modular Tests ausführen
    total_failed += run_modular_tests();
    printf("\n-------------------------------\n\n");

    total_failed += run_barrett_tests();
    printf("\n-------------------------------\n\n");

    total_failed += run_secp256k1_tests();
    printf("\n-------------------------------\n\n");

    // Gesamtergebnis auswerten
    if (total_failed == 0) {
        printf(" [SUCCESS] ALL TEST SUITES PASSED SUCCESSFULLY!\n");
    } else {
        printf(" [FAIL] System check failed. Total errors found: %d\n", total_failed);
    }

    return total_failed;
}