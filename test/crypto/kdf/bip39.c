//
// Created by M Lunkeit on 28.07.26.
//

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <crypto/kdf/bip39.h>

static uint8_t test_zero_entropy() {
    uint8_t entropy[16];
    memset(entropy, 0x7f, sizeof(entropy));

    char mnemonic[120] = {0};
    bip39_generate_mnemonic(mnemonic, entropy);

    printf("Mnemonic: %s\n", mnemonic);

    return 0;
}

int run_bip39_tests() {
    return test_zero_entropy();
}