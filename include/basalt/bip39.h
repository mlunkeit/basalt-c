//
// Created by M Lunkeit on 28.07.26.
//

#ifndef BASALT_BIP39_H
#define BASALT_BIP39_H

#include <stddef.h>
#include <stdint.h>

#include "error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BASALT_BIP39_MAX_WORD_LENGTH 10
#define BASALT_BIP39_WORDS 12

typedef struct {
    char word[BASALT_BIP39_MAX_WORD_LENGTH];
} basalt_bip39_word_t;

typedef struct {
    basalt_bip39_word_t words[BASALT_BIP39_WORDS];
} basalt_bip39_mnemonic_t;

basalt_err_t basalt_bip39_generate_mnemonic(basalt_bip39_mnemonic_t *mnemonic, const uint8_t entropy[16]);

#ifdef __cplusplus
}
#endif

#endif //BASALT_BIP39_H
