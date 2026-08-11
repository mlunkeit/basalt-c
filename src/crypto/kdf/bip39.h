//
// Created by M Lunkeit on 28.07.26.
//

#ifndef BASALT_INTERNAL_BIP39_H
#define BASALT_INTERNAL_BIP39_H

#include <stdint.h>
#include <stddef.h>

#include "basalt/error.h"

#define BIP39_PASSPHRASE_MAX_LENGTH 64
#define BIP39_SEED_BYTES 64

basalt_err_t bip39_generate_mnemonic(char *mnemonic, const uint8_t *entropy, size_t len_entropy);

// Uses PBKDF2 standard specified in RFC-2898 to generate a 512-bit seed.
// The given mnemonic and passphrase have to be null terminated.
basalt_err_t bip39_generate_seed(uint8_t seed[BIP39_SEED_BYTES], const char *mnemonic, const char *passphrase);

#endif //BASALT_INTERNAL_BIP39_H
