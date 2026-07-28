//
// Created by M Lunkeit on 28.07.26.
//

#ifndef BASALT_INTERNAL_BIP39_H
#define BASALT_INTERNAL_BIP39_H

#include <stdint.h>

void bip39_generate_mnemonic(char *mnemonic, const uint8_t entropy[16]);

#endif //BASALT_INTERNAL_BIP39_H
