//
// Created by M Lunkeit on 28.07.26.
//

#include <string.h>

#include "basalt/mem.h"

#include "crypto/hash/sha256.h"
#include "crypto/kdf/bip39.h"
#include "crypto/kdf/bip39words.h"
#include "crypto/kdf/pbkdf2.h"

void bip39_generate_mnemonic(char *mnemonic, const uint8_t entropy[16]) {
    uint8_t hash[32];
    sha256(hash, entropy, 16);

    uint8_t seed[17];
    memcpy(seed, entropy, 16);
    seed[16] = hash[0] & 0xF0;

    size_t mnemonic_pos = 0;

    for (size_t i = 0; i < 12; i++) {
        size_t bit = i * 11;
        size_t byte_idx = bit >> 3;
        size_t byte_offset = bit & 7;

        uint8_t seg0 = byte_idx < 17 ? seed[byte_idx] : 0;
        uint8_t seg1 = byte_idx < 16 ? seed[byte_idx + 1] : 0;
        uint8_t seg2 = byte_idx < 15 ? seed[byte_idx + 2] : 0;

        uint32_t wordidx = seg0 << 24 | seg1 << 16 | seg2 << 8;
        wordidx <<= byte_offset;
        wordidx >>= 21;

        const char *word = WORDLIST[wordidx];
        size_t wordlen = strlen(word);

        memcpy(mnemonic + mnemonic_pos, word, wordlen);
        mnemonic_pos += wordlen;
        mnemonic[mnemonic_pos] = ' ';
        mnemonic_pos++;
    }

    mnemonic[mnemonic_pos - 1] = '\0';
}

basalt_err_t bip39_generate_seed(uint8_t seed[64], const char *mnemonic, const char *passphrase) {
    // 8 for "mnemonic" + maximum passphrase length
    char salt[8 + BIP39_PASSPHRASE_MAX_LENGTH] = "mnemonic";

    size_t len_salt = 8;

    if (passphrase) {
        size_t len_passphrase = strlen(passphrase);

        if (len_passphrase > BIP39_PASSPHRASE_MAX_LENGTH) {
            return BASALT_ERR_INPUT_TOO_LONG;
        }

        memcpy(salt + 8, passphrase, len_passphrase);
        len_salt += len_passphrase;
    }

    basalt_err_t status = pbkdf2_hmac_sha512(seed, 64,
        (uint8_t*) mnemonic, strlen(mnemonic),
        (uint8_t*) salt, len_salt,
        2048);

    basalt_memzero(salt, 8 + BIP39_PASSPHRASE_MAX_LENGTH);
    return status;
}
