//
// Created by M Lunkeit on 28.07.26.
//

#include <string.h>

#include "basalt/mem.h"

#include "crypto/hash/sha256.h"
#include "crypto/kdf/bip39.h"
#include "crypto/kdf/bip39words.h"
#include "crypto/kdf/pbkdf2.h"

basalt_err_t bip39_generate_mnemonic(char *mnemonic, const uint8_t *entropy, const size_t len_entropy) {

    if (!entropy) {
        return BASALT_ERR_NULL_POINTER;
    }

    if (len_entropy != 16 && len_entropy != 24 && len_entropy != 32) {
        return BASALT_ERR_INVALID_PARAM;
    }

    uint8_t hash[32];
    sha256(hash, entropy, 16);

    uint8_t seed[25];
    memcpy(seed, entropy, len_entropy);
    seed[len_entropy] = hash[0];

    size_t mnemonic_pos = 0;

    for (size_t i = 0; i < (len_entropy * 3) >> 2; i++) {
        const size_t bit = i * 11;
        const size_t byte_idx = bit >> 3;
        const size_t byte_offset = bit & 7;

        const uint8_t seg0 = byte_idx < 17 ? seed[byte_idx] : 0;
        const uint8_t seg1 = byte_idx < 16 ? seed[byte_idx + 1] : 0;
        const uint8_t seg2 = byte_idx < 15 ? seed[byte_idx + 2] : 0;

        uint32_t wordidx = seg0 << 24 | seg1 << 16 | seg2 << 8;
        wordidx <<= byte_offset;
        wordidx >>= 21;

        const char *word = WORDLIST[wordidx];
        const size_t wordlen = strlen(word);

        memcpy(mnemonic + mnemonic_pos, word, wordlen);
        mnemonic_pos += wordlen;
        mnemonic[mnemonic_pos] = ' ';
        mnemonic_pos++;
    }

    mnemonic[mnemonic_pos - 1] = '\0';

    return BASALT_OK;
}

basalt_err_t bip39_generate_seed(uint8_t seed[64], const char *mnemonic, const char *passphrase) {
    /*
     * Quoting BIP-39:
     *
     * A user may decide to protect their mnemonic with a passphrase. If a passphrase is not present,
     * an empty string "" is used instead.
     *
     * To create a binary seed from the mnemonic, we use the PBKDF2 function with a mnemonic
     * sentence (in UTF-8 NFKD) used as the password and the string "mnemonic" + passphrase
     * (again in UTF-8 NFKD) used as the salt.
     * The iteration count is set to 2048 and HMAC-SHA512 is used as the pseudo-random function.
     * The length of the derived key is 512 bits (= 64 bytes).
     */

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

    const basalt_err_t status = pbkdf2_hmac_sha512(seed, 64,
        (uint8_t*) mnemonic, strlen(mnemonic),
        (uint8_t*) salt, len_salt,
        2048);

    basalt_memzero(salt, 8 + BIP39_PASSPHRASE_MAX_LENGTH);
    return status;
}
