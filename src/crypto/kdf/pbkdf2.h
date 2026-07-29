//
// Created by M Lunkeit on 29.07.26.
//

#ifndef BASALT_PBKDF2_H
#define BASALT_PBKDF2_H

#include <stdint.h>
#include <stddef.h>

#include "basalt/error.h"

// Derives a key from a passphrase and a salt.
// Uses SHA-512 hash algorithm.
basalt_err_t pbkdf2_hmac_sha512(
    uint8_t *dkey, size_t len_dkey,
    const uint8_t *password, size_t len_password,
    const uint8_t *salt, size_t len_salt,
    size_t iterations
);

#endif //BASALT_PBKDF2_H
