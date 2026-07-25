//
// Created by M Lunkeit on 24.07.26.
//

#include <string.h>

#include "hmac.h"
#include "../hash/sha256.h"

#define IPAD 0x36
#define OPAD 0x5c

void hmac_sha256(uint8_t output[32], const uint8_t *key, const size_t len_key, const uint8_t *message, const size_t len_message) {
    uint8_t K0[64] = {0};

    if (len_key <= 64) {
        memcpy(K0, key, len_key * sizeof(uint8_t));
    } else {
        sha256(K0, key, len_key);
    }

    // inner_msg_buf = (K0 XOR IPAD) || message

    uint8_t inner_msg_buf[64 + len_message];
    for (size_t i = 0; i < 64; i++) {
        inner_msg_buf[i] = K0[i] ^ IPAD;
    }

    memcpy(inner_msg_buf + 64, message, len_message);

    // inner_hash = SHA256((K0 XOR IPAD) || message) = SHA256(inner_msg_buf)

    // outer_msg_buf = (K0 XOR OPAD) || SHA256((K0 XOR IPAD) || message) = (K0 XOR OPAD) || inner_hash

    uint8_t outer_msg_buf[96];
    for (size_t i = 0; i < 64; i++) {
        outer_msg_buf[i] = K0[i] ^ OPAD;
    }

    sha256(outer_msg_buf + 64, inner_msg_buf, 64 + len_message);

    // output = SHA256((K0 XOR OPAD) || SHA256((K0 XOR IPAD) || message)) = SHA256(outer_msg_buf)
    sha256(output, outer_msg_buf, 96);
}