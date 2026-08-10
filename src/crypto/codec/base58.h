//
// Created by M Lunkeit on 05.08.26.
//

#ifndef BASALT_BASE58_H
#define BASALT_BASE58_H

#include <stdint.h>
#include <stddef.h>

#include "basalt/error.h"

// Converts a byte array into a null terminated base-58 string
basalt_err_t base58_encode(char *out, const uint8_t *in, size_t len);

// Converts a null terminated base-58 string into a byte array
// Writes the amount of bytes written into the referenced integer
basalt_err_t base58_decode(uint8_t *out, size_t *written, const char *in);

#endif //BASALT_BASE58_H
