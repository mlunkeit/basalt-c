//
// Created by M Lunkeit on 05.08.26.
//

#include <string.h>

#include "basalt/error.h"
#include "basalt/mem.h"
#include "crypto/codec/base58.h"
#include "utils/strutil.h"

static constexpr char BASE58_CHARS[59] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static constexpr int8_t b58digits_map[] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

// quotient will have the amount of bytes the function returns
// remainder will be exactly one byte that is smaller than 58
// function is in-place safe as the input is copied into a buffer
// before modifying the output. input is then never read from again.
size_t div58(uint8_t *quotient, uint8_t *remainder, const uint8_t *in, size_t len) {
    uint8_t buf[len];
    memcpy(buf, in, len);

    uint8_t *p = buf;

    size_t len_out = 0;

    // skip all leading zeros as they won't have any
    // effect on the result of this function
    while (len > 0 && *p == 0) {
        p++;
        len--;
    }

    uint8_t carry = 0;

    for (;len > 0; len--) {
        const uint16_t c = (uint16_t) carry << 8 | (uint16_t) *p++;

        // carry is always less than 58 so c / 58 will always be less than 256
        const uint8_t q = (uint8_t) (c / 58);
        const uint8_t r = (uint8_t) (c - (uint16_t) q * 58);
        carry = r;

        *quotient++ = (uint8_t) q;
        len_out++;
    }

    *remainder = carry;

    // clear buffer as it is no longer used
    basalt_memzero(buf, len);

    return len_out;
}

basalt_err_t base58_encode(char *out, const uint8_t *in, size_t len) {
    uint8_t buf[len];
    memcpy(buf, in, len);

    uint8_t *p = buf;

    char *beginning = out;

    size_t leading_zeros = 0;

    for (; *p == 0; p++) {
        leading_zeros++;
        len--;
    }

    while (len > 1 || *p != 0) {
        uint8_t remainder;
        len = div58(p, &remainder, p, len);

        *out++ = BASE58_CHARS[remainder];
    }

    for (; leading_zeros > 0; leading_zeros--) {
        *out++ = *BASE58_CHARS;
    }

    *out = '\0';
    strrev(beginning);

    return BASALT_OK;
}

size_t mul58(uint8_t *product, const uint8_t *in, size_t len) {
    
}

basalt_err_t base58_decode(uint8_t *out, const char *in) {

}