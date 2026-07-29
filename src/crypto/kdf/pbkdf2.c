//
// Created by M Lunkeit on 29.07.26.
//

#include "crypto/kdf/pbkdf2.h"
#include "crypto/mac/hmac.h"

#include <string.h>

basalt_err_t pbkdf2_hmac_sha512(
    uint8_t *dkey, const size_t len_dkey,
    const uint8_t *password, const size_t len_password,
    const uint8_t *salt, const size_t len_salt,
    const size_t iterations)
{
    // RFC-2898 implementation. (page 9)

    if (iterations == 0) {
        return BASALT_ERR_INVALID_PARAM;
    }

    /*
     * Step 1:
     *
     * If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
     * stop.
     */

    if (len_dkey > (((size_t) 1 << 32) - 1) << 6) {
        return BASALT_ERR_DERIVED_KEY_TOO_LONG;
    }

    /*
     * Step 2:
     *
     * Let l be the number of hLen-octet blocks in the derived key,
     * rounding up, and let r be the number of octets in the last
     * block:
     *
     *               l = CEIL (dkLen / hLen) ,
     *               r = dkLen - (l - 1) * hLen .
     *
     * Here, CEIL (x) is the "ceiling" function, i.e. the smallest
     * integer greater than, or equal to, x.
     */

    const size_t l = (len_dkey + 63) >> 6;
    const size_t r = len_dkey - ((l - 1) << 6);

    /*
     * Step 3:
     *
     * For each block of the derived key apply the function F defined
     * below to the password P, the salt S, the iteration count c, and
     * the block index to compute the block:
     *
     *      T_1 = F (P, S, c, 1) ,
     *      T_2 = F (P, S, c, 2) ,
     *      ...
     *      T_l = F (P, S, c, l) ,
     *
     *  where the function F is defined as the exclusive-or sum of the
     *  first c iterates of the underlying pseudorandom function PRF
     *  applied to the password P and the concatenation of the salt S
     *  and the block index i:
     *
     *      F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
     *
     *  where
     *
     *      U_1 = PRF (P, S || INT (i)) ,
     *      U_2 = PRF (P, U_1) ,
     *      ...
     *      U_c = PRF (P, U_{c-1}) .
     *
     *  Here, INT (i) is a four-octet encoding of the integer i, most
     *  significant octet first.
     */

    uint8_t T[64 * l];
    memset(T, 0, 64 * l);

    for (size_t i = 0; i < l; i++) {
        const size_t block_idx = i + 1;
        uint8_t U[64];

        uint8_t buf[len_salt + 4];
        memcpy(buf, salt, len_salt);

        buf[len_salt] = (uint8_t) (block_idx >> 24);
        buf[len_salt + 1] = (uint8_t) (block_idx >> 16);
        buf[len_salt + 2] = (uint8_t) (block_idx >> 8);
        buf[len_salt + 3] = (uint8_t) block_idx;

        hmac_sha512(U, password, len_password, buf, len_salt + 4);
        memcpy(T + 64 * i, U, 64);

        for (size_t j = 1; j < iterations; j++) {
            hmac_sha512(U, password, len_password, U, 64);

            for (size_t k = 0; k < 64; k++) {
                T[64 * i + k] ^= U[k];
            }
        }
    }

    /*
     * Step 4:
     *
     * Concatenate the blocks and extract the first dkLen octets to
     * produce a derived key DK:
     *
     *      DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
     */

    for (size_t i = 0; i < l - 1; i++) {
        memcpy(dkey + 64 * i, T + 64 * i, 64);
    }

    memcpy(dkey + 64 * (l - 1), T + 64 * (l - 1), r);

    /*
     * Step 5:
     *
     * Output the derived key DK.
     */

    return BASALT_OK;
}
