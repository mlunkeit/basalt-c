//
// Created by M Lunkeit on 04.08.26.
//

#include <string.h>

#include "basalt/mem.h"
#include "basalt/error.h"
#include "math/bigint.h"
#include "math/modular.h"
#include "math/curves/wcurve_point.h"
#include "crypto/kdf/bip32.h"
#include "crypto/mac/hmac.h"

basalt_err_t bip32_derive_private(
    const wcurve_spec_t *wcurve,
    bip32_extended_private_key_t *child,
    const bip32_extended_private_key_t *parent,
    const uint32_t index)
{
    if (!wcurve || !child || !parent) {
        return BASALT_ERR_NULL_POINTER;
    }

    if (wcurve->len_p != 8 || wcurve->len_n != 8) {
        return BASALT_ERR_INVALID_CURVE;
    }

    // Check whether i ≥ 2^31 (whether the child is a hardened key).
    static constexpr uint32_t hardened_mask = (uint32_t) 1 << 31;

    const modular_ctx modn_ctx = {.modulus = wcurve->n, .len_modulus = wcurve->len_n};

    // using buffer for in-place safety
    bip32_extended_private_key_t parent_buf;
    memcpy(&parent_buf, parent, sizeof(bip32_extended_private_key_t));

    uint8_t I[64];

    uint8_t buf[37];

    if (index & hardened_mask) {
        // If so (hardened child): let I = HMAC-SHA512(Key = c_par, Data = 0x00 || ser_256(k_par) || ser_32(i)).
        // (Note: The 0x00 pads the private key to make it 33 bytes long.)

        buf[0] = 0x00;
        bigint_to_bytes(buf + 1, parent_buf.k, 8);
        bigint_to_bytes(buf + 33, &index, 1);
    } else {
        // If not (normal child): let I = HMAC-SHA512(Key = c_par, Data = ser_P(point(k_par)) || ser_32(i)).

        wcurve_point_t point;
        wcurve_point_scale(wcurve, &point, &wcurve->g, parent_buf.k);

        wcurve_point_compress(wcurve, buf, &point);
        bigint_to_bytes(buf + 33, &index, 1);
    }

    hmac_sha512(I, parent_buf.c, BIP32_KEY_EXTENSION_BYTES, buf, 37);

    // Cleaning up private key from memory (in case hardened key was used)
    basalt_memzero(buf, 37);

    // Split I into two 32-byte sequences, I_L and I_R.
    const uint8_t *I_L = I;
    const uint8_t *I_R= I + 32;

    // The returned child key k_i is parse_256(I_L) + k_par (mod n).
    bytes_to_bigint(child->k, I_L, 32);

    // In case parse256(IL) ≥ n or k_i = 0, the resulting key is invalid, and one should
    // proceed with the next value for i. (Note: this has probability lower than 1 in 2^127.)
    if (bigint_cmp_raw(child->k, 8, wcurve->n, 8) >= 0) {
        return bip32_derive_private(wcurve, child, parent, index + 1);
    }

    modular_add_raw(&modn_ctx, child->k, child->k, 8, parent_buf.k, 8);

    if (bigint_cmp_raw(child->k, 8, nullptr, 0) == 0) {
        return bip32_derive_private(wcurve, child, parent, index + 1);
    }

    // The returned chain code c_i is I_R.
    memcpy(child->c, I_R, 32 * sizeof(uint8_t));

    return BASALT_OK;
}

basalt_err_t bip32_derive_public(
    const wcurve_spec_t *wcurve,
    bip32_extended_public_key_t *child,
    const bip32_extended_public_key_t *parent,
    const uint32_t index)
{
    if (!wcurve || !child || !parent) {
        return BASALT_ERR_NULL_POINTER;
    }

    if (wcurve->len_p != 8 || wcurve->len_n != 8) {
        return BASALT_ERR_INVALID_CURVE;
    }

    static constexpr uint32_t hardened_mask = (uint32_t) 1 << 31;

    // Check whether i ≥ 2^31 (whether the child is a hardened key).
    if (index & hardened_mask) {
        // If so (hardened child): return failure
        return BASALT_ERR_INVALID_PARAM;
    }

    // using buffer for in-place safety
    bip32_extended_public_key_t parent_buf;
    memcpy(&parent_buf, parent, sizeof(bip32_extended_public_key_t));

    // If not (normal child): let I = HMAC-SHA512(Key = c_par, Data = ser_P(K_par) || ser_32(i)).
    uint8_t buf[37];
    wcurve_point_compress(wcurve, buf, &child->K);
    bigint_to_bytes(buf + 33, &index, 1);

    // Split I into two 32-byte sequences, I_L and I_R.
    uint8_t I[64];
    hmac_sha512(I, parent_buf.c, BIP32_KEY_EXTENSION_BYTES, buf, 37);

    const uint8_t *I_L = I;
    const uint8_t *I_R = I + 32;

    // The returned child key K_i is point(parse_256(I_L)) + K_par.
    uint32_t scalar[8];
    bytes_to_bigint(scalar, I_L, 32);

    // In case parse_256(I_L) ≥ n or K_i is the point at infinity, the resulting key is invalid,
    // and one should proceed with the next value for i.
    if (bigint_cmp_raw(scalar, 8, wcurve->n, 8) >= 0) {
        return bip32_derive_public(wcurve, child, parent, index + 1);
    }

    wcurve_point_scale(wcurve, &child->K, &wcurve->g, scalar);
    wcurve_point_add(wcurve, &child->K, &child->K, &parent_buf.K);

    if (child->K.infinity) {
        return bip32_derive_public(wcurve, child, parent, index + 1);
    }

    // The returned chain code c_i is I_R.
    memcpy(child->c, I_R, 32 * sizeof(uint8_t));

    return BASALT_OK;
}

basalt_err_t bip32_derive_private_from_path(
    const wcurve_spec_t *wcurve,
    bip32_extended_private_key_t *child,
    const bip32_extended_private_key_t *parent,
    const uint32_t *path,
    size_t len_path)
{
    if (!wcurve || !child || !parent || !path) {
        return BASALT_ERR_NULL_POINTER;
    }

    bip32_extended_private_key_t temp;
    memcpy(&temp, parent, sizeof(bip32_extended_private_key_t));

    for (; len_path > 0; len_path--) {
        const basalt_err_t status = bip32_derive_private(wcurve, &temp, &temp, *path++);
        if (status != BASALT_OK) {
            return status;
        }
    }

    memcpy(child, &temp, sizeof(bip32_extended_private_key_t));

    return BASALT_OK;
}

basalt_err_t bip32_derive_public_from_path(
    const wcurve_spec_t *wcurve,
    bip32_extended_public_key_t *child,
    const bip32_extended_public_key_t *parent,
    const uint32_t *path,
    size_t len_path)
{
    if (!wcurve || !child || !parent || !path) {
        return BASALT_ERR_NULL_POINTER;
    }

    bip32_extended_public_key_t temp;
    memcpy(&temp, parent, sizeof(bip32_extended_public_key_t));

    for (; len_path > 0; len_path--) {
        const basalt_err_t status = bip32_derive_public(wcurve, &temp, &temp, *path++);
        if (status == BASALT_ERR_INVALID_PARAM) {
            return status;
        }
    }

    memcpy(child, &temp, sizeof(bip32_extended_public_key_t));

    return BASALT_OK;
}