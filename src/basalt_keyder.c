//
// Created by M Lunkeit on 10.08.26.
//

#include <string.h>

#include "basalt_ec.h"
#include "basalt/keyder.h"
#include "crypto/kdf/bip32.h"
#include "crypto/kdf/bip39.h"
#include "math/bigint.h"

basalt_err_t basalt_keyder_generate_mnemonic(char *mnemonic, const uint8_t entropy[BASALT_BIP39_ENTROPY_BYTES]) {

    if (!mnemonic || !entropy) {
        return BASALT_ERR_NULL_POINTER;
    }

    return bip39_generate_mnemonic(mnemonic, entropy, BASALT_BIP39_ENTROPY_BYTES);
}

basalt_err_t basalt_keyder_derive_seed(uint8_t seed[BASALT_BIP39_SEED_BYTES], const char *mnemonic, const char *passphrase) {

    if (!seed || !mnemonic || !passphrase) {
        return BASALT_ERR_NULL_POINTER;
    }

    return bip39_generate_seed(seed, mnemonic, passphrase);
}

basalt_err_t basalt_keyder_derive_master(
    const basalt_ec_curve_t curve,
    basalt_keyder_extended_private_key_t *master,
    const uint8_t seed[BASALT_BIP39_SEED_BYTES])
{

    if (!master || !seed) {
        return BASALT_ERR_NULL_POINTER;
    }

    const wcurve_spec_t* wcurve;
    basalt_err_t err = find_wcurve(&wcurve, curve);
    if (err) {
        return err;
    }

    bip32_extended_private_key_t master_tmp;

    err = bip32_derive_master(wcurve, &master_tmp, seed);
    if (err) {
        return err;
    }

    bigint_to_bytes(master->key.d, master_tmp.k, 8);
    memcpy(master->c, master_tmp.c, 32 * sizeof(uint8_t));

    return BASALT_OK;
}

basalt_err_t basalt_keyder_derive_private(
    const basalt_ec_curve_t curve,
    basalt_keyder_extended_private_key_t *child,
    const basalt_keyder_extended_private_key_t *parent,
    const uint32_t *path, const size_t len_path)
{
    if (!child || !parent || (!path && len_path > 0)) {
        return BASALT_ERR_NULL_POINTER;
    }

    const wcurve_spec_t* wcurve;
    basalt_err_t err = find_wcurve(&wcurve, curve);
    if (err) {
        return err;
    }

    bip32_extended_private_key_t parent_tmp;
    bytes_to_bigint(parent_tmp.k, parent->key.d, 32);
    memcpy(parent_tmp.c, parent->c, 32 * sizeof(uint8_t));

    bip32_extended_private_key_t child_tmp;

    err = bip32_derive_private_from_path(wcurve, &child_tmp, &parent_tmp, path, len_path);
    if (err) {
        return err;
    }

    bigint_to_bytes(child->key.d, child_tmp.k, 8);
    memcpy(child->c, child_tmp.c, 32 * sizeof(uint8_t));
    return BASALT_OK;
}

basalt_err_t basalt_keyder_derive_public(
    const basalt_ec_curve_t curve,
    basalt_keyder_extended_public_key_t *child,
    const basalt_keyder_extended_public_key_t *parent,
    const uint32_t *path, const size_t len_path)
{
    if (!child || !parent || (!path && len_path > 0)) {
        return BASALT_ERR_NULL_POINTER;
    }

    const wcurve_spec_t* wcurve;
    basalt_err_t err = find_wcurve(&wcurve, curve);
    if (err) {
        return err;
    }

    if (wcurve->len_p != 8 || wcurve->len_n != 8) {
        return BASALT_ERR_UNSUPPORTED_CURVE;
    }

    bip32_extended_public_key_t parent_tmp;
    parent_tmp.K.infinity = false;
    bytes_to_bigint(parent_tmp.K.x, parent->key.x, 32);
    bytes_to_bigint(parent_tmp.K.y, parent->key.y, 32);

    bip32_extended_public_key_t child_tmp;

    err = bip32_derive_public_from_path(wcurve, &child_tmp, &parent_tmp, path, len_path);
    if (err) {
        return err;
    }

    bigint_to_bytes(child->key.x, child_tmp.K.x, 8);
    bigint_to_bytes(child->key.y, child_tmp.K.y, 8);
    memcpy(child->c, child_tmp.c, 32 * sizeof(uint8_t));

    return BASALT_OK;
}