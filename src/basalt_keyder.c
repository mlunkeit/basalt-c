//
// Created by M Lunkeit on 10.08.26.
//

#include <string.h>

#include "basalt_ec.h"
#include "basalt/keyder.h"
#include "crypto/kdf/bip32.h"
#include "crypto/kdf/bip39.h"
#include "crypto/hash/sha256.h"
#include "crypto/hash/ripemd160.h"
#include "math/bigint.h"
#include "math/curves/wcurve_point.h"

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

    if (len_path == 0) {
        if (parent != child) {
            memcpy(child, parent, sizeof(basalt_keyder_extended_private_key_t));
        }
        return BASALT_OK;
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

    err = bip32_derive_private_from_path(wcurve, &child_tmp, &parent_tmp, path, len_path - 1);
    if (err) {
        return err;
    }

    // BIP-32:
    // Extended keys can be identified by the Hash160 (RIPEMD160 after SHA256)
    // of the serialized ECDSA public key K, ignoring the chain code.

    // calculate the compressed public key
    wcurve_point_t public_raw;
    wcurve_point_scale(wcurve, &public_raw, &wcurve->g, child_tmp.k);
    uint8_t compressed[33];
    wcurve_point_compress(wcurve, compressed, &public_raw);

    uint8_t sha256hash[32];
    sha256(sha256hash, compressed, 33);
    uint8_t hash160[20];
    ripemd160(hash160, sha256hash, 32);

    err = bip32_derive_private(wcurve, &child_tmp, &child_tmp, path[len_path - 1]);
    if (err) {
        return err;
    }

    child->version = parent->version;
    child->depth = parent->depth + len_path;
    bytes_to_bigint(&child->parent_fingerprint, hash160, 4);
    child->child_number = path[len_path - 1];
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

    if (len_path == 0) {
        if (parent != child) {
            memcpy(child, parent, sizeof(basalt_keyder_extended_public_key_t));
        }
        return BASALT_OK;
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
    memcpy(parent_tmp.c, parent->c, 32 * sizeof(uint8_t));

    bip32_extended_public_key_t child_tmp;

    err = bip32_derive_public_from_path(wcurve, &child_tmp, &parent_tmp, path, len_path - 1);
    if (err) {
        return err;
    }

    uint8_t compressed[33];
    wcurve_point_compress(wcurve, compressed, &child_tmp.K);

    uint8_t sha256hash[32];
    sha256(sha256hash, compressed, 33);
    uint8_t hash160[20];
    ripemd160(hash160, sha256hash, 32);

    err = bip32_derive_public(wcurve, &child_tmp, &child_tmp, path[len_path - 1]);
    if (err) {
        return err;
    }

    child->version = parent->version;
    child->depth = parent->depth + len_path;
    bytes_to_bigint(&child->parent_fingerprint, hash160, 4);
    child->child_number = path[len_path - 1];
    bigint_to_bytes(child->key.x, child_tmp.K.x, 8);
    bigint_to_bytes(child->key.y, child_tmp.K.y, 8);
    memcpy(child->c, child_tmp.c, 32 * sizeof(uint8_t));

    return BASALT_OK;
}