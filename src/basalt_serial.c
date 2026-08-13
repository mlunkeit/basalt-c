//
// Created by M Lunkeit on 13.08.26.
//

#include <string.h>

#include "basalt/mem.h"
#include "basalt/serial.h"
#include "basalt/ec.h"
#include "math/bigint.h"
#include "crypto/hash/sha256.h"
#include "crypto/codec/base58.h"

basalt_err_t basalt_serialize_raw_private(uint8_t out[78], const basalt_keyder_extended_private_key_t *key) {
    if (!out || !key) {
        return BASALT_ERR_NULL_POINTER;
    }

    // 4 bytes: version bytes
    bigint_to_bytes(out, &key->version, 1);
    // 1 byte: depth
    out[4] = key->depth;
    // 4 bytes: the fingerprint of the parent's key
    bigint_to_bytes(out + 5, &key->parent_fingerprint, 1);
    // 4 bytes: child number
    bigint_to_bytes(out + 9, &key->child_number, 1);

    // 32 bytes: the chain code
    memcpy(out + 13, key->c, 32);

    // 33 bytes: the public key or private key data (0x00 || ser_256(k) for private keys)
    out[45] = 0;
    memcpy(out + 46, key->key.d, 32);

    return BASALT_OK;
}

basalt_err_t basalt_serialize_raw_public(const basalt_ec_curve_t curve, uint8_t out[78], const basalt_keyder_extended_public_key_t *key) {
    if (!out || !key) {
        return BASALT_ERR_NULL_POINTER;
    }

    // 4 bytes: version bytes
    bigint_to_bytes(out, &key->version, 1);
    // 1 byte: depth
    out[4] = key->depth;
    // 4 bytes: the fingerprint of the parent's key
    bigint_to_bytes(out + 5, &key->parent_fingerprint, 1);
    // 4 bytes: child number
    bigint_to_bytes(out + 9, &key->child_number, 1);

    // 32 bytes: the chain code
    memcpy(out + 13, key->c, 32);

    // 33 bytes: the public key or private key data (ser_P(K) for public keys)
    basalt_ec_compressed_public_key_t compressed = {0};
    basalt_err_t err = basalt_ec_compress_public_key(curve, &compressed, &key->key);
    if (err) {
        return err;
    }
    memcpy(out + 45, compressed.data, 33);

    return BASALT_OK;
}

basalt_err_t basalt_serialize_b58_private(char *out, const basalt_keyder_extended_private_key_t *key) {
    uint8_t serialized[110];
    basalt_err_t err = basalt_serialize_raw_private(serialized, key);
    if (err) {
        return err;
    }

    // BIP-32: This 78 byte structure can be encoded like other Bitcoin data in Base58,
    // by first adding 32 checksum bits (derived from the double SHA-256 checksum),
    // and then converting to the Base58 representation.
    sha256(serialized + 78, serialized, 78);
    sha256(serialized + 78, serialized + 78, 32);

    err = base58_encode(out, serialized, 82);
    if (err) {
        return err;
    }

    basalt_memzero(serialized, 82);
    return BASALT_OK;
}

basalt_err_t basalt_serialize_b58_public(const basalt_ec_curve_t curve, char *out, const basalt_keyder_extended_public_key_t *key) {
    uint8_t serialized[110];
    const basalt_err_t err = basalt_serialize_raw_public(curve, serialized, key);
    if (err) {
        return err;
    }

    // BIP-32: This 78 byte structure can be encoded like other Bitcoin data in Base58,
    // by first adding 32 checksum bits (derived from the double SHA-256 checksum),
    // and then converting to the Base58 representation.
    sha256(serialized + 78, serialized, 78);
    sha256(serialized + 78, serialized + 78, 32);

    return base58_encode(out, serialized, 82);
}