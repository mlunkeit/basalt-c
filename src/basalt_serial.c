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

basalt_err_t basalt_serialize_raw_extended_private(uint8_t out[78], const basalt_keyder_extended_private_key_t *key) {
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

basalt_err_t basalt_serialize_raw_extended_public(const basalt_ec_curve_t curve, uint8_t out[78], const basalt_keyder_extended_public_key_t *key) {
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
    basalt_ec_compressed_public_key_t compressed;
    basalt_err_t err = basalt_ec_compress_public(curve, &compressed, &key->key);
    if (err) {
        return err;
    }
    memcpy(out + 45, compressed.data, 33);

    return BASALT_OK;
}

basalt_err_t basalt_deserialize_raw_extended_private(
    const basalt_ec_curve_t curve,
    basalt_keyder_extended_private_key_t *out,
    const uint8_t in[78])
{
    if (!out || !in) {
        return BASALT_ERR_NULL_POINTER;
    }

    bytes_to_bigint(&out->version, in, 4);
    out->depth = in[4];
    bytes_to_bigint(&out->parent_fingerprint, in + 5, 4);
    bytes_to_bigint(&out->child_number, in + 9, 4);

    // chain code
    memcpy(out->c, in + 13, 32);

    // private key
    if (in[45] != 0x00) {
        return BASALT_ERR_INVALID_KEY;
    }

    memcpy(out->key.d, in + 46, 32);
    if (basalt_ec_verify_private(curve, &out->key)) {
        return BASALT_ERR_INVALID_KEY;
    }

    return BASALT_OK;
}

basalt_err_t basalt_deserialize_raw_extended_public(
    const basalt_ec_curve_t curve,
    basalt_keyder_extended_public_key_t *out,
    const uint8_t in[78])
{
    if (!out || !in) {
        return BASALT_ERR_NULL_POINTER;
    }

    bytes_to_bigint(&out->version, in, 4);
    out->depth = in[4];
    bytes_to_bigint(&out->parent_fingerprint, in + 5, 4);
    bytes_to_bigint(&out->child_number, in + 9, 4);

    memcpy(out->c, in + 13, 32);

    basalt_ec_compressed_public_key_t compressed;
    memcpy(compressed.data, in + 45, 32);

    // public key doesn't have to be verified as decompression
    // always produces a valid public key.
    return basalt_ec_decompress_public(curve, &out->key, &compressed);
}

basalt_err_t basalt_serialize_b58_extended_private(char *out, const basalt_keyder_extended_private_key_t *key) {
    uint8_t serialized[110];
    basalt_err_t err = basalt_serialize_raw_extended_private(serialized, key);
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

basalt_err_t basalt_serialize_b58_extended_public(const basalt_ec_curve_t curve, char *out, const basalt_keyder_extended_public_key_t *key) {
    uint8_t serialized[110];
    const basalt_err_t err = basalt_serialize_raw_extended_public(curve, serialized, key);
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

basalt_err_t basalt_deserialize_b58_extended_private(const basalt_ec_curve_t curve, basalt_keyder_extended_private_key_t *out, const char *in) {
    if (!out || !in) {
        return BASALT_ERR_NULL_POINTER;
    }

    uint8_t raw[82];
    size_t written;
    const basalt_err_t err = base58_decode(raw, &written, in);

    if (err) {
        return err;
    }

    if (written != 82) {
        return BASALT_ERR_INVALID_KEY;
    }

    uint8_t hash[32];
    sha256(hash, raw, 78);
    sha256(hash, hash, 32);

    // check if 32 most significant bits match
    uint8_t diff = 0;
    for (size_t i = 0; i < 4; i++) {
        diff |= raw[78 + i] ^ hash[i];
    }

    if (diff) {
        return BASALT_ERR_INVALID_KEY;
    }

    return basalt_deserialize_raw_extended_private(curve, out, raw);
}

basalt_err_t basalt_deserialize_b58_extended_public(const basalt_ec_curve_t curve, basalt_keyder_extended_public_key_t *out, const char *in) {
    if (!out || !in) {
        return BASALT_ERR_NULL_POINTER;
    }

    uint8_t raw[82];
    size_t written;
    const basalt_err_t err = base58_decode(raw, &written, in);

    if (err) {
        return err;
    }

    if (written != 82) {
        return BASALT_ERR_INVALID_KEY;
    }

    uint8_t hash[32];
    sha256(hash, raw, 78);
    sha256(hash, hash, 32);

    uint8_t diff = 0;
    for (size_t i = 0; i < 4; i++) {
        diff |= raw[78 + i] ^ hash[i];
    }

    if (diff) {
        return BASALT_ERR_INVALID_KEY;
    }

    return basalt_deserialize_raw_extended_public(curve, out, raw);
}