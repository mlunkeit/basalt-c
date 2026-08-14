//
// Created by M Lunkeit on 13.08.26.
//

#ifndef BASALT_SERIAL_H
#define BASALT_SERIAL_H

#include "basalt/keyder.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Converts an extended private key into its serialized form.
 *
 * BIP-32:
 * Extended public and private keys are serialized as follows:
 *
 * - 4 bytes: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
 * - 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
 * - 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
 * - 4 bytes: child number. This is ser_32(i) for i in x_i = x_par/i, with x_i the key being serialized. (0x00000000 if master key)
 * - 32 bytes: the chain code
 * - 33 bytes: the public key or private key data (0x00 || ser_256(k) for private keys)
 *
 * @param[out] out  the output array. requires exactly 78 bytes.
 * @param[in] key   the extended private key.
 *
 * @return the error code, 0 otherwise
 */
basalt_err_t basalt_serialize_raw_extended_private(uint8_t out[78], const basalt_keyder_extended_private_key_t *key);

/**
 * @brief Converts an extended public key into its serialized form.
 *
 * BIP-32:
 * Extended public and private keys are serialized as follows:
 *
 * - 4 bytes: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
 * - 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
 * - 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
 * - 4 bytes: child number. This is ser_32(i) for i in x_i = x_par/i, with x_i the key being serialized. (0x00000000 if master key)
 * - 32 bytes: the chain code
 * - 33 bytes: the public key or private key data (ser_P(K) for public keys)
 *
 * @param[in]   curve   the curve. this parameter is required for public key compression.
 * @param[out]  out     the output array. requires exactly 78 bytes.
 * @param[in]   key     the extended public key.
 *
 * @return the error code, 0 otherwise
 */
basalt_err_t basalt_serialize_raw_extended_public(basalt_ec_curve_t curve, uint8_t out[78], const basalt_keyder_extended_public_key_t *key);

/**
 * @brief Parses a serialized extended private key in its raw form.
 *
 * BIP-32:
 * Extended public and private keys are serialized as follows:
 *
 * - 4 bytes: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
 * - 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
 * - 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
 * - 4 bytes: child number. This is ser_32(i) for i in x_i = x_par/i, with x_i the key being serialized. (0x00000000 if master key)
 * - 32 bytes: the chain code
 * - 33 bytes: the public key or private key data (0x00 || ser_256(k) for private keys)
 *
 * @param[in]   curve   the curve. required for key verification.
 * @param[out]  out     the parsed key.
 * @param[in]   in      the serialized private key.
 *
 * @return the error code, 0 otherwise
 */
basalt_err_t basalt_deserialize_raw_extended_private(basalt_ec_curve_t curve, basalt_keyder_extended_private_key_t *out, const uint8_t in[78]);

/**
 * @brief Parses a serialized extended public key in its raw form.
 *
 * BIP-32:
 * Extended public and private keys are serialized as follows:
 *
 * - 4 bytes: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
 * - 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
 * - 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
 * - 4 bytes: child number. This is ser_32(i) for i in x_i = x_par/i, with x_i the key being serialized. (0x00000000 if master key)
 * - 32 bytes: the chain code
 * - 33 bytes: the public key or private key data (ser_P(K) for public keys)
 *
 * @param[in]   curve   the curve. this parameter is required for public key decompression.
 * @param[out]  out     the parsed key.
 * @param[in]   in      the serialized public key.
 *
 * @return the error code, 0 otherwise
 */
basalt_err_t basalt_deserialize_raw_extended_public(basalt_ec_curve_t curve, basalt_keyder_extended_public_key_t *out, const uint8_t in[78]);

/**
 * @brief Converts an extended private key into its serialized base58 form.
 *
 * This function first converts the private key into its serialized byte form,
 * and then calculates the checksum by applying SHA-256 twice.
 * The 32 most significant bits are then appended to its byte form and then
 * converted to base58.
 *
 * @param[out] out  the output array. requires exactly 111 characters.
 * @param[in] key   the extended private key.
 *
 * @return the error code, 0 otherwise
 */
basalt_err_t basalt_serialize_b58_extended_private(char *out, const basalt_keyder_extended_private_key_t *key);

/**
 * @brief Converts an extended public key into its serialized base58 form.
 *
 * This function first converts the public key into its serialized byte form,
 * and then calculates the checksum by applying SHA-256 twice.
 * The 32 most significant bits are then appended to its byte from and then
 * converted to base58.
 *
 * @param[in] curve the curve. this paramter is required for public key compression.
 * @param[out] out  the output array. requires exactly 78 bytes.
 * @param[in] key   the extended public key.
 * @return
 */
basalt_err_t basalt_serialize_b58_extended_public(basalt_ec_curve_t curve, char *out, const basalt_keyder_extended_public_key_t *key);

/**
 * @brief Parses a serialized extended private key in its base58 form.
 *
 * BIP-32:
 * Extended public and private keys are serialized as follows:
 *
 * - 4 bytes: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
 * - 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
 * - 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
 * - 4 bytes: child number. This is ser_32(i) for i in x_i = x_par/i, with x_i the key being serialized. (0x00000000 if master key)
 * - 32 bytes: the chain code
 * - 33 bytes: the public key or private key data (0x00 || ser_256(k) for private keys)
 *
 * @note        this function also checks the appended base58 fingerprint. it will return BASALT_ERR_INVALID_KEY
 *              if the fingerprint does not match the parsed base58 value.
 *
 * @param[in]   curve   the curve. required for key verification.
 * @param[out]  out     the parsed key.
 * @param[in]   in      the serialized private key.
 *
 * @return the error code, 0 otherwise
 */
basalt_err_t basalt_deserialize_b58_extended_private(basalt_ec_curve_t curve, basalt_keyder_extended_private_key_t *out, const char *in);

/**
 * @brief Parses a serialized extended public key in its base58 form.
 *
 * BIP-32:
 * Extended public and private keys are serialized as follows:
 *
 * - 4 bytes: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
 * - 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
 * - 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
 * - 4 bytes: child number. This is ser_32(i) for i in x_i = x_par/i, with x_i the key being serialized. (0x00000000 if master key)
 * - 32 bytes: the chain code
 * - 33 bytes: the public key or private key data (ser_P(K) for public keys)
 *
 * @note        this function also checks the appended base58 fingerprint. it will return BASALT_ERR_INVALID_KEY
 *              if the fingerprint does not match the parsed base58 value.
 *
 * @param[in]   curve   the curve. this parameter is required for public key decompression.
 * @param[out]  out     the parsed key.
 * @param[in]   in      the serialized public key.
 *
 * @return the error code, 0 otherwise
 */
basalt_err_t basalt_deserialize_b58_extended_public(basalt_ec_curve_t curve, basalt_keyder_extended_public_key_t *out, const char *in);

#ifdef __cplusplus
}
#endif

#endif //BASALT_SERIAL_H
