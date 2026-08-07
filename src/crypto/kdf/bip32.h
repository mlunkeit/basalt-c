//
// Created by M Lunkeit on 04.08.26.
//

#ifndef BASALT_BIP32_H
#define BASALT_BIP32_H

#include "math/curves/wcurve.h"

#define BIP32_KEY_EXTENSION_BYTES 32

// BIP-32:
// We represent an extended private key as (k, c), with k the normal
// private key, and c the chain code.
typedef struct {
    uint32_t k[WCURVE_MAX_LIMBS];
    uint8_t c[BIP32_KEY_EXTENSION_BYTES];
} extended_private_key_t;

// BIP-32:
// An extended public key is represented as (K, c), with K = point(k)
// and c the chain code.
typedef struct {
    wcurve_point_t K;
    uint8_t c[BIP32_KEY_EXTENSION_BYTES];
} extended_public_key_t;

// BIP-32:
// The function CKDpriv((k_par, c_par), i) → (k_i, c_i) computes a child
// extended private key from the parent extended private key
basalt_err_t bip32_derive_private(
    const wcurve_spec_t *wcurve,
    extended_private_key_t *child,
    const extended_private_key_t *parent,
    uint32_t index
);

// BIP-32:
// The function CKDpub((K_par, c_par), i) → (K_i, c_i) computes a child
// extended public key from the parent extended public key.
// It is only defined for non-hardened child keys.
basalt_err_t bip32_derive_public(
    const wcurve_spec_t *wcurve,
    extended_public_key_t *child,
    const extended_public_key_t *parent,
    uint32_t index
);

#endif //BASALT_BIP32_H
