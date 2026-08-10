//
// Created by M Lunkeit on 04.08.26.
//

#ifndef BASALT_BIP32_H
#define BASALT_BIP32_H

#include "basalt/error.h"
#include "math/curves/wcurve.h"

#define BIP32_KEY_EXTENSION_BYTES 32

// BIP-32:
// We represent an extended private key as (k, c), with k the normal
// private key, and c the chain code.
typedef struct {
    uint32_t k[WCURVE_MAX_LIMBS];
    uint8_t c[BIP32_KEY_EXTENSION_BYTES];
} bip32_extended_private_key_t;

// BIP-32:
// An extended public key is represented as (K, c), with K = point(k)
// and c the chain code.
typedef struct {
    wcurve_point_t K;
    uint8_t c[BIP32_KEY_EXTENSION_BYTES];
} bip32_extended_public_key_t;

// BIP-32:
// The function CKDpriv((k_par, c_par), i) → (k_i, c_i) computes a child
// extended private key from the parent extended private key
basalt_err_t bip32_derive_private(
    const wcurve_spec_t *wcurve,
    bip32_extended_private_key_t *child,
    const bip32_extended_private_key_t *parent,
    uint32_t index
);

// BIP-32:
// The function CKDpub((K_par, c_par), i) → (K_i, c_i) computes a child
// extended public key from the parent extended public key.
// It is only defined for non-hardened child keys.
basalt_err_t bip32_derive_public(
    const wcurve_spec_t *wcurve,
    bip32_extended_public_key_t *child,
    const bip32_extended_public_key_t *parent,
    uint32_t index
);

// BIP-32:
// The next step is cascading several CKD constructions to build a tree.
// We start with one root, the master extended key m.
// By evaluating CKDpriv(m,i) for several values of i, we get a number of level-1 derived nodes.
// As each of these is again an extended key, CKDpriv can be applied to those as well.

// Building the private key tree
basalt_err_t bip32_derive_private_from_path(
    const wcurve_spec_t *wcurve,
    bip32_extended_private_key_t *child,
    const bip32_extended_private_key_t *parent,
    const uint32_t *path,
    size_t len_path
);

// Building the public key tree
basalt_err_t bip32_derive_public_from_path(
    const wcurve_spec_t *wcurve,
    bip32_extended_public_key_t *child,
    const bip32_extended_public_key_t *parent,
    const uint32_t *path,
    size_t len_path
);

#endif //BASALT_BIP32_H
