//
// Created by M Lunkeit on 27.07.26.
//

#include "basalt/ecdsa.h"

#include "crypto/ec/ecdsa.h"
#include "math/bigint.h"
#include "math/curves/wcurve.h"
#include "math/curves/secp256k1.h"
#include "math/curves/secp256r1.h"

basalt_err_t basalt_ecdsa_sign(
    const basalt_ecdsa_curve_t curve,
    basalt_ecdsa_signature_t *sig,
    const basalt_ecdsa_private_key_t *key,
    const uint8_t *hash, size_t len_hash)
{
    if (!sig || !key || !hash) {
        return BASALT_ERR_NULL_POINTER;
    }

    const wcurve_spec_t *wcurve;

    switch (curve) {
        case BASALT_CURVE_SECP256K1:
            wcurve = &SECP256K1;
            break;
        case BASALT_CURVE_SECP256R1:
            wcurve = &SECP256R1;
            break;
        default:
            wcurve = nullptr;
            break;
    }

    if (!wcurve) {
        return BASALT_ERR_UNSUPPORTED_CURVE;
    }

    uint32_t d[wcurve->len_n];
    bytes_to_bigint(d, key->d, wcurve->len_n);

    uint32_t r[wcurve->len_n];
    uint32_t s[wcurve->len_n];
    ecdsa_sign(wcurve, r, s, d, hash, len_hash);

    bigint_to_bytes(sig->r, r, wcurve->len_n);
    bigint_to_bytes(sig->s, s, wcurve->len_n);

    return BASALT_OK;
}
