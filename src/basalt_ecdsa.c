//
// Created by M Lunkeit on 27.07.26.
//

#include "basalt/ecdsa.h"
#include "basalt/mem.h"

#include "basalt_ec.h"
#include "crypto/ec/ecdsa.h"
#include "math/bigint.h"
#include "math/curves/wcurve.h"

basalt_err_t basalt_ecdsa_sign(
    const basalt_ec_curve_t curve,
    basalt_ecdsa_signature_t *sig,
    const basalt_ec_private_key_t *key,
    const uint8_t *hash, const size_t len_hash)
{
    if (!sig || !key || !hash) {
        return BASALT_ERR_NULL_POINTER;
    }

    const wcurve_spec_t *wcurve;

    const basalt_err_t status = find_wcurve(&wcurve, curve);
    if (status != BASALT_OK) {
        return status;
    }

    uint32_t d[wcurve->len_n];
    bytes_to_bigint(d, key->d, wcurve->len_n);

    uint32_t r[wcurve->len_n];
    uint32_t s[wcurve->len_n];
    ecdsa_sign(wcurve, r, s, d, hash, len_hash);

    bigint_to_bytes(sig->r, r, wcurve->len_n);
    bigint_to_bytes(sig->s, s, wcurve->len_n);

    // clearing the private key from memory
    basalt_memzero(d, wcurve->len_n * sizeof(uint32_t));

    return BASALT_OK;
}

basalt_err_t basalt_ecdsa_verify(
    const basalt_ec_curve_t curve,
    const basalt_ec_public_key_t *key,
    const uint8_t *hash, const size_t len_hash,
    const basalt_ecdsa_signature_t *sig)
{
    if (!curve || !key || !hash || !sig) {
        return BASALT_ERR_NULL_POINTER;
    }

    const wcurve_spec_t *wcurve;

    const basalt_err_t status = find_wcurve(&wcurve, curve);
    if (status != BASALT_OK) {
        return status;
    }

    wcurve_point_t point;
    bytes_to_bigint(point.x, key->x, wcurve->len_p * 4);
    bytes_to_bigint(point.y, key->y, wcurve->len_p * 4);

    uint32_t r[wcurve->len_n];
    uint32_t s[wcurve->len_n];
    bytes_to_bigint(r, sig->r, wcurve->len_n * 4);
    bytes_to_bigint(s, sig->s, wcurve->len_n * 4);

    if (!ecdsa_verify(wcurve, &point, hash, len_hash, r, s)) {
        return BASALT_ERR_INVALID_SIGNATURE;
    }

    return BASALT_OK;
}