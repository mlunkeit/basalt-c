//
// Created by M Lunkeit on 10.08.26.
//

#include "basalt/mem.h"
#include "basalt/ec.h"
#include "basalt_ec.h"
#include "math/bigint.h"
#include "math/curves/secp256k1.h"
#include "math/curves/secp256r1.h"
#include "math/curves/wcurve_point.h"

basalt_err_t basalt_ec_compress_public(
    const basalt_ec_curve_t curve,
    basalt_ec_compressed_public_key_t *compressed,
    const basalt_ec_public_key_t *decompressed
) {
    if (!compressed || !decompressed) {
        return BASALT_ERR_NULL_POINTER;
    }

    const wcurve_spec_t *wcurve;
    const basalt_err_t err = find_wcurve(&wcurve, curve);
    if (err) {
        return err;
    }

    if (wcurve->len_p != 8) {
        return BASALT_ERR_UNSUPPORTED_CURVE;
    }

    wcurve_point_t decompressed_buf;
    decompressed_buf.infinity = false;
    bytes_to_bigint(decompressed_buf.x, decompressed->x, wcurve->len_p * 4);
    bytes_to_bigint(decompressed_buf.y, decompressed->y, wcurve->len_p * 4);

    return wcurve_point_compress(wcurve, compressed->data, &decompressed_buf);
}

basalt_err_t basalt_ec_decompress_public(
    const basalt_ec_curve_t curve,
    basalt_ec_public_key_t *decompressed,
    const basalt_ec_compressed_public_key_t *compressed)
{
    if (!compressed || !decompressed) {
        return BASALT_ERR_NULL_POINTER;
    }

    const wcurve_spec_t *wcurve;
    basalt_err_t err = find_wcurve(&wcurve, curve);
    if (err) {
        return err;
    }

    if (wcurve->len_p != 8) {
        return BASALT_ERR_UNSUPPORTED_CURVE;
    }

    // check if the criteria p mod 4 = 3 is met
    // p is in little endian, therefore the first uint32 is
    // the most significant one.
    if ((*wcurve->p & 3) != 3) {
        return BASALT_ERR_UNSUPPORTED_CURVE;
    }

    wcurve_point_t decompressed_buf;
    err = wcurve_point_decompress(wcurve, &decompressed_buf, compressed->data);
    if (err) {
        return err;
    }

    bigint_to_bytes(decompressed->x, decompressed_buf.x, wcurve->len_p);
    bigint_to_bytes(decompressed->y, decompressed_buf.y, wcurve->len_p);

    return BASALT_OK;
}

basalt_err_t basalt_ec_calculate_public_key(
    const basalt_ec_curve_t curve,
    basalt_ec_public_key_t *pubkey,
    const basalt_ec_private_key_t *privkey)
{
    if (!pubkey || !privkey) {
        return BASALT_ERR_NULL_POINTER;
    }

    const wcurve_spec_t *wcurve;
    const basalt_err_t err = find_wcurve(&wcurve, curve);
    if (err) {
        return err;
    }

    wcurve_point_t buf;
    uint32_t scalar[wcurve->len_n];
    bytes_to_bigint(scalar, privkey->d, wcurve->len_n * 4);

    if (bigint_cmp_raw(scalar, wcurve->len_n, wcurve->n, wcurve->len_n) >= 0) {
        goto derivation_failed;
    }

    wcurve_point_scale(wcurve, &buf, &wcurve->g, scalar);

    if (buf.infinity) {
        goto derivation_failed;
    }

    bigint_to_bytes(pubkey->x, buf.x, wcurve->len_p);
    bigint_to_bytes(pubkey->y, buf.y, wcurve->len_p);

    basalt_memzero(scalar, wcurve->len_n * sizeof(uint32_t));
    return BASALT_OK;

derivation_failed:
    basalt_memzero(scalar, wcurve->len_n * sizeof(uint32_t));
    return BASALT_ERR_DERIVATION_FAILED;
}

basalt_err_t basalt_ec_verify_public(const basalt_ec_curve_t curve, const basalt_ec_public_key_t *pubkey)
{
    if (!pubkey) {
        return BASALT_ERR_NULL_POINTER;
    }

    const wcurve_spec_t *wcurve;

    const basalt_err_t err = find_wcurve(&wcurve, curve);
    if (err) {
        return err;
    }

    wcurve_point_t point;
    bytes_to_bigint(point.x, pubkey->x, wcurve->len_p);
    bytes_to_bigint(point.y, pubkey->y, wcurve->len_p);
    point.infinity = false;

    return wcurve_point_is_on_curve(wcurve, &point) ? BASALT_OK : BASALT_ERR_INVALID_KEY;
}

basalt_err_t basalt_ec_verify_private(const basalt_ec_curve_t curve, const basalt_ec_private_key_t *privkey)
{
    if (!privkey) {
        return BASALT_ERR_NULL_POINTER;
    }

    const wcurve_spec_t *wcurve;
    const basalt_err_t err = find_wcurve(&wcurve, curve);
    if (err) {
        return err;
    }

    uint32_t scalar[wcurve->len_n];
    bytes_to_bigint(scalar, privkey->d, wcurve->len_n * 4);

    // if 0 < scalar < n then BASALT_OK otherwise BASALT_ERR_INVALID_KEY
    const basalt_err_t status = ((bigint_cmp_raw(scalar, wcurve->len_n, wcurve->n, wcurve->len_n) < 0)
        && (bigint_cmp_raw(scalar, wcurve->len_n, nullptr, 0) > 0))
    ? BASALT_OK : BASALT_ERR_INVALID_KEY;

    // cleanup
    basalt_memzero(scalar, wcurve->len_n * sizeof(uint32_t));

    return status;
}

basalt_err_t find_wcurve(const wcurve_spec_t **out_curve, const basalt_ec_curve_t ec) {
    if (!out_curve) {
        return BASALT_ERR_NULL_POINTER;
    }

    switch (ec) {
        case BASALT_CURVE_SECP256K1:
            *out_curve = &SECP256K1;
            break;
        case BASALT_CURVE_SECP256R1:
            *out_curve = &SECP256R1;
            break;
        default:
            return BASALT_ERR_UNSUPPORTED_CURVE;
    }

    return BASALT_OK;
}