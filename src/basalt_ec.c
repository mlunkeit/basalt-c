//
// Created by M Lunkeit on 10.08.26.
//

#include "basalt/ec.h"
#include "basalt_ec.h"
#include "math/bigint.h"
#include "math/curves/secp256k1.h"
#include "math/curves/secp256r1.h"
#include "math/curves/wcurve_point.h"

basalt_err_t basalt_ec_compress_public_key(
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
    bytes_to_bigint(decompressed_buf.x, decompressed->x, wcurve->len_p * 4);
    bytes_to_bigint(decompressed_buf.y, decompressed->y, wcurve->len_p * 4);

    return wcurve_point_compress(wcurve, compressed->data, &decompressed_buf);
}

basalt_err_t basalt_ec_decompress_public_key(
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