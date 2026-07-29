//
// Created by M Lunkeit on 27.07.26.
//

#ifndef BASALT_ERROR_H
#define BASALT_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BASALT_OK = 0,

    // Parameter errors
    BASALT_ERR_INVALID_PARAM = -0x01,
    BASALT_ERR_UNSUPPORTED_CURVE = -0x02,
    BASALT_ERR_NULL_POINTER = -0x03,

    // Cryptographic / Mathematical errors
    BASALT_ERR_VERIFICATION_FAILED = -0x10,
    BASALT_ERR_INVALID_KEY = -0x11,
    BASALT_ERR_INVALID_SIGNATURE = -0x12,
    BASALT_ERR_DERIVED_KEY_TOO_LONG = -0x13,

    // System errors
} basalt_err_t;

#ifdef __cplusplus
}
#endif

#endif //BASALT_ERROR_H
