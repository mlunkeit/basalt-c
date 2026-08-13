//
// Created by M Lunkeit on 13.08.26.
//

#ifndef BASALT_SERIAL_H
#define BASALT_SERIAL_H

#include "basalt/keyder.h"

#ifdef __cplusplus
extern "C" {
#endif

basalt_err_t basalt_serialize_raw_private(uint8_t out[78], const basalt_keyder_extended_private_key_t *key);

basalt_err_t basalt_serialize_raw_public(basalt_ec_curve_t curve, uint8_t out[78], const basalt_keyder_extended_public_key_t *key);

basalt_err_t basalt_serialize_b58_private(char *out, const basalt_keyder_extended_private_key_t *key);

basalt_err_t basalt_serialize_b58_public(basalt_ec_curve_t curve, char *out, const basalt_keyder_extended_public_key_t *key);

#ifdef __cplusplus
}
#endif

#endif //BASALT_SERIAL_H
