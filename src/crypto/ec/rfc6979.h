//
// Created by M Lunkeit on 25.07.26.
//

#ifndef BASALT_RFC6979_H
#define BASALT_RFC6979_H

#include <stdint.h>

#include "../../math/bigint.h"

void rfc6979(uint32_t result[8], const uint8_t privkey[32], const uint8_t hash[32], const uint32_t order[8]);

#endif //BASALT_RFC6979_H
