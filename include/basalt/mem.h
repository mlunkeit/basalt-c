//
// Created by M Lunkeit on 30.07.26.
//

#ifndef BASALT_MEM_H
#define BASALT_MEM_H

#include <stdint.h>
#include <stddef.h>

static void basalt_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--) {
        *p++ = 0;
    }
}

#endif //BASALT_MEM_H
