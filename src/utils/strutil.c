//
// Created by M Lunkeit on 07.08.26.
//

#include <string.h>

#include "utils/strutil.h"

void strrev(char *str) {
    if (!str || *str == '\0') {
        return;
    }

    char *end = str + strlen(str) - 1;

#define XOR_SWAP(a, b)\
    do {\
        (a) ^= (b);\
        (b) ^= (a);\
        (a) ^= (b);\
    } while (0);\

    while (str < end) {
        XOR_SWAP (*str, *end);
        str++;
        end--;
    }
#undef XOR_SWAP
}