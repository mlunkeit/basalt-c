//
// Created by M Lunkeit on 23.07.26.
//

#include <string.h>

#include "sha256.h"

#define SHR(n, x) ((x) >> (n))
#define ROTR(n, x) (((x) >> (n)) | ((x) << (32 - (n))))

#define CH(x, y, z) ((x & y) ^ (~(x) & (z)))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define EP0(x) (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x))
#define EP1(x) (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x))
#define SIG0(x) (ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x))
#define SIG1(x) (ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x))

static constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static constexpr uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

size_t sha256_pad(uint32_t *output, const uint8_t *input, const size_t len) {
    const size_t blocks = 1 + (len >> 6) + (len % 64 >= 56 ? 1 : 0);

    uint8_t buf[blocks * 64];
    memset(buf, 0, blocks * 64 * sizeof(uint8_t));
    memcpy(buf, input, len * sizeof(uint8_t));
    memset(buf + len, 0x80, sizeof(uint8_t));

    const size_t bitlen = len << 3;

    for (size_t i = 0; i < 8; i++) {
        buf[blocks * 64 - i - 1] = (uint8_t) (bitlen >> (i * 8));
    }

    for (size_t i = 0; i < blocks * 16; i++) {
        output[i] = (buf[i * 4] << 24
            | (buf[i * 4 + 1] << 16)
            | (buf[i * 4 + 2] << 8)
            | (buf[i * 4 + 3]));
    }

    return blocks;
}

void sha256(uint8_t output[32], const uint8_t *input, const size_t len) {
    const size_t blocks = 1 + (len >> 6) + (len % 64 >= 56 ? 1 : 0);

    uint32_t buf[blocks * 16];
    sha256_pad(buf, input, len);

    uint32_t H[8];
    memcpy(H, H0, 8 * sizeof(uint32_t));

    for (size_t i = 0; i < blocks; i++) {
        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        uint32_t f = H[5];
        uint32_t g = H[6];
        uint32_t h = H[7];

        uint32_t W[64];

        for (size_t t = 0; t < 64; t++) {
            if (t < 16) {
                W[t] = buf[i * 16 + t];
            } else {
                W[t] = SIG1(W[t - 2]) + W[t - 7] + SIG0(W[t - 15]) + W[t - 16];
            }

            uint32_t T1 = h + EP1(e) + CH(e, f, g) + K[t] + W[t];
            uint32_t T2 = EP0(a) + MAJ(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    for (size_t i = 0; i < 8; i++) {
        output[i * 4 + 0] = H[i] >> 24;
        output[i * 4 + 1] = H[i] >> 16;
        output[i * 4 + 2] = H[i] >> 8;
        output[i * 4 + 3] = H[i];
    }
}