/*
 * RIPEMD160 implementation for CUDA
 */

#ifndef RIPEMD160_CUH
#define RIPEMD160_CUH

#include <stdint.h>

__device__ __forceinline__ uint32_t rotl32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

__device__ __forceinline__ uint32_t f0(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
__device__ __forceinline__ uint32_t f1(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
__device__ __forceinline__ uint32_t f2(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
__device__ __forceinline__ uint32_t f3(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
__device__ __forceinline__ uint32_t f4(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

__constant__ uint32_t KL[5] = { 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
__constant__ uint32_t KR[5] = { 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

__constant__ uint8_t RL[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

__constant__ uint8_t RR[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

__constant__ uint8_t SL[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

__constant__ uint8_t SR[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

__device__ void ripemd160_transform(uint32_t* state, const uint8_t* block) {
    uint32_t X[16];
    
    #pragma unroll 16
    for (int i = 0; i < 16; i++) {
        X[i] = ((uint32_t)block[i * 4]) |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }
    
    uint32_t al = state[0], bl = state[1], cl = state[2], dl = state[3], el = state[4];
    uint32_t ar = state[0], br = state[1], cr = state[2], dr = state[3], er = state[4];
    
    #pragma unroll 80
    for (int j = 0; j < 80; j++) {
        uint32_t t, f;
        int round = j / 16;
        
        switch (round) {
            case 0: f = f0(bl, cl, dl); break;
            case 1: f = f1(bl, cl, dl); break;
            case 2: f = f2(bl, cl, dl); break;
            case 3: f = f3(bl, cl, dl); break;
            case 4: f = f4(bl, cl, dl); break;
        }
        
        t = rotl32(al + f + X[RL[j]] + KL[round], SL[j]) + el;
        al = el; el = dl; dl = rotl32(cl, 10); cl = bl; bl = t;
        
        switch (round) {
            case 0: f = f4(br, cr, dr); break;
            case 1: f = f3(br, cr, dr); break;
            case 2: f = f2(br, cr, dr); break;
            case 3: f = f1(br, cr, dr); break;
            case 4: f = f0(br, cr, dr); break;
        }
        
        t = rotl32(ar + f + X[RR[j]] + KR[round], SR[j]) + er;
        ar = er; er = dr; dr = rotl32(cr, 10); cr = br; br = t;
    }
    
    uint32_t t = state[1] + cl + dr;
    state[1] = state[2] + dl + er;
    state[2] = state[3] + el + ar;
    state[3] = state[4] + al + br;
    state[4] = state[0] + bl + cr;
    state[0] = t;
}

__device__ void ripemd160(const uint8_t* data, size_t len, uint8_t* hash) {
    uint32_t state[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    
    uint8_t buffer[64];
    size_t buffer_len = 0;
    uint64_t total_len = 0;
    
    while (len >= 64) {
        ripemd160_transform(state, data);
        data += 64;
        len -= 64;
        total_len += 64;
    }
    
    for (size_t i = 0; i < len; i++) {
        buffer[i] = data[i];
    }
    buffer_len = len;
    total_len += len;
    
    buffer[buffer_len++] = 0x80;
    
    if (buffer_len > 56) {
        while (buffer_len < 64) buffer[buffer_len++] = 0;
        ripemd160_transform(state, buffer);
        buffer_len = 0;
    }
    
    while (buffer_len < 56) buffer[buffer_len++] = 0;
    
    uint64_t bit_len = total_len * 8;
    buffer[56] = bit_len & 0xFF;
    buffer[57] = (bit_len >> 8) & 0xFF;
    buffer[58] = (bit_len >> 16) & 0xFF;
    buffer[59] = (bit_len >> 24) & 0xFF;
    buffer[60] = (bit_len >> 32) & 0xFF;
    buffer[61] = (bit_len >> 40) & 0xFF;
    buffer[62] = (bit_len >> 48) & 0xFF;
    buffer[63] = (bit_len >> 56) & 0xFF;
    
    ripemd160_transform(state, buffer);
    
    for (int i = 0; i < 5; i++) {
        hash[i * 4] = state[i] & 0xFF;
        hash[i * 4 + 1] = (state[i] >> 8) & 0xFF;
        hash[i * 4 + 2] = (state[i] >> 16) & 0xFF;
        hash[i * 4 + 3] = (state[i] >> 24) & 0xFF;
    }
}

#endif // RIPEMD160_CUH
