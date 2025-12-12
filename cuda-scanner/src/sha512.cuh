/*
 * SHA512 implementation for CUDA
 */

#ifndef SHA512_CUH
#define SHA512_CUH

#include <stdint.h>

__constant__ uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// 64-bit rotation using funnel shift (standard intrinsic for CUDA)
__device__ __forceinline__ uint64_t rotr64(uint64_t x, uint32_t n) {
    // NVCC compiles this to a single instruction for constant n
    return (x >> n) | (x << (64 - n));
}

// BSWAP64 for endian conversion - accelerated
__device__ __forceinline__ uint64_t bswap64(uint64_t x) {
    // NVCC optimizes standard shifts to specific hardware instructions
    return (x >> 56) | 
           ((x >> 40) & 0x00FF000000000000ULL) |
           ((x >> 24) & 0x0000FF0000000000ULL) |
           ((x >> 8)  & 0x000000FF00000000ULL) |
           ((x << 8)  & 0x00000000FF000000ULL) |
           ((x << 24) & 0x0000000000FF0000ULL) |
           ((x << 40) & 0x000000000000FF00ULL) |
           (x << 56);
}

__device__ __forceinline__ uint64_t ch64(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}

__device__ __forceinline__ uint64_t maj64(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// Optimized Sigma/Gamma functions using PTX lop3 if possible (compiler handles it)
__device__ __forceinline__ uint64_t sigma0_512(uint64_t x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

__device__ __forceinline__ uint64_t sigma1_512(uint64_t x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

__device__ __forceinline__ uint64_t gamma0_512(uint64_t x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

__device__ __forceinline__ uint64_t gamma1_512(uint64_t x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

__device__ void sha512_transform(uint64_t* state, const uint8_t* block) {
    uint64_t W[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t1, t2;
    
    #pragma unroll 16
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint64_t)block[i * 8] << 56) |
               ((uint64_t)block[i * 8 + 1] << 48) |
               ((uint64_t)block[i * 8 + 2] << 40) |
               ((uint64_t)block[i * 8 + 3] << 32) |
               ((uint64_t)block[i * 8 + 4] << 24) |
               ((uint64_t)block[i * 8 + 5] << 16) |
               ((uint64_t)block[i * 8 + 6] << 8) |
               ((uint64_t)block[i * 8 + 7]);
    }
    
    #pragma unroll 64
    for (int i = 16; i < 80; i++) {
        W[i] = gamma1_512(W[i - 2]) + W[i - 7] + gamma0_512(W[i - 15]) + W[i - 16];
    }
    
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    #pragma unroll 80
    for (int i = 0; i < 80; i++) {
        t1 = h + sigma1_512(e) + ch64(e, f, g) + K512[i] + W[i];
        t2 = sigma0_512(a) + maj64(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ void sha512(const uint8_t* data, size_t len, uint8_t* hash) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    
    uint8_t buffer[128];
    size_t buffer_len = 0;
    uint64_t total_len = 0;
    
    while (len >= 128) {
        sha512_transform(state, data);
        data += 128;
        len -= 128;
        total_len += 128;
    }
    
    for (size_t i = 0; i < len; i++) {
        buffer[i] = data[i];
    }
    buffer_len = len;
    total_len += len;
    
    buffer[buffer_len++] = 0x80;
    
    if (buffer_len > 112) {
        while (buffer_len < 128) buffer[buffer_len++] = 0;
        sha512_transform(state, buffer);
        buffer_len = 0;
    }
    
    while (buffer_len < 112) buffer[buffer_len++] = 0;
    
    uint64_t bit_len = total_len * 8;
    for (int i = 0; i < 8; i++) buffer[112 + i] = 0;
    buffer[120] = (bit_len >> 56) & 0xFF;
    buffer[121] = (bit_len >> 48) & 0xFF;
    buffer[122] = (bit_len >> 40) & 0xFF;
    buffer[123] = (bit_len >> 32) & 0xFF;
    buffer[124] = (bit_len >> 24) & 0xFF;
    buffer[125] = (bit_len >> 16) & 0xFF;
    buffer[126] = (bit_len >> 8) & 0xFF;
    buffer[127] = bit_len & 0xFF;
    
    sha512_transform(state, buffer);
    
    for (int i = 0; i < 8; i++) {
        hash[i * 8] = (state[i] >> 56) & 0xFF;
        hash[i * 8 + 1] = (state[i] >> 48) & 0xFF;
        hash[i * 8 + 2] = (state[i] >> 40) & 0xFF;
        hash[i * 8 + 3] = (state[i] >> 32) & 0xFF;
        hash[i * 8 + 4] = (state[i] >> 24) & 0xFF;
        hash[i * 8 + 5] = (state[i] >> 16) & 0xFF;
        hash[i * 8 + 6] = (state[i] >> 8) & 0xFF;
        hash[i * 8 + 7] = state[i] & 0xFF;
    }
}

__device__ void hmac_sha512(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t* output
) {
    uint8_t k_ipad[128], k_opad[128];
    uint8_t tk[64];
    
    if (key_len > 128) {
        sha512(key, key_len, tk);
        key = tk;
        key_len = 64;
    }
    
    for (int i = 0; i < 128; i++) {
        k_ipad[i] = (i < key_len ? key[i] : 0) ^ 0x36;
        k_opad[i] = (i < key_len ? key[i] : 0) ^ 0x5c;
    }
    
    // Inner hash
    uint8_t inner_data[256];
    memcpy(inner_data, k_ipad, 128);
    memcpy(inner_data + 128, data, data_len);
    
    uint8_t inner_hash[64];
    sha512(inner_data, 128 + data_len, inner_hash);
    
    // Outer hash
    uint8_t outer_data[192];
    memcpy(outer_data, k_opad, 128);
    memcpy(outer_data + 128, inner_hash, 64);
    
    sha512(outer_data, 192, output);
}

__device__ void hmac_sha512_pads(
    const uint8_t* k_ipad,
    const uint8_t* k_opad,
    const uint8_t* data,
    size_t data_len,
    uint8_t* output
) {
    uint8_t inner_data[128 + 64];
    uint8_t inner_hash[64];
    uint8_t outer_data[128 + 64];

    // inner = sha512(k_ipad || data)
    for (int i = 0; i < 128; i++) inner_data[i] = k_ipad[i];
    for (size_t i = 0; i < data_len; i++) inner_data[128 + i] = data[i];
    sha512(inner_data, 128 + data_len, inner_hash);

    // outer = sha512(k_opad || inner_hash)
    for (int i = 0; i < 128; i++) outer_data[i] = k_opad[i];
    for (int i = 0; i < 64; i++) outer_data[128 + i] = inner_hash[i];
    sha512(outer_data, 128 + 64, output);
}

#endif // SHA512_CUH
