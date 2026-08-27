/*
 * keccak256.cuh — Keccak-256 (variante Ethereum, NAO SHA3-256) para device.
 * Padding domain 0x01; ETH addr = KECCAK256(pubkey NAO comprimida)[12..32).
 *
 * Estrutura VALIDADA contra oraculo pycryptodome (vetores "" e "abc"):
 * estado st[x + 5*y]; rho-pi via B[y + 5*((2x+3y)%5)] = rotl(A[x][y], rho);
 * chi em rows-y; iota RC[24]. Msg <= 135 bytes (caso: pubkey).
 */
#ifndef KECCAK256_CUH
#define KECCAK256_CUH

#include <stdint.h>
#include <string.h>

__device__ __forceinline__ uint64_t rotl64_k(uint64_t x, int n) {
    return (x << (n & 63)) | (x >> ((64 - (n & 63)) & 63));
}

__device__ static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
    0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
    0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
    0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
    0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
    0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};

// rho[x][y] oficial da spec
__device__ static const uint64_t KECCAK_RHO[5][5] = {
    { 0,36, 3,41,18},
    { 1,44,10,45, 2},
    {62, 6,43,15,61},
    {28,55,25,21,56},
    {27,20,39, 8,14}
};

__device__ void keccak_f1600(uint64_t st[25]) {
    for (int r = 0; r < 24; r++) {
        // theta
        uint64_t bc[5];
        #pragma unroll
        for (int x = 0; x < 5; x++)
            bc[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20];
        #pragma unroll
        for (int x = 0; x < 5; x++) {
            uint64_t t = bc[(x+4)%5] ^ rotl64_k(bc[(x+1)%5], 1);
            #pragma unroll
            for (int y = 0; y < 5; y++)
                st[x + 5*y] ^= t;
        }
        // rho + pi
        uint64_t B[25];
        #pragma unroll
        for (int x = 0; x < 5; x++)
            #pragma unroll
            for (int y = 0; y < 5; y++)
                B[y + 5*((2*x + 3*y) % 5)] = rotl64_k(st[x + 5*y], (int)KECCAK_RHO[x][y]);
        #pragma unroll
        for (int i = 0; i < 25; i++) st[i] = B[i];
        // chi (por row-y)
        #pragma unroll
        for (int y = 0; y < 5; y++) {
            uint64_t row[5];
            #pragma unroll
            for (int x = 0; x < 5; x++) row[x] = st[y*5+x];
            #pragma unroll
            for (int x = 0; x < 5; x++)
                st[y*5+x] = row[x] ^ (~row[(x+1)%5] & row[(x+2)%5]);
        }
        // iota
        st[0] ^= KECCAK_RC[r];
    }
}

// mensagem <= 135 bytes (uma faixa de absorcao)
__device__ void keccak256(const uint8_t* msg, uint32_t len, uint8_t out[32]) {
    uint64_t st[25];
    memset(st, 0, sizeof(st));
    uint8_t block[136];
    memset(block, 0, sizeof(block));
    memcpy(block, msg, len);
    block[len] ^= 0x01;
    block[135] ^= 0x80;

    #pragma unroll
    for (int i = 0; i < 17; i++) {
        uint64_t v = 0;
        #pragma unroll
        for (int b = 0; b < 8; b++)
            v |= ((uint64_t)block[i*8+b]) << (8*b);
        st[i] = v;
    }

    keccak_f1600(st);

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        uint64_t v = st[i];
        #pragma unroll
        for (int b = 0; b < 8; b++)
            out[i*8+b] = (uint8_t)(v >> (8*b));
    }
}

#endif
