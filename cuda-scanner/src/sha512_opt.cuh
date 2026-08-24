/*
 * SHA-512 otimizado para CUDA (drop-in para o caminho quente do PBKDF2).
 *
 * Diferencas vs sha512.cuh:
 *   1) Janela rolante W[16] no lugar de W[80]  -> 128B em vez de 640B por thread.
 *      Elimina o spill para memoria local e sobe a ocupancia.
 *   2) rotr64 via __funnelshift_r (2 instr) em vez de shift+shift+or (~6).
 *   3) API em uint64_t[8]: sem converter estado para bytes a cada iteracao.
 */

#ifndef SHA512_OPT_CUH
#define SHA512_OPT_CUH

#include <stdint.h>
#include "sha512.cuh"   // reaproveita K512[]

// ---------------------------------------------------------------------------
// Rotacao de 64 bits com funnel shift. n e sempre constante de compilacao aqui,
// entao o if some no compile time.
// ---------------------------------------------------------------------------
__device__ __forceinline__ uint64_t rotr64_fs(uint64_t x, int n) {
    uint32_t lo = (uint32_t)x, hi = (uint32_t)(x >> 32);
    uint32_t rlo, rhi;
    if (n < 32) {
        rlo = __funnelshift_r(lo, hi, n);
        rhi = __funnelshift_r(hi, lo, n);
    } else {
        rlo = __funnelshift_r(hi, lo, n - 32);
        rhi = __funnelshift_r(lo, hi, n - 32);
    }
    return ((uint64_t)rhi << 32) | rlo;
}

__device__ __forceinline__ uint64_t S0o(uint64_t x) { return rotr64_fs(x,28) ^ rotr64_fs(x,34) ^ rotr64_fs(x,39); }
__device__ __forceinline__ uint64_t S1o(uint64_t x) { return rotr64_fs(x,14) ^ rotr64_fs(x,18) ^ rotr64_fs(x,41); }
__device__ __forceinline__ uint64_t s0o(uint64_t x) { return rotr64_fs(x, 1) ^ rotr64_fs(x, 8) ^ (x >> 7); }
__device__ __forceinline__ uint64_t s1o(uint64_t x) { return rotr64_fs(x,19) ^ rotr64_fs(x,61) ^ (x >> 6); }
__device__ __forceinline__ uint64_t Cho(uint64_t x, uint64_t y, uint64_t z) { return z ^ (x & (y ^ z)); }
__device__ __forceinline__ uint64_t Majo(uint64_t x, uint64_t y, uint64_t z) { return (x & y) | (z & (x | y)); }

// Um round. Os papeis giram no call site (sem moves de registrador).
#define RND(a,b,c,d,e,f,g,h,kw)                       \
    {                                                 \
        uint64_t T1 = (h) + S1o(e) + Cho(e,f,g) + (kw); \
        uint64_t T2 = S0o(a) + Majo(a,b,c);           \
        (d) += T1;                                    \
        (h)  = T1 + T2;                               \
    }

// ---------------------------------------------------------------------------
// Compressao de UM bloco de 128 bytes, ja em palavras de 64 bits (big-endian).
// W e copiado para o array local rolante; o chamador nao e modificado.
// ---------------------------------------------------------------------------
__device__ __forceinline__ void sha512_compress_opt(uint64_t* st, const uint64_t* Win) {
    uint64_t w[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) w[i] = Win[i];

    uint64_t a = st[0], b = st[1], c = st[2], d = st[3];
    uint64_t e = st[4], f = st[5], g = st[6], h = st[7];

    // Rounds 0..15 — usa W direto.
    #pragma unroll
    for (int i = 0; i < 16; i += 8) {
        RND(a,b,c,d,e,f,g,h, K512[i+0] + w[i+0]);
        RND(h,a,b,c,d,e,f,g, K512[i+1] + w[i+1]);
        RND(g,h,a,b,c,d,e,f, K512[i+2] + w[i+2]);
        RND(f,g,h,a,b,c,d,e, K512[i+3] + w[i+3]);
        RND(e,f,g,h,a,b,c,d, K512[i+4] + w[i+4]);
        RND(d,e,f,g,h,a,b,c, K512[i+5] + w[i+5]);
        RND(c,d,e,f,g,h,a,b, K512[i+6] + w[i+6]);
        RND(b,c,d,e,f,g,h,a, K512[i+7] + w[i+7]);
    }

    // Rounds 16..79 — expande em janela rolante de 16.
    // (i-2)&15 == (i+14)&15 ; (i-7)&15 == (i+9)&15 ; (i-15)&15 == (i+1)&15
    #pragma unroll
    for (int i = 16; i < 80; i += 16) {
        #pragma unroll
        for (int j = 0; j < 16; j++) {
            w[j] += s1o(w[(j + 14) & 15]) + w[(j + 9) & 15] + s0o(w[(j + 1) & 15]);
        }
        RND(a,b,c,d,e,f,g,h, K512[i+ 0] + w[ 0]);
        RND(h,a,b,c,d,e,f,g, K512[i+ 1] + w[ 1]);
        RND(g,h,a,b,c,d,e,f, K512[i+ 2] + w[ 2]);
        RND(f,g,h,a,b,c,d,e, K512[i+ 3] + w[ 3]);
        RND(e,f,g,h,a,b,c,d, K512[i+ 4] + w[ 4]);
        RND(d,e,f,g,h,a,b,c, K512[i+ 5] + w[ 5]);
        RND(c,d,e,f,g,h,a,b, K512[i+ 6] + w[ 6]);
        RND(b,c,d,e,f,g,h,a, K512[i+ 7] + w[ 7]);
        RND(a,b,c,d,e,f,g,h, K512[i+ 8] + w[ 8]);
        RND(h,a,b,c,d,e,f,g, K512[i+ 9] + w[ 9]);
        RND(g,h,a,b,c,d,e,f, K512[i+10] + w[10]);
        RND(f,g,h,a,b,c,d,e, K512[i+11] + w[11]);
        RND(e,f,g,h,a,b,c,d, K512[i+12] + w[12]);
        RND(d,e,f,g,h,a,b,c, K512[i+13] + w[13]);
        RND(c,d,e,f,g,h,a,b, K512[i+14] + w[14]);
        RND(b,c,d,e,f,g,h,a, K512[i+15] + w[15]);
    }

    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

__device__ __forceinline__ void sha512_init_opt(uint64_t* st) {
    st[0] = 0x6a09e667f3bcc908ULL; st[1] = 0xbb67ae8584caa73bULL;
    st[2] = 0x3c6ef372fe94f82bULL; st[3] = 0xa54ff53a5f1d36f1ULL;
    st[4] = 0x510e527fade682d1ULL; st[5] = 0x9b05688c2b3e6c1fULL;
    st[6] = 0x1f83d9abfb41bd6bULL; st[7] = 0x5be0cd19137e2179ULL;
}

// ---------------------------------------------------------------------------
// Bloco final do HMAC: payload de 64 bytes (8 palavras) + padding, com o
// comprimento total fixo em 192 bytes (1536 bits) — o caso do PBKDF2 aqui.
// Tudo em uint64: nada de converter para bytes.
// ---------------------------------------------------------------------------
__device__ __forceinline__ void sha512_block64_pad192_opt(uint64_t* st, const uint64_t* payload8) {
    uint64_t W[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) W[i] = payload8[i];
    W[8]  = 0x8000000000000000ULL;
    W[9]  = 0; W[10] = 0; W[11] = 0; W[12] = 0; W[13] = 0; W[14] = 0;
    W[15] = 0x0000000000000600ULL;   // 1536 bits
    sha512_compress_opt(st, W);
}

#endif // SHA512_OPT_CUH
