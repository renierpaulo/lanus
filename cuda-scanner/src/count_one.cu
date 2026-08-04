/*
 * Kernels minimos para CONTAR instrucoes por parte do SHA-512.
 * Compilar com -cubin e contar o SASS de cada um da o orcamento exato:
 *   k_one      = 1 compressao inteira
 *   k_rounds   = so os 80 rounds (schedule substituido por leitura direta)
 *   k_sched    = so a expansao do message schedule
 * A diferenca isola quanto custa cada metade e onde vale cortar.
 */
#include <cuda_runtime.h>
#include <stdint.h>
#include "sha512.cuh"
#include "sha512_opt.cuh"

__global__ void k_one(uint64_t* io) {
    uint64_t st[8], W[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) st[i] = io[i];
    #pragma unroll
    for (int i = 0; i < 16; i++) W[i] = io[8 + i];
    sha512_compress_opt(st, W);
    #pragma unroll
    for (int i = 0; i < 8; i++) io[i] = st[i];
}

// So os 80 rounds: w[] vem pronto da memoria, sem expansao.
__global__ void k_rounds(uint64_t* io) {
    uint64_t w[80];
    #pragma unroll
    for (int i = 0; i < 80; i++) w[i] = io[i];
    uint64_t a = io[80], b = io[81], c = io[82], d = io[83];
    uint64_t e = io[84], f = io[85], g = io[86], h = io[87];
    #pragma unroll
    for (int i = 0; i < 80; i += 8) {
        RND(a,b,c,d,e,f,g,h, K512[i+0] + w[i+0]);
        RND(h,a,b,c,d,e,f,g, K512[i+1] + w[i+1]);
        RND(g,h,a,b,c,d,e,f, K512[i+2] + w[i+2]);
        RND(f,g,h,a,b,c,d,e, K512[i+3] + w[i+3]);
        RND(e,f,g,h,a,b,c,d, K512[i+4] + w[i+4]);
        RND(d,e,f,g,h,a,b,c, K512[i+5] + w[i+5]);
        RND(c,d,e,f,g,h,a,b, K512[i+6] + w[i+6]);
        RND(b,c,d,e,f,g,h,a, K512[i+7] + w[i+7]);
    }
    io[0] = a + b + c + d + e + f + g + h;
}

// So a expansao do schedule (64 passos), sem rounds.
__global__ void k_sched(uint64_t* io) {
    uint64_t w[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) w[i] = io[i];
    #pragma unroll
    for (int i = 16; i < 80; i += 16) {
        #pragma unroll
        for (int j = 0; j < 16; j++)
            w[j] += s1o(w[(j + 14) & 15]) + w[(j + 9) & 15] + s0o(w[(j + 1) & 15]);
    }
    uint64_t s = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) s ^= w[i];
    io[0] = s;
}

// So as funcoes Sigma (2 por round x 80), para isolar o custo das rotacoes.
__global__ void k_sigma(uint64_t* io) {
    uint64_t x = io[0], acc = 0;
    #pragma unroll
    for (int i = 0; i < 80; i++) { acc ^= S0o(x) ^ S1o(x); x += acc; }
    io[0] = acc;
}

int main() { return 0; }
