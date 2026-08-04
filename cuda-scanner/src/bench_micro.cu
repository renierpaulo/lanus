/*
 * Profiling por PRIMITIVA. Isola o custo de cada operacao do caminho quente e
 * monta um modelo de custo: quanto cada primitiva custa x quantas vezes roda
 * por candidato. O ncu esta bloqueado no container (ERR_NVGPUCTRPERM), entao
 * a medicao e por cronometragem isolada, que e o que realmente orienta onde
 * mexer.
 *
 * build: nvcc -O3 -arch=sm_120 --use_fast_math -maxrregcount=160 \
 *              -o build/micro src/bench_micro.cu
 */
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha256.cuh"
#include "sha512.cuh"
#include "ripemd160.cuh"
#include "secp256k1.cuh"
#include "sha512_opt.cuh"
#include "pbkdf2_fast.cuh"
#include "secp256k1_fast.cuh"

// ---------------------------------------------------------------- kernels
__global__ void k_sha512c(uint64_t* sink, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint64_t st[8], W[16];
    sha512_init_opt(st);
    for (int i = 0; i < 16; i++) W[i] = 0x0123456789ABCDEFULL ^ (t + i);
    for (uint32_t r = 0; r < reps; r++) { W[0] = st[0]; sha512_compress_opt(st, W); }
    sink[t] = st[0];
}

__global__ void k_pbkdf2(uint64_t* sink, uint32_t n) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint64_t kw[16]; uint8_t out[64];
    for (int i = 0; i < 16; i++) kw[i] = 0x6162636465666768ULL ^ (t * 31 + i);
    pbkdf2_bip39_packed(kw, 2048, out);
    sink[t] = ((uint64_t*)out)[0];
}

__global__ void k_hmac37(uint64_t* sink, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint8_t key[32], data[37], I[64];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(t + i);
    for (int i = 0; i < 37; i++) data[i] = (uint8_t)(i * 7 + t);
    for (uint32_t r = 0; r < reps; r++) { hmac_sha512_fast(key, 32, data, 37, I); key[0] = I[0]; }
    sink[t] = ((uint64_t*)I)[0];
}

__global__ void k_fmul(uint64_t* sink, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint256_t a, b, r;
    for (int i = 0; i < 8; i++) { a.d[i] = 0x9E3779B9u ^ (t + i); b.d[i] = 0x85EBCA6Bu ^ (t * 3 + i); }
    for (uint32_t k = 0; k < reps; k++) { uint256_mod_mul(&r, &a, &b, &SECP256K1_P); a = r; }
    sink[t] = r.d[0];
}

__global__ void k_fsqr(uint64_t* sink, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint256_t a, r;
    for (int i = 0; i < 8; i++) a.d[i] = 0x9E3779B9u ^ (t + i);
    for (uint32_t k = 0; k < reps; k++) { uint256_mod_sqr(&r, &a); a = r; }
    sink[t] = r.d[0];
}

__global__ void k_finv(uint64_t* sink, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint256_t a, r;
    for (int i = 0; i < 8; i++) a.d[i] = 0x9E3779B9u ^ (t + i);
    a.d[7] &= 0x7FFFFFFF;
    for (uint32_t k = 0; k < reps; k++) { fe_inv_chain(&r, &a); a = r; a.d[0] |= 1; }
    sink[t] = r.d[0];
}

__global__ void k_padd(uint64_t* sink, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    jpoint_t P; uint256_t qx, qy;
    gtable_load(0, 0, &qx, &qy);
    P.X = qx; P.Y = qy; uint256_set_one(&P.Z);
    for (uint32_t k = 0; k < reps; k++) {
        gtable_load((int)(k % GT_NWIN), (int)(k % GT_NPT), &qx, &qy);
        jpoint_add_affine(&P, &qx, &qy);
    }
    sink[t] = P.X.d[0];
}

__global__ void k_pubkey(uint64_t* sink, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint8_t priv[32], pub[33];
    for (int i = 0; i < 32; i++) priv[i] = (uint8_t)(t + i * 13);
    priv[0] |= 1;
    for (uint32_t k = 0; k < reps; k++) { secp256k1_pubkey_fast(priv, pub); for (int i = 0; i < 32; i++) priv[i] ^= pub[i + 1]; priv[0] |= 1; }
    sink[t] = pub[1];
}

__global__ void k_hash160(uint64_t* sink, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint8_t pub[33], sh[32], h[20];
    for (int i = 0; i < 33; i++) pub[i] = (uint8_t)(t + i);
    for (uint32_t k = 0; k < reps; k++) { sha256(pub, 33, sh); ripemd160(sh, 32, h); pub[0] = h[0]; }
    sink[t] = h[0];
}

// ---------------------------------------------------------------- host
static float run(void (*launch)(uint64_t*, uint32_t, uint32_t),
                 uint64_t* sink, uint32_t n, uint32_t reps) { return 0; }

#define TIME_KERNEL(K, N, REPS, ...) ({                                    \
    cudaEvent_t _a, _b; cudaEventCreate(&_a); cudaEventCreate(&_b);        \
    K<<<((N)+127)/128, 128>>>(__VA_ARGS__); cudaDeviceSynchronize();        \
    cudaEventRecord(_a);                                                   \
    K<<<((N)+127)/128, 128>>>(__VA_ARGS__);                                 \
    cudaEventRecord(_b); cudaEventSynchronize(_b);                         \
    float _ms; cudaEventElapsedTime(&_ms, _a, _b); _ms; })

struct Row { const char* nome; double ns; double por_cand; };

int main() {
    const uint32_t N = 65536;
    uint64_t* sink; cudaMalloc(&sink, (size_t)N * 8);
    cudaDeviceSetLimit(cudaLimitStackSize, 8192);

    printf("=== PROFILING POR PRIMITIVA (RTX 5090, %u threads) ===\n\n", N);
    printf("%-28s %12s %14s %10s\n", "primitiva", "ns/op", "ops/s", "x por cand");
    printf("%-28s %12s %14s %10s\n", "----------------------------", "------------", "--------------", "----------");

    double tot = 0;
    Row rows[16]; int nr = 0;

    #define MEASURE(K, REPS, NOME, PORCAND) do {                             \
        float ms = TIME_KERNEL(K, N, REPS, sink, N, (uint32_t)(REPS));       \
        double ops = (double)N * (REPS);                                     \
        double ns = ms * 1e6 / ops;                                          \
        double pc = ns * (PORCAND);                                          \
        printf("%-28s %12.2f %14.3e %10.0f\n", NOME, ns, 1e9 / ns * N, (double)(PORCAND)); \
        rows[nr].nome = NOME; rows[nr].ns = ns; rows[nr].por_cand = pc; nr++; \
        tot += pc;                                                           \
    } while (0)

    MEASURE(k_sha512c, 2000, "compressao SHA-512", 4096 + 24);
    MEASURE(k_fmul,    2000, "mult modular 256b", 3 * 700);
    MEASURE(k_fsqr,    2000, "quadrado modular 256b", 3 * 260);
    MEASURE(k_finv,     60,  "inversao modular", 3);
    MEASURE(k_padd,    500,  "adicao de ponto (mista)", 3 * 60);
    MEASURE(k_hash160, 2000, "SHA256+RIPEMD160", 1);
    MEASURE(k_hmac37,  300,  "HMAC-SHA512 (CKD)", 6);

    // PBKDF2 inteiro, para conferir contra o modelo
    float ms_pb = TIME_KERNEL(k_pbkdf2, N, 1, sink, N);
    double ns_pb = ms_pb * 1e6 / N;
    printf("%-28s %12.2f %14s %10d\n", "PBKDF2 completo (2048it)", ns_pb, "-", 1);

    // pubkey inteira, para conferir
    float ms_pk = TIME_KERNEL(k_pubkey, N, 20, sink, N, 20u);
    double ns_pk = ms_pk * 1e6 / ((double)N * 20);
    printf("%-28s %12.2f %14s %10d\n", "chave publica completa", ns_pk, "-", 3);

    printf("\n=== MODELO DE CUSTO POR CANDIDATO (checksum valido) ===\n");
    double medido = ns_pb + 3 * ns_pk;
    printf("  PBKDF2 medido direto ....... %9.0f ns  (%5.1f%%)\n", ns_pb, 100 * ns_pb / medido);
    printf("  3x chave publica medida .... %9.0f ns  (%5.1f%%)\n", 3 * ns_pk, 100 * 3 * ns_pk / medido);
    printf("  TOTAL das duas ............. %9.0f ns\n", medido);
    printf("\n  decomposicao da chave publica:\n");
    printf("    %-24s %9.0f ns/chave\n", "60 adicoes de ponto", rows[4].ns * 60);
    printf("    %-24s %9.0f ns/chave\n", "1 inversao", rows[3].ns);
    printf("    %-24s %9.0f ns/chave  <- soma\n", "", rows[4].ns * 60 + rows[3].ns);
    printf("    %-24s %9.0f ns/chave  <- medido\n", "", ns_pk);

    printf("\n=== ONDE ATACAR (ordem de impacto) ===\n");
    double pb_share = ns_pb / medido;
    printf("  1. PBKDF2 = %.0f%% -> so acelera com SHA-512 mais rapido\n", 100 * pb_share);
    printf("     ganho total se SHA-512 fosse X%% mais rapido:\n");
    for (int g = 10; g <= 30; g += 10)
        printf("       SHA-512 +%d%% -> total %.3fx\n", g, medido / (ns_pb / (1.0 + g / 100.0) + 3 * ns_pk));
    printf("  2. EC = %.0f%% -> teto se ficasse gratis: %.3fx\n",
           100 * (1 - pb_share), medido / ns_pb);
    return 0;
}
