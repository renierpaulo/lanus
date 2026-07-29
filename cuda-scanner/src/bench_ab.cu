/*
 * A/B: caminho de derivacao ORIGINAL vs OTIMIZADO.
 * Valida os dois contra vetores conhecidos e mede a vazao de cada um.
 *
 * build: nvcc -O3 -arch=sm_120 --use_fast_math -o build/bench_ab src/bench_ab.cu
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
#include "pbkdf2_opt.cuh"

#include "sha512_opt.cuh"
#include "pbkdf2_fast.cuh"
#include "secp256k1_fast.cuh"

#define PBKDF2_ITERS 2048
#define MNEM_STRIDE  128

// ===========================================================================
// CAMINHO ORIGINAL
// ===========================================================================
__device__ void ckd_base(const uint8_t* pk, const uint8_t* pcc, uint32_t index,
                         uint8_t* ck, uint8_t* ccc, bool hardened) {
    uint8_t data[37], I[64];
    if (hardened) {
        index |= 0x80000000u;
        data[0] = 0x00;
        memcpy(data + 1, pk, 32);
    } else {
        uint8_t pub[33];
        secp256k1_get_pubkey_compressed(pk, pub);
        memcpy(data, pub, 33);
    }
    data[33] = (index >> 24) & 0xFF; data[34] = (index >> 16) & 0xFF;
    data[35] = (index >>  8) & 0xFF; data[36] = index & 0xFF;
    hmac_sha512(pcc, 32, data, 37, I);
    secp256k1_scalar_add(I, pk, ck);
    memcpy(ccc, I + 32, 32);
}

__device__ void derive_baseline(const uint8_t* mnem, uint32_t mlen, uint8_t* h160) {
    uint8_t seed[64];
    pbkdf2_sha512_mnemonic(mnem, mlen, (const uint8_t*)"mnemonic", 8, PBKDF2_ITERS, seed);

    uint8_t key[32], cc[32], tk[32], tc[32], I[64];
    hmac_sha512((const uint8_t*)"Bitcoin seed", 12, seed, 64, I);
    memcpy(key, I, 32); memcpy(cc, I + 32, 32);

    ckd_base(key, cc, 44, tk, tc, true);  memcpy(key, tk, 32); memcpy(cc, tc, 32);
    ckd_base(key, cc,  0, tk, tc, true);  memcpy(key, tk, 32); memcpy(cc, tc, 32);
    ckd_base(key, cc,  0, tk, tc, true);  memcpy(key, tk, 32); memcpy(cc, tc, 32);
    ckd_base(key, cc,  0, tk, tc, false); memcpy(key, tk, 32); memcpy(cc, tc, 32);
    ckd_base(key, cc,  0, tk, tc, false); memcpy(key, tk, 32);

    uint8_t pub[33], sh[32];
    secp256k1_get_pubkey_compressed(key, pub);
    sha256(pub, 33, sh);
    ripemd160(sh, 32, h160);
}

// ===========================================================================
// CAMINHO OTIMIZADO
// ===========================================================================
__device__ void ckd_fast(const uint8_t* pk, const uint8_t* pcc, uint32_t index,
                         uint8_t* ck, uint8_t* ccc, bool hardened) {
    uint8_t data[37], I[64];
    if (hardened) {
        index |= 0x80000000u;
        data[0] = 0x00;
        #pragma unroll
        for (int i = 0; i < 32; i++) data[1 + i] = pk[i];
    } else {
        uint8_t pub[33];
        secp256k1_pubkey_fast(pk, pub);
        #pragma unroll
        for (int i = 0; i < 33; i++) data[i] = pub[i];
    }
    data[33] = (index >> 24) & 0xFF; data[34] = (index >> 16) & 0xFF;
    data[35] = (index >>  8) & 0xFF; data[36] = index & 0xFF;
    hmac_sha512_fast(pcc, 32, data, 37, I);
    secp256k1_scalar_add(I, pk, ck);
    #pragma unroll
    for (int i = 0; i < 32; i++) ccc[i] = I[32 + i];
}

__device__ void derive_fast(const uint8_t* mnem, uint32_t mlen, uint8_t* h160) {
    uint8_t seed[64];
    pbkdf2_sha512_mnemonic_fast(mnem, mlen, PBKDF2_ITERS, seed);

    uint8_t key[32], cc[32], tk[32], tc[32], I[64];
    hmac_sha512_fast((const uint8_t*)"Bitcoin seed", 12, seed, 64, I);
    #pragma unroll
    for (int i = 0; i < 32; i++) { key[i] = I[i]; cc[i] = I[32 + i]; }

    ckd_fast(key, cc, 44, tk, tc, true);
    #pragma unroll
    for (int i = 0; i < 32; i++) { key[i] = tk[i]; cc[i] = tc[i]; }
    ckd_fast(key, cc, 0, tk, tc, true);
    #pragma unroll
    for (int i = 0; i < 32; i++) { key[i] = tk[i]; cc[i] = tc[i]; }
    ckd_fast(key, cc, 0, tk, tc, true);
    #pragma unroll
    for (int i = 0; i < 32; i++) { key[i] = tk[i]; cc[i] = tc[i]; }
    ckd_fast(key, cc, 0, tk, tc, false);
    #pragma unroll
    for (int i = 0; i < 32; i++) { key[i] = tk[i]; cc[i] = tc[i]; }
    ckd_fast(key, cc, 0, tk, tc, false);
    #pragma unroll
    for (int i = 0; i < 32; i++) key[i] = tk[i];

    uint8_t pub[33], sh[32];
    secp256k1_pubkey_fast(key, pub);
    sha256(pub, 33, sh);
    ripemd160(sh, 32, h160);
}

// ===========================================================================
// Kernels
// ===========================================================================
__global__ void k_verify(const uint8_t* mnems, const uint32_t* lens, int n,
                         uint8_t* out_base, uint8_t* out_fast) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    derive_baseline(mnems + (size_t)i * MNEM_STRIDE, lens[i], out_base + i * 20);
    derive_fast    (mnems + (size_t)i * MNEM_STRIDE, lens[i], out_fast + i * 20);
}

__global__ void k_bench_base(const uint8_t* mnems, const uint32_t* lens, int n, uint8_t* sink) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    uint8_t h[20];
    derive_baseline(mnems + (size_t)i * MNEM_STRIDE, lens[i], h);
    if ((h[0] | h[1]) == 0xFF) sink[i] = h[0];   // impede otimizacao fora
}

__global__ void k_bench_fast(const uint8_t* mnems, const uint32_t* lens, int n, uint8_t* sink) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    uint8_t h[20];
    derive_fast(mnems + (size_t)i * MNEM_STRIDE, lens[i], h);
    if ((h[0] | h[1]) == 0xFF) sink[i] = h[0];
}

// ===========================================================================
static void hex(const uint8_t* b, int n, char* s) {
    for (int i = 0; i < n; i++) sprintf(s + i * 2, "%02x", b[i]);
    s[n * 2] = 0;
}

int main(int argc, char** argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 200000;

    // ---- vetores de teste (conferidos por referencia Python independente) --
    const char* tv[] = {
        "galaxy man boy evil donkey child cross chair egg meat blood space",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    };
    const char* tv_exp[] = {
        "232fb8a4bb0b8be8daeb78d9022d126006309c5c",
        "d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa"
    };
    int NTV = 2;

    // ---- corpus de benchmark: frases reais montadas da wordlist ------------
    char (*wl)[16] = (char(*)[16])malloc(2048 * 16);
    FILE* f = fopen("wordlist.txt", "r");
    if (!f) { printf("ERRO: wordlist.txt nao encontrada (rode de dentro de cuda-scanner/)\n"); return 1; }
    char line[64]; int nw = 0;
    while (nw < 2048 && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        memset(wl[nw], 0, 16); strncpy(wl[nw], line, 15); nw++;
    }
    fclose(f);
    if (nw != 2048) { printf("ERRO: wordlist com %d palavras\n", nw); return 1; }

    int total = N + NTV;
    uint8_t* h_mn = (uint8_t*)calloc((size_t)total * MNEM_STRIDE, 1);
    uint32_t* h_len = (uint32_t*)calloc(total, sizeof(uint32_t));

    for (int i = 0; i < NTV; i++) {
        strcpy((char*)h_mn + (size_t)i * MNEM_STRIDE, tv[i]);
        h_len[i] = strlen(tv[i]);
    }
    srand(12345);
    for (int i = NTV; i < total; i++) {
        char* p = (char*)h_mn + (size_t)i * MNEM_STRIDE;
        int len = 0;
        for (int w = 0; w < 12; w++) {
            const char* word = wl[rand() % 2048];
            if (w) p[len++] = ' ';
            for (int c = 0; word[c]; c++) p[len++] = word[c];
        }
        h_len[i] = len;
    }

    uint8_t *d_mn, *d_ob, *d_of, *d_sink; uint32_t* d_len;
    cudaMalloc(&d_mn, (size_t)total * MNEM_STRIDE);
    cudaMalloc(&d_len, total * sizeof(uint32_t));
    cudaMalloc(&d_ob, (size_t)total * 20);
    cudaMalloc(&d_of, (size_t)total * 20);
    cudaMalloc(&d_sink, total);
    cudaMemcpy(d_mn, h_mn, (size_t)total * MNEM_STRIDE, cudaMemcpyHostToDevice);
    cudaMemcpy(d_len, h_len, total * sizeof(uint32_t), cudaMemcpyHostToDevice);

    cudaDeviceSetLimit(cudaLimitStackSize, 8192);

    // ---- 1. CORRECAO -------------------------------------------------------
    printf("=== CORRECAO ===\n");
    int vN = NTV + 3000;
    k_verify<<<(vN + 127) / 128, 128>>>(d_mn, d_len, vN, d_ob, d_of);
    cudaError_t err = cudaDeviceSynchronize();
    if (err != cudaSuccess) { printf("ERRO kernel: %s\n", cudaGetErrorString(err)); return 1; }

    uint8_t* hb = (uint8_t*)malloc(vN * 20);
    uint8_t* hf = (uint8_t*)malloc(vN * 20);
    cudaMemcpy(hb, d_ob, vN * 20, cudaMemcpyDeviceToHost);
    cudaMemcpy(hf, d_of, vN * 20, cudaMemcpyDeviceToHost);

    char s1[64], s2[64];
    int ok = 1;
    for (int i = 0; i < NTV; i++) {
        hex(hb + i * 20, 20, s1); hex(hf + i * 20, 20, s2);
        int b_ok = (strcmp(s1, tv_exp[i]) == 0), f_ok = (strcmp(s2, tv_exp[i]) == 0);
        printf("  vetor %d  esperado %s\n", i, tv_exp[i]);
        printf("           original %s  %s\n", s1, b_ok ? "OK" : "FALHOU");
        printf("           otimizado %s  %s\n", s2, f_ok ? "OK" : "FALHOU");
        if (!b_ok || !f_ok) ok = 0;
    }
    int diff = 0;
    for (int i = 0; i < vN; i++) if (memcmp(hb + i * 20, hf + i * 20, 20)) diff++;
    printf("  %d frases aleatorias: %d divergencias entre original e otimizado %s\n",
           vN - NTV, diff, diff == 0 ? "[OK]" : "[FALHOU]");
    if (diff) ok = 0;
    if (!ok) { printf("\n!!! CORRECAO FALHOU - nao usar !!!\n"); return 1; }

    // ---- 2. VAZAO ----------------------------------------------------------
    printf("\n=== VAZAO (%d derivacoes/rodada) ===\n", N);
    cudaEvent_t e0, e1; cudaEventCreate(&e0); cudaEventCreate(&e1);
    int thr = 128, blk = (N + thr - 1) / thr;
    float tb = 0, tf = 0;

    k_bench_base<<<blk, thr>>>(d_mn, d_len, N, d_sink); cudaDeviceSynchronize();
    cudaEventRecord(e0);
    for (int r = 0; r < 3; r++) k_bench_base<<<blk, thr>>>(d_mn, d_len, N, d_sink);
    cudaEventRecord(e1); cudaEventSynchronize(e1);
    cudaEventElapsedTime(&tb, e0, e1); tb /= 3.0f;

    k_bench_fast<<<blk, thr>>>(d_mn, d_len, N, d_sink); cudaDeviceSynchronize();
    cudaEventRecord(e0);
    for (int r = 0; r < 3; r++) k_bench_fast<<<blk, thr>>>(d_mn, d_len, N, d_sink);
    cudaEventRecord(e1); cudaEventSynchronize(e1);
    cudaEventElapsedTime(&tf, e0, e1); tf /= 3.0f;

    printf("  ORIGINAL   %8.1f ms   %9.0f deriv/s\n", tb, N / (tb / 1000.0));
    printf("  OTIMIZADO  %8.1f ms   %9.0f deriv/s\n", tf, N / (tf / 1000.0));
    printf("  GANHO      %.2fx\n", tb / tf);
    return 0;
}
