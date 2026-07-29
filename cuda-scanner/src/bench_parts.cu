/* Isola o custo de cada etapa no caminho OTIMIZADO, para saber onde atacar. */
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

#define ITERS 2048
#define STRIDE 128

__global__ void k_pbkdf2(const uint8_t* m, const uint32_t* l, int n, uint8_t* sink) {
    int i = blockIdx.x * blockDim.x + threadIdx.x; if (i >= n) return;
    uint8_t seed[64];
    pbkdf2_sha512_mnemonic_fast(m + (size_t)i * STRIDE, l[i], ITERS, seed);
    if ((seed[0] & seed[1]) == 0xFF) sink[i] = seed[0];
}

__global__ void k_ec3(const uint8_t* m, const uint32_t* l, int n, uint8_t* sink) {
    int i = blockIdx.x * blockDim.x + threadIdx.x; if (i >= n) return;
    uint8_t key[32], pub[33];
    for (int j = 0; j < 32; j++) key[j] = m[(size_t)i * STRIDE + j] | 1;
    #pragma unroll 1
    for (int r = 0; r < 3; r++) {          // 3 pubkeys, como na cadeia BIP32
        secp256k1_pubkey_fast(key, pub);
        for (int j = 0; j < 32; j++) key[j] ^= pub[j + 1];
        key[31] |= 1;
    }
    if ((pub[0] & pub[1]) == 0xFF) sink[i] = pub[0];
}

__global__ void k_hmac5(const uint8_t* m, const uint32_t* l, int n, uint8_t* sink) {
    int i = blockIdx.x * blockDim.x + threadIdx.x; if (i >= n) return;
    uint8_t cc[32], data[37], I[64];
    for (int j = 0; j < 32; j++) cc[j] = m[(size_t)i * STRIDE + j];
    for (int j = 0; j < 37; j++) data[j] = m[(size_t)i * STRIDE + j];
    #pragma unroll 1
    for (int r = 0; r < 6; r++) {          // 1 master + 5 niveis
        hmac_sha512_fast(cc, 32, data, 37, I);
        for (int j = 0; j < 32; j++) cc[j] = I[j];
    }
    if ((I[0] & I[1]) == 0xFF) sink[i] = I[0];
}

int main(int argc, char** argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 200000;
    char (*wl)[16] = (char(*)[16])malloc(2048 * 16);
    FILE* f = fopen("wordlist.txt", "r"); char line[64]; int nw = 0;
    while (nw < 2048 && fgets(line, sizeof(line), f)) { line[strcspn(line,"\r\n")]=0; memset(wl[nw],0,16); strncpy(wl[nw],line,15); nw++; }
    fclose(f);

    uint8_t* h_mn = (uint8_t*)calloc((size_t)N * STRIDE, 1);
    uint32_t* h_len = (uint32_t*)calloc(N, sizeof(uint32_t));
    srand(1);
    for (int i = 0; i < N; i++) {
        char* p = (char*)h_mn + (size_t)i * STRIDE; int len = 0;
        for (int w = 0; w < 12; w++) { const char* s = wl[rand()%2048]; if (w) p[len++]=' '; for (int c=0;s[c];c++) p[len++]=s[c]; }
        h_len[i] = len;
    }
    uint8_t *d_mn, *d_sink; uint32_t* d_len;
    cudaMalloc(&d_mn, (size_t)N*STRIDE); cudaMalloc(&d_len, N*4); cudaMalloc(&d_sink, N);
    cudaMemcpy(d_mn, h_mn, (size_t)N*STRIDE, cudaMemcpyHostToDevice);
    cudaMemcpy(d_len, h_len, N*4, cudaMemcpyHostToDevice);
    cudaDeviceSetLimit(cudaLimitStackSize, 8192);

    cudaEvent_t a,b; cudaEventCreate(&a); cudaEventCreate(&b);
    int thr=128, blk=(N+thr-1)/thr; float t;
    #define TIME(K,label) \
        K<<<blk,thr>>>(d_mn,d_len,N,d_sink); cudaDeviceSynchronize(); \
        cudaEventRecord(a); for(int r=0;r<3;r++) K<<<blk,thr>>>(d_mn,d_len,N,d_sink); \
        cudaEventRecord(b); cudaEventSynchronize(b); cudaEventElapsedTime(&t,a,b); t/=3; \
        printf("  %-22s %8.2f ms\n", label, t);

    printf("=== custo por etapa (caminho otimizado, %d threads) ===\n", N);
    TIME(k_pbkdf2, "PBKDF2 (2048 iter)")
    TIME(k_ec3,    "3x pubkey (EC)")
    TIME(k_hmac5,  "6x HMAC (BIP32)")
    return 0;
}
