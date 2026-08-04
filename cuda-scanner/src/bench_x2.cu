/*
 * A/B do PBKDF2: 1 corrente por thread (atual) vs 2 correntes intercaladas (ILP).
 * Verifica que as saidas sao IDENTICAS e mede a vazao, varrendo o tamanho de bloco.
 *
 * build: nvcc -O3 -arch=sm_120 --use_fast_math -Xptxas -v -o build/bench_x2 src/bench_x2.cu
 */
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha512.cuh"
#include "sha512_opt.cuh"
#include "pbkdf2_fast.cuh"
#include "pbkdf2_x2.cuh"

#define ITERS  2048
#define STRIDE 128

__global__ void k_x1(const uint8_t* m, const uint32_t* l, uint32_t n, uint8_t* out) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    pbkdf2_sha512_mnemonic_fast(m + (size_t)i * STRIDE, l[i], ITERS, out + (size_t)i * 64);
}

__global__ void k_x2(const uint8_t* m, const uint32_t* l, uint32_t n, uint8_t* out) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t i = t * 2, j = i + 1;
    if (j >= n) return;
    pbkdf2_bip39_x2(m + (size_t)i * STRIDE, l[i], out + (size_t)i * 64,
                    m + (size_t)j * STRIDE, l[j], out + (size_t)j * 64, ITERS);
}

// ILP de 2 vias com os midstates em shared. Shared dinamica:
// 32 * blockDim.x uint64.
__global__ void k_x2s(const uint8_t* m, const uint32_t* l, uint32_t n, uint8_t* out) {
    extern __shared__ uint64_t sm[];
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t i = t * 2, j = i + 1;
    if (j >= n) return;
    pbkdf2_bip39_x2_smem(m + (size_t)i * STRIDE, l[i], out + (size_t)i * 64,
                         m + (size_t)j * STRIDE, l[j], out + (size_t)j * 64,
                         ITERS, sm, threadIdx.x, blockDim.x);
}

int main(int argc, char** argv) {
    uint32_t N = (argc > 1) ? (uint32_t)atoi(argv[1]) : 200000;
    N &= ~1u;   // par, para o x2

    char (*wl)[16] = (char(*)[16])malloc(2048 * 16);
    FILE* f = fopen("wordlist.txt", "r");
    if (!f) { printf("ERRO: rode de dentro de cuda-scanner/\n"); return 1; }
    char ln[64]; int nw = 0;
    while (nw < 2048 && fgets(ln, sizeof(ln), f)) {
        ln[strcspn(ln, "\r\n")] = 0; memset(wl[nw], 0, 16); strncpy(wl[nw], ln, 15); nw++;
    }
    fclose(f);

    uint8_t* h_mn = (uint8_t*)calloc((size_t)N * STRIDE, 1);
    uint32_t* h_len = (uint32_t*)calloc(N, 4);
    srand(99);
    for (uint32_t i = 0; i < N; i++) {
        char* p = (char*)h_mn + (size_t)i * STRIDE; int len = 0;
        for (int w = 0; w < 12; w++) {
            const char* s = wl[rand() % 2048];
            if (w) p[len++] = ' ';
            for (int c = 0; s[c]; c++) p[len++] = s[c];
        }
        h_len[i] = len;
    }

    uint8_t *d_mn, *d_o1, *d_o2; uint32_t* d_len;
    cudaMalloc(&d_mn, (size_t)N * STRIDE); cudaMalloc(&d_len, (size_t)N * 4);
    cudaMalloc(&d_o1, (size_t)N * 64);     cudaMalloc(&d_o2, (size_t)N * 64);
    cudaMemcpy(d_mn, h_mn, (size_t)N * STRIDE, cudaMemcpyHostToDevice);
    cudaMemcpy(d_len, h_len, (size_t)N * 4, cudaMemcpyHostToDevice);
    cudaDeviceSetLimit(cudaLimitStackSize, 8192);

    // ---- correcao: as duas versoes tem que dar exatamente a mesma seed ----
    printf("=== CORRECAO ===\n");
    uint32_t V = 4096;
    k_x1<<<(V + 127) / 128, 128>>>(d_mn, d_len, V, d_o1);
    k_x2<<<(V / 2 + 127) / 128, 128>>>(d_mn, d_len, V, d_o2);
    cudaError_t e = cudaDeviceSynchronize();
    if (e != cudaSuccess) { printf("ERRO CUDA: %s\n", cudaGetErrorString(e)); return 1; }
    uint8_t* a = (uint8_t*)malloc((size_t)V * 64);
    uint8_t* b = (uint8_t*)malloc((size_t)V * 64);
    cudaMemcpy(a, d_o1, (size_t)V * 64, cudaMemcpyDeviceToHost);
    cudaMemcpy(b, d_o2, (size_t)V * 64, cudaMemcpyDeviceToHost);
    uint32_t diff = 0;
    for (uint32_t i = 0; i < V; i++) if (memcmp(a + (size_t)i * 64, b + (size_t)i * 64, 64)) diff++;
    printf("  x1 vs x2      : %u seeds, %u divergencias %s\n", V, diff, diff ? "<<< FALHOU" : "[OK]");
    if (diff) return 1;

    cudaMemset(d_o2, 0, (size_t)N * 64);
    k_x2s<<<(V / 2 + 127) / 128, 128, 32 * 128 * sizeof(uint64_t)>>>(d_mn, d_len, V, d_o2);
    if (cudaDeviceSynchronize() != cudaSuccess) {
        printf("  ERRO no kernel com shared: %s\n", cudaGetErrorString(cudaGetLastError()));
        return 1;
    }
    cudaMemcpy(b, d_o2, (size_t)V * 64, cudaMemcpyDeviceToHost);
    diff = 0;
    for (uint32_t i = 0; i < V; i++) if (memcmp(a + (size_t)i * 64, b + (size_t)i * 64, 64)) diff++;
    printf("  x1 vs x2+smem : %u seeds, %u divergencias %s\n", V, diff, diff ? "<<< FALHOU" : "[OK]");
    if (diff) return 1;

    // ---- vazao, varrendo o tamanho de bloco ----
    printf("\n=== VAZAO (%u seeds/rodada) ===\n", N);
    cudaEvent_t t0, t1; cudaEventCreate(&t0); cudaEventCreate(&t1);
    float best1 = 1e30f, best2 = 1e30f, best3 = 1e30f;
    int bb1 = 0, bb2 = 0, bb3 = 0;

    printf("  %-6s %-22s %-22s %-22s\n", "bloco", "x1 (atual)", "x2 (ILP)", "x2+smem (ILP)");
    for (int thr : {64, 128, 256}) {
        float ms1, ms2, ms3;
        int g1 = (N + thr - 1) / thr, g2 = (N / 2 + thr - 1) / thr;
        size_t shb = (size_t)32 * thr * sizeof(uint64_t);

        k_x1<<<g1, thr>>>(d_mn, d_len, N, d_o1); cudaDeviceSynchronize();
        cudaEventRecord(t0);
        for (int r = 0; r < 3; r++) k_x1<<<g1, thr>>>(d_mn, d_len, N, d_o1);
        cudaEventRecord(t1); cudaEventSynchronize(t1);
        cudaEventElapsedTime(&ms1, t0, t1); ms1 /= 3;

        k_x2<<<g2, thr>>>(d_mn, d_len, N, d_o2); cudaDeviceSynchronize();
        cudaEventRecord(t0);
        for (int r = 0; r < 3; r++) k_x2<<<g2, thr>>>(d_mn, d_len, N, d_o2);
        cudaEventRecord(t1); cudaEventSynchronize(t1);
        cudaEventElapsedTime(&ms2, t0, t1); ms2 /= 3;

        // shared acima do limite do dispositivo faz o lancamento falhar sem
        // erro visivel no timing, e o resultado vira 0 ms (ganho absurdo).
        int shmax = 0;
        cudaDeviceGetAttribute(&shmax, cudaDevAttrMaxSharedMemoryPerBlock, 0);
        if ((int)shb > shmax) {
            printf("  %-6d shared %zu KB > limite %d KB, pulando x2+smem\n",
                   thr, shb / 1024, shmax / 1024);
            ms3 = 1e30f;
        } else {
        k_x2s<<<g2, thr, shb>>>(d_mn, d_len, N, d_o2);
        if (cudaDeviceSynchronize() != cudaSuccess) {
            printf("  thr=%3d  x2+smem indisponivel (%s)\n", thr, cudaGetErrorString(cudaGetLastError()));
            ms3 = 1e30f;
        } else {
            cudaEventRecord(t0);
            for (int r = 0; r < 3; r++) k_x2s<<<g2, thr, shb>>>(d_mn, d_len, N, d_o2);
            cudaEventRecord(t1); cudaEventSynchronize(t1);
            cudaEventElapsedTime(&ms3, t0, t1); ms3 /= 3;
        }
        }

        printf("  %-6d %7.1f ms %9.0f/s  %7.1f ms %9.0f/s  %7.1f ms %9.0f/s\n",
               thr, ms1, N / (ms1 / 1000.0), ms2, N / (ms2 / 1000.0),
               ms3, ms3 < 1e29f ? N / (ms3 / 1000.0) : 0.0);
        if (ms1 < best1) { best1 = ms1; bb1 = thr; }
        if (ms2 < best2) { best2 = ms2; bb2 = thr; }
        if (ms3 < best3) { best3 = ms3; bb3 = thr; }
    }

    printf("\n  x1      melhor: %7.1f ms @bloco=%d\n", best1, bb1);
    printf("  x2      melhor: %7.1f ms @bloco=%d   ganho %.3fx\n", best2, bb2, best1 / best2);
    if (best3 < 1e29f)
        printf("  x2+smem melhor: %7.1f ms @bloco=%d   ganho %.3fx\n", best3, bb3, best1 / best3);

    float bg = best2 < best3 ? best2 : best3;
    printf("\n  VEREDITO: %.3fx  ->  %s\n", best1 / bg,
           best1 / bg > 1.05 ? "vale integrar no scanner"
                             : "NAO compensa; manter o x1 e descartar o ILP");
    printf("  (teto teorico do ILP era 1.21x no PBKDF2 = 1.17x no total)\n");

    double comp = (double)N / (bg / 1000.0) * 4096.0;
    printf("\n  melhor taxa: %.2f G compressoes SHA-512/s\n", comp / 1e9);
    printf("  referencia : x1 medido 8.19 | hashcat escalado p/ 5090: PBKDF2 7.93, SHA-512 puro 9.95\n");
    return 0;
}
