/*
 * A/B: compressao generica vs ESPECIALIZADA para o bloco do PBKDF2.
 * Testa se o nvcc ja dobra sozinho as constantes de W[8..15].
 * Verifica primeiro que as duas dao o MESMO resultado.
 */
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha512.cuh"
#include "sha512_opt.cuh"
#include "sha512_spec.cuh"

__global__ void k_gen(uint64_t* out, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint64_t st[8], p[8];
    sha512_init_opt(st);
    for (int i = 0; i < 8; i++) p[i] = 0x0123456789ABCDEFULL ^ (t * 7 + i);
    for (uint32_t r = 0; r < reps; r++) { sha512_block64_pad192_opt(st, p); for (int i = 0; i < 8; i++) p[i] = st[i]; }
    for (int i = 0; i < 8; i++) out[(size_t)t * 8 + i] = st[i];
}

__global__ void k_spec(uint64_t* out, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint64_t st[8], p[8];
    sha512_init_opt(st);
    for (int i = 0; i < 8; i++) p[i] = 0x0123456789ABCDEFULL ^ (t * 7 + i);
    for (uint32_t r = 0; r < reps; r++) { sha512_block64_pad192_spec(st, p); for (int i = 0; i < 8; i++) p[i] = st[i]; }
    for (int i = 0; i < 8; i++) out[(size_t)t * 8 + i] = st[i];
}

int main(int argc, char** argv) {
    uint32_t N = (argc > 1) ? (uint32_t)atoi(argv[1]) : 65536;
    uint32_t R = (argc > 2) ? (uint32_t)atoi(argv[2]) : 2000;

    uint64_t *dA, *dB;
    cudaMalloc(&dA, (size_t)N * 8 * 8);
    cudaMalloc(&dB, (size_t)N * 8 * 8);
    cudaDeviceSetLimit(cudaLimitStackSize, 8192);

    // correcao
    k_gen<<<(N + 127) / 128, 128>>>(dA, N, 7);
    k_spec<<<(N + 127) / 128, 128>>>(dB, N, 7);
    if (cudaDeviceSynchronize() != cudaSuccess) { printf("ERRO CUDA\n"); return 1; }
    uint64_t* hA = (uint64_t*)malloc((size_t)N * 64);
    uint64_t* hB = (uint64_t*)malloc((size_t)N * 64);
    cudaMemcpy(hA, dA, (size_t)N * 64, cudaMemcpyDeviceToHost);
    cudaMemcpy(hB, dB, (size_t)N * 64, cudaMemcpyDeviceToHost);
    int dif = memcmp(hA, hB, (size_t)N * 64) ? 1 : 0;
    printf("=== CORRECAO ===\n  %u estados: %s\n\n", N,
           dif ? "DIVERGEM <<< a especializada esta ERRADA" : "identicos [OK]");
    if (dif) return 1;

    printf("=== VAZAO (%u threads x %u compressoes) ===\n", N, R);
    cudaEvent_t a, b; cudaEventCreate(&a); cudaEventCreate(&b);
    float mg = 0, ms = 0;

    k_gen<<<(N + 127) / 128, 128>>>(dA, N, R); cudaDeviceSynchronize();
    cudaEventRecord(a);
    for (int i = 0; i < 3; i++) k_gen<<<(N + 127) / 128, 128>>>(dA, N, R);
    cudaEventRecord(b); cudaEventSynchronize(b); cudaEventElapsedTime(&mg, a, b); mg /= 3;

    k_spec<<<(N + 127) / 128, 128>>>(dB, N, R); cudaDeviceSynchronize();
    cudaEventRecord(a);
    for (int i = 0; i < 3; i++) k_spec<<<(N + 127) / 128, 128>>>(dB, N, R);
    cudaEventRecord(b); cudaEventSynchronize(b); cudaEventElapsedTime(&ms, a, b); ms /= 3;

    double ops = (double)N * R;
    printf("  generica      %8.2f ms   %.2f G compressoes/s\n", mg, ops / (mg / 1000.0) / 1e9);
    printf("  especializada %8.2f ms   %.2f G compressoes/s\n", ms, ops / (ms / 1000.0) / 1e9);
    printf("\n  GANHO NA COMPRESSAO: %.3fx\n", mg / ms);
    double tot = 1.0 / (0.895 / (mg / ms) + 0.105);
    printf("  -> ganho TOTAL projetado (PBKDF2 = 89,5%%): %.3fx\n", tot);
    printf("  %s\n", (mg / ms) > 1.02
        ? ">>> o compilador NAO estava dobrando: vale integrar"
        : ">>> o nvcc JA dobrava as constantes: nao ha ganho aqui");
    return 0;
}
