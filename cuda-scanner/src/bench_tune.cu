/*
 * Varredura de tamanho de bloco para o kernel do PBKDF2.
 *
 * Motivo: o hashcat roda o modo 12100 com Thr:512 e atinge 8,48 G
 * compressoes/s numa RTX 5090; nos usamos 128 threads e estamos em 6,84 G.
 * O tamanho de bloco e a diferenca mais visivel e a mais barata de testar.
 *
 * A varredura e feita DENTRO do binario para nao depender de laco de shell.
 */
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "sha512.cuh"
#include "sha512_opt.cuh"
#include "pbkdf2_fast.cuh"

__global__ void k_pbkdf2(uint64_t* sink, uint32_t n) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= n) return;
    uint64_t kw[16]; uint8_t out[64];
    #pragma unroll
    for (int i = 0; i < 16; i++) kw[i] = 0x6162636465666768ULL ^ (t * 31 + i);
    pbkdf2_bip39_packed(kw, 2048, out);
    sink[t] = ((uint64_t*)out)[0];
}

int main(int argc, char** argv) {
    uint32_t N = (argc > 1) ? (uint32_t)atoi(argv[1]) : 262144;
    uint64_t* sink; cudaMalloc(&sink, (size_t)N * 8);
    cudaDeviceSetLimit(cudaLimitStackSize, 8192);

    int regs = 0;
    cudaFuncAttributes at;
    if (cudaFuncGetAttributes(&at, k_pbkdf2) == cudaSuccess) regs = at.numRegs;

    cudaDeviceProp pr; cudaGetDeviceProperties(&pr, 0);
    printf("=== VARREDURA DE BLOCO (PBKDF2, %u threads) ===\n", N);
    printf("GPU: %s | SMs: %d | regs/SM: %d | regs/thread do kernel: %d\n\n",
           pr.name, pr.multiProcessorCount, pr.regsPerMultiprocessor, regs);
    printf("%-8s %10s %14s %12s %10s\n", "bloco", "ms", "G comp/s", "blocos/SM", "ocupacao");
    printf("%-8s %10s %14s %12s %10s\n", "--------", "----------", "--------------", "------------", "----------");

    int blocos[] = {64, 128, 192, 256, 384, 512, 768, 1024};
    float melhor = 1e30f; int bmelhor = 0;

    cudaEvent_t a, b; cudaEventCreate(&a); cudaEventCreate(&b);
    for (int i = 0; i < 8; i++) {
        int thr = blocos[i];
        if (thr > pr.maxThreadsPerBlock) continue;
        if (regs > 0 && (long)regs * thr > pr.regsPerBlock) {
            printf("%-8d %10s (registradores nao cabem no bloco)\n", thr, "-");
            continue;
        }
        int grid = (N + thr - 1) / thr;

        k_pbkdf2<<<grid, thr>>>(sink, N);
        if (cudaDeviceSynchronize() != cudaSuccess) {
            printf("%-8d %10s (%s)\n", thr, "-", cudaGetErrorString(cudaGetLastError()));
            continue;
        }
        cudaEventRecord(a);
        for (int r = 0; r < 3; r++) k_pbkdf2<<<grid, thr>>>(sink, N);
        cudaEventRecord(b); cudaEventSynchronize(b);
        float ms; cudaEventElapsedTime(&ms, a, b); ms /= 3;

        int bloco_por_sm = 0;
        cudaOccupancyMaxActiveBlocksPerMultiprocessor(&bloco_por_sm, k_pbkdf2, thr, 0);
        double ocup = (double)bloco_por_sm * thr / pr.maxThreadsPerMultiProcessor;
        double gcs = (double)N * 4096.0 / (ms / 1000.0) / 1e9;

        printf("%-8d %10.2f %14.2f %12d %9.1f%%\n", thr, ms, gcs, bloco_por_sm, 100 * ocup);
        if (ms < melhor) { melhor = ms; bmelhor = thr; }
    }

    double gcs = (double)N * 4096.0 / (melhor / 1000.0) / 1e9;
    printf("\n  MELHOR: bloco=%d  %.2f ms  %.2f G compressoes/s\n", bmelhor, melhor, gcs);
    printf("  referencia hashcat na 5090 (modo 12100): 8.48 G comp/s\n");
    printf("  estamos a %.0f%% do hashcat\n", 100 * gcs / 8.48);
    return 0;
}
