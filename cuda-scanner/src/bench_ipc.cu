/*
 * Mede a VAZAO DE INSTRUCAO por tipo na GPU.
 *
 * Motivo: o kernel do PBKDF2 e 50% SHF (funnel shift), 27% LOP3, 23% IADD3.
 * Se SHF roda a meia taxa, ele consome ~2/3 dos ciclos e reduzir shift vira
 * a otimizacao de maior alavanca. Se roda a taxa cheia, o gargalo e outro.
 *
 * Cada kernel roda uma cadeia longa de um unico tipo de instrucao, com
 * dependencia suficiente para nao ser eliminada mas ILP suficiente para
 * saturar o pipe (8 acumuladores independentes).
 */
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define UNROLL 8

__global__ void k_shf(uint32_t* out, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint32_t a[UNROLL], b[UNROLL];
    #pragma unroll
    for (int i = 0; i < UNROLL; i++) { a[i] = t * 7 + i; b[i] = t * 13 + i; }
    for (uint32_t r = 0; r < reps; r++) {
        #pragma unroll
        for (int i = 0; i < UNROLL; i++) a[i] = __funnelshift_r(a[i], b[i], 13);
    }
    uint32_t s = 0;
    #pragma unroll
    for (int i = 0; i < UNROLL; i++) s ^= a[i];
    out[t] = s;
}

__global__ void k_lop3(uint32_t* out, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint32_t a[UNROLL], b[UNROLL], c[UNROLL];
    #pragma unroll
    for (int i = 0; i < UNROLL; i++) { a[i] = t * 7 + i; b[i] = t * 13 + i; c[i] = t * 3 + i; }
    for (uint32_t r = 0; r < reps; r++) {
        #pragma unroll
        for (int i = 0; i < UNROLL; i++) a[i] = (a[i] & b[i]) ^ (~a[i] & c[i]);  // Ch -> LOP3
    }
    uint32_t s = 0;
    #pragma unroll
    for (int i = 0; i < UNROLL; i++) s ^= a[i];
    out[t] = s;
}

__global__ void k_iadd(uint32_t* out, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint32_t a[UNROLL], b[UNROLL];
    #pragma unroll
    for (int i = 0; i < UNROLL; i++) { a[i] = t * 7 + i; b[i] = t * 13 + i; }
    for (uint32_t r = 0; r < reps; r++) {
        #pragma unroll
        for (int i = 0; i < UNROLL; i++) a[i] = a[i] + b[i] + i;
    }
    uint32_t s = 0;
    #pragma unroll
    for (int i = 0; i < UNROLL; i++) s ^= a[i];
    out[t] = s;
}

// rotacao de 64 bits por 8 usando PRMT (byte permute) em vez de SHF
__global__ void k_prmt(uint32_t* out, uint32_t n, uint32_t reps) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; if (t >= n) return;
    uint32_t a[UNROLL], b[UNROLL];
    #pragma unroll
    for (int i = 0; i < UNROLL; i++) { a[i] = t * 7 + i; b[i] = t * 13 + i; }
    for (uint32_t r = 0; r < reps; r++) {
        #pragma unroll
        for (int i = 0; i < UNROLL; i++) a[i] = __byte_perm(a[i], b[i], 0x4321);
    }
    uint32_t s = 0;
    #pragma unroll
    for (int i = 0; i < UNROLL; i++) s ^= a[i];
    out[t] = s;
}

int main(int argc, char** argv) {
    uint32_t N = (argc > 1) ? (uint32_t)atoi(argv[1]) : 262144;
    uint32_t R = (argc > 2) ? (uint32_t)atoi(argv[2]) : 20000;
    uint32_t* out; cudaMalloc(&out, (size_t)N * 4);

    cudaDeviceProp pr; cudaGetDeviceProperties(&pr, 0);
    double pico = (double)pr.multiProcessorCount * 128 * (pr.clockRate * 1000.0);
    printf("=== VAZAO POR TIPO DE INSTRUCAO ===\n");
    printf("GPU: %s | SMs: %d | clock: %.2f GHz\n", pr.name, pr.multiProcessorCount, pr.clockRate / 1e6);
    printf("pico teorico (128 lanes/SM): %.2f T instr/s\n\n", pico / 1e12);
    printf("%-10s %10s %14s %10s\n", "instrucao", "ms", "T instr/s", "%% do pico");
    printf("%-10s %10s %14s %10s\n", "----------", "----------", "--------------", "----------");

    cudaEvent_t a, b; cudaEventCreate(&a); cudaEventCreate(&b);
    double base = 0;

    #define RUN(K, NOME) do {                                                  \
        K<<<(N + 127) / 128, 128>>>(out, N, R); cudaDeviceSynchronize();        \
        cudaEventRecord(a);                                                    \
        for (int i = 0; i < 3; i++) K<<<(N + 127) / 128, 128>>>(out, N, R);     \
        cudaEventRecord(b); cudaEventSynchronize(b);                           \
        float ms; cudaEventElapsedTime(&ms, a, b); ms /= 3;                    \
        double ops = (double)N * R * UNROLL;                                   \
        double tps = ops / (ms / 1000.0);                                      \
        if (base == 0) base = tps;                                             \
        printf("%-10s %10.2f %14.2f %9.1f%%\n", NOME, ms, tps / 1e12, 100 * tps / pico); \
    } while (0)

    RUN(k_iadd, "IADD3");
    RUN(k_lop3, "LOP3");
    RUN(k_shf,  "SHF");
    RUN(k_prmt, "PRMT");

    printf("\nSe SHF ficar bem abaixo de IADD3/LOP3, ele e o gargalo do SHA-512\n");
    printf("(50%% das nossas instrucoes sao SHF) e reduzir shift e a maior alavanca.\n");
    return 0;
}
