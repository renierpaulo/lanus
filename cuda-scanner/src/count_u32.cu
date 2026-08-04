/*
 * Conta instrucoes das Sigma em 32 bits explicitos, para comparar com a
 * versao uint64. Mesmo teste do k_sigma anterior (160 chamadas).
 */
#include <cuda_runtime.h>
#include <stdint.h>
#include "sha512.cuh"
#include "sha512_opt.cuh"
#include "sha512_u32.cuh"

// referencia: uint64
__global__ void k_sig64(uint64_t* io) {
    uint64_t x = io[0], acc = 0;
    #pragma unroll
    for (int i = 0; i < 80; i++) { acc ^= S0o(x) ^ S1o(x); x += acc; }
    io[0] = acc;
}

// candidato: metades de 32 bits
__global__ void k_sig32(uint64_t* io) {
    u64x x = mk(io[0]), acc = mk(0);
    #pragma unroll
    for (int i = 0; i < 80; i++) {
        u64x a = S0x(x), b = S1x(x);
        acc.lo ^= a.lo ^ b.lo;
        acc.hi ^= a.hi ^ b.hi;
        x = addx(x, acc);
    }
    io[0] = un(acc);
}

// gamma: uint64
__global__ void k_gam64(uint64_t* io) {
    uint64_t x = io[0], acc = 0;
    #pragma unroll
    for (int i = 0; i < 64; i++) { acc ^= s0o(x) ^ s1o(x); x += acc; }
    io[0] = acc;
}

// gamma: 32 bits
__global__ void k_gam32(uint64_t* io) {
    u64x x = mk(io[0]), acc = mk(0);
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        u64x a = g0x(x), b = g1x(x);
        acc.lo ^= a.lo ^ b.lo;
        acc.hi ^= a.hi ^ b.hi;
        x = addx(x, acc);
    }
    io[0] = un(acc);
}

int main() { return 0; }
