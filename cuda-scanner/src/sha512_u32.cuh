/*
 * SHA-512 com o estado em metades de 32 bits EXPLICITAS.
 *
 * Motivo (medido): na versao com uint64_t, cada Sigma gasta 6 SHF + 3 LOP3,
 * mas o piso e 6 SHF + 2 LOP3 -- o XOR triplo de cada metade de 32 bits e
 * exatamente um LOP3. Sao 160 Sigma por compressao => ~160 instrucoes de
 * sobra, ~4,6% da compressao.
 *
 * Escrevendo as metades na mao, cada Sigma vira:
 *   lo = FS(..) ^ FS(..) ^ FS(..)   -> 3 SHF + 1 LOP3
 *   hi = FS(..) ^ FS(..) ^ FS(..)   -> 3 SHF + 1 LOP3
 *
 * Decomposicao das rotacoes (x = hi:lo, FS = __funnelshift_r):
 *   rotr64(x,n)   com n<32 : lo=FS(lo,hi,n)   hi=FS(hi,lo,n)
 *   rotr64(x,n)   com n>=32: troca as metades e rotaciona por n-32
 *   x >> n        com n<32 : lo=FS(lo,hi,n)   hi=hi>>n
 */
#ifndef SHA512_U32_CUH
#define SHA512_U32_CUH

#include <stdint.h>

struct u64x { uint32_t lo, hi; };

__device__ __forceinline__ u64x mk(uint64_t v) { u64x r; r.lo = (uint32_t)v; r.hi = (uint32_t)(v >> 32); return r; }
__device__ __forceinline__ uint64_t un(u64x v) { return ((uint64_t)v.hi << 32) | v.lo; }

#define FS(a, b, n) __funnelshift_r((a), (b), (n))

// Sigma0 = rotr28 ^ rotr34 ^ rotr39   (34=32+2, 39=32+7)
__device__ __forceinline__ u64x S0x(u64x x) {
    u64x r;
    r.lo = FS(x.lo, x.hi, 28) ^ FS(x.hi, x.lo, 2) ^ FS(x.hi, x.lo, 7);
    r.hi = FS(x.hi, x.lo, 28) ^ FS(x.lo, x.hi, 2) ^ FS(x.lo, x.hi, 7);
    return r;
}

// Sigma1 = rotr14 ^ rotr18 ^ rotr41   (41=32+9)
__device__ __forceinline__ u64x S1x(u64x x) {
    u64x r;
    r.lo = FS(x.lo, x.hi, 14) ^ FS(x.lo, x.hi, 18) ^ FS(x.hi, x.lo, 9);
    r.hi = FS(x.hi, x.lo, 14) ^ FS(x.hi, x.lo, 18) ^ FS(x.lo, x.hi, 9);
    return r;
}

// gamma0 = rotr1 ^ rotr8 ^ shr7
__device__ __forceinline__ u64x g0x(u64x x) {
    u64x r;
    r.lo = FS(x.lo, x.hi, 1) ^ FS(x.lo, x.hi, 8) ^ FS(x.lo, x.hi, 7);
    r.hi = FS(x.hi, x.lo, 1) ^ FS(x.hi, x.lo, 8) ^ (x.hi >> 7);
    return r;
}

// gamma1 = rotr19 ^ rotr61 ^ shr6    (61=32+29)
__device__ __forceinline__ u64x g1x(u64x x) {
    u64x r;
    r.lo = FS(x.lo, x.hi, 19) ^ FS(x.hi, x.lo, 29) ^ FS(x.lo, x.hi, 6);
    r.hi = FS(x.hi, x.lo, 19) ^ FS(x.lo, x.hi, 29) ^ (x.hi >> 6);
    return r;
}

__device__ __forceinline__ u64x Chx(u64x x, u64x y, u64x z) {
    u64x r;
    r.lo = z.lo ^ (x.lo & (y.lo ^ z.lo));
    r.hi = z.hi ^ (x.hi & (y.hi ^ z.hi));
    return r;
}

__device__ __forceinline__ u64x Majx(u64x x, u64x y, u64x z) {
    u64x r;
    r.lo = (x.lo & y.lo) | (z.lo & (x.lo | y.lo));
    r.hi = (x.hi & y.hi) | (z.hi & (x.hi | y.hi));
    return r;
}

// soma de 64 bits com vai-um explicito
__device__ __forceinline__ u64x addx(u64x a, u64x b) {
    u64x r;
    asm("add.cc.u32  %0, %2, %3;\n\t"
        "addc.u32    %1, %4, %5;"
        : "=r"(r.lo), "=r"(r.hi)
        : "r"(a.lo), "r"(b.lo), "r"(a.hi), "r"(b.hi));
    return r;
}

#endif // SHA512_U32_CUH
