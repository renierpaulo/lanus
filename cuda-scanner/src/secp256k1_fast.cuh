/*
 * secp256k1 rapido: multiplicacao escalar de BASE FIXA (k*G) com janela LARGA.
 *
 * v3 (wide-window): tabela nova com janelas de GT_WBITS=12 bits gerada e
 * verificada em Python (gen_gtable_w.py: scan == double-and-add em chaves
 * aleatorias). Janelas 4-bit -> 12-bit corta as adicoes mistas por chave de
 * ~60 para <=22 (media ~20.6), cada uma custando 11 mulmod (madd-2007-bl).
 * Tabela: 22 x 4095 pontos afins (~5.8 MB), residente em L2.
 *
 * A inversao continua pela cadeia de adicao do secp256k1 (255 quadrados +
 * 15 mults) no lugar do square-and-multiply generico.
 */

#ifndef SECP256K1_FAST_CUH
#define SECP256K1_FAST_CUH

#include <stdint.h>
#include "secp256k1.cuh"     // uint256_t, uint256_mod_*, SECP256K1_P
#include "secp_gtable_w.cuh" // d_gtable, GT_WBITS, GT_NWIN, GT_NPT

__device__ __forceinline__ void fe_mul(uint256_t* r, const uint256_t* a, const uint256_t* b) {
    uint256_mod_mul(r, a, b, &SECP256K1_P);
}
__device__ __forceinline__ void fe_sqr(uint256_t* r, const uint256_t* a) {
    uint256_mod_sqr(r, a);
}
__device__ __forceinline__ void fe_sub(uint256_t* r, const uint256_t* a, const uint256_t* b) {
    uint256_mod_sub(r, a, b, &SECP256K1_P);
}
__device__ __forceinline__ void fe_add(uint256_t* r, const uint256_t* a, const uint256_t* b) {
    uint256_mod_add(r, a, b, &SECP256K1_P);
}

// ---------------------------------------------------------------------------
// Inversao modular por cadeia de adicao (p-2), estilo libsecp256k1.
// ---------------------------------------------------------------------------
__device__ void fe_inv_chain(uint256_t* r, const uint256_t* a) {
    uint256_t x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t;

    fe_sqr(&x2, a);        fe_mul(&x2, &x2, a);            // a^(2^2-1)
    fe_sqr(&x3, &x2);      fe_mul(&x3, &x3, a);            // a^(2^3-1)

    t = x3;
    #pragma unroll
    for (int i = 0; i < 3; i++) fe_sqr(&t, &t);
    fe_mul(&x6, &t, &x3);                                   // a^(2^6-1)

    t = x6;
    #pragma unroll
    for (int i = 0; i < 3; i++) fe_sqr(&t, &t);
    fe_mul(&x9, &t, &x3);                                   // a^(2^9-1)

    t = x9;
    #pragma unroll
    for (int i = 0; i < 2; i++) fe_sqr(&t, &t);
    fe_mul(&x11, &t, &x2);                                  // a^(2^11-1)

    t = x11;
    #pragma unroll
    for (int i = 0; i < 11; i++) fe_sqr(&t, &t);
    fe_mul(&x22, &t, &x11);                                 // a^(2^22-1)

    t = x22;
    #pragma unroll
    for (int i = 0; i < 22; i++) fe_sqr(&t, &t);
    fe_mul(&x44, &t, &x22);                                 // a^(2^44-1)

    t = x44;
    #pragma unroll
    for (int i = 0; i < 44; i++) fe_sqr(&t, &t);
    fe_mul(&x88, &t, &x44);                                 // a^(2^88-1)

    t = x88;
    #pragma unroll
    for (int i = 0; i < 88; i++) fe_sqr(&t, &t);
    fe_mul(&x176, &t, &x88);                                // a^(2^176-1)

    t = x176;
    #pragma unroll
    for (int i = 0; i < 44; i++) fe_sqr(&t, &t);
    fe_mul(&x220, &t, &x44);                                // a^(2^220-1)

    t = x220;
    #pragma unroll
    for (int i = 0; i < 3; i++) fe_sqr(&t, &t);
    fe_mul(&x223, &t, &x3);                                 // a^(2^223-1)

    t = x223;
    #pragma unroll
    for (int i = 0; i < 23; i++) fe_sqr(&t, &t);
    fe_mul(&t, &t, &x22);
    #pragma unroll
    for (int i = 0; i < 5; i++) fe_sqr(&t, &t);
    fe_mul(&t, &t, a);
    #pragma unroll
    for (int i = 0; i < 3; i++) fe_sqr(&t, &t);
    fe_mul(&t, &t, &x2);
    #pragma unroll
    for (int i = 0; i < 2; i++) fe_sqr(&t, &t);
    fe_mul(r, &t, a);
}

// ---------------------------------------------------------------------------
// Ponto Jacobiano sem a flag `infinity` (usamos Z==0 para representar o
// infinito, o que evita divergencia de warp).
// ---------------------------------------------------------------------------
typedef struct { uint256_t X, Y, Z; } jpoint_t;

__device__ __forceinline__ bool fe_is_zero(const uint256_t* a) {
    return (a->d[0]|a->d[1]|a->d[2]|a->d[3]|a->d[4]|a->d[5]|a->d[6]|a->d[7]) == 0;
}

// Le o ponto afim T[win][idx] da tabela (idx 0..GT_NPT-1 -> (idx+1)*B^win*G).
__device__ __forceinline__ void gtable_load(int win, int idx, uint256_t* x, uint256_t* y) {
    const uint32_t* p = d_gtable + ((win * GT_NPT) + idx) * 16;
    #pragma unroll
    for (int i = 0; i < 8; i++) x->d[i] = __ldg(p + i);
    #pragma unroll
    for (int i = 0; i < 8; i++) y->d[i] = __ldg(p + 8 + i);
}

// Adicao mista: Jacobiano P += afim (qx,qy).   madd-2007-bl: 7M + 4S
__device__ void jpoint_add_affine(jpoint_t* P, const uint256_t* qx, const uint256_t* qy) {
    if (fe_is_zero(&P->Z)) {           // P no infinito -> vira o proprio afim
        P->X = *qx; P->Y = *qy;
        uint256_set_one(&P->Z);
        return;
    }

    uint256_t Z1Z1, U2, S2, H, HH, I, J, r, V, t1, t2;

    fe_sqr(&Z1Z1, &P->Z);
    fe_mul(&U2, qx, &Z1Z1);
    fe_mul(&S2, &P->Z, &Z1Z1);
    fe_mul(&S2, qy, &S2);

    fe_sub(&H, &U2, &P->X);
    fe_sub(&r, &S2, &P->Y);

    if (fe_is_zero(&H)) {
        if (fe_is_zero(&r)) {          // P == Q -> duplicacao
            uint256_t XX, YY, YYYY, S, M, T;
            fe_sqr(&XX, &P->X);
            fe_sqr(&YY, &P->Y);
            fe_sqr(&YYYY, &YY);
            fe_mul(&S, &P->X, &YY);
            fe_add(&S, &S, &S); fe_add(&S, &S, &S);
            fe_add(&M, &XX, &XX); fe_add(&M, &M, &XX);
            fe_sqr(&T, &M);
            fe_add(&t1, &S, &S);
            fe_sub(&T, &T, &t1);
            fe_mul(&t2, &P->Y, &P->Z);
            fe_add(&P->Z, &t2, &t2);
            fe_sub(&t1, &S, &T);
            fe_mul(&t1, &M, &t1);
            fe_add(&t2, &YYYY, &YYYY);
            fe_add(&t2, &t2, &t2);
            fe_add(&t2, &t2, &t2);
            fe_sub(&P->Y, &t1, &t2);
            P->X = T;
            return;
        }
        uint256_clear(&P->Z);          // P == -Q -> infinito
        return;
    }

    fe_add(&r, &r, &r);                // r = 2*(S2 - Y1)
    fe_sqr(&HH, &H);
    fe_add(&I, &HH, &HH); fe_add(&I, &I, &I);   // I = 4*HH
    fe_mul(&J, &H, &I);
    fe_mul(&V, &P->X, &I);

    fe_sqr(&t1, &r);
    fe_sub(&t1, &t1, &J);
    fe_add(&t2, &V, &V);
    fe_sub(&t1, &t1, &t2);             // X3

    fe_sub(&t2, &V, &t1);
    fe_mul(&t2, &r, &t2);
    fe_mul(&V, &P->Y, &J);
    fe_add(&V, &V, &V);
    fe_sub(&P->Y, &t2, &V);            // Y3

    fe_add(&t2, &P->Z, &H);
    fe_sqr(&t2, &t2);
    fe_sub(&t2, &t2, &Z1Z1);
    fe_sub(&P->Z, &t2, &HH);           // Z3
    P->X = t1;
}

// ---------------------------------------------------------------------------
// Chave publica comprimida a partir da privada — caminho rapido de base fixa,
// agora com janelas de GT_WBITS bits sobre a tabela larga.
// ---------------------------------------------------------------------------
__device__ void secp256k1_pubkey_fast(const uint8_t* privkey, uint8_t* pubkey) {
    uint256_t k;
    bytes_to_uint256(&k, privkey);

    jpoint_t P;
    uint256_clear(&P.X); uint256_clear(&P.Y); uint256_clear(&P.Z);  // infinito

    uint256_t qx, qy;
    #pragma unroll 1
    for (int win = 0; win < GT_NWIN; win++) {
        // digito de GT_WBITS bits; pode cruzar duas palavras de 32 bits.
        const uint32_t bit = (uint32_t)win * GT_WBITS;
        const uint32_t lo  = bit & 31u;
        const uint32_t li  = bit >> 5;
        uint32_t v = k.d[li] >> lo;
        // quando o digito cruza a fronteira, sobe bits da palavra seguinte.
        // (lo + GT_WBITS > 32 => lo > 20 => o deslocamento 32-lo esta em [1,11].)
        // Na ultima janela o pedaco que passaria de 256 bits e zero por definicao.
        if (lo + GT_WBITS > 32u && li < 7u)
            v |= k.d[li + 1] << (32u - lo);
        const uint32_t d = v & (GT_BASE - 1u);
        if (d) {
            gtable_load(win, (int)d - 1, &qx, &qy);
            jpoint_add_affine(&P, &qx, &qy);
        }
    }

    if (fe_is_zero(&P.Z)) {            // k == 0: nao acontece na pratica
        pubkey[0] = 0x02;
        #pragma unroll
        for (int i = 1; i < 33; i++) pubkey[i] = 0;
        return;
    }

    uint256_t zinv, z2, z3, xa, ya;
    fe_inv_chain(&zinv, &P.Z);
    fe_sqr(&z2, &zinv);
    fe_mul(&z3, &z2, &zinv);
    fe_mul(&xa, &P.X, &z2);
    fe_mul(&ya, &P.Y, &z3);

    pubkey[0] = (ya.d[0] & 1) ? 0x03 : 0x02;
    uint256_to_bytes(pubkey + 1, &xa);
}

#endif // SECP256K1_FAST_CUH

// Variante ETH: publica X e Y SEPARADOS (64 bytes, sem prefixo).
__device__ void secp256k1_pubkey_fast_uncompressed(const uint8_t* privkey, uint8_t* out64) {
    uint256_t k;
    bytes_to_uint256(&k, privkey);

    jpoint_t P;
    uint256_clear(&P.X); uint256_clear(&P.Y); uint256_clear(&P.Z);

    uint256_t qx, qy;
    #pragma unroll 1
    for (int win = 0; win < GT_NWIN; win++) {
        const uint32_t bit = (uint32_t)win * GT_WBITS;
        const uint32_t lo  = bit & 31u;
        const uint32_t li  = bit >> 5;
        uint32_t v = k.d[li] >> lo;
        if (lo + GT_WBITS > 32u && li < 7u)
            v |= k.d[li + 1] << (32u - lo);
        const uint32_t d = v & (GT_BASE - 1u);
        if (d) {
            gtable_load(win, (int)d - 1, &qx, &qy);
            jpoint_add_affine(&P, &qx, &qy);
        }
    }

    if (fe_is_zero(&P.Z)) {
        for (int i = 0; i < 64; i++) out64[i] = 0;
        return;
    }

    uint256_t zinv, z2, z3, xa, ya;
    fe_inv_chain(&zinv, &P.Z);
    fe_sqr(&z2, &zinv);
    fe_mul(&z3, &z2, &zinv);
    fe_mul(&xa, &P.X, &z2);
    fe_mul(&ya, &P.Y, &z3);

    uint256_to_bytes(out64, &xa);
    uint256_to_bytes(out64 + 32, &ya);
}
