/*
 * PBKDF2-HMAC-SHA512 para BIP39, caminho rapido.
 *
 * O algoritmo ja estava certo no pbkdf2_opt.cuh (midstates ipad/opad
 * pre-computados = 2 compressoes por iteracao). O que se ganha aqui e de
 * implementacao:
 *
 *   - sha512_compress_opt usa janela rolante W[16] (128B) no lugar de W[80]
 *     (640B), o que tira o spill para memoria local;
 *   - o estado circula como uint64_t[8] do inicio ao fim: sumiu o
 *     extract-para-bytes + re-empacota-para-uint64 que rodava 2x por iteracao
 *     (2048 iteracoes => ~500k operacoes de byte por candidato);
 *   - o XOR do acumulador T e feito em 8 x 64 bits em vez de 64 x 8 bits.
 */

#ifndef PBKDF2_FAST_CUH
#define PBKDF2_FAST_CUH

#include <stdint.h>
#include "sha512_opt.cuh"

// Variante que recebe a chave JA empacotada em 16 palavras de 64 bits
// (big-endian, zero-padded ate 128 bytes). Evita montar a frase como bytes
// em memoria local so para reempacotar aqui.
// O comprimento nao e necessario: a chave do HMAC e o bloco de 128 bytes
// completo, e a mensagem e sempre "mnemonic"||INT32BE(1).
__device__ void pbkdf2_bip39_packed(const uint64_t* kw, uint32_t iterations,
                                    uint8_t* output_64bytes) {
    uint64_t blk[16], inner_pre[8], outer_pre[8];

    #pragma unroll
    for (int i = 0; i < 16; i++) blk[i] = kw[i] ^ 0x3636363636363636ULL;
    sha512_init_opt(inner_pre);
    sha512_compress_opt(inner_pre, blk);

    #pragma unroll
    for (int i = 0; i < 16; i++) blk[i] = kw[i] ^ 0x5c5c5c5c5c5c5c5cULL;
    sha512_init_opt(outer_pre);
    sha512_compress_opt(outer_pre, blk);

    uint64_t st[8], U[8], T[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) st[i] = inner_pre[i];

    blk[0] = 0x6d6e656d6f6e6963ULL;   // "mnemonic"
    blk[1] = 0x0000000180000000ULL;   // INT32BE(1) + 0x80
    #pragma unroll
    for (int i = 2; i < 15; i++) blk[i] = 0;
    blk[15] = 0x460;
    sha512_compress_opt(st, blk);

    #pragma unroll
    for (int i = 0; i < 8; i++) U[i] = outer_pre[i];
    sha512_block64_pad192_opt(U, st);
    #pragma unroll
    for (int i = 0; i < 8; i++) T[i] = U[i];

    for (uint32_t it = 1; it < iterations; it++) {
        #pragma unroll
        for (int i = 0; i < 8; i++) st[i] = inner_pre[i];
        sha512_block64_pad192_opt(st, U);
        #pragma unroll
        for (int i = 0; i < 8; i++) U[i] = outer_pre[i];
        sha512_block64_pad192_opt(U, st);
        #pragma unroll
        for (int i = 0; i < 8; i++) T[i] ^= U[i];
    }

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        uint64_t x = T[i];
        #pragma unroll
        for (int b = 0; b < 8; b++) output_64bytes[i*8+b] = (uint8_t)(x >> (56 - 8*b));
    }
}

__device__ void pbkdf2_sha512_mnemonic_fast(
    const uint8_t* password, uint32_t password_len,
    uint32_t iterations,
    uint8_t* output_64bytes
) {
    // ---- chave HMAC: mnemonico com zero-padding ate 128 bytes -------------
    // (frases BIP39 de 12/24 palavras ficam sempre abaixo de 128 bytes)
    uint64_t kw[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        uint64_t w = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            uint32_t idx = i * 8 + j;
            w = (w << 8) | (uint64_t)(idx < password_len ? password[idx] : 0);
        }
        kw[i] = w;
    }

    uint64_t blk[16], inner_pre[8], outer_pre[8];

    #pragma unroll
    for (int i = 0; i < 16; i++) blk[i] = kw[i] ^ 0x3636363636363636ULL;
    sha512_init_opt(inner_pre);
    sha512_compress_opt(inner_pre, blk);

    #pragma unroll
    for (int i = 0; i < 16; i++) blk[i] = kw[i] ^ 0x5c5c5c5c5c5c5c5cULL;
    sha512_init_opt(outer_pre);
    sha512_compress_opt(outer_pre, blk);

    // ---- U1 = HMAC(pwd, "mnemonic" || INT32BE(1)) -------------------------
    uint64_t st[8], U[8], T[8];

    #pragma unroll
    for (int i = 0; i < 8; i++) st[i] = inner_pre[i];

    blk[0] = 0x6d6e656d6f6e6963ULL;   // "mnemonic"
    blk[1] = 0x0000000180000000ULL;   // INT32BE(1) + byte 0x80 de padding
    #pragma unroll
    for (int i = 2; i < 15; i++) blk[i] = 0;
    blk[15] = 0x460;                  // (128 + 12) * 8 bits
    sha512_compress_opt(st, blk);

    #pragma unroll
    for (int i = 0; i < 8; i++) U[i] = outer_pre[i];
    sha512_block64_pad192_opt(U, st);

    #pragma unroll
    for (int i = 0; i < 8; i++) T[i] = U[i];

    // ---- iteracoes restantes: U = HMAC(pwd, U); T ^= U --------------------
    for (uint32_t it = 1; it < iterations; it++) {
        #pragma unroll
        for (int i = 0; i < 8; i++) st[i] = inner_pre[i];
        sha512_block64_pad192_opt(st, U);

        #pragma unroll
        for (int i = 0; i < 8; i++) U[i] = outer_pre[i];
        sha512_block64_pad192_opt(U, st);

        #pragma unroll
        for (int i = 0; i < 8; i++) T[i] ^= U[i];
    }

    // ---- saida em bytes (uma unica vez) -----------------------------------
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        uint64_t x = T[i];
        output_64bytes[i*8+0] = (uint8_t)(x >> 56); output_64bytes[i*8+1] = (uint8_t)(x >> 48);
        output_64bytes[i*8+2] = (uint8_t)(x >> 40); output_64bytes[i*8+3] = (uint8_t)(x >> 32);
        output_64bytes[i*8+4] = (uint8_t)(x >> 24); output_64bytes[i*8+5] = (uint8_t)(x >> 16);
        output_64bytes[i*8+6] = (uint8_t)(x >>  8); output_64bytes[i*8+7] = (uint8_t)(x);
    }
}

// HMAC-SHA512 de uso geral (BIP32), com a compressao nova.
// data_len <= 128 (cobre os 37 bytes do CKDpriv e os 64 bytes da seed).
__device__ void hmac_sha512_fast(const uint8_t* key, uint32_t key_len,
                                 const uint8_t* data, uint32_t data_len,
                                 uint8_t* out64) {
    uint64_t kw[16], blk[16], st[8], oh[8];

    #pragma unroll
    for (int i = 0; i < 16; i++) {
        uint64_t w = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            uint32_t idx = i * 8 + j;
            w = (w << 8) | (uint64_t)(idx < key_len ? key[idx] : 0);
        }
        kw[i] = w;
    }

    // inner = SHA512(ipad || data)
    #pragma unroll
    for (int i = 0; i < 16; i++) blk[i] = kw[i] ^ 0x3636363636363636ULL;
    sha512_init_opt(st);
    sha512_compress_opt(st, blk);

    for (int i = 0; i < 16; i++) blk[i] = 0;
    for (uint32_t i = 0; i < data_len; i++)
        blk[i >> 3] |= (uint64_t)data[i] << (56 - 8 * (i & 7));
    blk[data_len >> 3] |= (uint64_t)0x80 << (56 - 8 * (data_len & 7));
    blk[15] = (uint64_t)(128 + data_len) * 8;
    sha512_compress_opt(st, blk);

    // outer = SHA512(opad || inner)
    #pragma unroll
    for (int i = 0; i < 16; i++) blk[i] = kw[i] ^ 0x5c5c5c5c5c5c5c5cULL;
    sha512_init_opt(oh);
    sha512_compress_opt(oh, blk);
    sha512_block64_pad192_opt(oh, st);

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        uint64_t x = oh[i];
        out64[i*8+0] = (uint8_t)(x >> 56); out64[i*8+1] = (uint8_t)(x >> 48);
        out64[i*8+2] = (uint8_t)(x >> 40); out64[i*8+3] = (uint8_t)(x >> 32);
        out64[i*8+4] = (uint8_t)(x >> 24); out64[i*8+5] = (uint8_t)(x >> 16);
        out64[i*8+6] = (uint8_t)(x >>  8); out64[i*8+7] = (uint8_t)(x);
    }
}

#endif // PBKDF2_FAST_CUH
