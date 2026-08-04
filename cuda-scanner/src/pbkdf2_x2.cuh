/*
 * PBKDF2 com ILP de 2 vias.
 *
 * MOTIVACAO (medida, nao suposta):
 *   taxa atual    = 8,19 G compressoes SHA-512/s numa 5090
 *   hashcat PBKDF2 (escalado p/ 5090) = 8,30  -> estamos a 99%
 *   hashcat SHA-512 PURO (escalado)   = 9,95  -> estamos a 82%
 *
 * Os 18% que faltam nao sao codigo desperdicado: sao stall da CADEIA DE
 * DEPENDENCIA. Em PBKDF2, U_i = HMAC(U_{i-1}) e estritamente sequencial, e
 * dentro de cada compressao os 80 rounds tambem sao. Com poucos warps
 * (255 registradores => ocupancia baixa) nao ha o que sobrepor, e a ALU
 * espera. O hashcat no modo SHA-512 puro nao tem cadeia nenhuma.
 *
 * A ideia aqui: cada thread processa DUAS frases independentes e intercala
 * as duas cadeias, para que as instrucoes de uma preencham os ciclos ociosos
 * da outra.
 *
 * ============================ RESULTADO: REJEITADO ==========================
 * MEDIDO numa RTX 5090 (sm_120, CUDA 12.8), 200 mil seeds, saidas conferidas
 * como identicas as do caminho de 1 corrente:
 *
 *     x1 (1 corrente, em uso) .... 2.037.210 seeds/s   <- o mais rapido
 *     x2 (ILP ingenuo) ........... 1.674.748 seeds/s   0,82x
 *     x2 + midstates em shared ... 1.582.100 seeds/s   0,78x
 *
 * A previsao era ate 1,17x. Deu 0,78-0,82x: MAIS LENTO.
 *
 * O diagnostico de registradores estava certo e o shared resolveu o que
 * prometia -- ptxas confirma 0 bytes de spill no x2+smem, contra 552B/676B
 * do x2 ingenuo. O que estava errado era a premissa: x1 usa 220
 * registradores e as duas variantes ILP usam 255, entao o ILP destroi mais
 * ocupancia do que ganha escondendo latencia. O kernel NAO e latency-bound.
 *
 * Mantido no repositorio como resultado negativo documentado, para nao ser
 * reatacado. Nao esta ligado em lugar nenhum do scanner.
 * ===========================================================================
 */

#ifndef PBKDF2_X2_CUH
#define PBKDF2_X2_CUH

#include <stdint.h>
#include "sha512_opt.cuh"

// ---------------------------------------------------------------------------
// Compressao de dois blocos independentes, com os rounds intercalados.
// As duas correntes nao compartilham dado nenhum, entao o escalonador pode
// emitir instrucoes de uma enquanto a outra espera.
// ---------------------------------------------------------------------------
__device__ __forceinline__ void sha512_compress_x2(
    uint64_t* A, const uint64_t* WA,
    uint64_t* B, const uint64_t* WB)
{
    uint64_t wa[16], wb[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) { wa[i] = WA[i]; wb[i] = WB[i]; }

    uint64_t a0=A[0],b0=A[1],c0=A[2],d0=A[3],e0=A[4],f0=A[5],g0=A[6],h0=A[7];
    uint64_t a1=B[0],b1=B[1],c1=B[2],d1=B[3],e1=B[4],f1=B[5],g1=B[6],h1=B[7];

    // rounds 0..15
    #pragma unroll
    for (int i = 0; i < 16; i += 8) {
        RND(a0,b0,c0,d0,e0,f0,g0,h0, K512[i+0]+wa[i+0]); RND(a1,b1,c1,d1,e1,f1,g1,h1, K512[i+0]+wb[i+0]);
        RND(h0,a0,b0,c0,d0,e0,f0,g0, K512[i+1]+wa[i+1]); RND(h1,a1,b1,c1,d1,e1,f1,g1, K512[i+1]+wb[i+1]);
        RND(g0,h0,a0,b0,c0,d0,e0,f0, K512[i+2]+wa[i+2]); RND(g1,h1,a1,b1,c1,d1,e1,f1, K512[i+2]+wb[i+2]);
        RND(f0,g0,h0,a0,b0,c0,d0,e0, K512[i+3]+wa[i+3]); RND(f1,g1,h1,a1,b1,c1,d1,e1, K512[i+3]+wb[i+3]);
        RND(e0,f0,g0,h0,a0,b0,c0,d0, K512[i+4]+wa[i+4]); RND(e1,f1,g1,h1,a1,b1,c1,d1, K512[i+4]+wb[i+4]);
        RND(d0,e0,f0,g0,h0,a0,b0,c0, K512[i+5]+wa[i+5]); RND(d1,e1,f1,g1,h1,a1,b1,c1, K512[i+5]+wb[i+5]);
        RND(c0,d0,e0,f0,g0,h0,a0,b0, K512[i+6]+wa[i+6]); RND(c1,d1,e1,f1,g1,h1,a1,b1, K512[i+6]+wb[i+6]);
        RND(b0,c0,d0,e0,f0,g0,h0,a0, K512[i+7]+wa[i+7]); RND(b1,c1,d1,e1,f1,g1,h1,a1, K512[i+7]+wb[i+7]);
    }

    // rounds 16..79, com a janela rolante das duas correntes
    #pragma unroll
    for (int i = 16; i < 80; i += 16) {
        #pragma unroll
        for (int j = 0; j < 16; j++) {
            wa[j] += s1o(wa[(j+14)&15]) + wa[(j+9)&15] + s0o(wa[(j+1)&15]);
            wb[j] += s1o(wb[(j+14)&15]) + wb[(j+9)&15] + s0o(wb[(j+1)&15]);
        }
        #pragma unroll
        for (int t = 0; t < 16; t += 8) {
            RND(a0,b0,c0,d0,e0,f0,g0,h0, K512[i+t+0]+wa[t+0]); RND(a1,b1,c1,d1,e1,f1,g1,h1, K512[i+t+0]+wb[t+0]);
            RND(h0,a0,b0,c0,d0,e0,f0,g0, K512[i+t+1]+wa[t+1]); RND(h1,a1,b1,c1,d1,e1,f1,g1, K512[i+t+1]+wb[t+1]);
            RND(g0,h0,a0,b0,c0,d0,e0,f0, K512[i+t+2]+wa[t+2]); RND(g1,h1,a1,b1,c1,d1,e1,f1, K512[i+t+2]+wb[t+2]);
            RND(f0,g0,h0,a0,b0,c0,d0,e0, K512[i+t+3]+wa[t+3]); RND(f1,g1,h1,a1,b1,c1,d1,e1, K512[i+t+3]+wb[t+3]);
            RND(e0,f0,g0,h0,a0,b0,c0,d0, K512[i+t+4]+wa[t+4]); RND(e1,f1,g1,h1,a1,b1,c1,d1, K512[i+t+4]+wb[t+4]);
            RND(d0,e0,f0,g0,h0,a0,b0,c0, K512[i+t+5]+wa[t+5]); RND(d1,e1,f1,g1,h1,a1,b1,c1, K512[i+t+5]+wb[t+5]);
            RND(c0,d0,e0,f0,g0,h0,a0,b0, K512[i+t+6]+wa[t+6]); RND(c1,d1,e1,f1,g1,h1,a1,b1, K512[i+t+6]+wb[t+6]);
            RND(b0,c0,d0,e0,f0,g0,h0,a0, K512[i+t+7]+wa[t+7]); RND(b1,c1,d1,e1,f1,g1,h1,a1, K512[i+t+7]+wb[t+7]);
        }
    }

    A[0]+=a0; A[1]+=b0; A[2]+=c0; A[3]+=d0; A[4]+=e0; A[5]+=f0; A[6]+=g0; A[7]+=h0;
    B[0]+=a1; B[1]+=b1; B[2]+=c1; B[3]+=d1; B[4]+=e1; B[5]+=f1; B[6]+=g1; B[7]+=h1;
}

// Bloco final do HMAC (payload de 64 bytes, total 192), para as duas correntes.
__device__ __forceinline__ void sha512_block64_pad192_x2(
    uint64_t* A, const uint64_t* pa, uint64_t* B, const uint64_t* pb)
{
    uint64_t WA[16], WB[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) { WA[i] = pa[i]; WB[i] = pb[i]; }
    WA[8] = WB[8] = 0x8000000000000000ULL;
    #pragma unroll
    for (int i = 9; i < 15; i++) { WA[i] = 0; WB[i] = 0; }
    WA[15] = WB[15] = 0x0000000000000600ULL;
    sha512_compress_x2(A, WA, B, WB);
}

// Prepara ipad/opad de uma senha (mnemonico) em palavras de 64 bits.
__device__ __forceinline__ void hmac_pads(const uint8_t* pw, uint32_t len,
                                          uint64_t* ipad, uint64_t* opad) {
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        uint64_t w = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            uint32_t idx = i * 8 + j;
            w = (w << 8) | (uint64_t)(idx < len ? pw[idx] : 0);
        }
        ipad[i] = w ^ 0x3636363636363636ULL;
        opad[i] = w ^ 0x5c5c5c5c5c5c5c5cULL;
    }
}

// ---------------------------------------------------------------------------
// PBKDF2-BIP39 para DUAS frases de uma vez.
// ---------------------------------------------------------------------------
__device__ void pbkdf2_bip39_x2(
    const uint8_t* pw0, uint32_t len0, uint8_t* out0,
    const uint8_t* pw1, uint32_t len1, uint8_t* out1,
    uint32_t iterations)
{
    uint64_t bi0[16], bo0[16], bi1[16], bo1[16];
    hmac_pads(pw0, len0, bi0, bo0);
    hmac_pads(pw1, len1, bi1, bo1);

    uint64_t ip0[8], op0[8], ip1[8], op1[8];
    sha512_init_opt(ip0); sha512_init_opt(ip1);
    sha512_compress_x2(ip0, bi0, ip1, bi1);
    sha512_init_opt(op0); sha512_init_opt(op1);
    sha512_compress_x2(op0, bo0, op1, bo1);

    // U1 = HMAC(pwd, "mnemonic" || INT32BE(1))
    uint64_t st0[8], st1[8], U0[8], U1[8], T0[8], T1[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) { st0[i] = ip0[i]; st1[i] = ip1[i]; }

    uint64_t blk[16];
    blk[0] = 0x6d6e656d6f6e6963ULL;   // "mnemonic"
    blk[1] = 0x0000000180000000ULL;
    #pragma unroll
    for (int i = 2; i < 15; i++) blk[i] = 0;
    blk[15] = 0x460;
    sha512_compress_x2(st0, blk, st1, blk);

    #pragma unroll
    for (int i = 0; i < 8; i++) { U0[i] = op0[i]; U1[i] = op1[i]; }
    sha512_block64_pad192_x2(U0, st0, U1, st1);
    #pragma unroll
    for (int i = 0; i < 8; i++) { T0[i] = U0[i]; T1[i] = U1[i]; }

    for (uint32_t it = 1; it < iterations; it++) {
        #pragma unroll
        for (int i = 0; i < 8; i++) { st0[i] = ip0[i]; st1[i] = ip1[i]; }
        sha512_block64_pad192_x2(st0, U0, st1, U1);

        #pragma unroll
        for (int i = 0; i < 8; i++) { U0[i] = op0[i]; U1[i] = op1[i]; }
        sha512_block64_pad192_x2(U0, st0, U1, st1);

        #pragma unroll
        for (int i = 0; i < 8; i++) { T0[i] ^= U0[i]; T1[i] ^= U1[i]; }
    }

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        uint64_t x = T0[i], y = T1[i];
        #pragma unroll
        for (int b = 0; b < 8; b++) {
            out0[i*8+b] = (uint8_t)(x >> (56 - 8*b));
            out1[i*8+b] = (uint8_t)(y >> (56 - 8*b));
        }
    }
}

// ---------------------------------------------------------------------------
// ILP de 2 vias com os midstates em MEMORIA COMPARTILHADA.
//
// Contagem de registradores por corrente (em unidades de 32 bits):
//   inner_pre 16 + outer_pre 16 + U 16 + T 16 + st 16 + w[16] 32 + a..h 16 = 128
// Duas correntes ingenuas = 256, e o teto e 255: estoura por um fio e o
// compilador comeca a derramar para memoria local, o que anula o ILP.
//
// inner_pre e outer_pre sao INVARIANTES DO LACO: ficam 2048 iteracoes
// ocupando 32 registradores por corrente sem mudar. Movendo os dois para
// memoria compartilhada sobram 192 registradores, que cabe folgado.
//
// Custo: 32 leituras de smem por iteracao contra ~6400 instrucoes (~0,5%).
// Layout TRANSPOSTO [palavra][thread]: threads consecutivas leem enderecos
// consecutivos, que e o padrao sem conflito de banco para acessos de 64 bits.
//
// Precisa de 32 * blockDim.x uint64 de shared (32 KB com 128 threads).
// ---------------------------------------------------------------------------
#define X2_SMEM_WORDS 32

__device__ __forceinline__ uint64_t sm_get(const uint64_t* sm, uint32_t nt, uint32_t tid,
                                           uint32_t slot, int w) {
    return sm[(size_t)(slot * 8 + w) * nt + tid];
}
__device__ __forceinline__ void sm_put(uint64_t* sm, uint32_t nt, uint32_t tid,
                                       uint32_t slot, int w, uint64_t v) {
    sm[(size_t)(slot * 8 + w) * nt + tid] = v;
}

__device__ void pbkdf2_bip39_x2_smem(
    const uint8_t* pw0, uint32_t len0, uint8_t* out0,
    const uint8_t* pw1, uint32_t len1, uint8_t* out1,
    uint32_t iterations,
    uint64_t* sm, uint32_t tid, uint32_t nt)
{
    // slots: 0 = inner corrente 0, 1 = outer c0, 2 = inner c1, 3 = outer c1
    {
        uint64_t bi0[16], bo0[16], bi1[16], bo1[16];
        hmac_pads(pw0, len0, bi0, bo0);
        hmac_pads(pw1, len1, bi1, bo1);

        uint64_t a[8], b[8];
        sha512_init_opt(a); sha512_init_opt(b);
        sha512_compress_x2(a, bi0, b, bi1);
        #pragma unroll
        for (int i = 0; i < 8; i++) { sm_put(sm, nt, tid, 0, i, a[i]); sm_put(sm, nt, tid, 2, i, b[i]); }

        sha512_init_opt(a); sha512_init_opt(b);
        sha512_compress_x2(a, bo0, b, bo1);
        #pragma unroll
        for (int i = 0; i < 8; i++) { sm_put(sm, nt, tid, 1, i, a[i]); sm_put(sm, nt, tid, 3, i, b[i]); }
    }

    uint64_t st0[8], st1[8], U0[8], U1[8], T0[8], T1[8];

    // U1 = HMAC(pwd, "mnemonic" || INT32BE(1))
    #pragma unroll
    for (int i = 0; i < 8; i++) { st0[i] = sm_get(sm, nt, tid, 0, i); st1[i] = sm_get(sm, nt, tid, 2, i); }
    {
        uint64_t blk[16];
        blk[0] = 0x6d6e656d6f6e6963ULL;
        blk[1] = 0x0000000180000000ULL;
        #pragma unroll
        for (int i = 2; i < 15; i++) blk[i] = 0;
        blk[15] = 0x460;
        sha512_compress_x2(st0, blk, st1, blk);
    }
    #pragma unroll
    for (int i = 0; i < 8; i++) { U0[i] = sm_get(sm, nt, tid, 1, i); U1[i] = sm_get(sm, nt, tid, 3, i); }
    sha512_block64_pad192_x2(U0, st0, U1, st1);
    #pragma unroll
    for (int i = 0; i < 8; i++) { T0[i] = U0[i]; T1[i] = U1[i]; }

    for (uint32_t it = 1; it < iterations; it++) {
        #pragma unroll
        for (int i = 0; i < 8; i++) { st0[i] = sm_get(sm, nt, tid, 0, i); st1[i] = sm_get(sm, nt, tid, 2, i); }
        sha512_block64_pad192_x2(st0, U0, st1, U1);

        #pragma unroll
        for (int i = 0; i < 8; i++) { U0[i] = sm_get(sm, nt, tid, 1, i); U1[i] = sm_get(sm, nt, tid, 3, i); }
        sha512_block64_pad192_x2(U0, st0, U1, st1);

        #pragma unroll
        for (int i = 0; i < 8; i++) { T0[i] ^= U0[i]; T1[i] ^= U1[i]; }
    }

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        uint64_t x = T0[i], y = T1[i];
        #pragma unroll
        for (int b = 0; b < 8; b++) {
            out0[i*8+b] = (uint8_t)(x >> (56 - 8*b));
            out1[i*8+b] = (uint8_t)(y >> (56 - 8*b));
        }
    }
}

#endif // PBKDF2_X2_CUH
