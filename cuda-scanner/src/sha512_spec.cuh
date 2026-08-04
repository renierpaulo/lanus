/* GERADO por gen_spec_header.py - NAO EDITAR A MAO */
/*
 * Compressao SHA-512 especializada para o bloco do laco do PBKDF2:
 *   W[0..7] = payload (varia), W[8]=0x80.., W[9..14]=0, W[15]=0x600.
 * Com isso, 8 s0() e 2 s1() do message schedule viram constantes ou zero,
 * e 19 somas desaparecem (~8,3% do schedule).
 * Existe para MEDIR se o nvcc ja faz essa dobra sozinho.
 */
#ifndef SHA512_SPEC_CUH
#define SHA512_SPEC_CUH
#include "sha512_opt.cuh"

__device__ __forceinline__ void sha512_block64_pad192_spec(uint64_t* st, const uint64_t* p8) {
    uint64_t w[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) w[i] = p8[i];
    w[8] = 0x8000000000000000ULL;
    #pragma unroll
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 0x0000000000000600ULL;

    uint64_t a = st[0], b = st[1], c = st[2], d = st[3];
    uint64_t e = st[4], f = st[5], g = st[6], h = st[7];

    // rounds 0..15
    {
        RND(a,b,c,d,e,f,g,h, K512[0+0] + w[0+0]);
        RND(h,a,b,c,d,e,f,g, K512[0+1] + w[0+1]);
        RND(g,h,a,b,c,d,e,f, K512[0+2] + w[0+2]);
        RND(f,g,h,a,b,c,d,e, K512[0+3] + w[0+3]);
        RND(e,f,g,h,a,b,c,d, K512[0+4] + w[0+4]);
        RND(d,e,f,g,h,a,b,c, K512[0+5] + w[0+5]);
        RND(c,d,e,f,g,h,a,b, K512[0+6] + w[0+6]);
        RND(b,c,d,e,f,g,h,a, K512[0+7] + w[0+7]);
        RND(a,b,c,d,e,f,g,h, K512[8+0] + w[8+0]);
        RND(h,a,b,c,d,e,f,g, K512[8+1] + w[8+1]);
        RND(g,h,a,b,c,d,e,f, K512[8+2] + w[8+2]);
        RND(f,g,h,a,b,c,d,e, K512[8+3] + w[8+3]);
        RND(e,f,g,h,a,b,c,d, K512[8+4] + w[8+4]);
        RND(d,e,f,g,h,a,b,c, K512[8+5] + w[8+5]);
        RND(c,d,e,f,g,h,a,b, K512[8+6] + w[8+6]);
        RND(b,c,d,e,f,g,h,a, K512[8+7] + w[8+7]);
    }

    // schedule 16..31 COM AS CONSTANTES DOBRADAS + rounds 16..31
    {
        w[0] = s0o(w[1]) + w[0];
        w[1] = 0x00c0000000003018ULL + s0o(w[2]) + w[1];
        w[2] = s1o(w[0]) + s0o(w[3]) + w[2];
        w[3] = s1o(w[1]) + s0o(w[4]) + w[3];
        w[4] = s1o(w[2]) + s0o(w[5]) + w[4];
        w[5] = s1o(w[3]) + s0o(w[6]) + w[5];
        w[6] = s1o(w[4]) + 0x0000000000000600ULL + s0o(w[7]) + w[6];
        w[7] = s1o(w[5]) + w[0] + 0x4180000000000000ULL + w[7];
        w[8] = s1o(w[6]) + w[1] + 0x8000000000000000ULL;
        w[9] = s1o(w[7]) + w[2];
        w[10] = s1o(w[8]) + w[3];
        w[11] = s1o(w[9]) + w[4];
        w[12] = s1o(w[10]) + w[5];
        w[13] = s1o(w[11]) + w[6];
        w[14] = s1o(w[12]) + w[7] + 0x000000000000030aULL;
        w[15] = s1o(w[13]) + w[8] + s0o(w[0]) + 0x0000000000000600ULL;
        RND(a,b,c,d,e,f,g,h, K512[16+0] + w[0+0]);
        RND(h,a,b,c,d,e,f,g, K512[16+1] + w[0+1]);
        RND(g,h,a,b,c,d,e,f, K512[16+2] + w[0+2]);
        RND(f,g,h,a,b,c,d,e, K512[16+3] + w[0+3]);
        RND(e,f,g,h,a,b,c,d, K512[16+4] + w[0+4]);
        RND(d,e,f,g,h,a,b,c, K512[16+5] + w[0+5]);
        RND(c,d,e,f,g,h,a,b, K512[16+6] + w[0+6]);
        RND(b,c,d,e,f,g,h,a, K512[16+7] + w[0+7]);
        RND(a,b,c,d,e,f,g,h, K512[24+0] + w[8+0]);
        RND(h,a,b,c,d,e,f,g, K512[24+1] + w[8+1]);
        RND(g,h,a,b,c,d,e,f, K512[24+2] + w[8+2]);
        RND(f,g,h,a,b,c,d,e, K512[24+3] + w[8+3]);
        RND(e,f,g,h,a,b,c,d, K512[24+4] + w[8+4]);
        RND(d,e,f,g,h,a,b,c, K512[24+5] + w[8+5]);
        RND(c,d,e,f,g,h,a,b, K512[24+6] + w[8+6]);
        RND(b,c,d,e,f,g,h,a, K512[24+7] + w[8+7]);
    }

    // 32..79: tudo dinamico, janela rolante normal
    #pragma unroll
    for (int i = 32; i < 80; i += 16) {
        #pragma unroll
        for (int j = 0; j < 16; j++)
            w[j] += s1o(w[(j + 14) & 15]) + w[(j + 9) & 15] + s0o(w[(j + 1) & 15]);
        RND(a,b,c,d,e,f,g,h, K512[i+0] + w[0+0]);
        RND(h,a,b,c,d,e,f,g, K512[i+1] + w[0+1]);
        RND(g,h,a,b,c,d,e,f, K512[i+2] + w[0+2]);
        RND(f,g,h,a,b,c,d,e, K512[i+3] + w[0+3]);
        RND(e,f,g,h,a,b,c,d, K512[i+4] + w[0+4]);
        RND(d,e,f,g,h,a,b,c, K512[i+5] + w[0+5]);
        RND(c,d,e,f,g,h,a,b, K512[i+6] + w[0+6]);
        RND(b,c,d,e,f,g,h,a, K512[i+7] + w[0+7]);
        RND(a,b,c,d,e,f,g,h, K512[i+8+0] + w[8+0]);
        RND(h,a,b,c,d,e,f,g, K512[i+8+1] + w[8+1]);
        RND(g,h,a,b,c,d,e,f, K512[i+8+2] + w[8+2]);
        RND(f,g,h,a,b,c,d,e, K512[i+8+3] + w[8+3]);
        RND(e,f,g,h,a,b,c,d, K512[i+8+4] + w[8+4]);
        RND(d,e,f,g,h,a,b,c, K512[i+8+5] + w[8+5]);
        RND(c,d,e,f,g,h,a,b, K512[i+8+6] + w[8+6]);
        RND(b,c,d,e,f,g,h,a, K512[i+8+7] + w[8+7]);
    }

    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d;
    st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}
#endif
