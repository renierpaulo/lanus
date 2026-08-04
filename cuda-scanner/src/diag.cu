/*
 * Diagnostico do scanner. Roda as FUNCOES REAIS de main.cu, etapa por etapa.
 *
 *   build: nvcc -O3 -arch=sm_120 -o build/diag src/diag.cu
 *   uso  : cd cuda-scanner && ./build/diag
 *
 * TESTE 1 - cadeia de derivacao contra um vetor conhecido
 *           (checksum -> PBKDF2 -> BIP32 -> hash160, e o decode do alvo)
 *
 * TESTE 2 - COBERTURA DO RNG. Este e o teste que pegou o bug de que
 *           cuda_rand devolvia o estado cru de um LCG: os bits baixos sao
 *           degenerados (o bit i tem periodo 2^(i+1)) e "% n" depende deles.
 *           Resultado: o gerador so alcancava 2.520 das 40.320 permutacoes
 *           (6,25%) -- 93,75% do espaco era inalcancavel e a busca nunca
 *           acharia a seed. Um bench A/B de derivacao NAO pega isso: as
 *           frases geradas eram validas e derivavam certo, so que sempre o
 *           mesmo subconjunto.
 */
#define main scanner_main_unused
#include "main.cu"
#undef main

#define COV_N 1048576   // amostras
#define COV_K 8         // permutacoes de 8 itens -> 8! = 40320

__global__ void k_derive_check(const uint16_t* idx, uint8_t* out_valid,
                               uint8_t* out_h160, char wordlist[2048][16]) {
    if (threadIdx.x || blockIdx.x) return;
    uint16_t ind[12];
    for (int i = 0; i < 12; i++) ind[i] = idx[i];

    out_valid[0] = verify_checksum_12(ind) ? 1 : 0;

    uint8_t mnem[256]; int ml = 0;
    for (int w = 0; w < 12; w++) {
        if (w) mnem[ml++] = ' ';
        const char* s = wordlist[ind[w]];
        for (int c = 0; s[c]; c++) mnem[ml++] = s[c];
    }

    uint8_t seed[64], key[32], cc[32], tk[32], tc[32], I[64];
    pbkdf2_sha512_mnemonic_fast(mnem, ml, PBKDF2_ITERATIONS, seed);
    hmac_sha512_fast((const uint8_t*)"Bitcoin seed", 12, seed, 64, I);
    for (int i = 0; i < 32; i++) { key[i] = I[i]; cc[i] = I[32 + i]; }
    derive_child_key(key, cc, 44, tk, tc, true , false); for(int i=0;i<32;i++){key[i]=tk[i];cc[i]=tc[i];}
    derive_child_key(key, cc,  0, tk, tc, true , false); for(int i=0;i<32;i++){key[i]=tk[i];cc[i]=tc[i];}
    derive_child_key(key, cc,  0, tk, tc, true , false); for(int i=0;i<32;i++){key[i]=tk[i];cc[i]=tc[i];}
    derive_child_key(key, cc,  0, tk, tc, false, false); for(int i=0;i<32;i++){key[i]=tk[i];cc[i]=tc[i];}
    derive_child_key(key, cc,  0, tk, tc, false, false); for(int i=0;i<32;i++) key[i]=tk[i];

    uint8_t pub[33], sh[32];
    secp256k1_pubkey_fast(key, pub);
    sha256(pub, 33, sh);
    ripemd160(sh, 32, out_h160);
}

// Sorteia uma permutacao de COV_K itens com o MESMO cuda_rand do gerador e
// devolve seu indice de Lehmer (0..COV_K!-1), para contar quantas distintas saem.
__global__ void k_coverage(uint32_t* hits) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= COV_N) return;

    uint64_t seed = mix64((uint64_t)tid * 0x9E3779B97F4A7C15ULL + 0x123456789ABCDEFULL);

    uint8_t pool[COV_K], out[COV_K];
    for (int i = 0; i < COV_K; i++) pool[i] = i;
    int navail = COV_K;
    for (int i = 0; i < COV_K; i++) {
        uint32_t j = cuda_rand(&seed) % navail;
        out[i] = pool[j];
        pool[j] = pool[navail - 1];
        navail--;
    }

    uint32_t rank = 0, fact = 1;
    for (int i = COV_K - 2; i >= 0; i--) {
        fact *= (COV_K - 1 - i);
        uint32_t smaller = 0;
        for (int j = i + 1; j < COV_K; j++) if (out[j] < out[i]) smaller++;
        rank += smaller * fact;
    }
    atomicOr(&hits[rank >> 5], 1u << (rank & 31));
}

// Assinatura de 64 bits da k-esima frase, para detectar colisoes no host.
__global__ void k_enum_sig(const uint16_t* base, uint32_t total_words,
                           uint32_t nsamples, uint64_t* out) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= nsamples) return;
    uint16_t ph[12];
    kth_phrase((uint64_t)tid, total_words, base, ph);
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < 12; i++) { h ^= ph[i]; h *= 1099511628211ULL; }
    out[tid] = h;
}

int main() {
    char wl[2048][16];
    FILE* f = fopen("wordlist.txt", "r");
    if (!f) { printf("ERRO: rode de dentro de cuda-scanner/ (falta wordlist.txt)\n"); return 1; }
    char ln[64]; int n = 0;
    while (n < 2048 && fgets(ln, sizeof(ln), f)) {
        ln[strcspn(ln, "\r\n")] = 0; memset(wl[n], 0, 16); strncpy(wl[n], ln, 15); n++;
    }
    fclose(f);
    cudaDeviceSetLimit(cudaLimitStackSize, 8192);
    int ok = 1;

    // ---------------- TESTE 1 ----------------
    // "galaxy man boy evil donkey child cross chair egg meat blood space"
    uint16_t h_idx[12] = {759, 1078, 213, 623, 521, 319, 416, 302, 566, 1104, 191, 1666};
    const char* EXP  = "232fb8a4bb0b8be8daeb78d9022d126006309c5c";
    const char* ADDR = "14D3pSqxVQdq2i9299k7KJpNmDoGPcw96B";

    printf("=== TESTE 1: cadeia de derivacao ===\nfrase: ");
    for (int i = 0; i < 12; i++) printf("%s ", wl[h_idx[i]]);
    printf("\n");

    uint16_t* d_idx; uint8_t *d_v, *d_h; char (*d_wl)[16];
    cudaMalloc(&d_idx, 24); cudaMalloc(&d_v, 1); cudaMalloc(&d_h, 20); cudaMalloc(&d_wl, 2048 * 16);
    cudaMemcpy(d_idx, h_idx, 24, cudaMemcpyHostToDevice);
    cudaMemcpy(d_wl, wl, 2048 * 16, cudaMemcpyHostToDevice);

    k_derive_check<<<1, 1>>>(d_idx, d_v, d_h, d_wl);
    cudaError_t e = cudaDeviceSynchronize();
    if (e != cudaSuccess) { printf("ERRO CUDA: %s\n", cudaGetErrorString(e)); return 1; }

    uint8_t v, h[20]; char s[41], ts[41];
    cudaMemcpy(&v, d_v, 1, cudaMemcpyDeviceToHost);
    cudaMemcpy(h, d_h, 20, cudaMemcpyDeviceToHost);
    for (int i = 0; i < 20; i++) sprintf(s + i * 2, "%02x", h[i]);

    printf("  checksum        : %s\n", v ? "valido" : "INVALIDO  <<< FALHOU");
    printf("  hash160         : %s %s\n", s, strcmp(s, EXP) == 0 ? "OK" : "<<< FALHOU");
    if (!v || strcmp(s, EXP)) ok = 0;

    uint8_t th[20];
    if (base58_decode_address(ADDR, th)) {
        for (int i = 0; i < 20; i++) sprintf(ts + i * 2, "%02x", th[i]);
        printf("  alvo base58     : %s %s\n", ts, strcmp(ts, EXP) == 0 ? "OK" : "<<< FALHOU");
        if (strcmp(ts, EXP)) ok = 0;
    }

    // ---------------- TESTE 2 ----------------
    printf("\n=== TESTE 2: cobertura do RNG ===\n");
    uint32_t total = 1; for (int i = 2; i <= COV_K; i++) total *= i;   // COV_K!
    uint32_t words = (total + 31) / 32;
    uint32_t* d_hits; cudaMalloc(&d_hits, words * 4); cudaMemset(d_hits, 0, words * 4);
    k_coverage<<<(COV_N + 255) / 256, 256>>>(d_hits);
    cudaDeviceSynchronize();

    uint32_t* hh = (uint32_t*)malloc(words * 4);
    cudaMemcpy(hh, d_hits, words * 4, cudaMemcpyDeviceToHost);
    uint32_t seen = 0;
    for (uint32_t i = 0; i < total; i++) if (hh[i >> 5] >> (i & 31) & 1) seen++;

    double cov = 100.0 * seen / total;
    printf("  %d amostras sobre %u! = %u permutacoes\n", COV_N, COV_K, total);
    printf("  distintas       : %u (%.2f%%)\n", seen, cov);
    printf("  %s\n", cov > 99.0 ? "OK (RNG uniforme)"
                                : "<<< FALHOU: RNG degenerado, parte do espaco e inalcancavel");
    if (cov <= 99.0) ok = 0;

    // ---------------- TESTE 3 ----------------
    // kth_phrase tem que ser BIJETIVO: k distintos -> frases distintas.
    // Um off-by-one no unranking faria a varredura exaustiva pular parte do
    // espaco em silencio -- o mesmo tipo de falha do bug do RNG.
    printf("\n=== TESTE 3: bijecao da enumeracao exaustiva ===\n");
    {
        const uint32_t NW = 20, NREQ = 4;      // 4 obrigatorias + 8 de 16
        uint32_t rc = NREQ;
        cudaMemcpyToSymbol(d_required_count, &rc, sizeof(uint32_t));

        static uint64_t hb[41][13];
        for (int a = 0; a <= 40; a++)
            for (int b = 0; b <= 12; b++)
                hb[a][b] = (b == 0) ? 1ULL : (b > a ? 0ULL : hb[a-1][b-1] + hb[a-1][b]);
        cudaMemcpyToSymbol(d_binom, hb, sizeof(hb));

        uint64_t hf[25]; hf[0] = 1;
        for (int i = 1; i <= 24; i++) hf[i] = hf[i-1] * i;
        cudaMemcpyToSymbol(d_factorials, hf, sizeof(hf));

        uint16_t hb_idx[MAX_WORDS];
        for (uint32_t i = 0; i < NW; i++) hb_idx[i] = (uint16_t)(100 + i);
        uint16_t* d_b; cudaMalloc(&d_b, MAX_WORDS * 2);
        cudaMemcpy(d_b, hb_idx, MAX_WORDS * 2, cudaMemcpyHostToDevice);

        const uint32_t NS = 1u << 20;          // 1M valores de k consecutivos
        uint64_t* d_sig; cudaMalloc(&d_sig, (size_t)NS * 8);
        k_enum_sig<<<(NS + 255) / 256, 256>>>(d_b, NW, NS, d_sig);
        if (cudaDeviceSynchronize() != cudaSuccess) { printf("  ERRO CUDA\n"); ok = 0; }

        uint64_t* hs = (uint64_t*)malloc((size_t)NS * 8);
        cudaMemcpy(hs, d_sig, (size_t)NS * 8, cudaMemcpyDeviceToHost);
        qsort(hs, NS, 8, [](const void* a, const void* b) {
            uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
            return x < y ? -1 : (x > y ? 1 : 0);
        });
        uint32_t dup = 0;
        for (uint32_t i = 1; i < NS; i++) if (hs[i] == hs[i-1]) dup++;

        printf("  %u valores de k -> %u frases, %u colisoes\n", NS, NS, dup);
        printf("  %s\n", dup == 0 ? "OK (bijetivo)"
                                  : "<<< FALHOU: enumeracao repete/pula frases");
        if (dup) ok = 0;
        free(hs); cudaFree(d_sig); cudaFree(d_b);
    }

    printf("\n%s\n", ok ? "TODOS OS TESTES PASSARAM" : "!!! ALGUM TESTE FALHOU !!!");
    return ok ? 0 : 1;
}
