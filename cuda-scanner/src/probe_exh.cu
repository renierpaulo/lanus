/*
 * Sonda generica do kth_phrase: le o mesmo arquivo -words e o mesmo -req do
 * scanner, roda so a geracao (sem PBKDF2) e valida os indices produzidos.
 *
 * uso: ./probe_exh <words.txt> <req> [amostras]
 */
#define main scanner_main_unused
#include "main.cu"
#undef main

__global__ void k_probe(const uint16_t* base, uint32_t total_words,
                        uint64_t total_space, uint32_t n,
                        uint16_t* out, uint8_t* flag) {
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= n) return;
    uint64_t k = (uint64_t)t;
    if (k >= total_space) { flag[t] = 2; return; }
    uint16_t ph[MAX_WORDS];
    #pragma unroll
    for (int i = 0; i < MAX_WORDS; i++) ph[i] = 0xEEEE;   // marca nao-escrito
    kth_phrase(k, total_words, base, ph);
    for (int i = 0; i < 12; i++) out[t * 12 + i] = ph[i];
    flag[t] = verify_checksum_12(ph) ? 1 : 0;
}

int main(int argc, char** argv) {
    if (argc < 3) { printf("uso: %s <words.txt> <req> [amostras]\n", argv[0]); return 1; }
    const char* wf = argv[1];
    uint32_t NREQ = (uint32_t)atoi(argv[2]);
    uint32_t N = (argc > 3) ? (uint32_t)atoi(argv[3]) : 4096;

    char wl[2048][16];
    FILE* f = fopen("wordlist.txt", "r");
    if (!f) { printf("sem wordlist.txt\n"); return 1; }
    char ln[64]; int n = 0;
    while (n < 2048 && fgets(ln, sizeof(ln), f)) {
        ln[strcspn(ln, "\r\n")] = 0; memset(wl[n], 0, 16); strncpy(wl[n], ln, 15); n++;
    }
    fclose(f);

    uint16_t h_base[MAX_WORDS];
    memset(h_base, 0, sizeof(h_base));
    uint32_t NW = 0;
    f = fopen(wf, "r");
    if (!f) { printf("sem %s\n", wf); return 1; }
    char w[64];
    while (fscanf(f, "%s", w) == 1 && NW < MAX_WORDS) {
        for (int j = 0; j < 2048; j++) if (!strcmp(w, wl[j])) { h_base[NW++] = (uint16_t)j; break; }
    }
    fclose(f);

    uint32_t Psz = NW - NREQ, K = 12 - NREQ;
    printf("arquivo=%s  palavras=%u  req=%u  ->  escolhe %u de %u\n", wf, NW, NREQ, K, Psz);

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

    uint64_t total_space = hb[Psz][K] * 479001600ULL;
    printf("C(%u,%u)=%llu  total_space=%llu\n", Psz, K,
           (unsigned long long)hb[Psz][K], (unsigned long long)total_space);

    uint16_t* d_base; uint16_t* d_out; uint8_t* d_f;
    cudaMalloc(&d_base, MAX_WORDS * 2); cudaMalloc(&d_out, (size_t)N * 12 * 2); cudaMalloc(&d_f, N);
    cudaMemcpy(d_base, h_base, MAX_WORDS * 2, cudaMemcpyHostToDevice);
    cudaDeviceSetLimit(cudaLimitStackSize, 8192);

    k_probe<<<(N + 127) / 128, 128>>>(d_base, NW, total_space, N, d_out, d_f);
    cudaError_t e = cudaDeviceSynchronize();
    if (e == cudaSuccess) e = cudaGetLastError();
    if (e != cudaSuccess) { printf(">>> CRASH NA GERACAO: %s\n", cudaGetErrorString(e)); return 1; }

    uint16_t* ho = (uint16_t*)malloc((size_t)N * 12 * 2);
    uint8_t* hf2 = (uint8_t*)malloc(N);
    cudaMemcpy(ho, d_out, (size_t)N * 12 * 2, cudaMemcpyDeviceToHost);
    cudaMemcpy(hf2, d_f, N, cudaMemcpyDeviceToHost);

    int val = 0, fora = 0, naoesc = 0, rep = 0, lim = 0;
    for (uint32_t t = 0; t < N; t++) {
        if (hf2[t] == 2) { lim++; continue; }
        if (hf2[t] == 1) val++;
        for (int i = 0; i < 12; i++) {
            uint16_t v = ho[t*12+i];
            if (v == 0xEEEE) naoesc++;
            else if (v >= 2048) fora++;
            for (int j = i+1; j < 12; j++) if (ho[t*12+i] == ho[t*12+j]) rep++;
        }
    }
    printf("%u amostras: %d validos, %d fora do limite, %d indices >=2048, "
           "%d nao escritos, %d pares repetidos\n", N, val, lim, fora, naoesc, rep);
    printf("%s\n", (fora || naoesc) ? ">>> GERACAO PRODUZ INDICES INVALIDOS" : "geracao ok");
    return 0;
}
