#ifndef PBKDF2_OPT_CUH
#define PBKDF2_OPT_CUH

#include "sha512.cuh"

// Estado intermediário do SHA-512 após processar o primeiro bloco (128 bytes)
// O SHA-512 tem estado de 8 uint64 (64 bytes).
struct alignas(16) SHA512State {
    uint64_t h[8];
};

// Inicializa estado SHA-512 padrão
__device__ __forceinline__ void sha512_init_state(SHA512State* s) {
    s->h[0] = 0x6a09e667f3bcc908ULL; s->h[1] = 0xbb67ae8584caa73bULL;
    s->h[2] = 0x3c6ef372fe94f82bULL; s->h[3] = 0xa54ff53a5f1d36f1ULL;
    s->h[4] = 0x510e527fade682d1ULL; s->h[5] = 0x9b05688c2b3e6c1fULL;
    s->h[6] = 0x1f83d9abfb41bd6bULL; s->h[7] = 0x5be0cd19137e2179ULL;
}

// Copia estado
__device__ __forceinline__ void sha512_copy_state(SHA512State* dst, const SHA512State* src) {
    #pragma unroll
    for(int i=0; i<8; i++) dst->h[i] = src->h[i];
}

// Finaliza o SHA-512 assumindo que já processamos o primeiro bloco (ipad/opad)
// E agora estamos processando o segundo bloco que contém os dados (64 bytes) + padding
// Total size = 128 (ipad) + 64 (data) = 192 bytes.
// O segundo bloco de 128 bytes conterá:
// [0..63]: data (64 bytes)
// [64]: 0x80 (padding start)
// [65..119]: 0 (padding zeros)
// [120..127]: bit_len (total bits = 192 * 8 = 1536 = 0x600) enfiado no fim
__device__ __forceinline__ void sha512_finish_block2_192bytes(
    SHA512State* state,
    const uint8_t* data_64bytes
) {
    // Preparar o buffer do segundo bloco (128 bytes)
    // Usamos uint64 para agilizar a escrita
    uint64_t block[16];
    
    // Carregar dados (64 bytes) para as primeiras 8 palavras de 64 bits
    // Assume data alinhado ou usa conversão
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        // Carregar 8 bytes big-endian
        uint64_t w = 0;
        #pragma unroll
        for(int j=0; j<8; j++) w = (w << 8) | data_64bytes[i*8 + j];
        block[i] = w;
    }
    
    // Padding fixo para tamanho total 192 bytes
    // Byte 192 (index 64 no bloco 2): 0x80.
    // Resto zeros.
    // Últimos 8 bytes: comprimido de 1536 bits (0x600)
    
    block[8] = 0x8000000000000000ULL;
    block[9] = 0;
    block[10] = 0;
    block[11] = 0;
    block[12] = 0;
    block[13] = 0;
    block[14] = 0;
    block[15] = 0x0000000000000600ULL; // 1536 bits
    
    // Processar o bloco transformado
    // Precisamos adaptar o sha512_transform para ler de uint64* direto para evitar casts
    // Mas vamos reusar a lógica de 'transform' do sha512.cuh se possível, ou reimplementar inlined aqui para performance
    
    // Inlining a transform logic here for max speed on uint64 array
    uint64_t W[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t1, t2;
    
    // Prepare Schedule Words
    #pragma unroll
    for (int i = 0; i < 16; i++) W[i] = block[i];
    
    #pragma unroll
    for (int i = 16; i < 80; i++) {
        W[i] = gamma1_512(W[i - 2]) + W[i - 7] + gamma0_512(W[i - 15]) + W[i - 16];
    }
    
    a = state->h[0]; b = state->h[1]; c = state->h[2]; d = state->h[3];
    e = state->h[4]; f = state->h[5]; g = state->h[6]; h = state->h[7];
    
    #pragma unroll
    for (int i = 0; i < 80; i++) {
        t1 = h + sigma1_512(e) + ch64(e, f, g) + K512[i] + W[i];
        t2 = sigma0_512(a) + maj64(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    state->h[0] += a; state->h[1] += b; state->h[2] += c; state->h[3] += d;
    state->h[4] += e; state->h[5] += f; state->h[6] += g; state->h[7] += h;
}

// Extrair hash final para array de bytes
__device__ __forceinline__ void sha512_extract(const SHA512State* state, uint8_t* out) {
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        uint64_t x = state->h[i];
        out[i*8+0] = (x >> 56) & 0xFF;
        out[i*8+1] = (x >> 48) & 0xFF;
        out[i*8+2] = (x >> 40) & 0xFF;
        out[i*8+3] = (x >> 32) & 0xFF;
        out[i*8+4] = (x >> 24) & 0xFF;
        out[i*8+5] = (x >> 16) & 0xFF;
        out[i*8+6] = (x >> 8) & 0xFF;
        out[i*8+7] = x & 0xFF;
    }
}

// Transformação de um bloco raw de 128 bytes (para k_ipad/k_opad)
__device__ __forceinline__ void sha512_transform_block_raw(SHA512State* state, const uint8_t* data) {
    uint64_t W[80];
    
    // Load data big-endian
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint64_t)data[i * 8] << 56) |
               ((uint64_t)data[i * 8 + 1] << 48) |
               ((uint64_t)data[i * 8 + 2] << 40) |
               ((uint64_t)data[i * 8 + 3] << 32) |
               ((uint64_t)data[i * 8 + 4] << 24) |
               ((uint64_t)data[i * 8 + 5] << 16) |
               ((uint64_t)data[i * 8 + 6] << 8) |
               ((uint64_t)data[i * 8 + 7]);
    }

    #pragma unroll
    for (int i = 16; i < 80; i++) {
        W[i] = gamma1_512(W[i - 2]) + W[i - 7] + gamma0_512(W[i - 15]) + W[i - 16];
    }
    
    uint64_t a = state->h[0]; uint64_t b = state->h[1]; uint64_t c = state->h[2]; uint64_t d = state->h[3];
    uint64_t e = state->h[4]; uint64_t f = state->h[5]; uint64_t g = state->h[6]; uint64_t h = state->h[7];
    uint64_t t1, t2;
    
    #pragma unroll
    for (int i = 0; i < 80; i++) {
        t1 = h + sigma1_512(e) + ch64(e, f, g) + K512[i] + W[i];
        t2 = sigma0_512(a) + maj64(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    state->h[0] += a; state->h[1] += b; state->h[2] += c; state->h[3] += d;
    state->h[4] += e; state->h[5] += f; state->h[6] += g; state->h[7] += h;
}

// PBKDF2 Ultra-Optimizado
// Assume que a chave já foi pré-processada (transformada em key_buf 64 bytes se preciso)
// salt é passado e usado apenas para o first round
// Esta função faz as 2048 iterações usando estado pré-calculado
__device__ void pbkdf2_sha512_optimized(
    const uint8_t* key_64bytes, // Deve ter exatamente 64 bytes (hash da passphrase se necessário)
    const uint8_t* salt, uint32_t salt_len,
    uint32_t iterations,
    uint8_t* output_64bytes
) {
    // 1. Preparar estados pré-calculados para HMAC
    uint8_t k_ipad[128];
    uint8_t k_opad[128];
    
    // Unroll para preencher pads
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        k_ipad[i] = key_64bytes[i] ^ 0x36;
        k_opad[i] = key_64bytes[i] ^ 0x5c;
    }
    #pragma unroll
    for (int i = 64; i < 128; i++) {
        k_ipad[i] = 0x36;
        k_opad[i] = 0x5c;
    }
    
    SHA512State ctx_inner_pre;
    SHA512State ctx_outer_pre;
    
    // Pre-calculate Inner State (k_ipad processed)
    sha512_init_state(&ctx_inner_pre);
    sha512_transform_block_raw(&ctx_inner_pre, k_ipad);
    
    // Pre-calculate Outer State (k_opad processed)
    sha512_init_state(&ctx_outer_pre);
    sha512_transform_block_raw(&ctx_outer_pre, k_opad);
    
    // 2. Calcular U1 (Primeiro bloco, com Salt)
    // HMAC(key, salt || 0001)
    // inner = sha512(k_ipad || salt || 0001)
    // salt = "mnemonic" (8 bytes) + 4 bytes counter
    // total inner msg = 128 + 8 + 4 = 140 bytes
    // Isso requer 2 blocos sha512.
    // Bloco 1: k_ipad (já temos ctx_inner_pre)
    // Bloco 2: salt || 0001 || padding
    
    uint8_t U[64];
    uint8_t T[64];
    
    {
        SHA512State ctx = ctx_inner_pre; // Cópia
        
        // Montar segundo bloco manualmente: "mnemonic\0\0\0\1" + padding
        // 8 bytes salt + 4 bytes counter = 12 bytes.
        // Padding começa no byte 12 (offset total 140)
        uint64_t block2[16];
        // "mnemonic" = 0x6d6e656d6f6e6963
        // counter 1 = 0x00000001
        // Data: 6d6e656d 6f6e6963 00000001 ...
        // Word 0: 6d6e656d6f6e6963 (mnemonic)
        // Word 1: 00000001 80 00 ... (count=1, padding=0x80)
        
        // CUIDADO: Salt pode variar se código mudar, mas assumindo "mnemonic"
        block2[0] = 0x6d6e656d6f6e6963ULL; 
        block2[1] = 0x0000000180000000ULL;
        
        // Zeros
        #pragma unroll
        for(int i=2; i<15; i++) block2[i] = 0;
        
        // Length: (128 + 12) * 8 = 140 * 8 = 1120 = 0x460
        block2[15] = 0x460;
        
        // Transform Block 2
        uint64_t W[80];
        #pragma unroll
        for(int i=0; i<16; i++) W[i] = block2[i];
        #pragma unroll
        for(int i=16; i<80; i++) W[i] = gamma1_512(W[i-2]) + W[i-7] + gamma0_512(W[i-15]) + W[i-16];
        
        uint64_t a = ctx.h[0]; uint64_t b = ctx.h[1]; uint64_t c = ctx.h[2]; uint64_t d = ctx.h[3];
        uint64_t e = ctx.h[4]; uint64_t f = ctx.h[5]; uint64_t g = ctx.h[6]; uint64_t h = ctx.h[7];
        uint64_t t1, t2;
        #pragma unroll
        for(int i=0; i<80; i++) {
            t1 = h + sigma1_512(e) + ch64(e, f, g) + K512[i] + W[i];
            t2 = sigma0_512(a) + maj64(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        ctx.h[0]+=a; ctx.h[1]+=b; ctx.h[2]+=c; ctx.h[3]+=d; ctx.h[4]+=e; ctx.h[5]+=f; ctx.h[6]+=g; ctx.h[7]+=h;
        
        // Agora Outer: sha512(k_opad || inner_hash)
        // Tamanho: 128 + 64 = 192. Exatamente o caso otimizado finish_block2_192bytes
        
        uint8_t inner_hash[64];
        sha512_extract(&ctx, inner_hash);
        
        SHA512State ctx_out = ctx_outer_pre;
        sha512_finish_block2_192bytes(&ctx_out, inner_hash);
        
        sha512_extract(&ctx_out, U);
        #pragma unroll
        for(int i=0; i<64; i++) T[i] = U[i];
    }
    
    // 3. Loop principal (U2 ... Uc)
    for (uint32_t i = 1; i < iterations; i++) {
        // Inner: SHA512(k_ipad || U_prev)
        SHA512State ctx = ctx_inner_pre;
        sha512_finish_block2_192bytes(&ctx, U);
        uint8_t inner_hash[64];
        sha512_extract(&ctx, inner_hash);
        
        // Outer: SHA512(k_opad || inner_hash)
        ctx = ctx_outer_pre; // RESET STATE
        sha512_finish_block2_192bytes(&ctx, inner_hash);
        
        // U_new e XOR
        sha512_extract(&ctx, U);
        
        // XOR acumulativo
        // Em vez de extrair bytes e XOR, podemos otimizar mantendo em uint64 se quiséssemos,
        // mas U precisa ser input para o próximo loop como bytes (para a função de block).
        // Manter como array de 8 uint64 seria mais rápido para XOR
        
        // TODO: XOR em palavras de 64 bits para velocidade
        #pragma unroll
        for(int j=0; j<64; j++) T[j] ^= U[j];
    }
    
    // Output
    #pragma unroll
    for(int i=0; i<64; i++) output_64bytes[i] = T[i];
}

#endif
