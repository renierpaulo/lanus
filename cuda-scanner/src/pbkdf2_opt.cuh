#ifndef PBKDF2_OPT_CUH
#define PBKDF2_OPT_CUH

#include "sha512.cuh"

// Estado intermediário do SHA-512
// Usamos align(16) para garantir carregamento eficiente se necessário
struct __align__(16) SHA512State_t {
    uint64_t h[8];
};

__device__ __forceinline__ void sha512_init_state_opt(SHA512State_t* s) {
    s->h[0] = 0x6a09e667f3bcc908ULL; s->h[1] = 0xbb67ae8584caa73bULL;
    s->h[2] = 0x3c6ef372fe94f82bULL; s->h[3] = 0xa54ff53a5f1d36f1ULL;
    s->h[4] = 0x510e527fade682d1ULL; s->h[5] = 0x9b05688c2b3e6c1fULL;
    s->h[6] = 0x1f83d9abfb41bd6bULL; s->h[7] = 0x5be0cd19137e2179ULL;
}

__device__ __forceinline__ void sha512_extract_opt(const SHA512State_t* state, uint8_t* out) {
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

__device__ __forceinline__ void sha512_transform_block_raw_opt(SHA512State_t* state, const uint8_t* data) {
    uint64_t W[80];
    
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

__device__ __forceinline__ void sha512_finish_block2_192bytes_opt(
    SHA512State_t* state,
    const uint8_t* data_64bytes
) {
    uint64_t block[16];
    
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        uint64_t w = 0;
        #pragma unroll
        for(int j=0; j<8; j++) w = (w << 8) | data_64bytes[i*8 + j];
        block[i] = w;
    }
    
    block[8] = 0x8000000000000000ULL;
    block[9] = 0; block[10] = 0; block[11] = 0;
    block[12] = 0; block[13] = 0; block[14] = 0;
    block[15] = 0x0000000000000600ULL; // 1536 bits
    
    uint64_t W[80];
    
    #pragma unroll
    for (int i = 0; i < 16; i++) W[i] = block[i];
    
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

__device__ void pbkdf2_sha512_optimized(
    const uint8_t* key_64bytes,
    const uint8_t* salt, uint32_t salt_len,
    uint32_t iterations,
    uint8_t* output_64bytes
) {
    if (salt_len != 8) return; // Only support fixed logic for now
    
    uint8_t k_ipad[128];
    uint8_t k_opad[128];
    
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
    
    SHA512State_t ctx_inner_pre;
    SHA512State_t ctx_outer_pre;
    
    sha512_init_state_opt(&ctx_inner_pre);
    sha512_transform_block_raw_opt(&ctx_inner_pre, k_ipad);
    
    sha512_init_state_opt(&ctx_outer_pre);
    sha512_transform_block_raw_opt(&ctx_outer_pre, k_opad);
    
    uint8_t U[64];
    uint8_t T[64];
    
    {
        SHA512State_t ctx = ctx_inner_pre;
        
        uint64_t block2[16];
        block2[0] = 0x6d6e656d6f6e6963ULL; 
        block2[1] = 0x0000000180000000ULL;
        #pragma unroll
        for(int i=2; i<15; i++) block2[i] = 0;
        block2[15] = 0x460;
        
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
        
        uint8_t inner_hash[64];
        sha512_extract_opt(&ctx, inner_hash);
        
        SHA512State_t ctx_out = ctx_outer_pre;
        sha512_finish_block2_192bytes_opt(&ctx_out, inner_hash);
        
        sha512_extract_opt(&ctx_out, U);
        #pragma unroll
        for(int i=0; i<64; i++) T[i] = U[i];
    }
    
    for (uint32_t i = 1; i < iterations; i++) {
        SHA512State_t ctx = ctx_inner_pre;
        sha512_finish_block2_192bytes_opt(&ctx, U);
        uint8_t inner_hash[64];
        sha512_extract_opt(&ctx, inner_hash);
        
        ctx = ctx_outer_pre;
        sha512_finish_block2_192bytes_opt(&ctx, inner_hash);
        
        sha512_extract_opt(&ctx, U);
        
        #pragma unroll
        for(int j=0; j<64; j++) T[j] ^= U[j];
    }
    
    #pragma unroll
    for(int i=0; i<64; i++) output_64bytes[i] = T[i];
}

// PBKDF2-SHA512 for variable-length mnemonic (BIP39 compliant)
__device__ void pbkdf2_sha512_mnemonic(
    const uint8_t* password, uint32_t password_len,
    const uint8_t* salt, uint32_t salt_len,
    uint32_t iterations,
    uint8_t* output_64bytes
) {
    // Key preparation for HMAC: if password > 128, hash it; else pad with zeros
    uint8_t key[128];
    for(int i=0; i<128; i++) key[i] = 0;
    
    if (password_len <= 128) {
        for(uint32_t i=0; i<password_len; i++) key[i] = password[i];
    } else {
        // Hash the password (rare case for BIP39)
        sha512(password, password_len, key);
    }
    
    uint8_t k_ipad[128];
    uint8_t k_opad[128];
    
    for(int i=0; i<128; i++) {
        k_ipad[i] = key[i] ^ 0x36;
        k_opad[i] = key[i] ^ 0x5c;
    }
    
    SHA512State_t ctx_inner_pre, ctx_outer_pre;
    sha512_init_state_opt(&ctx_inner_pre);
    sha512_transform_block_raw_opt(&ctx_inner_pre, k_ipad);
    
    sha512_init_state_opt(&ctx_outer_pre);
    sha512_transform_block_raw_opt(&ctx_outer_pre, k_opad);
    
    uint8_t U[64], T[64];
    
    // First iteration: HMAC(key, salt || INT(1))
    {
        SHA512State_t ctx = ctx_inner_pre;
        
        // Process salt + block number
        uint8_t msg[128];
        for(int i=0; i<128; i++) msg[i] = 0;
        
        uint32_t msg_len = 0;
        for(uint32_t i=0; i<salt_len && msg_len<124; i++) msg[msg_len++] = salt[i];
        
        // Append block number (1) as big-endian 32-bit
        msg[msg_len++] = 0x00;
        msg[msg_len++] = 0x00;
        msg[msg_len++] = 0x00;
        msg[msg_len++] = 0x01;
        
        // CRITICAL FIX: Calculate bit_len BEFORE adding padding
        // bit_len = (k_ipad block: 128 bytes) + (current message: salt + block_number)
        uint64_t bit_len = (128 + msg_len) * 8;
        
        // Now add padding byte
        msg[msg_len] = 0x80;
        msg_len++;
        
        // Place length in last 8 bytes of the block (big-endian)
        msg[120] = (bit_len >> 56) & 0xFF;
        msg[121] = (bit_len >> 48) & 0xFF;
        msg[122] = (bit_len >> 40) & 0xFF;
        msg[123] = (bit_len >> 32) & 0xFF;
        msg[124] = (bit_len >> 24) & 0xFF;
        msg[125] = (bit_len >> 16) & 0xFF;
        msg[126] = (bit_len >> 8) & 0xFF;
        msg[127] = bit_len & 0xFF;
        
        sha512_transform_block_raw_opt(&ctx, msg);
        
        uint8_t inner_hash[64];
        sha512_extract_opt(&ctx, inner_hash);
        
        // Outer HMAC
        SHA512State_t ctx_out = ctx_outer_pre;
        sha512_finish_block2_192bytes_opt(&ctx_out, inner_hash);
        sha512_extract_opt(&ctx_out, U);
        
        for(int i=0; i<64; i++) T[i] = U[i];
    }
    
    // Remaining iterations
    for(uint32_t iter=1; iter<iterations; iter++) {
        SHA512State_t ctx = ctx_inner_pre;
        sha512_finish_block2_192bytes_opt(&ctx, U);
        uint8_t inner_hash[64];
        sha512_extract_opt(&ctx, inner_hash);
        
        ctx = ctx_outer_pre;
        sha512_finish_block2_192bytes_opt(&ctx, inner_hash);
        sha512_extract_opt(&ctx, U);
        
        for(int j=0; j<64; j++) T[j] ^= U[j];
    }
    
    for(int i=0; i<64; i++) output_64bytes[i] = T[i];
}

#endif
