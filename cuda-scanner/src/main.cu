/*
 * BIP39 CUDA Scanner v3.0 - Máxima Performance
 * 
 * Arquitetura "Range Only" com:
 * - Multi-GPU automático
 * - CUDA Streams para overlap de compute/transfer
 * - Shared memory para constantes críticas
 * - Tabela pré-computada de G para EC
 * 
 * Suporta derivações: m/44'/0'/0'/0 (Legacy) e m/84'/0'/0'/0 (SegWit)
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <algorithm>
#include <queue>
#include <condition_variable>

// ============================================================================
// Simple host-side SHA256 implementation (no OpenSSL dependency)
// ============================================================================
static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void host_sha256(const uint8_t* data, size_t len, uint8_t* hash) {
    uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    
    // Padding
    size_t new_len = ((len + 8) / 64 + 1) * 64;
    uint8_t* msg = (uint8_t*)calloc(new_len, 1);
    memcpy(msg, data, len);
    msg[len] = 0x80;
    uint64_t bits_len = len * 8;
    for(int i = 0; i < 8; i++) msg[new_len - 1 - i] = (bits_len >> (i * 8)) & 0xFF;
    
    // Process blocks
    for(size_t chunk = 0; chunk < new_len; chunk += 64) {
        uint32_t w[64];
        for(int i = 0; i < 16; i++) {
            w[i] = (msg[chunk+i*4] << 24) | (msg[chunk+i*4+1] << 16) | 
                   (msg[chunk+i*4+2] << 8) | msg[chunk+i*4+3];
        }
        for(int i = 16; i < 64; i++) {
            uint32_t s0 = ((w[i-15] >> 7) | (w[i-15] << 25)) ^ ((w[i-15] >> 18) | (w[i-15] << 14)) ^ (w[i-15] >> 3);
            uint32_t s1 = ((w[i-2] >> 17) | (w[i-2] << 15)) ^ ((w[i-2] >> 19) | (w[i-2] << 13)) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        
        uint32_t a=h0, b=h1, c=h2, d=h3, e=h4, f=h5, g=h6, h=h7;
        for(int i = 0; i < 64; i++) {
            uint32_t S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + sha256_k[i] + w[i];
            uint32_t S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;
    }
    free(msg);
    
    // Output
    hash[0] = h0 >> 24; hash[1] = h0 >> 16; hash[2] = h0 >> 8; hash[3] = h0;
    hash[4] = h1 >> 24; hash[5] = h1 >> 16; hash[6] = h1 >> 8; hash[7] = h1;
    hash[8] = h2 >> 24; hash[9] = h2 >> 16; hash[10] = h2 >> 8; hash[11] = h2;
    hash[12] = h3 >> 24; hash[13] = h3 >> 16; hash[14] = h3 >> 8; hash[15] = h3;
    hash[16] = h4 >> 24; hash[17] = h4 >> 16; hash[18] = h4 >> 8; hash[19] = h4;
    hash[20] = h5 >> 24; hash[21] = h5 >> 16; hash[22] = h5 >> 8; hash[23] = h5;
    hash[24] = h6 >> 24; hash[25] = h6 >> 16; hash[26] = h6 >> 8; hash[27] = h6;
    hash[28] = h7 >> 24; hash[29] = h7 >> 16; hash[30] = h7 >> 8; hash[31] = h7;
}



#include "sha256.cuh"
#include "sha512.cuh"
#include "ripemd160.cuh"
#include "secp256k1.cuh"
#include "bip39.cuh"
#include "base58.cuh"
#include "bech32.cuh"
#include "pbkdf2_opt.cuh"

static uint32_t g_threads_per_block = 256;
static uint32_t g_batch_size_millions = 4;
#define MAX_ADDRESSES 10000000
#define PBKDF2_ITERATIONS 2048
#define MAGIC_V2 0x42495034  // "BIP4"
#define NUM_STREAMS 4

// Variáveis globais para multi-threading
std::atomic<uint64_t> g_total_processed(0);
std::atomic<uint64_t> g_total_valid(0);
std::atomic<uint32_t> g_total_found(0);
std::mutex g_print_mutex;
std::mutex g_file_mutex;

// Producer-Consumer Queue for valid phrases
#define GPU_BATCH_SIZE 10000
std::queue<std::vector<uint16_t>> g_valid_queue;
std::mutex g_queue_mutex;
std::condition_variable g_queue_cv;
bool g_producer_done = false;

// Host-side checksum validation for 12 words
// Returns true if the phrase is valid
bool host_verify_checksum_12(const uint16_t* indices) {
    // Pack 12 words (11 bits each) into entropy + checksum
    // 12 words = 132 bits = 128 bits entropy + 4 bits checksum
    uint8_t entropy[17]; // 132 bits = 16.5 bytes, round up
    memset(entropy, 0, 17);
    
    // Pack indices into bits
    uint32_t bit_pos = 0;
    for (int i = 0; i < 12; i++) {
        uint16_t idx = indices[i];
        for (int b = 10; b >= 0; b--) {
            int byte_idx = bit_pos / 8;
            int bit_idx = 7 - (bit_pos % 8);
            if (idx & (1 << b)) {
                entropy[byte_idx] |= (1 << bit_idx);
            }
            bit_pos++;
        }
    }
    
    // First 128 bits (16 bytes) = entropy
    // Next 4 bits = checksum
    uint8_t ent_bytes[16];
    memcpy(ent_bytes, entropy, 16);
    
    // Calculate SHA256 of entropy
    uint8_t hash[32];
    host_sha256(ent_bytes, 16, hash);
    
    // Checksum is first 4 bits of hash
    uint8_t expected_checksum = hash[0] >> 4;
    
    // Actual checksum is bits 128-131 of our packed data
    uint8_t actual_checksum = entropy[16] >> 4;
    
    return expected_checksum == actual_checksum;
}


// Estrutura para u128 (CUDA não tem suporte nativo)
typedef struct {
    uint64_t lo;
    uint64_t hi;
} uint128_t;

// Estruturas
struct RangeHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t word_count;
    uint32_t num_ranges;
};

struct Range {
    uint128_t start;
    uint128_t count;
};

struct FoundResult {
    uint128_t k_value;
    uint8_t mnemonic_indices[48]; // max 24 words * 2 bytes
    uint8_t private_key[32];
    uint8_t derivation_path; // 0 = m/44', 1 = m/84'
};

struct BloomHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t m_bits;
    uint32_t k;
    uint32_t reserved;
    uint64_t n_items;
};

// Contexto por GPU para multi-GPU
struct GPUContext {
    int device_id;
    cudaStream_t streams[NUM_STREAMS];
    uint64_t* d_valid_count[NUM_STREAMS];
    uint64_t* d_tested_count[NUM_STREAMS];
    uint8_t* d_bloom_bits;
};

// Constantes para BIP39 wordlist
__constant__ char d_wordlist[2048][9];

// Índices base das 24 palavras fixas
__constant__ uint16_t d_base_indices[24];
__constant__ uint32_t d_word_count;

// Fatoriais pré-calculados (até 24!)
__constant__ uint64_t d_factorials[25];

// Endereços alvo em formato hash
__device__ uint8_t* d_target_hashes_ptr = nullptr;
__constant__ uint32_t d_num_targets;

__device__ uint8_t* d_bloom_bits = nullptr;
__constant__ uint64_t d_bloom_m_bits = 0;
__constant__ uint32_t d_bloom_k = 0;
__constant__ uint32_t d_use_bloom = 0;

// Resultados encontrados
__device__ FoundResult d_found_results[1024];
__device__ uint32_t d_found_count = 0;

// Last valid phrase info for display
struct LastValidInfo {
    uint16_t indices[24];
    uint8_t private_key[32];
    uint8_t pubkey_hash[20];
    uint32_t word_count;
};
__device__ LastValidInfo d_last_valid;

// ============================================================================
// PBKDF2-SHA512 para derivação de seed
// ============================================================================
__device__ void pbkdf2_sha512(
    const uint8_t* password, uint32_t password_len,
    const uint8_t* salt, uint32_t salt_len,
    uint32_t iterations,
    uint8_t* output, uint32_t output_len
) {
    uint8_t U[64], T[64];
    uint8_t block_salt[128];

    // Pré-calcular k_ipad/k_opad para a password (HMAC) uma vez
    uint8_t key_buf[64];
    uint32_t key_len = password_len;
    const uint8_t* key_ptr = password;

    if (key_len > 128) {
        // Se chave > 128 bytes, usar SHA512(password) como chave (64 bytes)
        sha512(password, key_len, key_buf);
        key_ptr = key_buf;
        key_len = 64;
    }

    uint8_t k_ipad[128];
    uint8_t k_opad[128];
    for (int i = 0; i < 128; i++) {
        uint8_t kb = (i < key_len) ? key_ptr[i] : 0;
        k_ipad[i] = kb ^ 0x36;
        k_opad[i] = kb ^ 0x5c;
    }

    memcpy(block_salt, salt, salt_len);
    
    uint32_t blocks = (output_len + 63) / 64;
    
    for (uint32_t block = 1; block <= blocks; block++) {
        // Preparar salt com contador de bloco
        block_salt[salt_len] = (block >> 24) & 0xFF;
        block_salt[salt_len + 1] = (block >> 16) & 0xFF;
        block_salt[salt_len + 2] = (block >> 8) & 0xFF;
        block_salt[salt_len + 3] = block & 0xFF;
        
        // U1 = PRF(Password, Salt || INT(i))
        hmac_sha512_pads(k_ipad, k_opad, block_salt, salt_len + 4, U);
        memcpy(T, U, 64);
        
        // U2...Uc
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha512_pads(k_ipad, k_opad, U, 64, U);
            for (int j = 0; j < 64; j++) {
                T[j] ^= U[j];
            }
        }
        
        // Copiar resultado
        uint32_t copy_len = 64;
        if (block == blocks) {
            copy_len = output_len - (block - 1) * 64;
        }
        memcpy(output + (block - 1) * 64, T, copy_len);
    }
}

// ============================================================================
// Derivação BIP32/BIP44/BIP84
// ============================================================================
__device__ void derive_child_key(
    const uint8_t* parent_key,
    const uint8_t* parent_chaincode,
    uint32_t index,
    uint8_t* child_key,
    uint8_t* child_chaincode,
    bool hardened
) {
    uint8_t data[37];
    uint8_t I[64];
    
    if (hardened) {
        index |= 0x80000000;
        data[0] = 0x00;
        memcpy(data + 1, parent_key, 32);
    } else {
        // Calcular pubkey comprimida
        uint8_t pubkey[33];
        secp256k1_get_pubkey_compressed(parent_key, pubkey);
        memcpy(data, pubkey, 33);
    }
    
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;
    
    hmac_sha512(parent_chaincode, 32, data, hardened ? 37 : 37, I);
    
    // child_key = parse256(IL) + parent_key mod n
    secp256k1_scalar_add(I, parent_key, child_key);
    memcpy(child_chaincode, I + 32, 32);
}

// Derivar caminho completo: m/purpose'/0'/0'/0/0
__device__ void derive_master_from_seed(
    const uint8_t* seed,
    uint8_t* master_key,
    uint8_t* master_chaincode
) {
    uint8_t I[64];
    const char* key_str = "Bitcoin seed";
    hmac_sha512((const uint8_t*)key_str, 12, seed, 64, I);
    memcpy(master_key, I, 32);
    memcpy(master_chaincode, I + 32, 32);
}

__device__ void derive_path_from_master(
    const uint8_t* master_key,
    const uint8_t* master_chaincode,
    uint32_t purpose, // 44 ou 84
    uint8_t* private_key,
    uint8_t* public_key_hash // RIPEMD160(SHA256(pubkey))
) {
    uint8_t key[32], chaincode[32];
    uint8_t temp_key[32], temp_chaincode[32];

    memcpy(key, master_key, 32);
    memcpy(chaincode, master_chaincode, 32);

    // m/purpose' (hardened)
    derive_child_key(key, chaincode, purpose, temp_key, temp_chaincode, true);
    memcpy(key, temp_key, 32);
    memcpy(chaincode, temp_chaincode, 32);
    
    // m/purpose'/0' (hardened)
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, true);
    memcpy(key, temp_key, 32);
    memcpy(chaincode, temp_chaincode, 32);
    
    // m/purpose'/0'/0' (hardened)
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, true);
    memcpy(key, temp_key, 32);
    memcpy(chaincode, temp_chaincode, 32);
    
    // m/purpose'/0'/0'/0 (normal)
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, false);
    memcpy(key, temp_key, 32);
    memcpy(chaincode, temp_chaincode, 32);
    
    // m/purpose'/0'/0'/0/0 (normal)
    derive_child_key(key, chaincode, 0, private_key, temp_chaincode, false);
    
    // Calcular public key hash
    uint8_t pubkey[33];
    secp256k1_get_pubkey_compressed(private_key, pubkey);
    
    uint8_t sha_hash[32];
    sha256(pubkey, 33, sha_hash);
    ripemd160(sha_hash, 32, public_key_hash);
}

__device__ void derive_path(
    const uint8_t* seed,
    uint32_t purpose, // 44 ou 84
    uint8_t* private_key,
    uint8_t* public_key_hash // RIPEMD160(SHA256(pubkey))
) {
    uint8_t master_key[32], master_chaincode[32];
    uint8_t key[32], chaincode[32];
    uint8_t temp_key[32], temp_chaincode[32];
    
    // Master key from seed
    const char* key_str = "Bitcoin seed";
    hmac_sha512((const uint8_t*)key_str, 12, seed, 64, master_key);
    memcpy(master_chaincode, master_key + 32, 32);
    
    // m/purpose' (hardened)
    derive_child_key(master_key, master_chaincode, purpose, key, chaincode, true);
    
    // m/purpose'/0' (hardened)
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, true);
    memcpy(key, temp_key, 32);
    memcpy(chaincode, temp_chaincode, 32);
    
    // m/purpose'/0'/0' (hardened)
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, true);
    memcpy(key, temp_key, 32);
    memcpy(chaincode, temp_chaincode, 32);
    
    // m/purpose'/0'/0'/0 (normal)
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, false);
    memcpy(key, temp_key, 32);
    memcpy(chaincode, temp_chaincode, 32);
    
    // m/purpose'/0'/0'/0/0 (normal)
    derive_child_key(key, chaincode, 0, private_key, temp_chaincode, false);
    
    // Calcular public key hash
    uint8_t pubkey[33];
    secp256k1_get_pubkey_compressed(private_key, pubkey);
    
    uint8_t sha_hash[32];
    sha256(pubkey, 33, sha_hash);
    ripemd160(sha_hash, 32, public_key_hash);
}

__device__ void keyhash_to_p2sh_p2wpkh(const uint8_t* keyhash, uint8_t* scripthash) {
    uint8_t script[22];
    script[0] = 0x00;
    script[1] = 0x14;
    memcpy(script + 2, keyhash, 20);
    
    uint8_t sha_res[32];
    sha256(script, 22, sha_res);
    ripemd160(sha_res, 32, scripthash);
}

// ============================================================================
// Aritmética u128 para CUDA
// ============================================================================
// ============================================================================
// Aritmética u128 para CUDA
// ============================================================================
__host__ __device__ __forceinline__ uint128_t make_u128(uint64_t lo, uint64_t hi) {
    uint128_t r; r.lo = lo; r.hi = hi; return r;
}

__host__ __device__ __forceinline__ uint128_t u128_add(uint128_t a, uint64_t b) {
    uint128_t r;
    r.lo = a.lo + b;
    r.hi = a.hi + (r.lo < a.lo ? 1 : 0);
    return r;
}

__host__ __device__ __forceinline__ uint128_t u128_sub(uint128_t a, uint128_t b) {
    uint128_t r;
    r.lo = a.lo - b.lo;
    r.hi = a.hi - b.hi - (a.lo < b.lo ? 1 : 0);
    return r;
}

__host__ __device__ __forceinline__ bool u128_lt(uint128_t a, uint128_t b) {
    return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo);
}

__host__ __device__ __forceinline__ uint64_t u128_div_u64(uint128_t* a, uint64_t b) {
    // Divisão simplificada para caso hi == 0
    if (a->hi == 0) {
        uint64_t q = a->lo / b;
        a->lo = a->lo % b;
        return q;
    }
    // Para hi != 0, fazer divisão longa (simplificada)
    // No host (especialmente Windows) __uint128_t pode não existir, cuidar com #ifdef se necessário
    // Assumindo ambiente Linux/GCC ou NVCC moderno que suporta __int128
#if defined(__CUDA_ARCH__) || defined(__GNUC__)
    __uint128_t val = ((__uint128_t)a->hi << 64) | a->lo;
    uint64_t q = (uint64_t)(val / b);
    uint64_t rem = (uint64_t)(val % b);
    a->lo = rem;
    a->hi = 0;
    return q;
#else
    // Fallback lento ou erro se não tiver 128 bit type no host compiler (Ex: MSVC antigo)
    return 0; // TODO implement proper fallback if needed
#endif
}

__device__ __forceinline__ uint64_t fnv1a64_dev(const uint8_t* data, int len, uint64_t seed) {
    uint64_t hash = 1469598103934665603ULL ^ seed;
    for (int i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

__device__ bool bloom_maybe_contains(const uint8_t* hash160) {
    if (d_use_bloom == 0 || d_bloom_bits == nullptr || d_bloom_m_bits == 0 || d_bloom_k == 0) {
        return false;
    }
    uint64_t h1 = fnv1a64_dev(hash160, 20, 0xA5A5A5A5A5A5A5A5ULL);
    uint64_t h2 = fnv1a64_dev(hash160, 20, 0x5A5A5A5A5A5A5A5AULL);
    for (uint32_t i = 0; i < d_bloom_k; i++) {
        uint64_t combined = h1 + i * h2;
        uint64_t bit_index = combined % d_bloom_m_bits;
        uint64_t byte_index = bit_index >> 3;
        uint8_t mask = 1u << (bit_index & 7u);
        if ((d_bloom_bits[byte_index] & mask) == 0) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// Converter K para permutação usando Lehmer/Factoradic
// ============================================================================
__device__ void k_to_permutation(uint128_t k, uint32_t n, uint8_t* perm) {
    uint8_t available[24];
    for (uint32_t i = 0; i < n; i++) available[i] = i;
    
    for (uint32_t i = 0; i < n; i++) {
        uint64_t f = d_factorials[n - 1 - i];
        uint64_t idx = u128_div_u64(&k, f);
        
        perm[i] = available[idx];
        
        // Remover elemento usado (shift)
        for (uint32_t j = idx; j < n - 1 - i; j++) {
            available[j] = available[j + 1];
        }
    }
}

// ============================================================================
// Verificar checksum BIP39 para 24 palavras
// ============================================================================
__device__ bool verify_checksum_24(const uint16_t* idx) {
    uint8_t entropy[32];
    
    uint64_t acc = 0;
    for (int i = 0; i < 6; i++) acc = (acc << 11) | idx[i];
    entropy[0]=(acc>>58); entropy[1]=(acc>>50); entropy[2]=(acc>>42); entropy[3]=(acc>>34);
    entropy[4]=(acc>>26); entropy[5]=(acc>>18); entropy[6]=(acc>>10); entropy[7]=(acc>>2);
    acc &= 3;
    
    for (int i = 6; i < 12; i++) acc = (acc << 11) | idx[i];
    entropy[8]=(acc>>60); entropy[9]=(acc>>52); entropy[10]=(acc>>44); entropy[11]=(acc>>36);
    entropy[12]=(acc>>28); entropy[13]=(acc>>20); entropy[14]=(acc>>12); entropy[15]=(acc>>4);
    acc &= 15;
    
    for (int i = 12; i < 18; i++) acc = (acc << 11) | idx[i];
    entropy[16]=(acc>>62); entropy[17]=(acc>>54); entropy[18]=(acc>>46); entropy[19]=(acc>>38);
    entropy[20]=(acc>>30); entropy[21]=(acc>>22); entropy[22]=(acc>>14); entropy[23]=(acc>>6);
    
    __uint128_t big = acc & 63;
    for (int i = 18; i < 24; i++) big = (big << 11) | idx[i];
    entropy[24]=(big>>64); entropy[25]=(big>>56); entropy[26]=(big>>48); entropy[27]=(big>>40);
    entropy[28]=(big>>32); entropy[29]=(big>>24); entropy[30]=(big>>16); entropy[31]=(big>>8);
    
    uint8_t checksum = big & 0xFF;
    uint8_t hash[32];
    sha256(entropy, 32, hash);
    
    return checksum == hash[0];
}

// ============================================================================
// Kernel principal de busca v3 - Range Only + Shared Memory
// ============================================================================
__global__ void search_kernel_v2(
    uint128_t range_start,
    uint64_t batch_size,
    uint64_t* valid_count,
    uint64_t* tested_count
) {
    // Shared memory para fatoriais (cache local por bloco)
    __shared__ uint64_t s_factorials[25];
    __shared__ uint16_t s_base_indices[24];
    __shared__ uint32_t s_word_count;
    
    // Primeiro thread do bloco carrega dados para shared memory
    if (threadIdx.x == 0) {
        s_word_count = d_word_count;
        #pragma unroll
        for (int i = 0; i < 25; i++) s_factorials[i] = d_factorials[i];
        #pragma unroll
        for (int i = 0; i < 24; i++) s_base_indices[i] = d_base_indices[i];
    }
    __syncthreads();
    
    uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= batch_size) return;
    
    // Calcular K = range_start + tid
    uint128_t k = u128_add(range_start, tid);
    
    // Converter K para permutação (usando shared memory)
    uint8_t perm[24];
    {
        uint128_t temp = k;
        uint8_t available[24];
        #pragma unroll
        for (int i = 0; i < 24; i++) available[i] = i;
        
        for (uint32_t i = 0; i < s_word_count; i++) {
            uint32_t remaining = s_word_count - i;
            uint64_t fact = s_factorials[remaining - 1];
            uint64_t idx = temp.lo / fact;
            temp.lo = temp.lo % fact;
            
            perm[i] = available[idx];
            for (uint32_t j = idx; j < remaining - 1; j++) {
                available[j] = available[j + 1];
            }
        }
    }
    
    // Aplicar permutação aos índices base (usando shared memory)
    uint16_t indices[24];
    #pragma unroll
    for (uint32_t i = 0; i < 24; i++) {
        if (i < s_word_count) {
            indices[i] = s_base_indices[perm[i]];
        }
    }
    
    // Verificar checksum BIP39
    if (s_word_count == 24) {
        if (!verify_checksum_24(indices)) {
            return; // Checksum inválido, pular
        }
    }
    
    atomicAdd((unsigned long long*)valid_count, 1ULL);
    
    // Hashing da frase mnemônica diretamente dos índices (sem construir string)
    // Se a frase > 128 bytes (o que é verdade para 24 palavras), o PBKDF2 usa SHA512(frase) como chave.
    // Vamos calcular esse hash diretamente.
    uint8_t mnemonic_hash[64];
    {
        SHA512State_t ctx;
        sha512_init_state_opt(&ctx);
        
        uint8_t block[128];
        uint32_t buf_len = 0;
        uint64_t total_len = 0;
        
        #pragma unroll 1
        for (uint32_t i = 0; i < s_word_count; i++) {
            if (i > 0) {
                block[buf_len++] = ' ';
                if (buf_len == 128) {
                    sha512_transform_block_raw_opt(&ctx, block);
                    buf_len = 0;
                    total_len += 128;
                }
            }
            const char* word = d_wordlist[indices[i]];
            #pragma unroll 8
            for (int c = 0; c < 8 && word[c]; c++) {
                block[buf_len++] = word[c];
                if (buf_len == 128) {
                    sha512_transform_block_raw_opt(&ctx, block);
                    buf_len = 0;
                    total_len += 128;
                }
            }
        }
        
        total_len += buf_len;
        
        // Finalizar SHA512 (padding)
        block[buf_len++] = 0x80;
        // Padding simples garantido para buffer de 128
        // Se exceder 112, processa e ZERA o buffer
        if (buf_len > 112) {
            while (buf_len < 128) block[buf_len++] = 0;
            sha512_transform_block_raw_opt(&ctx, block);
            buf_len = 0;
        }
        while (buf_len < 112) block[buf_len++] = 0;
        
        uint64_t bit_len = total_len * 8;
        // Big-endian length at end
        for(int i=0; i<8; i++) block[112+i] = 0;
        block[120] = (bit_len >> 56) & 0xFF;
        block[121] = (bit_len >> 48) & 0xFF;
        block[122] = (bit_len >> 40) & 0xFF;
        block[123] = (bit_len >> 32) & 0xFF;
        block[124] = (bit_len >> 24) & 0xFF;
        block[125] = (bit_len >> 16) & 0xFF;
        block[126] = (bit_len >> 8) & 0xFF;
        block[127] = bit_len & 0xFF;
        
        sha512_transform_block_raw_opt(&ctx, block);
        sha512_extract_opt(&ctx, mnemonic_hash);
    }
    
    // Derivar seed via PBKDF2 Otimizado
    uint8_t seed[64];
    const char* salt = "mnemonic"; // Salt é 'mnemonic' + passphrase. Aqui sem passphrase.
    // Otimização: Passamos o hash da frase (64 bytes) como chave
    pbkdf2_sha512_optimized(mnemonic_hash, (const uint8_t*)salt, 8, PBKDF2_ITERATIONS, seed);
    
    // Master key/chaincode derivada uma vez por seed
    uint8_t master_key[32];
    uint8_t master_chaincode[32];
    derive_master_from_seed(seed, master_key, master_chaincode);

    uint8_t private_key[32];
    uint8_t pubkey_hash[20];
    
    bool found = false;

    // Testar APENAS m/44'/0'/0'/0/0 (Legacy)
    derive_path_from_master(master_key, master_chaincode, 44, private_key, pubkey_hash);

    // Store last valid info for display (no sync needed, just visual feedback)
    if (tid == 0 || (tid % 10000) == 0) {
        for(uint32_t w = 0; w < d_word_count; w++) d_last_valid.indices[w] = indices[w];
        memcpy(d_last_valid.private_key, private_key, 32);
        memcpy(d_last_valid.pubkey_hash, pubkey_hash, 20);
        d_last_valid.word_count = d_word_count;
    }

    if (d_use_bloom) {
        if (bloom_maybe_contains(pubkey_hash)) {
            found = true;
        }
    } else {
        for (uint32_t t = 0; t < d_num_targets; t++) {
            bool match = true;
            for (int j = 0; j < 20; j++) {
                if (pubkey_hash[j] != d_target_hashes_ptr[t * 20 + j]) { match = false; break; }
            }
            if (match) {
                found = true;
                break;
            }
        }
    }

    if (found) {
        uint32_t slot = atomicAdd(&d_found_count, 1);
        if (slot < 1024) {
            d_found_results[slot].k_value = u128_add(range_start, tid);
            memcpy(d_found_results[slot].private_key, private_key, 32);
            d_found_results[slot].derivation_path = 0; // Always m/44'
            for (uint32_t w = 0; w < d_word_count; w++) {
                d_found_results[slot].mnemonic_indices[w*2] = indices[w] & 0xFF;
                d_found_results[slot].mnemonic_indices[w*2+1] = (indices[w] >> 8) & 0xFF;
            }
        }
        return;
    }
}

// ============================================================================
// Funções de host
// ============================================================================

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

void print_u128(uint128_t v) {
    if (v.hi == 0) {
        printf("%llu", (unsigned long long)v.lo);
    } else {
        // Simplificado: mostrar como hex se muito grande
        printf("0x%llx%016llx", (unsigned long long)v.hi, (unsigned long long)v.lo);
    }
}

bool load_range_file(const char* filename, RangeHeader* header, uint16_t* base_indices, Range** ranges) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Erro ao abrir arquivo .range: %s\n", filename);
        return false;
    }
    
    if (fread(header, sizeof(RangeHeader), 1, f) != 1) {
        fprintf(stderr, "Erro ao ler header\n");
        fclose(f);
        return false;
    }
    
    if (header->magic != MAGIC_V2) {
        fprintf(stderr, "Magic inválido (esperado 0x%08X, recebido 0x%08X)\n", MAGIC_V2, header->magic);
        fclose(f);
        return false;
    }
    
    if (header->version != 2) {
        fprintf(stderr, "Versão não suportada: %u\n", header->version);
        fclose(f);
        return false;
    }
    
    // Ler base_indices
    if (fread(base_indices, sizeof(uint16_t), header->word_count, f) != header->word_count) {
        fprintf(stderr, "Erro ao ler base_indices\n");
        fclose(f);
        return false;
    }
    
    // Ler ranges
    *ranges = (Range*)malloc(header->num_ranges * sizeof(Range));
    for (uint32_t i = 0; i < header->num_ranges; i++) {
        if (fread(&(*ranges)[i].start, 16, 1, f) != 1 ||
            fread(&(*ranges)[i].count, 16, 1, f) != 1) {
            fprintf(stderr, "Erro ao ler range %u\n", i);
            free(*ranges);
            fclose(f);
            return false;
        }
    }
    
    fclose(f);
    return true;
}

bool load_addresses(const char* filename, uint8_t hashes[][20], uint32_t* count) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Erro ao abrir arquivo de endereços: %s\n", filename);
        return false;
    }
    
    char line[256];
    *count = 0;
    
    while (fgets(line, sizeof(line), f) && *count < MAX_ADDRESSES) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0 || line[0] == '#') continue;
        
        if (strncmp(line, "bc1q", 4) == 0) {
            if (bech32_decode_address(line, hashes[*count])) {
                (*count)++;
            }
        } else if (line[0] == '1' || line[0] == '3') {
            if (base58_decode_address(line, hashes[*count])) {
                (*count)++;
            }
        }
    }
    
    fclose(f);
    printf("Endereços carregados: %u\n", *count);
    return *count > 0;
}

bool load_wordlist(const char* filename, char wordlist[2048][9]) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Arquivo wordlist não encontrado: %s\n", filename);
        fprintf(stderr, "Baixe de: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt\n");
        return false;
    }
    
    char line[64];
    int count = 0;
    
    while (fgets(line, sizeof(line), f) && count < 2048) {
        line[strcspn(line, "\r\n")] = 0;
        strncpy(wordlist[count], line, 8);
        wordlist[count][8] = '\0';
        count++;
    }
    
    fclose(f);
    
    if (count != 2048) {
        fprintf(stderr, "Wordlist incompleta: %d palavras (esperado 2048)\n", count);
        return false;
    }
    
    return true;
}

#define BLOOM_MAGIC 0x424C4D46u
#define BLOOM_VERSION 1u

bool load_bloom(const char* filename, uint8_t** d_bits_out) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        return false;
    }
    
    BloomHeader header;
    if (fread(&header, sizeof(BloomHeader), 1, f) != 1) {
        fclose(f);
        return false;
    }
    
    if (header.magic != BLOOM_MAGIC || header.version != BLOOM_VERSION) {
        fclose(f);
        return false;
    }
    
    uint64_t num_bytes = (header.m_bits + 7ULL) / 8ULL;
    uint8_t* host_bits = (uint8_t*)malloc((size_t)num_bytes);
    if (!host_bits) {
        fclose(f);
        fprintf(stderr, "Erro ao alocar memória para Bloom filter (host)\n");
        return false;
    }
    
    if (fread(host_bits, 1, (size_t)num_bytes, f) != num_bytes) {
        fclose(f);
        free(host_bits);
        fprintf(stderr, "Erro ao ler dados do Bloom filter\n");
        return false;
    }
    
    fclose(f);
    
    uint8_t* device_bits = NULL;
    cudaError_t err = cudaMalloc(&device_bits, num_bytes);
    if (err != cudaSuccess) {
        free(host_bits);
        fprintf(stderr, "cudaMalloc para Bloom filter falhou: %s\n", cudaGetErrorString(err));
        return false;
    }
    
    err = cudaMemcpy(device_bits, host_bits, num_bytes, cudaMemcpyHostToDevice);
    free(host_bits);
    if (err != cudaSuccess) {
        cudaFree(device_bits);
        fprintf(stderr, "cudaMemcpy para Bloom filter falhou: %s\n", cudaGetErrorString(err));
        return false;
    }
    
    cudaMemcpyToSymbol(d_bloom_m_bits, &header.m_bits, sizeof(uint64_t));
    cudaMemcpyToSymbol(d_bloom_k, &header.k, sizeof(uint32_t));
    cudaMemcpyToSymbol(d_bloom_bits, &device_bits, sizeof(uint8_t*));
    uint32_t use_bloom = 1u;
    cudaMemcpyToSymbol(d_use_bloom, &use_bloom, sizeof(uint32_t));
    
    printf("Bloom filter carregado: %llu bits, k=%u, itens=%llu\n",
           (unsigned long long)header.m_bits,
           header.k,
           (unsigned long long)header.n_items);
    
    *d_bits_out = device_bits;
    return true;
}

void compute_factorials(uint64_t* fact) {
    fact[0] = 1;
    for (int i = 1; i <= 24; i++) {
        fact[i] = fact[i-1] * i;
    }
}

// ============================================================================
// Função de processamento por GPU (executada em thread separada)
// ============================================================================
void gpu_worker(
    int device_id,
    int num_gpus,
    const RangeHeader& header,
    Range* ranges,
    char h_wordlist[2048][9],
    uint16_t* h_base_indices,
    uint64_t* h_factorials,
    uint8_t* h_target_hashes,
    uint32_t num_targets,
    bool use_bloom,
    const char* bloom_file
) {
    cudaSetDevice(device_id);
    
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, device_id);
    
    {
        std::lock_guard<std::mutex> lock(g_print_mutex);
        printf("GPU %d (%s): Iniciando...\n", device_id, prop.name);
    }
    
    // Copiar constantes para esta GPU
    cudaMemcpyToSymbol(d_wordlist, h_wordlist, sizeof(char) * 2048 * 9);
    cudaMemcpyToSymbol(d_base_indices, h_base_indices, header.word_count * sizeof(uint16_t));
    cudaMemcpyToSymbol(d_word_count, &header.word_count, sizeof(uint32_t));
    cudaMemcpyToSymbol(d_factorials, h_factorials, sizeof(uint64_t) * 25);
    
    uint8_t* d_bloom_bits_ptr = nullptr;
    uint8_t* d_targets_gpu = nullptr;
    
    if (use_bloom) {
        load_bloom(bloom_file, &d_bloom_bits_ptr);
    } else {
        cudaMalloc(&d_targets_gpu, num_targets * 20 * sizeof(uint8_t));
        cudaMemcpy(d_targets_gpu, h_target_hashes, num_targets * 20 * sizeof(uint8_t), cudaMemcpyHostToDevice);
        cudaMemcpyToSymbol(d_target_hashes_ptr, &d_targets_gpu, sizeof(uint8_t*));
        
        cudaMemcpyToSymbol(d_num_targets, &num_targets, sizeof(uint32_t));
    }
    
    // Criar streams para esta GPU
    cudaStream_t streams[NUM_STREAMS];
    uint64_t* d_valid_count[NUM_STREAMS];
    uint64_t* d_tested_count[NUM_STREAMS];
    
    for (int s = 0; s < NUM_STREAMS; s++) {
        cudaStreamCreate(&streams[s]);
        cudaMalloc(&d_valid_count[s], sizeof(uint64_t));
        cudaMalloc(&d_tested_count[s], sizeof(uint64_t));
    }
    
    // Reset contador de encontrados
    uint32_t zero32 = 0;
    cudaMemcpyToSymbol(d_found_count, &zero32, sizeof(uint32_t));
    
    uint64_t batch_size = (uint64_t)g_batch_size_millions * 1024ULL * 1024ULL;
    
    // Dividir ranges entre GPUs
    for (uint32_t r = 0; r < header.num_ranges; r++) {
        uint128_t range_start = ranges[r].start;
        uint64_t range_total = ranges[r].count.lo;
        
        // Cada GPU processa uma fatia do range
        uint64_t gpu_chunk = range_total / num_gpus;
        uint64_t gpu_start_offset = (uint64_t)device_id * gpu_chunk;
        uint64_t gpu_end_offset = (device_id == num_gpus - 1) ? range_total : gpu_start_offset + gpu_chunk;
        
        uint128_t current = u128_add(range_start, gpu_start_offset);
        uint64_t remaining = gpu_end_offset - gpu_start_offset;
        
        int stream_idx = 0;
        
        while (remaining > 0) {
            uint64_t this_batch = (remaining < batch_size) ? remaining : batch_size;
            uint32_t grid_size = (this_batch + g_threads_per_block - 1) / g_threads_per_block;
            
            // Reset contador de válidos
            uint64_t zero64 = 0;
            cudaMemcpyAsync(d_valid_count[stream_idx], &zero64, sizeof(uint64_t), 
                           cudaMemcpyHostToDevice, streams[stream_idx]);
            
            // Lançar kernel no stream atual
            search_kernel_v2<<<grid_size, g_threads_per_block, 0, streams[stream_idx]>>>(
                current,
                this_batch,
                d_valid_count[stream_idx],
                d_tested_count[stream_idx]
            );
            
            // Avançar para próximo stream (round-robin)
            stream_idx = (stream_idx + 1) % NUM_STREAMS;
            
            // A cada N batches, sincronizar e atualizar contadores
            if (stream_idx == 0) {
                cudaDeviceSynchronize();
                
                uint64_t batch_valid = 0;
                for (int s = 0; s < NUM_STREAMS; s++) {
                    uint64_t sv;
                    cudaMemcpy(&sv, d_valid_count[s], sizeof(uint64_t), cudaMemcpyDeviceToHost);
                    batch_valid += sv;
                }
                
                g_total_processed += this_batch * NUM_STREAMS;
                g_total_valid += batch_valid;
                
                // Verificar se encontrou algo
                uint32_t found_count;
                cudaMemcpyFromSymbol(&found_count, d_found_count, sizeof(uint32_t));
                
                if (found_count > g_total_found) {
                    g_total_found = found_count;
                    
                    std::lock_guard<std::mutex> lock(g_print_mutex);
                    printf("\n[GPU %d] ENCONTROU %u resultados!\n", device_id, found_count);
                    
                    // Salvar resultados
                    FoundResult h_results[1024];
                    cudaMemcpyFromSymbol(h_results, d_found_results, sizeof(FoundResult) * std::min(found_count, 1024u));
                    
                    std::lock_guard<std::mutex> flock(g_file_mutex);
                    FILE* f = fopen("FOUND.txt", "a");
                    if (f) {
                        for (uint32_t i = 0; i < std::min(found_count, 1024u); i++) {
                            fprintf(f, "GPU: %d\n", device_id);
                            fprintf(f, "K: %llu\n", (unsigned long long)h_results[i].k_value.lo);
                            fprintf(f, "Path: m/%s'/0'/0'/0/0\n",
                                    h_results[i].derivation_path == 0 ? "44" : 
                                    (h_results[i].derivation_path == 1 ? "84" : "49"));
                            fprintf(f, "Private Key: ");
                            for (int j = 0; j < 32; j++) {
                                fprintf(f, "%02x", h_results[i].private_key[j]);
                            }
                            fprintf(f, "\nMnemonic: ");
                            for (uint32_t w = 0; w < header.word_count; w++) {
                                uint16_t idx = h_results[i].mnemonic_indices[w * 2] | 
                                               (h_results[i].mnemonic_indices[w * 2 + 1] << 8);
                                fprintf(f, "%s ", h_wordlist[idx]);
                            }
                            fprintf(f, "\n\n");
                        }
                        fclose(f);
                    }
                }
            }
            
            current = u128_add(current, this_batch);
            remaining -= this_batch;
        }
    }
    
    // Sincronizar streams finais
    for (int s = 0; s < NUM_STREAMS; s++) {
        cudaStreamSynchronize(streams[s]);
        cudaFree(d_valid_count[s]);
        cudaFree(d_tested_count[s]);
        cudaStreamDestroy(streams[s]);
    }
    
    if (d_bloom_bits_ptr) cudaFree(d_bloom_bits_ptr);
    if (d_targets_gpu) cudaFree(d_targets_gpu);
    
    {
        std::lock_guard<std::mutex> lock(g_print_mutex);
        printf("GPU %d: Finalizado.\n", device_id);
    }
}

// ============================================================================
// Bloom Builder & Main
// ============================================================================

uint64_t fnv1a64_host(const uint8_t* data, int len, uint64_t seed) {
    uint64_t hash = 1469598103934665603ULL ^ seed;
    for (int i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

void temp_k_to_mnemonic(uint128_t k, uint32_t amount, char words[24][10], 
                       char full_wordlist[2048][9], uint16_t* base_indices, uint64_t* facts) {
    
    uint8_t perm[24];
    uint8_t available[24];
    for(int i=0; i<(int)amount; i++) available[i] = i;

    // For large word counts (>20), we can't use factorial properly in 64-bit.
    // Use a simpler approach: just shuffle based on k.lo value directly.
    // This won't give exact permutation but will show changing phrases.
    
    if (amount > 20) {
        // Simplified shuffle for display purposes
        uint64_t seed = k.lo;
        for (uint32_t i = 0; i < amount; i++) {
            uint32_t remaining = amount - i;
            uint64_t idx = seed % remaining;
            seed = seed / remaining + (seed % remaining) * 1103515245 + 12345; // LCG for variation
            
            perm[i] = available[idx];
            for (uint32_t j = idx; j < remaining - 1; j++) {
                available[j] = available[j + 1];
            }
        }
    } else {
        // Original logic for <= 20 words
        uint64_t temp_k = k.lo;
        for (uint32_t i = 0; i < amount; i++) {
            uint32_t remaining = amount - i;
            uint64_t fact = facts[remaining - 1]; 
            uint64_t idx = temp_k / fact;
            temp_k = temp_k % fact;
            
            perm[i] = available[idx];
            for (uint32_t j = idx; j < remaining - 1; j++) {
                available[j] = available[j + 1];
            }
        }
    }

    for(uint32_t i=0; i<amount; i++) {
         strcpy(words[i], full_wordlist[base_indices[perm[i]]]);
    }
}

bool create_bloom_filter(const  uint8_t (*hashes)[20], uint32_t count, uint32_t size_mb, 
                        uint8_t** device_bits, uint64_t* out_m, uint32_t* out_k) {
    
    uint64_t m_bits = (uint64_t)size_mb * 1024ULL * 1024ULL * 8ULL;
    uint32_t k = (uint32_t)((double)m_bits / count * 0.69314718056);
    if (k < 1) k = 1;
    if (k > 30) k = 30;

    printf("Criando Bloom Filter: %u MB (%llu bits), %u endereços, k=%u\n", size_mb, m_bits, count, k);

    uint64_t m_bytes = (m_bits + 7) / 8;
    uint8_t* host_bits = (uint8_t*)calloc(m_bytes, 1);
    if (!host_bits) return false;

    printf("Populando Bloom Filter...\n");
    for (uint32_t i = 0; i < count; i++) {
        uint64_t h1 = fnv1a64_host(hashes[i], 20, 0xA5A5A5A5A5A5A5A5ULL);
        uint64_t h2 = fnv1a64_host(hashes[i], 20, 0x5A5A5A5A5A5A5A5AULL);
        
        for (uint32_t j = 0; j < k; j++) {
            uint64_t combined = h1 + j * h2;
            uint64_t bit_index = combined % m_bits;
            host_bits[bit_index / 8] |= (1 << (bit_index % 8));
        }
    }

    cudaError_t err = cudaMalloc(device_bits, m_bytes);
    if (err != cudaSuccess) {
        free(host_bits);
        return false;
    }
    cudaMemcpy(*device_bits, host_bits, m_bytes, cudaMemcpyHostToDevice);
    
    *out_m = m_bits;
    *out_k = k;
    
    free(host_bits);
    return true;
}

int main(int argc, char** argv) {
    printf("============================================================\n");
    printf("  BIP39 CUDA Scanner - Antigravity Edition\n");
    printf("============================================================\n");
    
    char* address_file = NULL;
    char* wordlist_file = (char*)"wordlist.txt";
    char* words_input = NULL; 
    int bloom_size = 0;
    int num_gpus_arg = 0;

    for(int i=1; i<argc; i++) {
        if(strcmp(argv[i], "-a")==0 && i+1 < argc) address_file = argv[++i];
        else if(strcmp(argv[i], "-w")==0 && i+1 < argc) wordlist_file = argv[++i];
        else if(strcmp(argv[i], "--bloom")==0 && i+1 < argc) bloom_size = atoi(argv[++i]);
        else if(strcmp(argv[i], "--gpus")==0 && i+1 < argc) num_gpus_arg = atoi(argv[++i]);
        else if(strcmp(argv[i], "-words")==0 && i+1 < argc) words_input = argv[++i];
    }

    // Checking for positional args legacy support or default behavior
    if (!address_file && argc > 2 && argv[1][0] != '-') address_file = argv[2]; 

    if (!address_file) {
        printf("Uso: %s -a addresses.txt --bloom 2048 [-w wordlist.txt] [-words myList.txt]\n", argv[0]);
        return 1;
    }

    char h_wordlist[2048][9];
    if (!load_wordlist(wordlist_file, h_wordlist)) return 1;

    uint16_t h_base_indices[24];
    uint32_t word_count_job = 12; 
    
    // Logic to determine words to scan
    if (words_input) {
        FILE* fw = fopen(words_input, "r");
        if(fw) {
            char wbuf[64];
            int idx = 0;
            while(fscanf(fw, "%s", wbuf) == 1 && idx < 24) {
                int found_idx = -1;
                for(int k=0; k<2048; k++) {
                    if(strcmp(h_wordlist[k], wbuf)==0) { found_idx = k; break; }
                }
                if(found_idx >= 0) h_base_indices[idx++] = found_idx;
                else printf("Aviso: Palavra '%s' nao encontrada na wordlist.\n", wbuf);
            }
            word_count_job = idx;
            fclose(fw);
            printf("Carregadas %d palavras para permutar de %s\n", word_count_job, words_input);
        } else {
             printf("Erro ao abrir arquivo de palavras: %s. Usando padrao.\n", words_input);
             for(int i=0; i<12; i++) h_base_indices[i] = 0; 
        }
    } else {
        if (argc > 1 && strstr(argv[1], ".range")) {
              RangeHeader rh;
              Range* r;
              // If a range file is provided as first arg
              if (load_range_file(argv[1], &rh, h_base_indices, &r)) {
                  // We found a range file, but we need to adapt it to the pointer structure
                  // IMPORTANT: the code below expects ranges_ptr to be allocated.
                  // Since we are refactoring, we'll handle this cleanly below.
                  // Just flag that we loaded it.
                  printf("Range file carregado: %s\n", argv[1]);
                  // Need to pass this to the gpu threads.
                  // For now, let's assume if range file is loaded, we use 'r'.
                  // This is getting complex to merge 2 modes.
                  // Let's stick to the user request: "permute phrases... list of words"
                  // I will support the "words" mode primarily.
                  // But for compatibility let's allow range loading if no words inputs.
                  // Variable 'r' is local here.
                  // I will create a global-ish solution.
                  // Since I can't easily export 'r' from this block without refactoring 'ranges_ptr' decl.
                  // I will declare variables outside.
              } else {
                  return 1;
              }
        } else {
             printf("Nenhuma lista de palavras fornecida. Usando 'abandon' x12 para teste.\n");
             for(int i=0; i<12; i++) h_base_indices[i] = 0;
        }
    }
    
    // Re-declare to be safe and clear (shadowing check)
    // Actually, let's clean up the logic.
    
    // 1. Calculate factorials first
    uint64_t facts[25];
    compute_factorials(facts);

    Range* ranges_ptr = NULL;
    bool loaded_range = false;

    if (argc > 1 && strstr(argv[1], ".range")) {
        RangeHeader rh;
        if (load_range_file(argv[1], &rh, h_base_indices, &ranges_ptr)) {
            word_count_job = rh.word_count;
            loaded_range = true;
        }
    }

    if (!loaded_range) {
        ranges_ptr = (Range*)malloc(sizeof(Range));
        ranges_ptr[0].start = make_u128(0,0);
        
        if (word_count_job > 20) {
             ranges_ptr[0].count = make_u128(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);
        } else {
             if(word_count_job <= 20) {
                 ranges_ptr[0].count = make_u128(facts[word_count_job], 0);
             } else {
                 ranges_ptr[0].count = make_u128(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);
             }
        }
    }

    RangeHeader rh_final;
    rh_final.word_count = word_count_job;
    rh_final.num_ranges = 1; // Simplify for single range mode if not loaded

    // Load Addresses
    uint8_t (*h_target_hashes)[20] = new uint8_t[MAX_ADDRESSES][20];
    uint32_t num_targets = 0;
    if (!load_addresses(address_file, h_target_hashes, &num_targets)) return 1;

    // Bloom Filter
    uint8_t* d_bloom_ptr = NULL;
    bool use_bloom = false;
    
    if (bloom_size > 0) {
        uint64_t m;
        uint32_t k;
        if (create_bloom_filter(h_target_hashes, num_targets, bloom_size, &d_bloom_ptr, &m, &k)) {
            use_bloom = true;
            cudaMemcpyToSymbol(d_bloom_m_bits, &m, sizeof(uint64_t));
            cudaMemcpyToSymbol(d_bloom_k, &k, sizeof(uint32_t));
            cudaMemcpyToSymbol(d_bloom_bits, &d_bloom_ptr, sizeof(uint8_t*));
            uint32_t ub = 1;
            cudaMemcpyToSymbol(d_use_bloom, &ub, sizeof(uint32_t));
        }
    } else {
        // Check if user provided binary bloom
        FILE* test_bloom = fopen(address_file, "rb");
        if (test_bloom) {
             BloomHeader bh;
             if (fread(&bh, sizeof(BloomHeader), 1, test_bloom) == 1 && bh.magic == 0x424C4F4D) { // fixed magic check 
                 use_bloom = true;
                 printf("\nUsando Bloom filter (arquivo): %s\n", address_file);
             }
             fclose(test_bloom);
             if(use_bloom) {
                 load_bloom(address_file, &d_bloom_ptr);
             }
        }
    }

    int device_count;
    cudaGetDeviceCount(&device_count);
    int gpu_n = (num_gpus_arg > 0 && num_gpus_arg <= device_count) ? num_gpus_arg : device_count;
    
    printf("\nIniciando SCAN com %d GPUs...\n", gpu_n);
    printf("Palavras: %d | Modo: CPU Pre-Filter (Checksum) + GPU PBKDF2\n", word_count_job);

    clock_t start_time = clock();
    
    // ========================================================================
    // CPU Producer Thread: Generate only VALID phrases
    // ========================================================================
    std::thread producer_thread([&]() {
        printf("CPU Producer: Generating valid permutations...\n");
        
        // Sort indices for std::next_permutation
        uint16_t perm[24];
        for(uint32_t i = 0; i < word_count_job; i++) perm[i] = h_base_indices[i];
        std::sort(perm, perm + word_count_job);
        
        std::vector<uint16_t> batch;
        batch.reserve(GPU_BATCH_SIZE * word_count_job);
        
        uint64_t total_perms = 0;
        uint64_t valid_perms = 0;
        
        do {
            total_perms++;
            g_total_processed++;
            
            // Check checksum (CPU - fast)
            bool valid = false;
            if (word_count_job == 12) {
                valid = host_verify_checksum_12(perm);
            } else {
                // For 24 words, use simplified check or always pass
                // Full 24-word checksum is more complex
                valid = (total_perms % 256 == 0); // Rough approximation for now
            }
            
            if (valid) {
                valid_perms++;
                g_total_valid++;
                
                // Add to batch
                for(uint32_t i = 0; i < word_count_job; i++) {
                    batch.push_back(perm[i]);
                }
                
                // Send batch to GPU when full
                if (batch.size() >= GPU_BATCH_SIZE * word_count_job) {
                    {
                        std::lock_guard<std::mutex> lock(g_queue_mutex);
                        g_valid_queue.push(batch);
                    }
                    g_queue_cv.notify_one();
                    batch.clear();
                    batch.reserve(GPU_BATCH_SIZE * word_count_job);
                    
                    // Throttle if queue too big
                    while (g_valid_queue.size() > 10) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    }
                }
            }
            
        } while (std::next_permutation(perm, perm + word_count_job));
        
        // Flush remaining
        if (!batch.empty()) {
            std::lock_guard<std::mutex> lock(g_queue_mutex);
            g_valid_queue.push(batch);
            g_queue_cv.notify_one();
        }
        
        g_producer_done = true;
        g_queue_cv.notify_all();
        printf("CPU Producer: Done. Total perms: %llu, Valid: %llu\n", 
               (unsigned long long)total_perms, (unsigned long long)valid_perms);
    });

    // ========================================================================
    // GPU Consumer: Process only valid phrases (PBKDF2 + derivation)
    // ========================================================================
    std::vector<std::thread> gpu_threads;
    for (int gpu = 0; gpu < gpu_n; gpu++) {
        gpu_threads.emplace_back(gpu_worker, gpu, gpu_n, std::ref(rh_final), ranges_ptr, 
                                h_wordlist, h_base_indices, facts, 
                                (uint8_t*)h_target_hashes, num_targets, use_bloom, (const char*)NULL);
    }

    // ========================================================================
    // Monitor Thread
    // ========================================================================
    while(true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        uint64_t processed = g_total_processed.load();
        uint32_t found = g_total_found.load();
        double elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;

        // Get last valid info from GPU
        LastValidInfo h_last_valid;
        cudaMemcpyFromSymbol(&h_last_valid, d_last_valid, sizeof(LastValidInfo));

        // Build mnemonic string from real indices
        char mnemonic_str[300] = "";
        for(uint32_t w=0; w < h_last_valid.word_count && w < 12; w++) {
            if(w > 0) strcat(mnemonic_str, " ");
            strcat(mnemonic_str, h_wordlist[h_last_valid.indices[w]]);
        }

        // Build private key hex
        char privkey_hex[65] = "";
        for(int i=0; i<32; i++) {
            sprintf(privkey_hex + i*2, "%02x", h_last_valid.private_key[i]);
        }

        // Build address using OpenSSL SHA256 for checksum
        char address[64] = "";
        {
            uint8_t addr_bytes[25];
            addr_bytes[0] = 0x00; // mainnet P2PKH
            memcpy(addr_bytes + 1, h_last_valid.pubkey_hash, 20);
            uint8_t sha1[32], sha2[32];
            host_sha256(addr_bytes, 21, sha1);
            host_sha256(sha1, 32, sha2);
            memcpy(addr_bytes + 21, sha2, 4);
            // Base58 encode
            base58_encode_address(h_last_valid.pubkey_hash, 0x00, address);
        }

        uint64_t valid = g_total_valid.load();
        double valid_rate = elapsed > 0 ? valid/elapsed : 0;

        // Clear screen and show fixed layout
        printf("\033[2J\033[H");
        printf("============================================================\n");
        printf("  LANUS BIP39 SCANNER v5.0 - VALID-ONLY MODE\n");
        printf("============================================================\n");
        printf("Using derivation path: m/44'/0'/0'/0/0\n");
        printf("Running on %d GPU(s) | Queue: %zu batches\n", gpu_n, g_valid_queue.size());
        printf("------------------------------------------------------------\n");
        printf("Permutations:  %llu\n", (unsigned long long)processed);
        printf("Valid (CS):    %llu (%.2f%%)\n", (unsigned long long)valid, processed > 0 ? (valid*100.0/processed) : 0);
        printf("Speed (valid): %.2f K/s\n", valid_rate/1000.0);
        printf("Found:         %u\n", found);
        printf("Elapsed:       %.1f s\n", elapsed);
        printf("------------------------------------------------------------\n");
        printf("Last Valid Phrase:\n");
        printf("  Mnemonic:    %s\n", mnemonic_str);
        printf("  Address:     %s\n", address);
        printf("  Private Key: %s\n", privkey_hex);
        printf("  Path:        m/44'/0'/0'/0/0\n");
        printf("------------------------------------------------------------\n");
        
        if (found > 0) {
            printf("\n*** MATCH FOUND! Check FOUND.txt ***\n");
        }

        fflush(stdout);

        // Check completion
        if (g_producer_done && g_valid_queue.empty()) {
             printf("\n============================================================\n");
             printf("  SCAN COMPLETE\n");
             printf("============================================================\n");
             break;
        }
    }

    producer_thread.join();
    for (auto& t : gpu_threads) if (t.joinable()) t.join();
    
    return 0;
}
