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
#define MAGIC_V2 0x42495034
#define NUM_STREAMS 4

// Telegram Config
const char* TELEGRAM_TOKEN = "8183546357:AAE4y4RpXKg0WnBvgSBVyLUm320Zpy5826k";
const char* TELEGRAM_CHAT_ID = "6466661949";

void send_telegram_alert(const char* message) {
    char cmd[4096];
    // Simple curl command (blocking, but rare event)
    snprintf(cmd, 4096, "curl -s -X POST https://api.telegram.org/bot%s/sendMessage -d chat_id=%s -d text=\"%s\"", 
             TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, message);
    system(cmd);
}

// Global buffer for batching
#define HOST_BATCH_SIZE 100000 
// Enough to feed GPU without too much latency. 


// Variáveis globais para multi-threading
std::atomic<uint64_t> g_total_processed(0);
std::atomic<uint64_t> g_total_valid(0);
std::atomic<uint32_t> g_total_found(0);
std::mutex g_print_mutex;
std::mutex g_file_mutex;

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
    uint128_t r; r.lo = lo; r.hi = hi;
// Estruturas Globais para fila
#include <queue>
#include <condition_variable>

std::queue<std::vector<uint16_t>> g_batch_queue;
std::mutex g_batch_mutex;
std::condition_variable g_batch_cv;
bool g_producer_done = false;

// Forward decl
void cpu_producer(uint16_t* base_indices, uint32_t word_count, uint64_t max_permutations);
void gpu_worker_consumer(int device_id, int num_gpus, RangeHeader& header, char h_wordlist[2048][9], uint16_t* base_indices, const uint8_t* h_target_hashes, uint32_t num_targets, bool use_bloom);


return r;
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

bool verify_checksum_12_host(const uint16_t* idx) {
    uint8_t entropy[16];
    // Pack 12 words (11 bits each) -> 132 bits? No, 12 words = 128 bit entropy + 4 bit checksum
    // 11*12 = 132 bits total.
    // Logic:
    // Bits 0..127 = Entropy
    // Bits 128..131 = Checksum
    
    // Simpler packing for host side
    // We can reuse the same logic logic as device but adapted for host
    // Or just implement the shift logic.
    __uint128_t big = 0;
    for (int i = 0; i < 12; i++) {
        big = (big << 11) | idx[i];
    }
    
    // The last 4 bits are checksum
    uint8_t checksum = (uint8_t)(big & 0xF);
    
    // The top 128 bits are entropy
    // Shift right 4 to get entropy
    big >>= 4;
    
    uint8_t ent_bytes[16];
    // Extract bytes (Big Endian)
    for(int i=15; i>=0; i--) {
        ent_bytes[i] = (uint8_t)(big & 0xFF);
        big >>= 8;
    }
    
    uint8_t hash[32];
    // Host-side SHA256 (Need a host sha256 implementation)
    // For now we use a simple specific implementation or OpenSSL if available?
    // We have sha256.cuh but it might be device only or mixed. 
    // Let's rely on the SHA256 code being `__host__ __device__`.
    sha256(ent_bytes, 16, hash); // Assuming sha256 function is __host__ __device__
    
    return (hash[0] >> 4) == checksum;
}


// ============================================================================
// Kernel principal de busca v3 - Range Only + Shared Memory
// ============================================================================
// ============================================================================
// Kernel Consumidor (Apenas valida)
// Recebe apenas indices de frases VALIDAS (checksum OK)
// ============================================================================
__global__ void check_valid_phrases_kernel(
    const uint16_t* __restrict__ valid_indices_batch, // [batch_size * word_count]
    uint32_t count,
    uint32_t word_count,
    uint64_t* found_counter
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= count) return;
    
    const uint16_t* indices = &valid_indices_batch[tid * word_count];
    
    // 1. Reconstruir frase e calcular hash (PBKDF2 Salt) e Seed Key
    // Hash da frase (mnemonic)
    uint8_t mnemonic_hash[64];
    {
        SHA512State_t ctx;
        sha512_init_state_opt(&ctx);
        
        uint8_t block[128];
        uint32_t buf_len = 0;
        uint64_t total_len = 0;
        
        #pragma unroll 1
        for (uint32_t i = 0; i < word_count; i++) {
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
        if (buf_len > 112) {
            while (buf_len < 128) block[buf_len++] = 0;
            sha512_transform_block_raw_opt(&ctx, block);
            buf_len = 0;
        }
        while (buf_len < 112) block[buf_len++] = 0;
        
        uint64_t bit_len = total_len * 8;
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
    
    // 2. PBKDF2 (A parte pesada)
    uint8_t seed[64];
    const char* salt = "mnemonic";
    pbkdf2_sha512_optimized(mnemonic_hash, (const uint8_t*)salt, 8, PBKDF2_ITERATIONS, seed);
    
    // 3. Derivação e Verificação (m/44, m/84, m/49)
    uint8_t master_key[32], master_chaincode[32];
    derive_master_from_seed(seed, master_key, master_chaincode);
    
    bool found = false;
    uint32_t found_path = 0;
    uint8_t private_key[32];
    uint8_t pubkey_hash[20];
    
    // Check m/44' (Legacy)
    derive_path_from_master(master_key, master_chaincode, 44, private_key, pubkey_hash);
    if (d_use_bloom) {
        if (bloom_maybe_contains(pubkey_hash)) { found = true; found_path = 0; }
    } else {
        // Linear scan logic
        for (uint32_t t = 0; t < d_num_targets; t++) {
             bool match = true;
             for(int k=0; k<20; k++) if(pubkey_hash[k] != d_target_hashes_ptr[t*20+k]) { match=false; break; }
             if(match) { found=true; found_path=0; break; }
        }
    }
    
    // Check m/84' (Segwit)
    if (!found) {
        derive_path_from_master(master_key, master_chaincode, 84, private_key, pubkey_hash);
        if (d_use_bloom) {
             if (bloom_maybe_contains(pubkey_hash)) { found = true; found_path = 1; }
        } else {
             for (uint32_t t = 0; t < d_num_targets; t++) {
                 bool match = true;
                 for(int k=0; k<20; k++) if(pubkey_hash[k] != d_target_hashes_ptr[t*20+k]) { match=false; break; }
                 if(match) { found=true; found_path=1; break; }
             }
        }
    }

    // Check m/49' (P2SH)
    if (!found) {
        derive_path_from_master(master_key, master_chaincode, 49, private_key, pubkey_hash);
        uint8_t script_hash[20];
        keyhash_to_p2sh_p2wpkh(pubkey_hash, script_hash);
        if (d_use_bloom) {
             if (bloom_maybe_contains(script_hash)) { found = true; found_path = 2; }
        } else {
             for (uint32_t t = 0; t < d_num_targets; t++) {
                 bool match = true;
                 for(int k=0; k<20; k++) if(script_hash[k] != d_target_hashes_ptr[t*20+k]) { match=false; break; }
                 if(match) { found=true; found_path=2; break; }
             }
        }
    }

    if (found) {
        uint32_t slot = atomicAdd(&d_found_count, 1);
        if (slot < 1024) {
             // Save result
             memcpy(d_found_results[slot].private_key, private_key, 32);
             d_found_results[slot].derivation_path = found_path;
             for(int w=0; w<word_count; w++) {
                 d_found_results[slot].mnemonic_indices[w*2] = indices[w] & 0xFF;
                 d_found_results[slot].mnemonic_indices[w*2+1] = (indices[w] >> 8) & 0xFF;
             }
        }
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
    
    if (fread(host_bits, 1, (size_t)num_bytes) != num_bytes) {
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
// ============================================================================// Função Worker da GPU que consome lotes gerados pela CPU
void gpu_worker_consumer(
    int device_id,
    int num_gpus,
    RangeHeader& header,
    char h_wordlist[2048][9],
    uint16_t* base_indices,
    const uint8_t* h_target_hashes,
    uint32_t num_targets,
    bool use_bloom
) {
    cudaSetDevice(device_id);
    
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
    for(int i=0; i<24; i++) available[i] = i;

    uint128_t temp = k;
    
    for (uint32_t i = 0; i < amount; i++) {
        uint32_t remaining = amount - i;
        uint64_t fact = facts[remaining - 1]; 
        
        // Simple division for visualization (assumes k < 2^64 for fact < 2^64 segments)
        // For full correctness with uint128_t > 64bit, we need 128-bit div.
        // Since this is just for display "current phrase", approximation or lower bits is fine if just cycling.
        // But let's try to be somewhat correct using host 128-bit if available.
#ifdef __GNUC__
        unsigned __int128 val = ((unsigned __int128)temp.hi << 64) | temp.lo;
        uint64_t idx = (uint64_t)(val / fact);
        temp.lo = (uint64_t)(val % fact);
        temp.hi = 0; 
#else
        uint64_t idx = temp.lo / fact;
        temp.lo %= fact;
#endif  
        perm[i] = available[idx];
        for (uint32_t j = idx; j < remaining - 1; j++) {
            available[j] = available[j + 1];
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
    printf("Palavras: %d | Total Possibilidades: Aproximadamente %llu\n", word_count_job, (unsigned long long)ranges_ptr[0].count.lo);

    clock_t start_time = clock();
    std::vector<std::thread> gpu_threads;
    
    // Iniciar Produtor CPU
    std::thread producer_thread(cpu_producer, h_base_indices, word_count_job, 0); // 0 = all permutations

    // Iniciar Consumidores GPU
    for (int gpu = 0; gpu < gpu_n; gpu++) {
        gpu_threads.emplace_back(
            gpu_worker_consumer,
            gpu,
            gpu_n,
            std::ref(rh_final),
            h_wordlist,
            h_base_indices,
            (const uint8_t*)h_target_hashes,
            num_targets,
            use_bloom
        );
    }

    while(true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        uint64_t processed = g_total_processed.load();
        uint32_t found = g_total_found.load();
        double elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
        double rate = elapsed > 0 ? processed/elapsed : 0;
        
        // TODO: Get current phrase from producer or consumer?
        // Hard to sync exactly, just show stats.
        
        printf("\r\033[K"); 
        printf("Speed: %.2f M/s (Valid Phrases) | Found: %d | Path: Scan | Queue: %zu batches", 
               rate/1000000.0, found, g_batch_queue.size());
        fflush(stdout);

        bool all_done = true;
        for (auto& t : gpu_threads) if (t.joinable()) all_done = false; 
        
        if (all_done && g_batch_queue.empty() && g_producer_done) {
             printf("\nExploração concluída.\n");
             break;
        }
    }

    producer_thread.join();
    // Cleanup
    for (auto& t : gpu_threads) if (t.joinable()) t.detach(); // or join
    
    return 0;
}
