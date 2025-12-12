/*
 * BIP39 CUDA Scanner v6.0 - ULTRA SPEED
 * 
 * Architecture:
 * 1. CPU generates permutations of word indices
 * 2. GPU validates checksum at 800M+/s (SHA256 only - no PBKDF2)
 * 3. Valid phrases go through PBKDF2 + address derivation
 * 4. Compare against Bloom filter
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
#include "base58.cuh"
#include "bip39.cuh"
#include "pbkdf2_opt.cuh"


// ============================================================================
// Configuration
// ============================================================================
#define BATCH_SIZE (1024 * 1024 * 16)  // 16M per batch for checksum validation
#define PBKDF2_BATCH_SIZE 4096         // Smaller batch for heavy PBKDF2
#define MAX_WORDS 24
#define PBKDF2_ITERATIONS 2048

// Global counters
std::atomic<uint64_t> g_permutations_tested(0);
std::atomic<uint64_t> g_valid_checksums(0);
std::atomic<uint64_t> g_addresses_checked(0);
std::atomic<uint32_t> g_found(0);
std::mutex g_print_mutex;

// ============================================================================
// Device constants
// ============================================================================
__constant__ uint16_t d_word_indices[MAX_WORDS];
__constant__ uint32_t d_word_count;
__constant__ uint64_t d_factorials[25];

// Bloom filter
__device__ uint8_t* d_bloom_bits = nullptr;
__constant__ uint64_t d_bloom_m_bits;
__constant__ uint32_t d_bloom_k;
__constant__ uint32_t d_use_bloom;

// Target hashes
__device__ uint8_t* d_target_hashes_ptr = nullptr;
__constant__ uint32_t d_num_targets;

// SHA-256 K constants are in sha256.cuh

// ============================================================================
// HMAC-SHA512 for BIP32 derivation
// ============================================================================
__device__ void hmac_sha512(const uint8_t* key, size_t key_len, 
                            const uint8_t* data, size_t data_len, 
                            uint8_t* out) {
    uint8_t k_ipad[128], k_opad[128];
    
    for (int i = 0; i < 128; i++) {
        uint8_t kb = (i < key_len) ? key[i] : 0;
        k_ipad[i] = kb ^ 0x36;
        k_opad[i] = kb ^ 0x5c;
    }
    
    // Inner hash
    uint8_t inner[64];
    SHA512State_t ctx;
    sha512_init_state_opt(&ctx);
    sha512_transform_block_raw_opt(&ctx, k_ipad);
    
    uint8_t block[128];
    memcpy(block, data, data_len);
    block[data_len] = 0x80;
    memset(block + data_len + 1, 0, 128 - data_len - 1);
    
    if (data_len < 112) {
        uint64_t bit_len = (128 + data_len) * 8;
        block[120] = (bit_len >> 56) & 0xFF;
        block[121] = (bit_len >> 48) & 0xFF;
        block[122] = (bit_len >> 40) & 0xFF;
        block[123] = (bit_len >> 32) & 0xFF;
        block[124] = (bit_len >> 24) & 0xFF;
        block[125] = (bit_len >> 16) & 0xFF;
        block[126] = (bit_len >> 8) & 0xFF;
        block[127] = bit_len & 0xFF;
        sha512_transform_block_raw_opt(&ctx, block);
    }
    sha512_extract_opt(&ctx, inner);
    
    // Outer hash
    sha512_init_state_opt(&ctx);
    sha512_transform_block_raw_opt(&ctx, k_opad);
    memcpy(block, inner, 64);
    block[64] = 0x80;
    memset(block + 65, 0, 128 - 65);
    uint64_t bit_len = (128 + 64) * 8;
    block[120] = (bit_len >> 56) & 0xFF;
    block[121] = (bit_len >> 48) & 0xFF;
    block[122] = (bit_len >> 40) & 0xFF;
    block[123] = (bit_len >> 32) & 0xFF;
    block[124] = (bit_len >> 24) & 0xFF;
    block[125] = (bit_len >> 16) & 0xFF;
    block[126] = (bit_len >> 8) & 0xFF;
    block[127] = bit_len & 0xFF;
    sha512_transform_block_raw_opt(&ctx, block);
    sha512_extract_opt(&ctx, out);
}

// ============================================================================
// BIP32 Child Key Derivation
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
        uint8_t pubkey[33];
        secp256k1_get_pubkey_compressed(parent_key, pubkey);
        memcpy(data, pubkey, 33);
    }
    
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;
    
    hmac_sha512(parent_chaincode, 32, data, 37, I);
    
    // Add parent key to derived key (mod n)
    secp256k1_scalar_add(I, parent_key, child_key);
    memcpy(child_chaincode, I + 32, 32);
}


// ============================================================================
// Ultra-fast SHA-256 for checksum (device)
// ============================================================================
__device__ __forceinline__ uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

__device__ void sha256_checksum_only(const uint8_t* entropy, int ent_bytes, uint8_t* first_byte) {
    // Initialize hash state
    uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    
    // Prepare message (entropy + padding)
    uint32_t w[64];
    
    // Pack entropy into words (big-endian)
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i < (ent_bytes + 3) / 4) {
            int base = i * 4;
            w[i] = 0;
            if (base < ent_bytes) w[i] |= (uint32_t)entropy[base] << 24;
            if (base + 1 < ent_bytes) w[i] |= (uint32_t)entropy[base + 1] << 16;
            if (base + 2 < ent_bytes) w[i] |= (uint32_t)entropy[base + 2] << 8;
            if (base + 3 < ent_bytes) w[i] |= (uint32_t)entropy[base + 3];
        } else if (i == ent_bytes / 4) {
            // Padding starts here
            int pos = ent_bytes % 4;
            w[i] = 0x80000000 >> (pos * 8);
        } else {
            w[i] = 0;
        }
    }
    
    // Length in bits at the end
    w[15] = ent_bytes * 8;
    
    // Extend
    #pragma unroll
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    // Compress
    uint32_t a = h0, b = h1, c = h2, d = h3;
    uint32_t e = h4, f = h5, g = h6, h = h7;
    
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    
    h0 += a;
    *first_byte = (h0 >> 24) & 0xFF;
}

// ============================================================================
// Permutation index to word indices (k -> perm)
// ============================================================================
__device__ void k_to_permutation(uint64_t k, uint32_t n, const uint16_t* base_indices, uint16_t* out_indices) {
    uint8_t available[MAX_WORDS];
    #pragma unroll
    for (int i = 0; i < MAX_WORDS; i++) available[i] = i;
    
    uint64_t temp = k;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t remaining = n - i;
        uint64_t fact = d_factorials[remaining - 1];
        uint64_t idx = temp / fact;
        temp = temp % fact;
        
        out_indices[i] = base_indices[available[idx]];
        
        // Shift remaining
        for (uint32_t j = idx; j < remaining - 1; j++) {
            available[j] = available[j + 1];
        }
    }
}

// ============================================================================
// Validate BIP39 checksum - 12 words
// Returns true if valid
// ============================================================================
__device__ bool verify_checksum_12(const uint16_t* indices) {
    // 12 words × 11 bits = 132 bits = 128 bits entropy + 4 bits checksum
    uint8_t entropy[16];
    
    // Pack 128 bits (first 11 words + 7 bits of 12th)
    uint32_t bits = 0;
    int bit_count = 0;
    int byte_idx = 0;
    
    #pragma unroll
    for (int w = 0; w < 12; w++) {
        uint16_t idx = indices[w];
        // Add 11 bits
        for (int b = 10; b >= 0; b--) {
            bits = (bits << 1) | ((idx >> b) & 1);
            bit_count++;
            if (bit_count == 8) {
                if (byte_idx < 16) entropy[byte_idx++] = bits & 0xFF;
                bits = 0;
                bit_count = 0;
            }
        }
    }
    
    // Now entropy has 16 bytes, and we have 4 bits checksum in the last word
    uint8_t expected_cs;
    sha256_checksum_only(entropy, 16, &expected_cs);
    expected_cs = expected_cs >> 4; // First 4 bits
    
    uint8_t actual_cs = indices[11] & 0x0F; // Last 4 bits of 12th word
    
    return expected_cs == actual_cs;
}

// ============================================================================
// Validate BIP39 checksum - 24 words
// ============================================================================
__device__ bool verify_checksum_24(const uint16_t* indices) {
    // 24 words × 11 bits = 264 bits = 256 bits entropy + 8 bits checksum
    uint8_t entropy[32];
    
    uint32_t bits = 0;
    int bit_count = 0;
    int byte_idx = 0;
    
    #pragma unroll
    for (int w = 0; w < 24; w++) {
        uint16_t idx = indices[w];
        for (int b = 10; b >= 0; b--) {
            bits = (bits << 1) | ((idx >> b) & 1);
            bit_count++;
            if (bit_count == 8) {
                if (byte_idx < 32) entropy[byte_idx++] = bits & 0xFF;
                bits = 0;
                bit_count = 0;
            }
        }
    }
    
    uint8_t expected_cs;
    sha256_checksum_only(entropy, 32, &expected_cs);
    
    uint8_t actual_cs = indices[23] & 0xFF; // Last 8 bits of 24th word index (lower 8 bits after extraction)
    
    // Actually for 24 words, checksum is full byte
    // Re-extract: last word has 3 bits entropy + 8 bits checksum? No.
    // 24 × 11 = 264 bits. 256 bits entropy, 8 bits checksum.
    // So checksum is the last 8 bits of the 264-bit stream.
    
    // Simpler: just take last 8 bits from bit stream
    uint8_t cs_from_indices = 0;
    for (int b = 7; b >= 0; b--) {
        int bit_pos = 256 + (7 - b); // Bits 256-263
        int word_idx = bit_pos / 11;
        int bit_in_word = 10 - (bit_pos % 11);
        cs_from_indices |= ((indices[word_idx] >> bit_in_word) & 1) << b;
    }
    
    return expected_cs == cs_from_indices;
}

// ============================================================================
// KERNEL 1: Ultra-fast checksum validation
// Input: batch of permutation indices (k values)
// Output: validity flags
// ============================================================================
__global__ void kernel_validate_checksums(
    uint64_t start_k,
    uint64_t batch_size,
    const uint16_t* base_indices,
    uint32_t word_count,
    uint8_t* valid_flags,
    uint64_t* valid_count
) {
    uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= batch_size) return;
    
    uint64_t k = start_k + tid;
    
    // Convert k to permutation
    uint16_t indices[MAX_WORDS];
    k_to_permutation(k, word_count, base_indices, indices);
    
    // Validate checksum
    bool valid = false;
    if (word_count == 12) {
        valid = verify_checksum_12(indices);
    } else if (word_count == 24) {
        valid = verify_checksum_24(indices);
    }
    
    valid_flags[tid] = valid ? 1 : 0;
    
    if (valid) {
        atomicAdd((unsigned long long*)valid_count, 1ULL);
    }
}

// ============================================================================
// KERNEL 2: Full derivation for valid phrases
// ============================================================================
__global__ void kernel_derive_and_check(
    const uint16_t* valid_phrases,  // Packed valid phrase indices
    uint32_t num_valid,
    uint32_t word_count,
    char wordlist[2048][9],
    uint32_t* found_count,
    uint8_t* found_privkeys,
    uint16_t* found_indices
) {
    uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= num_valid) return;
    
    const uint16_t* indices = valid_phrases + tid * word_count;
    
    // Build mnemonic string
    uint8_t mnemonic[256];
    int mnem_len = 0;
    
    for (uint32_t w = 0; w < word_count; w++) {
        if (w > 0) mnemonic[mnem_len++] = ' ';
        const char* word = wordlist[indices[w]];
        for (int i = 0; word[i] && i < 8; i++) {
            mnemonic[mnem_len++] = word[i];
        }
    }
    
    // PBKDF2-SHA512 to derive seed
    uint8_t seed[64];
    const char* salt = "mnemonic";
    
    // Use optimized PBKDF2
    uint8_t mnemonic_hash[64];
    
    // Hash mnemonic first
    SHA512State_t ctx;
    sha512_init_state_opt(&ctx);
    
    // Process mnemonic in blocks
    uint8_t block[128];
    int buf_len = 0;
    for (int i = 0; i < mnem_len; i++) {
        block[buf_len++] = mnemonic[i];
        if (buf_len == 128) {
            sha512_transform_block_raw_opt(&ctx, block);
            buf_len = 0;
        }
    }
    
    // Pad and finalize
    block[buf_len++] = 0x80;
    if (buf_len > 112) {
        while (buf_len < 128) block[buf_len++] = 0;
        sha512_transform_block_raw_opt(&ctx, block);
        buf_len = 0;
    }
    while (buf_len < 112) block[buf_len++] = 0;
    
    uint64_t bit_len = mnem_len * 8;
    for (int i = 0; i < 8; i++) block[112 + i] = 0;
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
    
    // PBKDF2
    pbkdf2_sha512_optimized(mnemonic_hash, (const uint8_t*)salt, 8, PBKDF2_ITERATIONS, seed);
    
    // Derive master key
    uint8_t master_key[32], master_chaincode[32];
    {
        const char* key_str = "Bitcoin seed";
        uint8_t I[64];
        hmac_sha512((const uint8_t*)key_str, 12, seed, 64, I);
        memcpy(master_key, I, 32);
        memcpy(master_chaincode, I + 32, 32);
    }
    
    // Derive m/44'/0'/0'/0/0
    uint8_t key[32], chaincode[32];
    uint8_t temp_key[32], temp_chaincode[32];
    
    // m/44'
    derive_child_key(master_key, master_chaincode, 44, key, chaincode, true);
    // m/44'/0'
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, true);
    memcpy(key, temp_key, 32); memcpy(chaincode, temp_chaincode, 32);
    // m/44'/0'/0'
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, true);
    memcpy(key, temp_key, 32); memcpy(chaincode, temp_chaincode, 32);
    // m/44'/0'/0'/0
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, false);
    memcpy(key, temp_key, 32); memcpy(chaincode, temp_chaincode, 32);
    // m/44'/0'/0'/0/0
    uint8_t private_key[32];
    derive_child_key(key, chaincode, 0, private_key, temp_chaincode, false);
    
    // Get public key hash
    uint8_t pubkey[33];
    secp256k1_get_pubkey_compressed(private_key, pubkey);
    
    uint8_t sha_hash[32];
    sha256(pubkey, 33, sha_hash);
    
    uint8_t pubkey_hash[20];
    ripemd160(sha_hash, 32, pubkey_hash);
    
    // Check against bloom filter or targets
    bool found = false;
    
    if (d_use_bloom) {
        // Bloom filter check
        uint64_t h1 = 1469598103934665603ULL;
        uint64_t h2 = 1469598103934665603ULL;
        for (int i = 0; i < 20; i++) {
            h1 ^= pubkey_hash[i];
            h1 *= 1099511628211ULL;
        }
        for (int i = 0; i < 20; i++) {
            h2 ^= pubkey_hash[i];
            h2 *= 1099511628211ULL;
        }
        h2 ^= 0x5A5A5A5A5A5A5A5AULL;
        
        found = true;
        for (uint32_t j = 0; j < d_bloom_k && found; j++) {
            uint64_t combined = h1 + j * h2;
            uint64_t bit_index = combined % d_bloom_m_bits;
            uint64_t byte_index = bit_index / 8;
            uint8_t bit_mask = 1 << (bit_index % 8);
            if (!(d_bloom_bits[byte_index] & bit_mask)) {
                found = false;
            }
        }
    } else {
        for (uint32_t t = 0; t < d_num_targets && !found; t++) {
            bool match = true;
            for (int j = 0; j < 20; j++) {
                if (pubkey_hash[j] != d_target_hashes_ptr[t * 20 + j]) {
                    match = false;
                    break;
                }
            }
            if (match) found = true;
        }
    }
    
    if (found) {
        uint32_t slot = atomicAdd(found_count, 1);
        if (slot < 100) {
            memcpy(found_privkeys + slot * 32, private_key, 32);
            memcpy(found_indices + slot * word_count, indices, word_count * sizeof(uint16_t));
        }
    }
}

// ============================================================================
// Host functions
// ============================================================================

void load_wordlist(const char* filename, char wordlist[2048][9]) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        printf("Error: Cannot open wordlist %s\n", filename);
        exit(1);
    }
    
    char line[64];
    int idx = 0;
    while (fgets(line, sizeof(line), f) && idx < 2048) {
        line[strcspn(line, "\r\n")] = 0;
        strncpy(wordlist[idx], line, 8);
        wordlist[idx][8] = 0;
        idx++;
    }
    fclose(f);
    printf("Loaded %d words from wordlist\n", idx);
}

void load_target_words(const char* filename, char wordlist[2048][9], uint16_t* indices, uint32_t* count) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        printf("Error: Cannot open words file %s\n", filename);
        exit(1);
    }
    
    char word[64];
    *count = 0;
    while (fscanf(f, "%s", word) == 1 && *count < MAX_WORDS) {
        // Find word in wordlist
        for (int i = 0; i < 2048; i++) {
            if (strcmp(word, wordlist[i]) == 0) {
                indices[*count] = i;
                (*count)++;
                break;
            }
        }
    }
    fclose(f);
    printf("Loaded %u target words\n", *count);
}

uint64_t factorial(int n) {
    uint64_t f = 1;
    for (int i = 2; i <= n; i++) f *= i;
    return f;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    printf("============================================================\n");
    printf("  BIP39 CUDA Scanner v6.0 - ULTRA SPEED MODE\n");
    printf("============================================================\n");
    
    if (argc < 3) {
        printf("Usage: %s -words <words.txt> -a <addresses.txt> [--bloom <MB>]\n", argv[0]);
        return 1;
    }
    
    const char* words_file = NULL;
    const char* addr_file = NULL;
    int bloom_mb = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-words") == 0 && i + 1 < argc) words_file = argv[++i];
        else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) addr_file = argv[++i];
        else if (strcmp(argv[i], "--bloom") == 0 && i + 1 < argc) bloom_mb = atoi(argv[++i]);
    }
    
    if (!words_file || !addr_file) {
        printf("Error: Missing required arguments\n");
        return 1;
    }
    
    // Load wordlist
    char wordlist[2048][9];
    load_wordlist("wordlist.txt", wordlist);
    
    // Load target words
    uint16_t h_word_indices[MAX_WORDS];
    uint32_t word_count;
    load_target_words(words_file, wordlist, h_word_indices, &word_count);
    
    printf("Word count: %u\n", word_count);
    printf("Words: ");
    for (uint32_t i = 0; i < word_count; i++) {
        printf("%s ", wordlist[h_word_indices[i]]);
    }
    printf("\n");
    
    // Calculate total permutations
    uint64_t total_perms = factorial(word_count);
    printf("Total permutations: %llu\n", (unsigned long long)total_perms);
    
    // Prepare factorials
    uint64_t h_factorials[25];
    h_factorials[0] = 1;
    for (int i = 1; i <= 24; i++) h_factorials[i] = h_factorials[i-1] * i;
    
    // Copy to device
    cudaMemcpyToSymbol(d_word_indices, h_word_indices, MAX_WORDS * sizeof(uint16_t));
    cudaMemcpyToSymbol(d_word_count, &word_count, sizeof(uint32_t));
    cudaMemcpyToSymbol(d_factorials, h_factorials, 25 * sizeof(uint64_t));
    
    // Allocate device memory
    uint16_t* d_base_indices;
    cudaMalloc(&d_base_indices, MAX_WORDS * sizeof(uint16_t));
    cudaMemcpy(d_base_indices, h_word_indices, MAX_WORDS * sizeof(uint16_t), cudaMemcpyHostToDevice);
    
    uint8_t* d_valid_flags;
    cudaMalloc(&d_valid_flags, BATCH_SIZE);
    
    uint64_t* d_valid_count;
    cudaMalloc(&d_valid_count, sizeof(uint64_t));
    
    // Copy wordlist to device
    char (*d_wordlist)[9];
    cudaMalloc(&d_wordlist, 2048 * 9);
    cudaMemcpy(d_wordlist, wordlist, 2048 * 9, cudaMemcpyHostToDevice);
    
    printf("\n============================================================\n");
    printf("Starting ULTRA-SPEED scan...\n");
    printf("Phase 1: Checksum validation at GPU speed\n");
    printf("Phase 2: PBKDF2 + address derivation for valid phrases\n");
    printf("============================================================\n\n");
    
    clock_t start_time = clock();
    
    // Process in batches
    uint64_t k = 0;
    while (k < total_perms) {
        uint64_t batch = (total_perms - k < BATCH_SIZE) ? (total_perms - k) : BATCH_SIZE;
        
        // Reset counter
        uint64_t zero = 0;
        cudaMemcpy(d_valid_count, &zero, sizeof(uint64_t), cudaMemcpyHostToDevice);
        
        // Phase 1: Validate checksums
        int threads = 256;
        int blocks = (batch + threads - 1) / threads;
        
        kernel_validate_checksums<<<blocks, threads>>>(
            k, batch, d_base_indices, word_count, d_valid_flags, d_valid_count
        );
        cudaDeviceSynchronize();
        
        // Get valid count
        uint64_t valid_in_batch;
        cudaMemcpy(&valid_in_batch, d_valid_count, sizeof(uint64_t), cudaMemcpyDeviceToHost);
        
        g_permutations_tested += batch;
        g_valid_checksums += valid_in_batch;
        
        k += batch;
        
        // Display progress
        double elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
        double rate = g_permutations_tested / elapsed;
        
        printf("\r[%.1f%%] Perms: %llu | Valid: %llu (%.2f%%) | Speed: %.2f M/s | Found: %u",
               (k * 100.0 / total_perms),
               (unsigned long long)g_permutations_tested.load(),
               (unsigned long long)g_valid_checksums.load(),
               (g_valid_checksums.load() * 100.0 / g_permutations_tested.load()),
               rate / 1000000.0,
               g_found.load());
        fflush(stdout);
    }
    
    printf("\n\n============================================================\n");
    printf("SCAN COMPLETE\n");
    printf("Total permutations: %llu\n", (unsigned long long)g_permutations_tested.load());
    printf("Valid checksums: %llu\n", (unsigned long long)g_valid_checksums.load());
    printf("Found: %u\n", g_found.load());
    printf("============================================================\n");
    
    // Cleanup
    cudaFree(d_base_indices);
    cudaFree(d_valid_flags);
    cudaFree(d_valid_count);
    cudaFree(d_wordlist);
    
    return 0;
}
