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
#define MAX_WORDS 40
#define PBKDF2_ITERATIONS 2048
#define DEBUG_MODE 0  // Set to 1 to enable debug output

// Global counters
std::atomic<uint64_t> g_permutations_tested(0);
std::atomic<uint64_t> g_valid_checksums(0);
std::atomic<uint64_t> g_addresses_checked(0);
std::atomic<uint32_t> g_found(0);
std::mutex g_print_mutex;

// Sample storage for display
#define MAX_SAMPLES 5
struct SampleResult {
    uint16_t indices[MAX_WORDS];
    uint8_t private_key[32];
    uint8_t pubkey_hash[20];
    uint32_t word_count;
};
__device__ SampleResult d_samples[MAX_SAMPLES];
__device__ uint32_t d_sample_count = 0;


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
__constant__ uint8_t* d_target_hashes_ptr = nullptr;
__constant__ uint32_t d_num_targets;

// SHA-256 K constants are in sha256.cuh
// hmac_sha512 is in sha512.cuh

// ============================================================================
// BIP32 Child Key Derivation
// ============================================================================
__device__ void derive_child_key(
    const uint8_t* parent_key,
    const uint8_t* parent_chaincode,
    uint32_t index,
    uint8_t* child_key,
    uint8_t* child_chaincode,
    bool hardened,
    bool debug = false
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
    
    if (debug) {
        printf("DEBUG data: ");
        for(int k=0; k<37; k++) printf("%02x", data[k]);
        printf("\n");
    }
    
    hmac_sha512(parent_chaincode, 32, data, 37, I);
    
    if (debug) {
        printf("DEBUG IL: ");
        for(int k=0; k<32; k++) printf("%02x", I[k]);
        printf("\n");
    }
    
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
// Simple LCG random number generator for CUDA
// ============================================================================
__device__ uint64_t cuda_rand(uint64_t* seed) {
    *seed = (*seed * 6364136223846793005ULL + 1442695040888963407ULL);
    return *seed;
}

// ============================================================================
// Random 12-word phrase with 4 REQUIRED words + 8 random from remaining
// Required words: galaxy, egg, venture, oxygen (indices 0, 7, 10, 12 in word list)
// ============================================================================
__device__ void random_12word_with_required(uint64_t seed, uint32_t total_words, const uint16_t* base_indices, uint16_t* out_indices) {
    // Required word indices in the base_indices array
    const uint32_t required_positions[4] = {0, 7, 10, 12}; // galaxy, egg, venture, oxygen
    
    // First, add the 4 required words
    out_indices[0] = base_indices[required_positions[0]]; // galaxy
    out_indices[1] = base_indices[required_positions[1]]; // egg
    out_indices[2] = base_indices[required_positions[2]]; // venture
    out_indices[3] = base_indices[required_positions[3]]; // oxygen
    
    // Create list of available indices (excluding required ones)
    uint16_t available[MAX_WORDS];
    uint32_t available_count = 0;
    for (uint32_t i = 0; i < total_words; i++) {
        bool is_required = false;
        for (uint32_t r = 0; r < 4; r++) {
            if (i == required_positions[r]) {
                is_required = true;
                break;
            }
        }
        if (!is_required) {
            available[available_count++] = base_indices[i];
        }
    }
    
    // Select 8 random words from the remaining (total_words - 4)
    // Fisher-Yates shuffle to select 8
    for (uint32_t i = 0; i < 8; i++) {
        uint32_t j = i + (cuda_rand(&seed) % (available_count - i));
        out_indices[4 + i] = available[j];
        // Swap
        uint16_t temp = available[j];
        available[j] = available[i];
        available[i] = temp;
    }
    
    // Now shuffle all 12 words to randomize positions
    for (uint32_t i = 11; i > 0; i--) {
        uint32_t j = cuda_rand(&seed) % (i + 1);
        uint16_t temp = out_indices[i];
        out_indices[i] = out_indices[j];
        out_indices[j] = temp;
    }
}

// ============================================================================
// Random permutation generator (Fisher-Yates shuffle) - LEGACY
// ============================================================================
__device__ void random_permutation(uint64_t seed, uint32_t n, const uint16_t* base_indices, uint16_t* out_indices) {
    // Initialize with base indices
    for (uint32_t i = 0; i < n; i++) {
        out_indices[i] = base_indices[i];
    }
    
    // Fisher-Yates shuffle
    for (uint32_t i = n - 1; i > 0; i--) {
        uint32_t j = cuda_rand(&seed) % (i + 1);
        // Swap
        uint16_t temp = out_indices[i];
        out_indices[i] = out_indices[j];
        out_indices[j] = temp;
    }
}

// ============================================================================
// Permutation index to word indices (k -> perm) - LEGACY, kept for compatibility
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
    uint64_t* valid_count,
    uint16_t* valid_phrases_buffer
) {
    uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= batch_size) return;
    
    uint64_t k = start_k + tid;
    
    // Generate RANDOM 12-word phrase with 4 REQUIRED words (galaxy, egg, venture, oxygen)
    uint16_t indices[MAX_WORDS];
    uint64_t seed = k ^ (blockIdx.x * 1000000007ULL) ^ (threadIdx.x * 2654435761ULL);
    random_12word_with_required(seed, word_count, base_indices, indices);
    
    // Force word_count to 12 for this search mode
    uint32_t actual_word_count = 12;
    
    // Validate checksum (always 12 words in this mode)
    bool valid = verify_checksum_12(indices);
    
    // Debug specific target sequence (galaxy man ...)
    bool exact_match = false;
    if (word_count == 12) {
        uint16_t expected[] = {759, 1078, 213, 623, 521, 319, 416, 302, 566, 1104, 191, 1666};
        exact_match = true;
        for(int i=0; i<12; i++) {
             if (indices[i] != expected[i]) {
                 exact_match = false;
                 break;
             }
        }
    }
    
    if (exact_match) {
         printf("\n!!! FOUND EXACT TARGET AT K=%llu !!!\n", (unsigned long long)k);
         printf("Indices: ");
         for(int i=0; i<word_count; i++) printf("%d ", indices[i]);
         printf("\n");
         printf("Valid Checksum: %d\n", valid);
         if (!valid) printf("WARNING: CHECKSUM FAILED FOR TARGET!\n");
    }
    
    if (k == 0) {
        printf("\nK=0 GENERATED INDICES: ");
        for(int i=0; i<word_count; i++) printf("%d ", indices[i]);
        printf("\n");
    }
    
    valid_flags[tid] = valid ? 1 : 0;
    
    if (valid) {
        uint64_t count = atomicAdd((unsigned long long*)valid_count, 1ULL);
        
        // Store indices for Phase 2 (always 12 words)
        for (int i = 0; i < 12; i++) {
            valid_phrases_buffer[count * 12 + i] = indices[i];
        }
    }
}

// ============================================================================
// KERNEL 2: Full derivation for valid phrases
// ============================================================================
__global__ void kernel_derive_and_check(
    const uint16_t* valid_phrases,  // Packed valid phrase indices
    uint32_t num_valid,
    uint32_t word_count,
    char wordlist[2048][16],
    uint32_t* found_count,
    uint8_t* found_privkeys,
    uint16_t* found_indices
) {
    uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= num_valid) return;
    
    // Always process 12 words in this mode
    const uint16_t* indices = valid_phrases + tid * 12;
    
    // Debug: Check if we are processing target indices
    bool is_target_indices = false;
    if (word_count == 12) {
        uint16_t expected[] = {759, 1078, 213, 623, 521, 319, 416, 302, 566, 1104, 191, 1666};
        is_target_indices = true;
        for(int i=0; i<12; i++) {
             if (indices[i] != expected[i]) {
                 is_target_indices = false;
                 break;
             }
        }
    }
    
    // Build mnemonic string
    uint8_t mnemonic[256];
    int mnem_len = 0;
    
    for (uint32_t w = 0; w < word_count; w++) {
        if (w > 0) mnemonic[mnem_len++] = ' ';
        const char* word = wordlist[indices[w]];
        // Copy full word (BIP39 words are max 8 chars, but use full length for safety)
        for (int i = 0; word[i] && i < 16; i++) {
            mnemonic[mnem_len++] = word[i];
        }
    }
    
    if (is_target_indices) {
         // Found target permutation
         printf("\n!!! PHASE 2: PROCESSING TARGET INDICES (TID=%llu) !!!\n", (unsigned long long)tid);
    }
    
    // Debug: print first mnemonic
    #if DEBUG_MODE
    if (tid == 0) {
        mnemonic[mnem_len] = 0;
        printf("[DEBUG] MNEMONIC: %s\n", (char*)mnemonic);
        printf("[DEBUG] INDICES: ");
        for(uint32_t w=0; w<word_count; w++) printf("%d ", indices[w]);
        printf("\n");
    }
    #endif
    
    // PBKDF2-SHA512 to derive seed
    uint8_t seed[64];
    const char* salt = "mnemonic";
    
    // BIP39: PBKDF2(password=mnemonic, salt="mnemonic", iterations=2048)
    // Pass mnemonic directly with its length
    pbkdf2_sha512_mnemonic(mnemonic, mnem_len, (const uint8_t*)salt, 8, PBKDF2_ITERATIONS, seed);

    if (is_target_indices) {
         printf("\n");
         printf("Mnemonic length: %d bytes\n", mnem_len);
         printf("Computed SEED: ");
         for(int k=0; k<64; k++) printf("%02x", seed[k]);
         printf("\n");
         
         // Expected seed for "galaxy man boy evil donkey child cross chair egg meat blood space"
         // 4cd832a5c862ef5117870c15bdf792ed558499a2c81d8bd5c68f28bf0f66671b
         // 76e6522d90fb4996cc29d1a7b37ccf0bcc8157dea21f5f065e89921841323ab8
         printf("Expected SEED: 4cd832a5c862ef5117870c15bdf792ed558499a2c81d8bd5c68f28bf0f66671b76e6522d90fb4996cc29d1a7b37ccf0bcc8157dea21f5f065e89921841323ab8\n");
    }

    
    #if DEBUG_MODE
    if (tid == 0) {
        printf("[DEBUG] SEED: ");
        for(int k=0; k<32; k++) printf("%02x", seed[k]);
        printf("...\n");
    }
    #endif
    
    // Derive master key
    uint8_t master_key[32], master_chaincode[32];
    {
        const char* key_str = "Bitcoin seed";
        uint8_t I[64];
        hmac_sha512((const uint8_t*)key_str, 12, seed, 64, I);
        memcpy(master_key, I, 32);
        memcpy(master_chaincode, I + 32, 32);
    }
    
    if (is_target_indices) {
         printf("Computed MASTER KEY: ");
         for(int k=0; k<32; k++) printf("%02x", master_key[k]);
         printf("\n");
         printf("Computed CHAIN CODE: ");
         for(int k=0; k<32; k++) printf("%02x", master_chaincode[k]);
         printf("\n");
    }
    
    #if DEBUG_MODE
    if (tid == 0) {
        printf("[DEBUG] MASTER KEY: ");
        for(int k=0; k<32; k++) printf("%02x", master_key[k]);
        printf("\n");
    }
    #endif
    
    // Derive m/44'/0'/0'/0/0
    uint8_t key[32], chaincode[32];
    uint8_t temp_key[32], temp_chaincode[32];
    
    // m/44'
    derive_child_key(master_key, master_chaincode, 44, key, chaincode, true, false);
    // Debug disabled for m/44'
    
    // m/44'/0'
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, true, false);
    memcpy(key, temp_key, 32); memcpy(chaincode, temp_chaincode, 32);
    // Debug disabled for m/44'/0'

    // m/44'/0'/0'
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, true, false);
    memcpy(key, temp_key, 32); memcpy(chaincode, temp_chaincode, 32);
    
    // m/44'/0'/0'/0
    derive_child_key(key, chaincode, 0, temp_key, temp_chaincode, false, false);
    memcpy(key, temp_key, 32); memcpy(chaincode, temp_chaincode, 32);
    
    // m/44'/0'/0'/0/0
    uint8_t private_key[32];
    derive_child_key(key, chaincode, 0, private_key, temp_chaincode, false, false);
    
    // Get public key hash
    uint8_t pubkey[33];
    secp256k1_get_pubkey_compressed(private_key, pubkey);

    uint8_t sha_hash[32];
    sha256(pubkey, 33, sha_hash);
    
    uint8_t pubkey_hash[20];
    ripemd160(sha_hash, 32, pubkey_hash);
    
    if (is_target_indices) {
        printf("Computed PUBKEY: ");
        for(int k=0; k<33; k++) printf("%02x", pubkey[k]);
        printf("\n");
        printf("Computed HASH160: ");
        for(int k=0; k<20; k++) printf("%02x", pubkey_hash[k]);
        printf("\n");
        printf("Expected HASH160: 232fb8a4bb0b8be8daeb78d9022d126006309c5c\n");
        printf("d_num_targets = %u\n", d_num_targets);
    }
    
    // Save sample with hash160 (every 100k processed phrases for better visibility)
    if (tid % 100000 == 0) {
        uint32_t slot = atomicAdd(&d_sample_count, 1);
        if (slot < MAX_SAMPLES) {
            for (uint32_t i = 0; i < 12; i++) {
                d_samples[slot].indices[i] = indices[i];
            }
            d_samples[slot].word_count = 12;
            memcpy(d_samples[slot].private_key, private_key, 32);
            memcpy(d_samples[slot].pubkey_hash, pubkey_hash, 20);
        }
    }
    
    // Check against bloom filter or targets
    bool found = false;
    
    // Debug: print first thread's comparison details
    if (tid == 0) {
        printf("\n[DEBUG TID=0] d_use_bloom=%u, d_num_targets=%u\n", d_use_bloom, d_num_targets);
        if (d_num_targets > 0 && d_target_hashes_ptr != nullptr) {
            printf("[DEBUG TID=0] Target hash: ");
            for (int i = 0; i < 20; i++) printf("%02x", d_target_hashes_ptr[i]);
            printf("\n[DEBUG TID=0] Computed hash: ");
            for (int i = 0; i < 20; i++) printf("%02x", pubkey_hash[i]);
            printf("\n");
        }
    }
    
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
            for (int k = 0; k < 20; k++) {
                if (pubkey_hash[k] != d_target_hashes_ptr[t * 20 + k]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                found = true;
            }
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

void load_wordlist(const char* filename, char wordlist[2048][16]) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        printf("Error: Cannot open wordlist %s\n", filename);
        exit(1);
    }
    
    char line[64];
    int idx = 0;
    while (fgets(line, sizeof(line), f) && idx < 2048) {
        line[strcspn(line, "\r\n")] = 0;
        // Initialize buffer to zeros to avoid garbage
        memset(wordlist[idx], 0, 16);
        // Copy full word (up to 15 chars to leave room for null terminator)
        strncpy(wordlist[idx], line, 15);
        idx++;
    }
    fclose(f);
    printf("First word in list: '%s'\n", wordlist[0]);
    printf("Last word (idx-1): '%s'\n", wordlist[idx-1]);
    printf("Loaded %d words from wordlist\n", idx);
}

void load_target_words(const char* filename, char wordlist[2048][16], uint16_t* indices, uint32_t* count) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        printf("Error: Cannot open words file %s\n", filename);
        exit(1);
    }
    
    char word[64];
    *count = 0;
    while (fscanf(f, "%s", word) == 1 && *count < MAX_WORDS) {
        bool found_match = false;
        // Find word in wordlist
        for (int i = 0; i < 2048; i++) {
            if (strcmp(word, wordlist[i]) == 0) {
                indices[*count] = i;
                (*count)++;
                found_match = true;
                break;
            }
        }
        if (!found_match) {
             printf("Warning: Word '%s' not found in wordlist!\n", word);
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

    // Increase stack size to prevent corruption in deep crypto functions
    cudaDeviceSetLimit(cudaLimitStackSize, 8192);
    cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 1024 * 1024 * 32); // 32MB printf buffer
    
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

    // Load addresses
    std::vector<uint8_t> target_hashes;
    int num_targets = 0;
    
    FILE* f_addr = fopen(addr_file, "r");
    if (f_addr) {
        char line[128];
        while (fgets(line, sizeof(line), f_addr)) {
            line[strcspn(line, "\r\n")] = 0;
            if (strlen(line) < 20) continue;
            
            uint8_t hash[20];
            if (base58_decode_address(line, hash)) {
                for(int i=0; i<20; i++) target_hashes.push_back(hash[i]);
            }
        }
        fclose(f_addr);
        num_targets = target_hashes.size() / 20;
        printf("Loaded %d target addresses\n", num_targets);
    } else {
        printf("Error: Cannot open address file %s\n", addr_file);
        return 1;
    }
    
    // Load wordlist
    char wordlist[2048][16];
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
    char (*d_wordlist)[16];
    cudaMalloc(&d_wordlist, 2048 * 16);
    cudaMemcpy(d_wordlist, wordlist, 2048 * 16, cudaMemcpyHostToDevice);

    // Buffer for valid phrases (Phase 2 input)
    uint16_t* d_valid_phrases;
    // Size: Batch size * Max words. 16M * 24 * 2 bytes = 768MB. OK for 24GB VRAM.
    cudaMalloc(&d_valid_phrases, BATCH_SIZE * MAX_WORDS * sizeof(uint16_t));

    // Found results storage
    uint32_t* d_found_count;
    cudaMalloc(&d_found_count, sizeof(uint32_t));
    cudaMemset(d_found_count, 0, sizeof(uint32_t));

    uint8_t* d_found_privkeys;
    cudaMalloc(&d_found_privkeys, 100 * 32); // Store up to 100 found keys

    uint16_t* d_found_indices;
    cudaMalloc(&d_found_indices, 100 * MAX_WORDS * sizeof(uint16_t));
    
    // Target hashes pointers
    uint32_t use_bloom = 0;
    cudaMemcpyToSymbol(d_use_bloom, &use_bloom, sizeof(uint32_t));
    
    if (num_targets > 0) {
        uint8_t* d_targets;
        cudaMalloc(&d_targets, target_hashes.size());
        cudaMemcpy(d_targets, target_hashes.data(), target_hashes.size(), cudaMemcpyHostToDevice);
        
        // Update device symbols
        cudaMemcpyToSymbol(d_target_hashes_ptr, &d_targets, sizeof(uint8_t*));
        cudaMemcpyToSymbol(d_num_targets, &num_targets, sizeof(uint32_t));
    }
    
    printf("\n============================================================\n");
    printf("Starting REQUIRED WORDS MODE...\n");
    printf("Required words: galaxy, egg, venture, oxygen\n");
    printf("Selecting 8 additional random words from remaining 36\n");
    printf("Total search space: C(36,8) × 12! ≈ 2.9 × 10^16 permutations\n");
    printf("Phase 1: Checksum validation at GPU speed\n");
    printf("Phase 2: PBKDF2 + address derivation for valid phrases\n");
    printf("Press Ctrl+C to stop\n");
    printf("============================================================\n\n");
    
    clock_t start_time = clock();
    
    // Process in batches - INFINITE LOOP for random search
    uint64_t k = 0;
    while (true) {
        uint64_t batch = BATCH_SIZE;
        
        // Reset counter
        uint64_t zero = 0;
        cudaMemcpy(d_valid_count, &zero, sizeof(uint64_t), cudaMemcpyHostToDevice);
        
        // Phase 1: Validate checksums
        int threads = 256;
        int blocks = (batch + threads - 1) / threads;
        
        kernel_validate_checksums<<<blocks, threads>>>(
            k, batch, d_base_indices, word_count, d_valid_flags, d_valid_count, d_valid_phrases
        );
        cudaDeviceSynchronize();
        
        // Get valid count
        uint64_t valid_in_batch;
        cudaMemcpy(&valid_in_batch, d_valid_count, sizeof(uint64_t), cudaMemcpyDeviceToHost);

        // Phase 2: PBKDF2 + Address Check
        if (valid_in_batch > 0) {
            // Reset found counter before this batch
            cudaMemset(d_found_count, 0, sizeof(uint32_t));
            
            int threads_p2 = 256;
            int blocks_p2 = (valid_in_batch + threads_p2 - 1) / threads_p2;
            
            kernel_derive_and_check<<<blocks_p2, threads_p2>>>(
                d_valid_phrases,
                (uint32_t)valid_in_batch,
                word_count,
                d_wordlist,
                d_found_count,
                d_found_privkeys,
                d_found_indices
            );
            cudaDeviceSynchronize();
            
            // Check found
            uint32_t found_now;
            cudaMemcpy(&found_now, d_found_count, sizeof(uint32_t), cudaMemcpyDeviceToHost);
            if (found_now > 0) {
                g_found.store(found_now);
                printf("\n[+] FOUND %u MATCHES!\n", found_now);
                break;
            }
        }
        
        g_permutations_tested += batch;
        g_valid_checksums += valid_in_batch;
        
        k += batch;
        
        // Display progress and samples every 10 batches
        if ((k / BATCH_SIZE) % 10 == 0) {
            double elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
            double rate = g_permutations_tested / elapsed;
            printf("\n[REQUIRED WORDS MODE] Tested: %llu | Valid: %llu | Speed: %.2f M/s | Elapsed: %.1fs\n",
                   (unsigned long long)g_permutations_tested.load(),
                   (unsigned long long)g_valid_checksums.load(),
                   rate / 1000000.0,
                   elapsed);
            
            // Display samples for progress verification
            SampleResult h_samples[MAX_SAMPLES];
            uint32_t h_sample_count = 0;
            cudaMemcpyFromSymbol(h_samples, d_samples, sizeof(SampleResult) * MAX_SAMPLES);
            cudaMemcpyFromSymbol(&h_sample_count, d_sample_count, sizeof(uint32_t));
            
            if (h_sample_count > 0) {
                printf("Sample phrases (last %u):\n", h_sample_count < MAX_SAMPLES ? h_sample_count : MAX_SAMPLES);
                for (uint32_t s = 0; s < h_sample_count && s < MAX_SAMPLES; s++) {
                    printf("  %u: ", s + 1);
                    for (uint32_t w = 0; w < h_samples[s].word_count && w < 12; w++) {
                        printf("%s ", wordlist[h_samples[s].indices[w]]);
                    }
                    printf("\n");
                }
                // Reset sample counter for next batch
                uint32_t zero = 0;
                cudaMemcpyToSymbol(d_sample_count, &zero, sizeof(uint32_t));
            }
            fflush(stdout);
        }
    }
    
    printf("\n\n============================================================\n");
    printf("SCAN COMPLETE\n");
    printf("Total permutations: %llu\n", (unsigned long long)g_permutations_tested.load());
    printf("Valid checksums: %llu\n", (unsigned long long)g_valid_checksums.load());
    printf("Found: %u\n", g_found.load());
    printf("============================================================\n");
    
    // Display sample valid phrases with full derivation
    printf("\n============ SAMPLE VALID PHRASES ============\n");
    
    SampleResult h_samples[MAX_SAMPLES];
    uint32_t h_sample_count = 0;
    cudaMemcpyFromSymbol(h_samples, d_samples, sizeof(SampleResult) * MAX_SAMPLES);
    cudaMemcpyFromSymbol(&h_sample_count, d_sample_count, sizeof(uint32_t));
    
    printf("Found %u sample valid phrases:\n\n", h_sample_count);
    
    for (uint32_t s = 0; s < h_sample_count && s < MAX_SAMPLES; s++) {
        printf("--- Sample %u ---\n", s + 1);
        
        // Build mnemonic
        printf("Mnemonic: ");
        for (uint32_t w = 0; w < h_samples[s].word_count && w < 12; w++) {
            if (w > 0) printf(" ");
            printf("%s", wordlist[h_samples[s].indices[w]]);
        }
        printf("\n");
        
        // Indices
        printf("Indices:  ");
        for (uint32_t w = 0; w < h_samples[s].word_count && w < 12; w++) {
            if (w > 0) printf(" ");
            printf("%u", h_samples[s].indices[w]);
        }
        printf("\n");

        printf("Address Hash: ");
        for (int i = 0; i < 20; i++) printf("%02x", h_samples[s].pubkey_hash[i]);
        printf("\n");
        printf("\n");
    }
    
    printf("==============================================\n");
    
    // Cleanup
    cudaFree(d_base_indices);
    cudaFree(d_valid_flags);
    cudaFree(d_valid_count);
    cudaFree(d_valid_phrases);
    cudaFree(d_found_count);
    cudaFree(d_found_privkeys);
    cudaFree(d_found_indices);
    cudaFree(d_wordlist);
    
    return 0;
}
