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
#include <chrono>

#include "sha256.cuh"
#include "sha512.cuh"
#include "ripemd160.cuh"
#include "secp256k1.cuh"
#include "base58.cuh"
#include "bip39.cuh"
#include "pbkdf2_opt.cuh"
#include "sha512_opt.cuh"
#include "pbkdf2_fast.cuh"
#include "secp256k1_fast.cuh"


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
std::atomic<bool> g_stop(false);   // uma GPU achou -> todas param
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
__constant__ uint32_t d_required_count;
__constant__ uint32_t d_wild_count;      // palavras livres da lista de 2048
__constant__ uint16_t d_pin[12];         // -pin: palavra fixa por posicao (0xFFFF = livre)
__constant__ uint32_t d_pin_count;       // quantas posicoes estao fixadas
__constant__ uint64_t d_perm_free;       // (12 - d_pin_count)!
__constant__ uint64_t d_binom[41][13];   // C(n,k), n<=40, k<=12
#define PERM12 479001600ULL              // 12!
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
        secp256k1_pubkey_fast(parent_key, pubkey);
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
    
    hmac_sha512_fast(parent_chaincode, 32, data, 37, I);
    
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
// splitmix64 finalizer. Sem isto, os bits BAIXOS do LCG sao degenerados
// (o bit i tem periodo 2^(i+1)), entao "cuda_rand() % n" nas ultimas escolhas
// fica travado e o gerador so alcanca 1/16 das permutacoes possiveis.
// Medido: 2.520 de 40.320 (6,25%) antes; 40.320 de 40.320 (100%) depois.
__device__ __forceinline__ uint64_t mix64(uint64_t z) {
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

__device__ uint64_t cuda_rand(uint64_t* seed) {
    *seed = (*seed * 6364136223846793005ULL + 1442695040888963407ULL);
    return mix64(*seed);
}

// ============================================================================
// Random 12-word phrase with 4 REQUIRED words + 8 random from remaining
// Required words: galaxy, egg, venture, oxygen (indices 0, 7, 10, 12 in word list)
// ============================================================================
// Monta uma frase de 12 palavras:
//   - as d_required_count primeiras palavras do arquivo -words entram SEMPRE;
//   - as (12 - d_required_count) restantes sao sorteadas do resto do arquivo;
//   - por fim as 12 posicoes sao embaralhadas (ordem desconhecida).
// Tudo vem do arquivo: para mudar a busca basta editar o .txt e usar -req N,
// sem recompilar.
__device__ void random_12word_with_required(uint64_t seed, uint32_t total_words, const uint16_t* base_indices, uint16_t* out_indices) {
    const uint32_t nreq  = d_required_count;
    const uint32_t nwild = d_wild_count;      // -wild N: livres das 2048

    for (uint32_t i = 0; i < nreq; i++) out_indices[i] = base_indices[i];

    // curingas: qualquer palavra da lista BIP39 completa
    for (uint32_t i = 0; i < nwild; i++)
        out_indices[nreq + i] = (uint16_t)(cuda_rand(&seed) % 2048u);

    uint16_t pool[MAX_WORDS];
    uint32_t navail = total_words - nreq;
    for (uint32_t i = 0; i < navail; i++) pool[i] = base_indices[nreq + i];

    const uint32_t nchoose = 12u - nreq - nwild;
    for (uint32_t i = 0; i < nchoose; i++) {
        uint32_t j = cuda_rand(&seed) % navail;
        out_indices[nreq + nwild + i] = pool[j];
        pool[j] = pool[navail - 1];
        navail--;
    }

    if (d_pin_count == 0) {
        for (int i = 11; i > 0; i--) {
            uint32_t j = cuda_rand(&seed) % (uint32_t)(i + 1);
            uint16_t t = out_indices[i];
            out_indices[i] = out_indices[j];
            out_indices[j] = t;
        }
    } else {
        // embaralha so as palavras livres; as fixas vao direto na posicao
        uint16_t doze[12];
        #pragma unroll
        for (int i = 0; i < 12; i++) doze[i] = out_indices[i];

        bool used[12];
        #pragma unroll
        for (int i = 0; i < 12; i++) used[i] = false;
        for (int p = 0; p < 12; p++) {
            uint16_t w = d_pin[p];
            if (w == 0xFFFFu) continue;
            for (int i = 0; i < 12; i++)
                if (!used[i] && doze[i] == w) { used[i] = true; break; }
        }

        uint16_t fr[12];
        int nf = 0;
        for (int i = 0; i < 12; i++) if (!used[i]) fr[nf++] = doze[i];
        for (int i = nf - 1; i > 0; i--) {
            uint32_t j = cuda_rand(&seed) % (uint32_t)(i + 1);
            uint16_t t = fr[i]; fr[i] = fr[j]; fr[j] = t;
        }

        int t2 = 0;
        for (int p = 0; p < 12; p++)
            out_indices[p] = (d_pin[p] != 0xFFFFu) ? d_pin[p] : fr[t2++];
    }
}

// ============================================================================
// ENUMERACAO EXAUSTIVA: k -> frase, bijetivo sobre C(P,K) * 12!
// ============================================================================
__device__ void unrank_combo(uint64_t idx, uint32_t nn, uint32_t kk, uint8_t* out) {
    uint64_t x = d_binom[nn][kk] - 1 - idx;
    int a = (int)nn, b = (int)kk;
    for (uint32_t i = 0; i < kk; i++) {
        a--;
        while (a > 0 && d_binom[a][b] > x) a--;
        x -= d_binom[a][b];
        out[i] = (uint8_t)((int)nn - 1 - a);
        b--;
    }
}

__device__ void unrank_perm12(uint64_t idx, const uint16_t* items, uint16_t* out) {
    uint16_t pool[12];
    #pragma unroll
    for (int i = 0; i < 12; i++) pool[i] = items[i];
    int navail = 12;
    for (int i = 12; i > 0; i--) {
        uint64_t f = d_factorials[i - 1];
        uint32_t j = (uint32_t)(idx / f);
        idx -= (uint64_t)j * f;
        out[12 - i] = pool[j];
        for (int m = j; m < navail - 1; m++) pool[m] = pool[m + 1];
        navail--;
    }
}

// Coloca as 12 palavras nas posicoes, respeitando o -pin.
// As posicoes fixas recebem a palavra dada; as livres recebem a idx-esima
// permutacao das palavras restantes. Bijetivo sobre (12 - pin_count)!.
__device__ void place_with_pins(uint64_t idx, const uint16_t* doze, uint16_t* out) {
    if (d_pin_count == 0) { unrank_perm12(idx, doze, out); return; }

    // marca, para cada palavra fixada, UMA ocorrencia dela em doze[]
    bool used[12];
    #pragma unroll
    for (int i = 0; i < 12; i++) used[i] = false;
    for (int p = 0; p < 12; p++) {
        uint16_t w = d_pin[p];
        if (w == 0xFFFFu) continue;
        for (int i = 0; i < 12; i++)
            if (!used[i] && doze[i] == w) { used[i] = true; break; }
    }

    // as que sobraram entram na permutacao
    uint16_t pool[12];
    int nfree = 0;
    for (int i = 0; i < 12; i++) if (!used[i]) pool[nfree++] = doze[i];

    uint16_t perm[12];
    int navail = nfree;
    for (int i = nfree; i > 0; i--) {
        uint64_t f = d_factorials[i - 1];
        uint32_t j = (uint32_t)(idx / f);
        idx -= (uint64_t)j * f;
        perm[nfree - i] = pool[j];
        for (int m = j; m < navail - 1; m++) pool[m] = pool[m + 1];
        navail--;
    }

    int t = 0;
    for (int p = 0; p < 12; p++)
        out[p] = (d_pin[p] != 0xFFFFu) ? d_pin[p] : perm[t++];
}

// k-esima frase do espaco de busca (sem repetir e sem pular).
__device__ void kth_phrase(uint64_t k, uint32_t total_words,
                           const uint16_t* base_indices, uint16_t* out_indices) {
    const uint32_t nreq  = d_required_count;
    const uint32_t nwild = d_wild_count;
    const uint32_t K = 12u - nreq - nwild;
    const uint32_t Psz = total_words - nreq;

    uint64_t rest      = k / d_perm_free;     // (combo, curingas)
    uint64_t perm_idx  = k - rest * d_perm_free;

    // desempacota os curingas (base 2048), depois a combinacao
    uint16_t wild[3];
    for (uint32_t i = 0; i < nwild; i++) {
        wild[i] = (uint16_t)(rest % 2048ULL);
        rest /= 2048ULL;
    }
    uint64_t combo_idx = rest;

    uint8_t sel[12];
    unrank_combo(combo_idx, Psz, K, sel);

    uint16_t doze[12];
    for (uint32_t i = 0; i < nreq; i++)  doze[i] = base_indices[i];
    for (uint32_t i = 0; i < nwild; i++) doze[nreq + i] = wild[i];
    for (uint32_t i = 0; i < K; i++)     doze[nreq + nwild + i] = base_indices[nreq + sel[i]];

    place_with_pins(perm_idx, doze, out_indices);
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
    uint32_t exhaustive,
    uint64_t total_space,
    const uint16_t* base_indices,
    uint32_t word_count,
    uint8_t* valid_flags,
    uint64_t* valid_count,
    uint16_t* valid_phrases_buffer
) {
    uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= batch_size) return;
    
    uint64_t k = start_k + tid;
    
    // Exaustivo: k -> frase (bijetivo). Aleatorio: sorteio com reposicao.
    uint16_t indices[MAX_WORDS];
    if (exhaustive) {
        if (k >= total_space) return;          // fim do espaco
        kth_phrase(k, word_count, base_indices, indices);
    } else {
        uint64_t seed = mix64(k * 0x9E3779B97F4A7C15ULL + 0x123456789ABCDEFULL);
        random_12word_with_required(seed, word_count, base_indices, indices);
    }
    
    // Force word_count to 12 for this search mode
    uint32_t actual_word_count = 12;
    
    // Validate checksum (always 12 words in this mode)
    bool valid = verify_checksum_12(indices);
    
    valid_flags[tid] = valid ? 1 : 0;
    
    if (valid) {
        uint64_t count = atomicAdd((unsigned long long*)valid_count, 1ULL);
        
        // Store indices for Phase 2 (always 12 words)
        for (int i = 0; i < 12; i++) {
            valid_phrases_buffer[count * 12 + i] = indices[i];
        }
    }
}

// Monta as 12 palavras direto no formato do PBKDF2 (16 x uint64 big-endian,
// zero-padded), sem passar por um array de bytes em memoria local.
__device__ __forceinline__ void pack_mnemonic_words(
    const uint16_t* indices, const char wl[2048][16], uint64_t* kw)
{
    #pragma unroll
    for (int i = 0; i < 16; i++) kw[i] = 0;
    uint32_t pos = 0;
    #pragma unroll 1
    for (int w = 0; w < 12; w++) {
        if (w) {
            kw[pos >> 3] |= (uint64_t)' ' << (56 - 8 * (pos & 7));
            pos++;
        }
        const char* s = wl[indices[w]];
        #pragma unroll 1
        for (int c = 0; c < 16; c++) {
            char ch = s[c];
            if (!ch) break;
            kw[pos >> 3] |= (uint64_t)(uint8_t)ch << (56 - 8 * (pos & 7));
            pos++;
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
    
    
    // Monta a frase direto no formato do PBKDF2 (16 x uint64): sai o array de
    // 256 bytes em memoria local E o reempacotamento byte->uint64 do pbkdf2.
    uint64_t kw[16];
    pack_mnemonic_words(indices, wordlist, kw);
    

    
    // Debug: imprime a primeira frase (kw esta empacotado em uint64 big-endian)
    #if DEBUG_MODE
    if (tid == 0) {
        char dbg[129];
        for (int i = 0; i < 16; i++)
            for (int b = 0; b < 8; b++)
                dbg[i*8+b] = (char)(kw[i] >> (56 - 8*b));
        dbg[128] = 0;
        printf("[DEBUG] MNEMONIC: %s\n", dbg);
        printf("[DEBUG] INDICES: ");
        for (int w = 0; w < 12; w++) printf("%d ", indices[w]);
        printf("\n");
    }
    #endif
    
    // PBKDF2-SHA512 to derive seed
    uint8_t seed[64];
    
    // BIP39: PBKDF2(password=mnemonic, salt="mnemonic", iterations=2048)
    // Pass mnemonic directly with its length
    pbkdf2_bip39_packed(kw, PBKDF2_ITERATIONS, seed);



    
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
        hmac_sha512_fast((const uint8_t*)key_str, 12, seed, 64, I);
        memcpy(master_key, I, 32);
        memcpy(master_chaincode, I + 32, 32);
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
    secp256k1_pubkey_fast(private_key, pubkey);

    uint8_t sha_hash[32];
    sha256(pubkey, 33, sha_hash);
    
    uint8_t pubkey_hash[20];
    ripemd160(sha_hash, 32, pubkey_hash);
    

    
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
// Checa uma chamada CUDA e aborta dizendo onde falhou. O codigo original nao
// checava nada, entao qualquer falha de setup virava um erro fantasma no kernel.
#define CUDA_CHECK(call) do {                                                  \
    cudaError_t _e = (call);                                                   \
    if (_e != cudaSuccess) {                                                   \
        printf("\n[X] CUDA falhou em %s:%d -> %s\n    chamada: %s\n",          \
               __FILE__, __LINE__, cudaGetErrorString(_e), #call);             \
        return 1;                                                              \
    }                                                                          \
} while (0)

int main(int argc, char** argv) {
    printf("============================================================\n");
    printf("  BIP39 CUDA Scanner v6.0 - ULTRA SPEED MODE\n");
    printf("============================================================\n");
    
    if (argc < 3) {
        printf("Usage: %s -words <words.txt> -a <addresses.txt> [-req N] [--bloom <MB>]\n", argv[0]);
        printf("  -req N : as N primeiras palavras do arquivo sao OBRIGATORIAS (default 4)\n");
        printf("  -gpus N: usar N GPUs (default: todas as detectadas)\n");
        printf("  -wild N: N palavras LIVRES da lista BIP39 completa (2048)\n");
        printf("  -pin POS:PALAVRA: fixa PALAVRA na posicao POS (1..12)\n");
        printf("           ex: -pin 1:hazard -pin 12:source\n");
        printf("           a palavra tem de estar entre as -req; cada pin divide o espaco\n");
        printf("           cada curinga multiplica o espaco por 2048 (max 3)\n");
        printf("  -exh   : varredura EXAUSTIVA (cobertura garantida, ~2x mais rapido\n");
        printf("           que o sorteio aleatorio no tempo esperado)\n");
        printf("  -resume K : retoma a varredura exaustiva a partir de k=K\n");
        printf("           as (12-N) restantes sao sorteadas do resto do arquivo\n");
        return 1;
    }

    // Increase stack size to prevent corruption in deep crypto functions
    cudaDeviceSetLimit(cudaLimitStackSize, 8192);
    cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 1024 * 1024 * 32); // 32MB printf buffer
    
    const char* words_file = NULL;
    const char* addr_file = NULL;
    int bloom_mb = 0;
    int required_count = 4;
    int exhaustive = 0;
    int n_gpus = 0;   // 0 = usar todas as detectadas
    int wild_count = 0;   // -wild N: N palavras livres das 2048
    uint16_t h_pin[12];   // -pin POS:PALAVRA (0xFFFF = posicao livre)
    for (int i = 0; i < 12; i++) h_pin[i] = 0xFFFFu;
    char pin_txt[12][16];
    for (int i = 0; i < 12; i++) pin_txt[i][0] = 0;
    int pin_count = 0;
    unsigned long long resume_k = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-words") == 0 && i + 1 < argc) words_file = argv[++i];
        else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) addr_file = argv[++i];
        else if (strcmp(argv[i], "--bloom") == 0 && i + 1 < argc) bloom_mb = atoi(argv[++i]);
        else if (strcmp(argv[i], "-req") == 0 && i + 1 < argc) required_count = atoi(argv[++i]);
        else if (strcmp(argv[i], "-exh") == 0) exhaustive = 1;
        else if (strcmp(argv[i], "-gpus") == 0 && i + 1 < argc) n_gpus = atoi(argv[++i]);
        else if (strcmp(argv[i], "-wild") == 0 && i + 1 < argc) wild_count = atoi(argv[++i]);
        else if (strcmp(argv[i], "-pin") == 0 && i + 1 < argc) {
            const char* spec = argv[++i];
            const char* dp = strchr(spec, ':');
            if (!dp) { printf("Error: -pin espera POSICAO:PALAVRA (ex: -pin 1:hazard)\n"); return 1; }
            int pos = atoi(spec);
            if (pos < 1 || pos > 12) { printf("Error: -pin posicao %d fora de 1..12\n", pos); return 1; }
            if (pin_txt[pos-1][0]) { printf("Error: -pin posicao %d definida duas vezes\n", pos); return 1; }
            snprintf(pin_txt[pos-1], 16, "%s", dp + 1);
            pin_count++;
        }
        else if (strcmp(argv[i], "-resume") == 0 && i + 1 < argc) resume_k = strtoull(argv[++i], NULL, 10);
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

    // -pin: resolve texto -> indice BIP39 e valida
    if (pin_count > 0) {
        for (int p = 0; p < 12; p++) {
            if (!pin_txt[p][0]) continue;
            int idx = -1;
            for (int w = 0; w < 2048; w++)
                if (strcmp(pin_txt[p], wordlist[w]) == 0) { idx = w; break; }
            if (idx < 0) {
                printf("Error: -pin %d:%s -- '%s' nao e palavra BIP39\n",
                       p + 1, pin_txt[p], pin_txt[p]);
                return 1;
            }
            // tem de estar entre as obrigatorias, senao pode nao ser sorteada
            bool obrig = false;
            for (int r = 0; r < required_count && r < (int)word_count; r++)
                if (h_word_indices[r] == (uint16_t)idx) { obrig = true; break; }
            if (!obrig) {
                printf("Error: -pin %d:%s -- essa palavra precisa estar entre as %d\n"
                       "       obrigatorias (as primeiras do -words). Aumente o -req\n"
                       "       ou mova '%s' para o inicio do arquivo.\n",
                       p + 1, pin_txt[p], required_count, pin_txt[p]);
                return 1;
            }
            h_pin[p] = (uint16_t)idx;
        }
        printf("Posicoes fixas (-pin): ");
        for (int p = 0; p < 12; p++)
            if (h_pin[p] != 0xFFFFu) printf("%d:%s ", p + 1, wordlist[h_pin[p]]);
        printf("\n");
    }

    // (12 - pin_count)! -- precisa existir antes dos cudaMemcpyToSymbol
    uint64_t h_perm_free = 1ULL;
    for (int i = 2; i <= 12 - pin_count; i++) h_perm_free *= (uint64_t)i;
    
    if (required_count < 0 || required_count > 12) {
        printf("Error: -req deve estar entre 0 e 12 (recebido %d)\n", required_count);
        return 1;
    }
    if (word_count < 12) {
        printf("Error: o arquivo -words precisa de pelo menos 12 palavras (tem %u)\n", word_count);
        return 1;
    }
    if ((uint32_t)required_count > word_count) {
        printf("Error: -req %d maior que o total de palavras (%u)\n", required_count, word_count);
        return 1;
    }
    if (wild_count < 0 || wild_count > 3) {
        printf("Error: -wild deve estar entre 0 e 3 (recebido %d)\n", wild_count);
        return 1;
    }
    if (required_count + wild_count > 12) {
        printf("Error: -req %d + -wild %d passa de 12 palavras\n", required_count, wild_count);
        return 1;
    }
    {
        int precisa = 12 - required_count - wild_count;   // sorteadas do pool
        int tem = (int)word_count - required_count;
        if (tem < precisa) {
            printf("Error: pool tem %d palavras, precisa de %d\n", tem, precisa);
            return 1;
        }
    }
    {
        uint32_t rc = (uint32_t)required_count;
        CUDA_CHECK(cudaMemcpyToSymbol(d_required_count, &rc, sizeof(uint32_t)));
        uint32_t wc = (uint32_t)wild_count;
        CUDA_CHECK(cudaMemcpyToSymbol(d_wild_count, &wc, sizeof(uint32_t)));
        CUDA_CHECK(cudaMemcpyToSymbol(d_pin, h_pin, 12 * sizeof(uint16_t)));
        uint32_t pc_a = (uint32_t)pin_count;
        CUDA_CHECK(cudaMemcpyToSymbol(d_pin_count, &pc_a, sizeof(uint32_t)));
        CUDA_CHECK(cudaMemcpyToSymbol(d_perm_free, &h_perm_free, sizeof(uint64_t)));
    }
    // C(n,k) para o unranking combinatorio
    static uint64_t h_binom[41][13];
    for (int a = 0; a <= 40; a++) {
        for (int b = 0; b <= 12; b++) {
            if (b == 0)      h_binom[a][b] = 1;
            else if (b > a)  h_binom[a][b] = 0;
            else             h_binom[a][b] = h_binom[a-1][b-1] + h_binom[a-1][b];
        }
    }
    CUDA_CHECK(cudaMemcpyToSymbol(d_binom, h_binom, sizeof(h_binom)));

    uint64_t total_space = h_binom[word_count - required_count][12 - required_count - wild_count]
                           * h_perm_free;
    for (int w = 0; w < wild_count; w++) total_space *= 2048ULL;
    if (pin_count > 0)
        printf("Permutacoes: %llu (12! dividido por %llu por causa dos %d pin)\n",
               (unsigned long long)h_perm_free,
               (unsigned long long)(479001600ULL / h_perm_free), pin_count);
    printf("Word count: %u\n", word_count);
    if (wild_count > 0)
        printf("Curingas: %d palavra(s) LIVRE(s) da lista completa (2048)\n", wild_count);
    printf("Obrigatorias (%d): ", required_count);
    for (int i = 0; i < required_count; i++) printf("%s ", wordlist[h_word_indices[i]]);
    printf("\nPool (%u) - sorteia %d: ", word_count - required_count,
           12 - required_count - wild_count);
    for (uint32_t i = required_count; i < word_count; i++) printf("%s ", wordlist[h_word_indices[i]]);
    printf("\n");
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
    CUDA_CHECK(cudaMemcpyToSymbol(d_word_indices, h_word_indices, MAX_WORDS * sizeof(uint16_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_word_count, &word_count, sizeof(uint32_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_factorials, h_factorials, 25 * sizeof(uint64_t)));
    
    // ========================================================================
    // Worker por GPU. Tudo declarado daqui pra baixo e LOCAL da thread, que e
    // o necessario: cudaMalloc e por dispositivo. O resto do main() e
    // capturado por referencia (so leitura).
    // ========================================================================
    auto worker = [&](int dev, uint64_t k_ini, uint64_t k_fim) -> int {
    CUDA_CHECK(cudaSetDevice(dev));
    cudaDeviceSetLimit(cudaLimitStackSize, 8192);
    cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 1024 * 1024 * 32);
    // simbolos __constant__ existem por dispositivo: reenviar em cada um
    CUDA_CHECK(cudaMemcpyToSymbol(d_word_indices, h_word_indices, MAX_WORDS * sizeof(uint16_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_word_count, &word_count, sizeof(uint32_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_factorials, h_factorials, 25 * sizeof(uint64_t)));
    {
        uint32_t rc_ = (uint32_t)required_count;
        CUDA_CHECK(cudaMemcpyToSymbol(d_required_count, &rc_, sizeof(uint32_t)));
        uint32_t wc_ = (uint32_t)wild_count;
        CUDA_CHECK(cudaMemcpyToSymbol(d_wild_count, &wc_, sizeof(uint32_t)));
        CUDA_CHECK(cudaMemcpyToSymbol(d_pin, h_pin, 12 * sizeof(uint16_t)));
        uint32_t pc_b = (uint32_t)pin_count;
        CUDA_CHECK(cudaMemcpyToSymbol(d_pin_count, &pc_b, sizeof(uint32_t)));
        CUDA_CHECK(cudaMemcpyToSymbol(d_perm_free, &h_perm_free, sizeof(uint64_t)));
        CUDA_CHECK(cudaMemcpyToSymbol(d_binom, h_binom, sizeof(h_binom)));
    }

    // Allocate device memory
    uint16_t* d_base_indices;
    CUDA_CHECK(cudaMalloc(&d_base_indices, MAX_WORDS * sizeof(uint16_t)));
    CUDA_CHECK(cudaMemcpy(d_base_indices, h_word_indices, MAX_WORDS * sizeof(uint16_t), cudaMemcpyHostToDevice));
    
    uint8_t* d_valid_flags;
    CUDA_CHECK(cudaMalloc(&d_valid_flags, BATCH_SIZE));
    
    uint64_t* d_valid_count;
    CUDA_CHECK(cudaMalloc(&d_valid_count, sizeof(uint64_t)));
    
    // Copy wordlist to device
    char (*d_wordlist)[16];
    CUDA_CHECK(cudaMalloc(&d_wordlist, 2048 * 16));
    CUDA_CHECK(cudaMemcpy(d_wordlist, wordlist, 2048 * 16, cudaMemcpyHostToDevice));

    // Buffer for valid phrases (Phase 2 input)
    uint16_t* d_valid_phrases;
    // Size: Batch size * Max words. 16M * 24 * 2 bytes = 768MB. OK for 24GB VRAM.
    CUDA_CHECK(cudaMalloc(&d_valid_phrases, BATCH_SIZE * MAX_WORDS * sizeof(uint16_t)));

    // Found results storage
    uint32_t* d_found_count;
    CUDA_CHECK(cudaMalloc(&d_found_count, sizeof(uint32_t)));
    CUDA_CHECK(cudaMemset(d_found_count, 0, sizeof(uint32_t)));

    uint8_t* d_found_privkeys;
    CUDA_CHECK(cudaMalloc(&d_found_privkeys, 100 * 32)); // Store up to 100 found keys

    uint16_t* d_found_indices;
    CUDA_CHECK(cudaMalloc(&d_found_indices, 100 * MAX_WORDS * sizeof(uint16_t)));
    
    // Target hashes pointers
    uint32_t use_bloom = 0;
    CUDA_CHECK(cudaMemcpyToSymbol(d_use_bloom, &use_bloom, sizeof(uint32_t)));
    
    if (num_targets > 0) {
        uint8_t* d_targets;
        CUDA_CHECK(cudaMalloc(&d_targets, target_hashes.size()));
        CUDA_CHECK(cudaMemcpy(d_targets, target_hashes.data(), target_hashes.size(), cudaMemcpyHostToDevice));
        
        // Update device symbols
        CUDA_CHECK(cudaMemcpyToSymbol(d_target_hashes_ptr, &d_targets, sizeof(uint8_t*)));
        CUDA_CHECK(cudaMemcpyToSymbol(d_num_targets, &num_targets, sizeof(uint32_t)));
    }
    
    printf("\n============================================================\n");
    printf("Starting REQUIRED WORDS MODE...\n");
    printf("Words are read from the file given with -words\n");
    printf("Pattern: 4 required + fill, see random_12word_with_required()\n");
    printf("Edit random_12word_with_required() to customize the pattern\n");
    printf("Phase 1: Checksum validation at GPU speed\n");
    printf("Phase 2: PBKDF2 + address derivation for valid phrases\n");
    printf("Press Ctrl+C to stop\n");
    printf("============================================================\n\n");
    
    if (exhaustive) {
        printf("Modo EXAUSTIVO: %llu frases (C(%u,%d) x 12!)\n",
               (unsigned long long)total_space, word_count - required_count, 12 - required_count);
        printf("Cobertura garantida; retomar com -resume <k>\n");
    } else {
        printf("Modo ALEATORIO (sorteio com reposicao, sem garantia de cobertura)\n");
    }
    printf("============================================================\n\n");

    // tempo de RELOGIO (clock() mede CPU e infla com varias threads)
    auto start_time = std::chrono::steady_clock::now();
    
    // Process in batches - INFINITE LOOP for random search
    uint64_t k = k_ini;
    while (true) {
        if (g_stop.load()) break;                 // outra GPU achou
        if (exhaustive && k >= k_fim) {
            printf("\n[GPU %d] faixa varrida por completo.\n", dev);
            break;
        }
        uint64_t batch = BATCH_SIZE;
        
        // Reset counter
        uint64_t zero = 0;
        cudaMemcpy(d_valid_count, &zero, sizeof(uint64_t), cudaMemcpyHostToDevice);
        
        // Phase 1: Validate checksums
        int threads = 256;
        int blocks = (batch + threads - 1) / threads;
        
        kernel_validate_checksums<<<blocks, threads>>>(
            k, batch, exhaustive ? 1u : 0u, total_space,
            d_base_indices, word_count, d_valid_flags, d_valid_count, d_valid_phrases
        );
        {
            cudaError_t ke = cudaDeviceSynchronize();
            if (ke == cudaSuccess) ke = cudaGetLastError();
            if (ke != cudaSuccess) {
                printf("\n[X] ERRO no kernel da Fase 1: %s\n", cudaGetErrorString(ke));
                printf("    (sem esta checagem o programa seguiria com Valid: 0 e taxa absurda)\n");
                return 1;
            }
        }
        
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
            {
                cudaError_t ke = cudaDeviceSynchronize();
                if (ke == cudaSuccess) ke = cudaGetLastError();
                if (ke != cudaSuccess) {
                    printf("\n[X] ERRO no kernel da Fase 2: %s\n", cudaGetErrorString(ke));
                    return 1;
                }
            }
            // Check found
            uint32_t found_now;
            cudaMemcpy(&found_now, d_found_count, sizeof(uint32_t), cudaMemcpyDeviceToHost);
            if (found_now > 0) {
                g_found.store(found_now);
                g_stop.store(true);
                printf("\n[+] FOUND %u MATCHES!\n", found_now);

                // O kernel guarda a frase e a chave; sem copiar de volta o
                // resultado se perdia junto com a memoria da GPU.
                uint32_t nshow = found_now > 100 ? 100 : found_now;
                uint16_t h_fidx[100 * MAX_WORDS];
                uint8_t  h_fkey[100 * 32];
                cudaMemcpy(h_fidx, d_found_indices, (size_t)nshow * MAX_WORDS * sizeof(uint16_t), cudaMemcpyDeviceToHost);
                cudaMemcpy(h_fkey, d_found_privkeys, (size_t)nshow * 32, cudaMemcpyDeviceToHost);

                FILE* ff = fopen("FOUND.txt", "a");
                for (uint32_t s = 0; s < nshow; s++) {
                    char phrase[512]; int pl = 0;
                    for (uint32_t w = 0; w < 12; w++) {
                        const char* wd = wordlist[h_fidx[s * word_count + w]];
                        if (w) phrase[pl++] = ' ';
                        for (int c = 0; wd[c]; c++) phrase[pl++] = wd[c];
                    }
                    phrase[pl] = 0;

                    char keyhex[80];
                    for (int b = 0; b < 32; b++) sprintf(keyhex + b * 2, "%02x", h_fkey[s * 32 + b]);
                    keyhex[64] = 0;

                    printf("\n*** FRASE ENCONTRADA ***\n");
                    printf("  Frase   : %s\n", phrase);
                    printf("  Privkey : %s\n", keyhex);
                    printf("  Caminho : m/44'/0'/0'/0/0\n");
                    if (ff) fprintf(ff, "%s\t%s\n", phrase, keyhex);
                }
                if (ff) { fclose(ff); printf("\n  (tambem salvo em FOUND.txt)\n"); }
                fflush(stdout);
                break;
            }
        }
        
        g_permutations_tested += batch;
        g_valid_checksums += valid_in_batch;
        
        k += batch;
        
        // Display progress and samples every 10 batches
        if (dev == 0 && (k / BATCH_SIZE) % 10 == 0) {
            double elapsed = std::chrono::duration<double>(
                                 std::chrono::steady_clock::now() - start_time).count();
            double rate = g_permutations_tested / elapsed;
            if (exhaustive) {
                double pct = 100.0 * (double)k / (double)total_space;
                double rate_now = g_permutations_tested.load() / elapsed;
                double eta_h = rate_now > 0 ? (total_space - k) / rate_now / 3600.0 : 0;
                printf("\n[EXAUSTIVO] k=%llu (%.4f%%) | restam ~%.1f h | Valid: %llu | %.2f M/s\n",
                       (unsigned long long)k, pct, eta_h,
                       (unsigned long long)g_valid_checksums.load(), rate_now / 1e6);
                FILE* pf = fopen("progress.txt", "w");
                if (pf) { fprintf(pf, "%llu\n", (unsigned long long)k); fclose(pf); }
            }
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
    
    // libera os buffers DESTA GPU
    cudaFree(d_base_indices);
    cudaFree(d_valid_flags);
    cudaFree(d_valid_count);
    cudaFree(d_valid_phrases);
    cudaFree(d_found_count);
    cudaFree(d_found_privkeys);
    cudaFree(d_found_indices);
    cudaFree(d_wordlist);
    return 0;
    };  // fim do worker

    // ------------------------------------------------------------------
    // Dispara uma thread por GPU, fatiando o espaco entre elas.
    // ------------------------------------------------------------------
    int dev_count = 0;
    cudaGetDeviceCount(&dev_count);
    if (dev_count < 1) { printf("Nenhuma GPU CUDA encontrada\n"); return 1; }
    int G = (n_gpus > 0 && n_gpus <= dev_count) ? n_gpus : dev_count;

    printf("Usando %d GPU(s) de %d disponiveis\n", G, dev_count);
    for (int d = 0; d < G; d++) {
        cudaDeviceProp p;
        if (cudaGetDeviceProperties(&p, d) == cudaSuccess)
            printf("  GPU %d: %s\n", d, p.name);
    }

    uint64_t base_k = exhaustive ? (uint64_t)resume_k : 0;
    uint64_t restante = (exhaustive && total_space > base_k) ? (total_space - base_k) : 0;
    uint64_t fatia = (G > 0) ? (restante / (uint64_t)G) : restante;

    if (exhaustive) {
        printf("Espaco fatiado entre as GPUs (%llu frases cada)\n",
               (unsigned long long)fatia);
    }
    printf("============================================================\n\n");

    std::vector<std::thread> ths;
    for (int d = 0; d < G; d++) {
        uint64_t ki, kf;
        if (exhaustive) {
            ki = base_k + fatia * (uint64_t)d;
            kf = (d == G - 1) ? total_space : (base_k + fatia * (uint64_t)(d + 1));
        } else {
            // no modo aleatorio a semente vem de k: deslocar evita caminhos iguais
            ki = base_k + (uint64_t)d * 0x1000000000ULL;
            kf = ~0ULL;
        }
        ths.emplace_back([&worker, d, ki, kf]() { worker(d, ki, kf); });
    }
    for (auto& t : ths) t.join();

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
    
    return 0;
}
