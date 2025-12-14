/*
 * Simple test for BIP39 derivation
 * Tests one specific mnemonic phrase step by step
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha256.cuh"
#include "sha512.cuh"
#include "ripemd160.cuh"
#include "secp256k1.cuh"
#include "base58.cuh"
#include "pbkdf2_opt.cuh"

#define PBKDF2_ITERATIONS 2048

// BIP32 Child Key Derivation
__device__ void derive_child_key_test(
    const uint8_t* parent_key,
    const uint8_t* parent_chaincode,
    uint32_t index,
    uint8_t* child_key,
    uint8_t* child_chaincode,
    bool hardened,
    const char* step_name
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
        printf("  Pubkey for %s: ", step_name);
        for(int k=0; k<33; k++) printf("%02x", pubkey[k]);
        printf("\n");
    }
    
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;
    
    printf("  HMAC data for %s: ", step_name);
    for(int k=0; k<37; k++) printf("%02x", data[k]);
    printf("\n");
    
    hmac_sha512(parent_chaincode, 32, data, 37, I);
    
    printf("  HMAC result (IL): ");
    for(int k=0; k<32; k++) printf("%02x", I[k]);
    printf("\n");
    printf("  HMAC result (IR): ");
    for(int k=0; k<32; k++) printf("%02x", I[k+32]);
    printf("\n");
    
    // Add parent key to derived key (mod n)
    secp256k1_scalar_add(I, parent_key, child_key);
    memcpy(child_chaincode, I + 32, 32);
    
    printf("  Child key for %s: ", step_name);
    for(int k=0; k<32; k++) printf("%02x", child_key[k]);
    printf("\n");
}

__global__ void test_derivation_kernel(char wordlist[2048][16]) {
    // Hardcoded test phrase: "galaxy man boy evil donkey child cross chair egg meat blood space"
    const char* test_mnemonic = "galaxy man boy evil donkey child cross chair egg meat blood space";
    int mnem_len = 71; // Pre-calculated length
    
    printf("=================================================================\n");
    printf("Testing BIP39 derivation for:\n");
    printf("Mnemonic: %s\n", test_mnemonic);
    printf("Length: %d bytes\n", mnem_len);
    printf("=================================================================\n\n");
    
    // Step 1: PBKDF2-SHA512
    printf("STEP 1: PBKDF2-SHA512\n");
    uint8_t seed[64];
    const char* salt = "mnemonic";
    
    pbkdf2_sha512_mnemonic((const uint8_t*)test_mnemonic, mnem_len, (const uint8_t*)salt, 8, PBKDF2_ITERATIONS, seed);
    
    printf("Computed Seed: ");
    for(int k=0; k<64; k++) printf("%02x", seed[k]);
    printf("\n");
    printf("Expected Seed: 4cd832a5c862ef5117870c15bdf792ed558499a2c81d8bd5c68f28bf0f66671b76e6522d90fb4996cc29d1a7b37ccf0bcc8157dea21f5f065e89921841323ab8\n\n");
    
    // Compare first 8 bytes
    uint8_t expected_seed_start[] = {0x4c, 0xd8, 0x32, 0xa5, 0xc8, 0x62, 0xef, 0x51};
    bool seed_match = true;
    for(int i=0; i<8; i++) {
        if(seed[i] != expected_seed_start[i]) seed_match = false;
    }
    printf("Seed first 8 bytes match: %s\n\n", seed_match ? "YES" : "NO - ERROR!");
    
    // Step 2: Master Key
    printf("STEP 2: Master Key (HMAC-SHA512 with 'Bitcoin seed')\n");
    uint8_t master_key[32], master_chaincode[32];
    {
        const char* key_str = "Bitcoin seed";
        uint8_t I[64];
        hmac_sha512((const uint8_t*)key_str, 12, seed, 64, I);
        memcpy(master_key, I, 32);
        memcpy(master_chaincode, I + 32, 32);
    }
    
    printf("Master Key: ");
    for(int k=0; k<32; k++) printf("%02x", master_key[k]);
    printf("\n");
    printf("Master Chain: ");
    for(int k=0; k<32; k++) printf("%02x", master_chaincode[k]);
    printf("\n\n");
    
    // Step 3: Derive m/44'/0'/0'/0/0
    printf("STEP 3: Key Derivation\n\n");
    
    uint8_t key[32], chaincode[32];
    uint8_t temp_key[32], temp_chaincode[32];
    
    printf("m/44' derivation:\n");
    derive_child_key_test(master_key, master_chaincode, 44, key, chaincode, true, "m/44'");
    printf("\n");
    
    printf("m/44'/0' derivation:\n");
    derive_child_key_test(key, chaincode, 0, temp_key, temp_chaincode, true, "m/44'/0'");
    memcpy(key, temp_key, 32); memcpy(chaincode, temp_chaincode, 32);
    printf("\n");
    
    printf("m/44'/0'/0' derivation:\n");
    derive_child_key_test(key, chaincode, 0, temp_key, temp_chaincode, true, "m/44'/0'/0'");
    memcpy(key, temp_key, 32); memcpy(chaincode, temp_chaincode, 32);
    printf("\n");
    
    printf("m/44'/0'/0'/0 derivation:\n");
    derive_child_key_test(key, chaincode, 0, temp_key, temp_chaincode, false, "m/44'/0'/0'/0");
    memcpy(key, temp_key, 32); memcpy(chaincode, temp_chaincode, 32);
    printf("\n");
    
    printf("m/44'/0'/0'/0/0 derivation:\n");
    uint8_t private_key[32];
    derive_child_key_test(key, chaincode, 0, private_key, temp_chaincode, false, "m/44'/0'/0'/0/0");
    printf("\n");
    
    // Step 4: Public key
    printf("STEP 4: Public Key\n");
    uint8_t pubkey[33];
    secp256k1_get_pubkey_compressed(private_key, pubkey);
    
    printf("Final Private Key: ");
    for(int k=0; k<32; k++) printf("%02x", private_key[k]);
    printf("\n");
    printf("Expected Priv Key: 20bbcda671e9f66cfededb3cc676358c02db5530cb1975dfa82d003e5233fae2\n");
    
    printf("Compressed Pubkey: ");
    for(int k=0; k<33; k++) printf("%02x", pubkey[k]);
    printf("\n");
    printf("Expected Pubkey:   026397423d347ccb8f2d394e419d53eac9009830f13a69dd6ff834b87c9e347169\n\n");
    
    // Step 5: Hash160
    printf("STEP 5: Hash160\n");
    uint8_t sha_hash[32];
    sha256(pubkey, 33, sha_hash);
    
    printf("SHA256(pubkey): ");
    for(int k=0; k<32; k++) printf("%02x", sha_hash[k]);
    printf("\n");
    
    uint8_t pubkey_hash[20];
    ripemd160(sha_hash, 32, pubkey_hash);
    
    printf("RIPEMD160(sha): ");
    for(int k=0; k<20; k++) printf("%02x", pubkey_hash[k]);
    printf("\n");
    printf("Expected Hash:  232fb8a4bb0b8be8daeb78d9022d126006309c5c\n\n");
    
    // Compare
    uint8_t expected_hash[] = {0x23, 0x2f, 0xb8, 0xa4, 0xbb, 0x0b, 0x8b, 0xe8, 0xda, 0xeb, 0x78, 0xd9, 0x02, 0x2d, 0x12, 0x60, 0x06, 0x30, 0x9c, 0x5c};
    bool match = true;
    for(int i=0; i<20; i++) {
        if(pubkey_hash[i] != expected_hash[i]) match = false;
    }
    printf("=================================================================\n");
    printf("FINAL RESULT: %s\n", match ? "MATCH!" : "MISMATCH - ERROR IN DERIVATION");
    printf("=================================================================\n");
}

int main() {
    printf("BIP39 Derivation Test\n");
    printf("=====================\n\n");
    
    // Load wordlist
    char wordlist[2048][16];
    FILE* f = fopen("wordlist.txt", "r");
    if (!f) {
        printf("Error: Cannot open wordlist.txt\n");
        return 1;
    }
    
    char line[64];
    int idx = 0;
    while (fgets(line, sizeof(line), f) && idx < 2048) {
        line[strcspn(line, "\r\n")] = 0;
        memset(wordlist[idx], 0, 16);
        strncpy(wordlist[idx], line, 15);
        idx++;
    }
    fclose(f);
    printf("Loaded %d words\n\n", idx);
    
    // Allocate and copy wordlist to GPU
    char (*d_wordlist)[16];
    cudaMalloc(&d_wordlist, 2048 * 16);
    cudaMemcpy(d_wordlist, wordlist, 2048 * 16, cudaMemcpyHostToDevice);
    
    // Set printf buffer size
    cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 1024 * 1024 * 32);
    
    // Run test kernel with 1 thread
    test_derivation_kernel<<<1, 1>>>(d_wordlist);
    cudaDeviceSynchronize();
    
    cudaFree(d_wordlist);
    
    return 0;
}
