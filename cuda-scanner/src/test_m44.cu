/*
 * Simple test for ONLY the m/44' derivation
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "sha512.cuh"
#include "secp256k1.cuh"

__global__ void test_m44() {
    printf("Testing ONLY m/44' derivation\n\n");
    
    // Master key and chaincode
    uint8_t master_key[32] = {
        0x74, 0x41, 0x87, 0x69, 0x23, 0xf2, 0xe9, 0x1c,
        0x3f, 0x89, 0xd3, 0xd1, 0xeb, 0x6e, 0x49, 0x8a,
        0xe6, 0x84, 0xf8, 0xd2, 0xad, 0x4a, 0x0b, 0xdd,
        0xe6, 0x55, 0xcb, 0x35, 0x24, 0x72, 0xe2, 0x27
    };
    
    uint8_t master_chain[32] = {
        0xb6, 0x0f, 0x97, 0x4f, 0x13, 0x68, 0x37, 0x30,
        0x53, 0xf8, 0x93, 0x78, 0x0a, 0x7c, 0x6b, 0xcf,
        0x95, 0xfe, 0xb4, 0xf7, 0x25, 0x49, 0x22, 0x65,
        0x8a, 0x1a, 0xf1, 0xdd, 0xe8, 0x93, 0x2e, 0x2c
    };
    
    // Build data for m/44' (hardened)
    uint32_t index = 44 | 0x80000000;
    uint8_t data[37];
    data[0] = 0x00;
    memcpy(data + 1, master_key, 32);
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;
    
    printf("Master Key:   ");
    for(int i=0; i<32; i++) printf("%02x", master_key[i]);
    printf("\n");
    
    printf("Master Chain: ");
    for(int i=0; i<32; i++) printf("%02x", master_chain[i]);
    printf("\n");
    
    printf("HMAC Data:    ");
    for(int i=0; i<37; i++) printf("%02x", data[i]);
    printf("\n");
    
    // Expected:
    printf("Expected Data:007441876923f2e91c3f89d3d1eb6e498ae684f8d2ad4a0bdde655cb352472e2278000002c\n");
    
    // Compute HMAC
    uint8_t I[64];
    hmac_sha512(master_chain, 32, data, 37, I);
    
    printf("HMAC IL:      ");
    for(int i=0; i<32; i++) printf("%02x", I[i]);
    printf("\n");
    printf("Expected IL:  437eb78e567b6820716b4054fe3508027df7f923988eb24802b072ac8f116f54\n");
    
    printf("HMAC IR:      ");
    for(int i=0; i<32; i++) printf("%02x", I[32+i]);
    printf("\n");
    printf("Expected IR:  a7e8ff955cd3edd8c93eb80f5fe80c39c0ff9013b64132db43c435b45857020c\n");
    
    // Compare IL
    uint8_t expected_IL[32] = {
        0x43, 0x7e, 0xb7, 0x8e, 0x56, 0x7b, 0x68, 0x20,
        0x71, 0x6b, 0x40, 0x54, 0xfe, 0x35, 0x08, 0x02,
        0x7d, 0xf7, 0xf9, 0x23, 0x98, 0x8e, 0xb2, 0x48,
        0x02, 0xb0, 0x72, 0xac, 0x8f, 0x11, 0x6f, 0x54
    };
    
    bool match = true;
    for(int i=0; i<32; i++) {
        if(I[i] != expected_IL[i]) match = false;
    }
    
    printf("\nHMAC IL Match: %s\n", match ? "YES!" : "NO - BUG!");
    
    // Compute child key
    uint8_t child_key[32];
    secp256k1_scalar_add(I, master_key, child_key);
    
    printf("\nChild Key:    ");
    for(int i=0; i<32; i++) printf("%02x", child_key[i]);
    printf("\n");
    printf("Expected Key: b7c03ef77a6e513cb0f51426e9a3518d647cf1f645d8be25e9063de1b384517b\n");
}

int main() {
    cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 1024 * 1024);
    test_m44<<<1, 1>>>();
    cudaDeviceSynchronize();
    return 0;
}
