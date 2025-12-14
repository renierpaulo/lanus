/*
 * Test secp256k1_get_pubkey_compressed for m/44'/0'/0' key
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdint.h>

#include "secp256k1.cuh"

__global__ void test_pubkey() {
    printf("Testing secp256k1_get_pubkey_compressed\n\n");
    
    // m/44'/0'/0' private key (expected from Python)
    uint8_t privkey[32] = {
        0x68, 0x6f, 0x74, 0x58, 0xb9, 0x54, 0x5f, 0xe5,
        0x40, 0x9b, 0x06, 0xe6, 0xbb, 0xe6, 0x74, 0xb1,
        0xc5, 0x4c, 0xdb, 0x2c, 0x82, 0x4f, 0x76, 0xed,
        0xec, 0x21, 0xb0, 0x54, 0xe6, 0xeb, 0xb5, 0x17
    };
    
    printf("Private Key: ");
    for(int i=0; i<32; i++) printf("%02x", privkey[i]);
    printf("\n");
    
    // Expected compressed pubkey from Python:
    // 0274a47fb32fbe2012c93c5743ee1cbb7be9a058bfc1bd9c96fd4df384d831c90b
    
    printf("Expected:    0274a47fb32fbe2012c93c5743ee1cbb7be9a058bfc1bd9c96fd4df384d831c90b\n");
    
    uint8_t pubkey[33];
    secp256k1_get_pubkey_compressed(privkey, pubkey);
    
    printf("Computed:    ");
    for(int i=0; i<33; i++) printf("%02x", pubkey[i]);
    printf("\n");
    
    // Check match
    uint8_t expected[33] = {
        0x02,
        0x74, 0xa4, 0x7f, 0xb3, 0x2f, 0xbe, 0x20, 0x12,
        0xc9, 0x3c, 0x57, 0x43, 0xee, 0x1c, 0xbb, 0x7b,
        0xe9, 0xa0, 0x58, 0xbf, 0xc1, 0xbd, 0x9c, 0x96,
        0xfd, 0x4d, 0xf3, 0x84, 0xd8, 0x31, 0xc9, 0x0b
    };
    
    bool match = true;
    for(int i=0; i<33; i++) {
        if(pubkey[i] != expected[i]) match = false;
    }
    
    printf("\nMatch: %s\n", match ? "YES!" : "NO - BUG IN SECP256K1!");
    
    // Test with a simpler key too - just 1
    printf("\n\nTesting with private key = 1 (should give G):\n");
    uint8_t one[32] = {0};
    one[31] = 1;
    
    printf("Private Key: ");
    for(int i=0; i<32; i++) printf("%02x", one[i]);
    printf("\n");
    
    // G = 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    printf("Expected:    0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\n");
    
    secp256k1_get_pubkey_compressed(one, pubkey);
    
    printf("Computed:    ");
    for(int i=0; i<33; i++) printf("%02x", pubkey[i]);
    printf("\n");
}

int main() {
    cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 1024 * 1024);
    test_pubkey<<<1, 1>>>();
    cudaDeviceSynchronize();
    return 0;
}
