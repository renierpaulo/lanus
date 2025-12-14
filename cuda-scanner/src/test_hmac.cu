/*
 * Test HMAC-SHA512 for BIP32 child key derivation
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "sha512.cuh"

__global__ void test_hmac() {
    printf("Testing HMAC-SHA512 for m/44' derivation:\n\n");
    
    // m/44' derivation:
    // key (chaincode) = b60f974f1368373053f893780a7c6bcf95feb4f7254922658a1af1dde8932e2c
    // data = 00 || parent_key || index (37 bytes)
    // data = 007441876923f2e91c3f89d3d1eb6e498ae684f8d2ad4a0bdde655cb352472e2278000002c
    
    uint8_t chaincode[32] = {
        0xb6, 0x0f, 0x97, 0x4f, 0x13, 0x68, 0x37, 0x30,
        0x53, 0xf8, 0x93, 0x78, 0x0a, 0x7c, 0x6b, 0xcf,
        0x95, 0xfe, 0xb4, 0xf7, 0x25, 0x49, 0x22, 0x65,
        0x8a, 0x1a, 0xf1, 0xdd, 0xe8, 0x93, 0x2e, 0x2c
    };
    
    uint8_t data[37] = {
        0x00,
        0x74, 0x41, 0x87, 0x69, 0x23, 0xf2, 0xe9, 0x1c,
        0x3f, 0x89, 0xd3, 0xd1, 0xeb, 0x6e, 0x49, 0x8a,
        0xe6, 0x84, 0xf8, 0xd2, 0xad, 0x4a, 0x0b, 0xdd,
        0xe6, 0x55, 0xcb, 0x35, 0x24, 0x72, 0xe2, 0x27,
        0x80, 0x00, 0x00, 0x2c  // 44 | 0x80000000 in big-endian
    };
    
    // Expected HMAC result (from Python):
    // IL: 437eb78e567b6820716b4054fe3508027df7f923988eb24802b072ac8f116f54
    // IR: a7e8ff955cd3edd8c93eb80f5fe80c39c0ff9013b64132db43c435b45857020c
    
    uint8_t expected_IL[32] = {
        0x43, 0x7e, 0xb7, 0x8e, 0x56, 0x7b, 0x68, 0x20,
        0x71, 0x6b, 0x40, 0x54, 0xfe, 0x35, 0x08, 0x02,
        0x7d, 0xf7, 0xf9, 0x23, 0x98, 0x8e, 0xb2, 0x48,
        0x02, 0xb0, 0x72, 0xac, 0x8f, 0x11, 0x6f, 0x54
    };
    
    printf("Key (chaincode): ");
    for(int i=0; i<32; i++) printf("%02x", chaincode[i]);
    printf("\n");
    
    printf("Data (37 bytes): ");
    for(int i=0; i<37; i++) printf("%02x", data[i]);
    printf("\n");
    
    printf("Expected IL:     ");
    for(int i=0; i<32; i++) printf("%02x", expected_IL[i]);
    printf("\n");
    
    uint8_t output[64];
    hmac_sha512(chaincode, 32, data, 37, output);
    
    printf("Computed IL:     ");
    for(int i=0; i<32; i++) printf("%02x", output[i]);
    printf("\n");
    
    printf("Computed IR:     ");
    for(int i=0; i<32; i++) printf("%02x", output[32+i]);
    printf("\n");
    
    bool match = true;
    for(int i=0; i<32; i++) {
        if(output[i] != expected_IL[i]) match = false;
    }
    
    printf("\nIL Match: %s\n", match ? "YES" : "NO - BUG IN HMAC_SHA512!");
}

int main() {
    cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 1024 * 1024);
    test_hmac<<<1, 1>>>();
    cudaDeviceSynchronize();
    return 0;
}
