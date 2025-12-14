/*
 * Minimal test for secp256k1_scalar_add
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdint.h>

#include "secp256k1.cuh"

__global__ void test_scalar_add() {
    // Test case from m/44' derivation:
    // IL = 437eb78e567b6820716b4054fe3508027df7f923988eb24802b072ac8f116f54
    // parent_key = 7441876923f2e91c3f89d3d1eb6e498ae684f8d2ad4a0bdde655cb352472e227
    // Expected child = (IL + parent) mod n = b7c03ef77a6e513cb0f51426e9a3518d647cf1f645d8be25e9063de1b384517b
    
    uint8_t IL[32] = {
        0x43, 0x7e, 0xb7, 0x8e, 0x56, 0x7b, 0x68, 0x20,
        0x71, 0x6b, 0x40, 0x54, 0xfe, 0x35, 0x08, 0x02,
        0x7d, 0xf7, 0xf9, 0x23, 0x98, 0x8e, 0xb2, 0x48,
        0x02, 0xb0, 0x72, 0xac, 0x8f, 0x11, 0x6f, 0x54
    };
    
    uint8_t parent[32] = {
        0x74, 0x41, 0x87, 0x69, 0x23, 0xf2, 0xe9, 0x1c,
        0x3f, 0x89, 0xd3, 0xd1, 0xeb, 0x6e, 0x49, 0x8a,
        0xe6, 0x84, 0xf8, 0xd2, 0xad, 0x4a, 0x0b, 0xdd,
        0xe6, 0x55, 0xcb, 0x35, 0x24, 0x72, 0xe2, 0x27
    };
    
    uint8_t expected[32] = {
        0xb7, 0xc0, 0x3e, 0xf7, 0x7a, 0x6e, 0x51, 0x3c,
        0xb0, 0xf5, 0x14, 0x26, 0xe9, 0xa3, 0x51, 0x8d,
        0x64, 0x7c, 0xf1, 0xf6, 0x45, 0xd8, 0xbe, 0x25,
        0xe9, 0x06, 0x3d, 0xe1, 0xb3, 0x84, 0x51, 0x7b
    };
    
    uint8_t result[32];
    
    printf("Testing secp256k1_scalar_add:\n");
    printf("IL:       ");
    for(int i=0; i<32; i++) printf("%02x", IL[i]);
    printf("\n");
    
    printf("Parent:   ");
    for(int i=0; i<32; i++) printf("%02x", parent[i]);
    printf("\n");
    
    printf("Expected: ");
    for(int i=0; i<32; i++) printf("%02x", expected[i]);
    printf("\n");
    
    secp256k1_scalar_add(IL, parent, result);
    
    printf("Result:   ");
    for(int i=0; i<32; i++) printf("%02x", result[i]);
    printf("\n");
    
    bool match = true;
    for(int i=0; i<32; i++) {
        if(result[i] != expected[i]) match = false;
    }
    
    printf("Match: %s\n", match ? "YES" : "NO - BUG IN SCALAR_ADD!");
    
    // Also test bytes_to_uint256 and uint256_to_bytes
    printf("\n\nTesting bytes_to_uint256 and uint256_to_bytes:\n");
    uint256_t test_val;
    bytes_to_uint256(&test_val, IL);
    
    printf("IL as uint256_t.d:\n");
    for(int i=0; i<8; i++) printf("  d[%d] = 0x%08x\n", i, test_val.d[i]);
    
    uint8_t back[32];
    uint256_to_bytes(back, &test_val);
    printf("Back to bytes: ");
    for(int i=0; i<32; i++) printf("%02x", back[i]);
    printf("\n");
    
    bool round_trip = true;
    for(int i=0; i<32; i++) {
        if(back[i] != IL[i]) round_trip = false;
    }
    printf("Round-trip match: %s\n", round_trip ? "YES" : "NO - BUG IN BYTE CONVERSION!");
}

int main() {
    cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 1024 * 1024);
    test_scalar_add<<<1, 1>>>();
    cudaDeviceSynchronize();
    return 0;
}
