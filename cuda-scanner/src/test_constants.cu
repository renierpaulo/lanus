/*
 * Test to verify SECP256K1_N constant is correct
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdint.h>

#include "secp256k1.cuh"

__global__ void test_constants() {
    printf("Testing secp256k1 constants:\n\n");
    
    // SECP256K1_N should be: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    printf("SECP256K1_N:\n");
    printf("  d[7] = %08x (should be FFFFFFFF)\n", SECP256K1_N.d[7]);
    printf("  d[6] = %08x (should be FFFFFFFF)\n", SECP256K1_N.d[6]);
    printf("  d[5] = %08x (should be FFFFFFFF)\n", SECP256K1_N.d[5]);
    printf("  d[4] = %08x (should be FFFFFFFE)\n", SECP256K1_N.d[4]);
    printf("  d[3] = %08x (should be BAAEDCE6)\n", SECP256K1_N.d[3]);
    printf("  d[2] = %08x (should be AF48A03B)\n", SECP256K1_N.d[2]);
    printf("  d[1] = %08x (should be BFD25E8C)\n", SECP256K1_N.d[1]);
    printf("  d[0] = %08x (should be D0364141)\n", SECP256K1_N.d[0]);
    
    printf("\nSECP256K1_P:\n");
    printf("  d[7] = %08x (should be FFFFFFFF)\n", SECP256K1_P.d[7]);
    printf("  d[6] = %08x (should be FFFFFFFF)\n", SECP256K1_P.d[6]);
    printf("  d[5] = %08x (should be FFFFFFFF)\n", SECP256K1_P.d[5]);
    printf("  d[4] = %08x (should be FFFFFFFF)\n", SECP256K1_P.d[4]);
    printf("  d[3] = %08x (should be FFFFFFFF)\n", SECP256K1_P.d[3]);
    printf("  d[2] = %08x (should be FFFFFFFF)\n", SECP256K1_P.d[2]);
    printf("  d[1] = %08x (should be FFFFFFFE)\n", SECP256K1_P.d[1]);
    printf("  d[0] = %08x (should be FFFFFC2F)\n", SECP256K1_P.d[0]);
    
    // Test uint256_mod_add with known values
    printf("\n\nTesting uint256_mod_add:\n");
    
    uint8_t a_bytes[32] = {
        0x43, 0x7e, 0xb7, 0x8e, 0x56, 0x7b, 0x68, 0x20,
        0x71, 0x6b, 0x40, 0x54, 0xfe, 0x35, 0x08, 0x02,
        0x7d, 0xf7, 0xf9, 0x23, 0x98, 0x8e, 0xb2, 0x48,
        0x02, 0xb0, 0x72, 0xac, 0x8f, 0x11, 0x6f, 0x54
    };
    
    uint8_t b_bytes[32] = {
        0x74, 0x41, 0x87, 0x69, 0x23, 0xf2, 0xe9, 0x1c,
        0x3f, 0x89, 0xd3, 0xd1, 0xeb, 0x6e, 0x49, 0x8a,
        0xe6, 0x84, 0xf8, 0xd2, 0xad, 0x4a, 0x0b, 0xdd,
        0xe6, 0x55, 0xcb, 0x35, 0x24, 0x72, 0xe2, 0x27
    };
    
    uint256_t a, b, r;
    bytes_to_uint256(&a, a_bytes);
    bytes_to_uint256(&b, b_bytes);
    
    printf("a = ");
    for(int i=0; i<32; i++) printf("%02x", a_bytes[i]);
    printf("\n");
    
    printf("b = ");
    for(int i=0; i<32; i++) printf("%02x", b_bytes[i]);
    printf("\n");
    
    uint256_mod_add(&r, &a, &b, &SECP256K1_N);
    
    uint8_t result[32];
    uint256_to_bytes(result, &r);
    
    printf("(a + b) mod n = ");
    for(int i=0; i<32; i++) printf("%02x", result[i]);
    printf("\n");
    printf("Expected:       b7c03ef77a6e513cb0f51426e9a3518d647cf1f645d8be25e9063de1b384517b\n");
}

int main() {
    cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 1024 * 1024);
    test_constants<<<1, 1>>>();
    cudaDeviceSynchronize();
    return 0;
}
