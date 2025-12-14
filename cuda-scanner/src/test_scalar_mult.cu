/*
 * Test scalar_mult with simple values
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdint.h>

#include "secp256k1.cuh"

__global__ void test_scalar_mult() {
    printf("Testing scalar_mult with simple values\n\n");
    
    // Test k = 1 (should give G)
    printf("=== k = 1 ===\n");
    uint8_t k1[32] = {0};
    k1[31] = 1;
    
    uint8_t pubkey1[33];
    secp256k1_get_pubkey_compressed(k1, pubkey1);
    printf("k=1: ");
    for(int i=0; i<33; i++) printf("%02x", pubkey1[i]);
    printf("\nExp: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\n\n");
    
    // Test k = 2 (should give 2*G)
    // 2*G.x = c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    // 2*G is even so prefix is 02
    printf("=== k = 2 ===\n");
    uint8_t k2[32] = {0};
    k2[31] = 2;
    
    uint8_t pubkey2[33];
    secp256k1_get_pubkey_compressed(k2, pubkey2);
    printf("k=2: ");
    for(int i=0; i<33; i++) printf("%02x", pubkey2[i]);
    printf("\nExp: 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\n\n");
    
    // Test k = 3 (should give 3*G)
    // 3*G.x = f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
    printf("=== k = 3 ===\n");
    uint8_t k3[32] = {0};
    k3[31] = 3;
    
    uint8_t pubkey3[33];
    secp256k1_get_pubkey_compressed(k3, pubkey3);
    printf("k=3: ");
    for(int i=0; i<33; i++) printf("%02x", pubkey3[i]);
    printf("\nExp: 02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\n\n");
    
    // Test k = 7 
    printf("=== k = 7 ===\n");
    uint8_t k7[32] = {0};
    k7[31] = 7;
    
    uint8_t pubkey7[33];
    secp256k1_get_pubkey_compressed(k7, pubkey7);
    printf("k=7: ");
    for(int i=0; i<33; i++) printf("%02x", pubkey7[i]);
    printf("\nExp: 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc\n\n");
    
    // Test k = 0x100 (256)
    printf("=== k = 256 ===\n");
    uint8_t k256[32] = {0};
    k256[30] = 1;  // 0x0100
    
    uint8_t pubkey256[33];
    secp256k1_get_pubkey_compressed(k256, pubkey256);
    printf("k=256: ");
    for(int i=0; i<33; i++) printf("%02x", pubkey256[i]);
    printf("\n");
    // Can verify this with Python
}

int main() {
    cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 1024 * 1024);
    test_scalar_mult<<<1, 1>>>();
    cudaDeviceSynchronize();
    return 0;
}
