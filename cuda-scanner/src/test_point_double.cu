/*
 * Test point_double with G
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdint.h>

#include "secp256k1.cuh"

__global__ void test_point_double() {
    printf("Testing point_double(G)\n\n");
    
    // G in affine coordinates
    // Gx = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    // Gy = 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    
    // 2*G expected:
    // 2G.x = C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
    // 2G.y = 1AE168FEA63DC339A3C58419466CEAE1061B7CD340607F4C57C9C5E06D2EA4BD (even, so prefix 02)
    
    printf("Testing: 2*G = G + G\n");
    printf("Expected 2G.x: c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\n\n");
    
    // Create G with Z = 1 (affine)
    point_t G;
    G.x = SECP256K1_GX;
    G.y = SECP256K1_GY;
    uint256_set_one(&G.z);
    G.infinity = false;
    
    printf("G.x: ");
    for(int i=7; i>=0; i--) printf("%08x", G.x.d[i]);
    printf("\n");
    
    printf("G.y: ");
    for(int i=7; i>=0; i--) printf("%08x", G.y.d[i]);
    printf("\n");
    
    printf("G.z: ");
    for(int i=7; i>=0; i--) printf("%08x", G.z.d[i]);
    printf("\n\n");
    
    // Double G
    point_t twoG;
    point_double(&twoG, &G);
    
    printf("After point_double:\n");
    printf("2G.x (Jacobian): ");
    for(int i=7; i>=0; i--) printf("%08x", twoG.x.d[i]);
    printf("\n");
    
    printf("2G.y (Jacobian): ");
    for(int i=7; i>=0; i--) printf("%08x", twoG.y.d[i]);
    printf("\n");
    
    printf("2G.z (Jacobian): ");
    for(int i=7; i>=0; i--) printf("%08x", twoG.z.d[i]);
    printf("\n\n");
    
    // Convert to affine: x = X/Z^2, y = Y/Z^3
    uint256_t zinv, z2inv, z3inv, x_aff, y_aff;
    uint256_mod_inv(&zinv, &twoG.z, &SECP256K1_P);
    uint256_mod_mul(&z2inv, &zinv, &zinv, &SECP256K1_P);
    uint256_mod_mul(&z3inv, &z2inv, &zinv, &SECP256K1_P);
    uint256_mod_mul(&x_aff, &twoG.x, &z2inv, &SECP256K1_P);
    uint256_mod_mul(&y_aff, &twoG.y, &z3inv, &SECP256K1_P);
    
    printf("2G.x (Affine): ");
    for(int i=7; i>=0; i--) printf("%08x", x_aff.d[i]);
    printf("\n");
    printf("Expected:      c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\n\n");
    
    printf("2G.y (Affine): ");
    for(int i=7; i>=0; i--) printf("%08x", y_aff.d[i]);
    printf("\n");
    printf("Expected:      1ae168fea63dc339a3c58419466ceae1061b7cd340607f4c57c9c5e06d2ea4bd (even)\n");
    
    // Check X coordinate
    uint8_t expected_x[32] = {
        0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d,
        0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
        0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7,
        0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5
    };
    
    uint8_t computed_x[32];
    uint256_to_bytes(computed_x, &x_aff);
    
    bool match = true;
    for(int i=0; i<32; i++) {
        if(computed_x[i] != expected_x[i]) match = false;
    }
    
    printf("\n2G.x Match: %s\n", match ? "YES!" : "NO - BUG IN POINT_DOUBLE!");
}

int main() {
    cudaDeviceSetLimit(cudaLimitPrintfFifoSize, 1024 * 1024);
    test_point_double<<<1, 1>>>();
    cudaDeviceSynchronize();
    return 0;
}
