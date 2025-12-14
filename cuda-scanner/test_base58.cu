
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include "base58.cuh"

// Mock definitions needed for linking if base58.cuh depends on them
// Assuming base58.cuh is standalone-ish or header-only for this test
// If it needs implementations from other files, we might need to include them or link against them.
// Looking at previous file views, base58.cuh seems to be included in main.cu.

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <address>\n", argv[0]);
        return 1;
    }

    const char* address = argv[1];
    printf("Testing Base58 Decode for: %s\n", address);

    uint8_t hash[20];
    bool success = base58_decode_address(address, hash);

    if (success) {
        printf("Decode SUCCESS.\n");
        printf("Hash160: ");
        for(int i=0; i<20; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");

        // Expected hash for 14D3pSqxVQdq2i9299k7KJpNmDoGPcw96B
        // is 232fb8a4bb0b8be8daeb78d9022d126006309c5c
        uint8_t expected[] = {
            0x23, 0x2f, 0xb8, 0xa4, 0xbb, 0x0b, 0x8b, 0xe8, 0xda, 0xeb, 
            0x78, 0xd9, 0x02, 0x2d, 0x12, 0x60, 0x06, 0x30, 0x9c, 0x5c
        };

        bool match = true;
        for(int i=0; i<20; i++) {
            if(hash[i] != expected[i]) match = false;
        }

        if(match) printf("MATCHES EXPECTED HASH!\n");
        else printf("MISMATCH! Expected: 232fb8a4bb0b8be8daeb78d9022d126006309c5c\n");

    } else {
        printf("Decode FAILED.\n");
    }

    return 0;
}
