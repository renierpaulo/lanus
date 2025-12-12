/*
 * BIP39 utilities for CUDA
 */

#ifndef BIP39_CUH
#define BIP39_CUH

#include <stdint.h>

// Verificar checksum de mnemônico de 12 palavras
__device__ bool bip39_verify_checksum_12(const uint16_t* indices) {
    // 12 palavras = 132 bits = 128 bits entropia + 4 bits checksum
    uint8_t entropy[16];
    
    uint64_t acc = 0;
    for (int i = 0; i < 6; i++) {
        acc = (acc << 11) | indices[i];
    }
    entropy[0] = (acc >> 58) & 0xFF;
    entropy[1] = (acc >> 50) & 0xFF;
    entropy[2] = (acc >> 42) & 0xFF;
    entropy[3] = (acc >> 34) & 0xFF;
    entropy[4] = (acc >> 26) & 0xFF;
    entropy[5] = (acc >> 18) & 0xFF;
    entropy[6] = (acc >> 10) & 0xFF;
    entropy[7] = (acc >> 2) & 0xFF;
    
    uint64_t carry = acc & 3;
    for (int i = 6; i < 12; i++) {
        carry = (carry << 11) | indices[i];
    }
    entropy[8] = (carry >> 60) & 0xFF;
    entropy[9] = (carry >> 52) & 0xFF;
    entropy[10] = (carry >> 44) & 0xFF;
    entropy[11] = (carry >> 36) & 0xFF;
    entropy[12] = (carry >> 28) & 0xFF;
    entropy[13] = (carry >> 20) & 0xFF;
    entropy[14] = (carry >> 12) & 0xFF;
    entropy[15] = (carry >> 4) & 0xFF;
    
    uint8_t checksum_bits = carry & 0xF;
    
    // Calcular SHA256(entropy)[0] >> 4
    uint8_t hash[32];
    sha256(entropy, 16, hash);
    
    return checksum_bits == (hash[0] >> 4);
}

// Verificar checksum de mnemônico de 24 palavras
__device__ bool bip39_verify_checksum_24(const uint16_t* indices) {
    // 24 palavras = 264 bits = 256 bits entropia + 8 bits checksum
    uint8_t entropy[32];
    
    uint64_t acc = 0;
    for (int i = 0; i < 6; i++) {
        acc = (acc << 11) | indices[i];
    }
    entropy[0] = (acc >> 58) & 0xFF;
    entropy[1] = (acc >> 50) & 0xFF;
    entropy[2] = (acc >> 42) & 0xFF;
    entropy[3] = (acc >> 34) & 0xFF;
    entropy[4] = (acc >> 26) & 0xFF;
    entropy[5] = (acc >> 18) & 0xFF;
    entropy[6] = (acc >> 10) & 0xFF;
    entropy[7] = (acc >> 2) & 0xFF;
    acc &= 3;
    
    for (int i = 6; i < 12; i++) {
        acc = (acc << 11) | indices[i];
    }
    entropy[8] = (acc >> 60) & 0xFF;
    entropy[9] = (acc >> 52) & 0xFF;
    entropy[10] = (acc >> 44) & 0xFF;
    entropy[11] = (acc >> 36) & 0xFF;
    entropy[12] = (acc >> 28) & 0xFF;
    entropy[13] = (acc >> 20) & 0xFF;
    entropy[14] = (acc >> 12) & 0xFF;
    entropy[15] = (acc >> 4) & 0xFF;
    acc &= 15;
    
    for (int i = 12; i < 18; i++) {
        acc = (acc << 11) | indices[i];
    }
    entropy[16] = (acc >> 62) & 0xFF;
    entropy[17] = (acc >> 54) & 0xFF;
    entropy[18] = (acc >> 46) & 0xFF;
    entropy[19] = (acc >> 38) & 0xFF;
    entropy[20] = (acc >> 30) & 0xFF;
    entropy[21] = (acc >> 22) & 0xFF;
    entropy[22] = (acc >> 14) & 0xFF;
    entropy[23] = (acc >> 6) & 0xFF;
    
    __uint128_t big = acc & 63;
    for (int i = 18; i < 24; i++) {
        big = (big << 11) | indices[i];
    }
    entropy[24] = (big >> 64) & 0xFF;
    entropy[25] = (big >> 56) & 0xFF;
    entropy[26] = (big >> 48) & 0xFF;
    entropy[27] = (big >> 40) & 0xFF;
    entropy[28] = (big >> 32) & 0xFF;
    entropy[29] = (big >> 24) & 0xFF;
    entropy[30] = (big >> 16) & 0xFF;
    entropy[31] = (big >> 8) & 0xFF;
    
    uint8_t checksum_bits = big & 0xFF;
    
    // Calcular SHA256(entropy)[0]
    uint8_t hash[32];
    sha256(entropy, 32, hash);
    
    return checksum_bits == hash[0];
}

#endif // BIP39_CUH
