/*
 * Bech32 encoding/decoding for CUDA
 * Used for SegWit addresses (bc1...)
 */

#ifndef BECH32_CUH
#define BECH32_CUH

#include <stdint.h>
#include <string.h>

static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t BECH32_MAP[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    15,-1,10,17,21,20,26,30,  7, 5,-1,-1,-1,-1,-1,-1,
    -1,29,-1,24,13,25, 9, 8, 23,-1,18,22,31,27,19,-1,
     1, 0, 3,16,11,28,12,14,  6, 4, 2,-1,-1,-1,-1,-1,
    -1,29,-1,24,13,25, 9, 8, 23,-1,18,22,31,27,19,-1,
     1, 0, 3,16,11,28,12,14,  6, 4, 2,-1,-1,-1,-1,-1
};

// Polymod para Bech32
__host__ __device__ uint32_t bech32_polymod(const uint8_t* values, size_t len) {
    const uint32_t GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    
    for (size_t i = 0; i < len; i++) {
        uint8_t b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ values[i];
        for (int j = 0; j < 5; j++) {
            if ((b >> j) & 1) {
                chk ^= GEN[j];
            }
        }
    }
    
    return chk;
}

// Expandir HRP para verificação
__host__ void bech32_hrp_expand(const char* hrp, uint8_t* ret) {
    size_t len = strlen(hrp);
    for (size_t i = 0; i < len; i++) {
        ret[i] = hrp[i] >> 5;
    }
    ret[len] = 0;
    for (size_t i = 0; i < len; i++) {
        ret[len + 1 + i] = hrp[i] & 31;
    }
}

// Decodificar endereço Bech32 para hash (20 bytes para P2WPKH)
__host__ bool bech32_decode_address(const char* address, uint8_t* hash) {
    size_t len = strlen(address);
    
    // Encontrar separador '1'
    size_t sep_pos = 0;
    for (size_t i = len - 1; i > 0; i--) {
        if (address[i] == '1') {
            sep_pos = i;
            break;
        }
    }
    
    if (sep_pos == 0 || sep_pos + 7 > len) return false;
    
    // Verificar HRP (deve ser "bc" para mainnet)
    if (sep_pos != 2 || address[0] != 'b' || address[1] != 'c') {
        // Permitir também "tb" para testnet
        if (!(sep_pos == 2 && address[0] == 't' && address[1] == 'b')) {
            return false;
        }
    }
    
    // Decodificar dados
    size_t data_len = len - sep_pos - 1;
    uint8_t data[100];
    
    for (size_t i = 0; i < data_len; i++) {
        char c = address[sep_pos + 1 + i];
        if (c < 0 || c >= 128) return false;
        int8_t val = BECH32_MAP[(int)c];
        if (val < 0) return false;
        data[i] = val;
    }
    
    // Primeiro byte é a versão do witness (deve ser 0 para P2WPKH)
    if (data[0] != 0) return false;
    
    // Converter de 5 bits para 8 bits
    uint32_t acc = 0;
    int bits = 0;
    int hash_idx = 0;
    
    // Pular version byte e checksum (últimos 6 bytes)
    for (size_t i = 1; i < data_len - 6 && hash_idx < 20; i++) {
        acc = (acc << 5) | data[i];
        bits += 5;
        
        if (bits >= 8) {
            bits -= 8;
            hash[hash_idx++] = (acc >> bits) & 0xFF;
        }
    }
    
    return hash_idx == 20;
}

// Codificar hash para endereço Bech32 (para debug/output)
__host__ void bech32_encode_address(const uint8_t* hash, char* address) {
    // Prefixo para mainnet
    strcpy(address, "bc1q");
    int idx = 4;
    
    // Converter 20 bytes (160 bits) para base32 (5 bits cada)
    // 160 / 5 = 32 caracteres
    uint32_t acc = 0;
    int bits = 0;
    
    for (int i = 0; i < 20; i++) {
        acc = (acc << 8) | hash[i];
        bits += 8;
        
        while (bits >= 5) {
            bits -= 5;
            address[idx++] = BECH32_CHARSET[(acc >> bits) & 31];
        }
    }
    
    // Padding se necessário
    if (bits > 0) {
        address[idx++] = BECH32_CHARSET[(acc << (5 - bits)) & 31];
    }
    
    // Adicionar checksum (6 caracteres)
    // Simplificado: checksum real requer polymod completo
    // Para produção, implementar corretamente
    
    address[idx] = '\0';
}

#endif // BECH32_CUH
