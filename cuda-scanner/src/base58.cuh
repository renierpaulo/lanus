/*
 * Base58 encoding/decoding for CUDA
 */

#ifndef BASE58_CUH
#define BASE58_CUH

#include <stdint.h>
#include <string.h>

static const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t BASE58_MAP[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1
};

// Decodificar endereço Base58Check para hash (20 bytes)
__host__ bool base58_decode_address(const char* address, uint8_t* hash) {
    size_t len = strlen(address);
    
    // Converter Base58 para número grande
    uint8_t bytes[25];
    memset(bytes, 0, 25);
    
    for (size_t i = 0; i < len; i++) {
        char c = address[i];
        if (c < 0 || c >= 128) return false;
        int8_t val = BASE58_MAP[(int)c];
        if (val < 0) return false;
        
        // Multiplicar por 58 e adicionar
        uint32_t carry = val;
        for (int j = 24; j >= 0; j--) {
            carry += 58 * bytes[j];
            bytes[j] = carry & 0xFF;
            carry >>= 8;
        }
    }
    
    // bytes[0] = version, bytes[1-20] = hash, bytes[21-24] = checksum
    // Verificar checksum (opcional para performance)
    
    // Extrair hash (20 bytes após version byte)
    memcpy(hash, bytes + 1, 20);
    
    return true;
}

// Codificar hash para endereço Base58Check (para debug/output)
__host__ void base58_encode_address(const uint8_t* hash, uint8_t version, char* address) {
    uint8_t data[25];
    data[0] = version;
    memcpy(data + 1, hash, 20);
    
    // Calcular checksum (SHA256(SHA256(data[0:21])))
    // Simplificado: usar biblioteca externa ou pré-calculado
    
    // Converter para Base58
    char temp[50];
    int idx = 49;
    temp[idx--] = '\0';
    
    // Conversão simplificada
    uint8_t num[25];
    memcpy(num, data, 25);
    
    while (idx >= 0) {
        uint32_t remainder = 0;
        bool all_zero = true;
        
        for (int i = 0; i < 25; i++) {
            uint32_t acc = remainder * 256 + num[i];
            num[i] = acc / 58;
            remainder = acc % 58;
            if (num[i] != 0) all_zero = false;
        }
        
        temp[idx--] = BASE58_ALPHABET[remainder];
        
        if (all_zero) break;
    }
    
    // Adicionar '1' para cada byte zero inicial
    for (int i = 0; i < 25 && data[i] == 0; i++) {
        temp[idx--] = '1';
    }
    
    strcpy(address, temp + idx + 1);
}

#endif // BASE58_CUH
