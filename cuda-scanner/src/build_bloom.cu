/*
 * build_bloom.cu
 * 
 * Ferramenta de pré-processamento de endereços para o BIP39 CUDA Scanner.
 * Lê um arquivo de endereços (Base58/Bech32), converte para hash160 e
 * constrói um Bloom filter em disco (bloom.bin) para uso direto na GPU.
 *
 * Uso (exemplo):
 *   build_bloom.exe addresses_big.txt bloom.bin 4096 10
 *
 *   4096 = tamanho do Bloom em MB (aqui, 4 GiB de bits)
 *   10   = número de funções hash (k)
 */

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "base58.cuh"
#include "bech32.cuh"

struct BloomHeader {
    uint32_t magic;      // 'BLMF' = 0x424C4D46
    uint32_t version;    // 1
    uint64_t m_bits;     // tamanho do Bloom em bits
    uint32_t k;          // número de funções hash
    uint32_t reserved;   // padding
    uint64_t n_items;    // elementos efetivamente inseridos
};

static const uint32_t BLOOM_MAGIC = 0x424C4D46; // 'BLMF'
static const uint32_t BLOOM_VERSION = 1;

// FNV-1a simples 64-bit
static inline uint64_t fnv1a64(const uint8_t* data, size_t len, uint64_t seed) {
    uint64_t hash = 1469598103934665603ULL ^ seed;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static inline void bloom_add(uint8_t* bits, uint64_t m_bits, uint32_t k, const uint8_t hash160[20]) {
    uint64_t h1 = fnv1a64(hash160, 20, 0xA5A5A5A5A5A5A5A5ULL);
    uint64_t h2 = fnv1a64(hash160, 20, 0x5A5A5A5A5A5A5A5AULL);

    for (uint32_t i = 0; i < k; i++) {
        uint64_t combined = h1 + i * h2;
        uint64_t bit_index = combined % m_bits;
        uint64_t byte_index = bit_index >> 3;
        uint8_t mask = 1u << (bit_index & 7u);
        bits[byte_index] |= mask;
    }
}

int main(int argc, char** argv) {
    if (argc < 5) {
        std::fprintf(stderr,
            "Uso: %s <enderecos.txt> <bloom.bin> <bloom_mb> <k>\n"
            "  <enderecos.txt> : arquivo com endereços (um por linha)\n"
            "  <bloom.bin>     : arquivo de saída do Bloom filter\n"
            "  <bloom_mb>      : tamanho do Bloom em MB (ex: 2048 = 2 GiB)\n"
            "  <k>             : número de hashes por elemento (ex: 10)\n",
            argv[0]);
        return 1;
    }

    const char* addresses_path = argv[1];
    const char* bloom_path = argv[2];
    uint64_t bloom_mb = std::strtoull(argv[3], nullptr, 10);
    uint32_t k = static_cast<uint32_t>(std::strtoul(argv[4], nullptr, 10));

    if (bloom_mb == 0 || k == 0) {
        std::fprintf(stderr, "Erro: bloom_mb e k devem ser > 0\n");
        return 1;
    }

    uint64_t m_bits = bloom_mb * 1024ULL * 1024ULL * 8ULL;
    uint64_t num_bytes = (m_bits + 7ULL) / 8ULL;

    std::printf("Construindo Bloom filter:\n");
    std::printf("  Arquivo de endereços: %s\n", addresses_path);
    std::printf("  Saída: %s\n", bloom_path);
    std::printf("  Tamanho: %llu bits (%.2f MiB)\n",
                (unsigned long long)m_bits,
                (double)num_bytes / (1024.0 * 1024.0));
    std::printf("  k (hashes): %u\n", k);

    std::vector<uint8_t> bits;
    try {
        bits.assign((size_t)num_bytes, 0);
    } catch (...) {
        std::fprintf(stderr, "Erro: não foi possível alocar %llu bytes para o Bloom filter\n",
                     (unsigned long long)num_bytes);
        return 1;
    }

    FILE* f = std::fopen(addresses_path, "r");
    if (!f) {
        std::perror("Erro ao abrir arquivo de endereços");
        return 1;
    }

    char line[512];
    uint64_t total = 0;
    uint64_t inserted = 0;

    while (std::fgets(line, sizeof(line), f)) {
        size_t len = std::strlen(line);
        if (len == 0) continue;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' || line[len - 1] == ' ' || line[len - 1] == '\t')) {
            line[--len] = '\0';
        }
        if (len == 0 || line[0] == '#') continue;

        uint8_t hash160[20];
        bool ok = false;
        if (std::strncmp(line, "bc1", 3) == 0 || std::strncmp(line, "tb1", 3) == 0) {
            ok = bech32_decode_address(line, hash160);
        } else if (line[0] == '1' || line[0] == '3') {
            ok = base58_decode_address(line, hash160);
        }

        if (ok) {
            bloom_add(bits.data(), m_bits, k, hash160);
            inserted++;
        }

        total++;
        if ((total & 0xFFFFF) == 0) { // a cada ~1M linhas
            std::printf("  Lidas: %llu, inseridas: %llu\r",
                        (unsigned long long)total,
                        (unsigned long long)inserted);
            std::fflush(stdout);
        }
    }

    std::fclose(f);
    std::printf("\nTotal de linhas lidas: %llu\n", (unsigned long long)total);
    std::printf("Total de endereços válidos inseridos: %llu\n", (unsigned long long)inserted);

    // Estimar taxa de falso positivo
    double m = (double)m_bits;
    double n = (double)inserted;
    double kk = (double)k;
    double fp = std::pow(1.0 - std::exp(-kk * n / m), kk);
    std::printf("Estimativa de falso positivo: %.8f (%.6f%%)\n", fp, fp * 100.0);

    BloomHeader header;
    header.magic = BLOOM_MAGIC;
    header.version = BLOOM_VERSION;
    header.m_bits = m_bits;
    header.k = k;
    header.reserved = 0;
    header.n_items = inserted;

    FILE* out = std::fopen(bloom_path, "wb");
    if (!out) {
        std::perror("Erro ao criar arquivo bloom.bin");
        return 1;
    }

    if (std::fwrite(&header, sizeof(header), 1, out) != 1) {
        std::fprintf(stderr, "Erro ao escrever header no bloom.bin\n");
        std::fclose(out);
        return 1;
    }

    if (std::fwrite(bits.data(), 1, (size_t)num_bytes, out) != num_bytes) {
        std::fprintf(stderr, "Erro ao escrever bits no bloom.bin\n");
        std::fclose(out);
        return 1;
    }

    std::fclose(out);
    std::printf("Bloom filter salvo com sucesso em %s\n", bloom_path);

    return 0;
}
