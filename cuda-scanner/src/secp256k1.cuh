/*
 * secp256k1 implementation for CUDA
 * Simplified implementation for Bitcoin key derivation
 */

#ifndef SECP256K1_CUH
#define SECP256K1_CUH

#include <stdint.h>

// secp256k1 curve parameters (simplified 256-bit arithmetic)
// p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
//      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

// Representação de números de 256 bits como 8 x uint32_t (little-endian)
typedef struct {
    uint32_t d[8];
} uint256_t;

// Ponto na curva elíptica
typedef struct {
    uint256_t x;
    uint256_t y;
    uint256_t z;
    bool infinity;
} point_t;

// Constantes da curva
__constant__ uint256_t SECP256K1_P = {{
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
}};

__constant__ uint256_t SECP256K1_N = {{
    0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
}};

__constant__ uint256_t SECP256K1_GX = {{
    0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
    0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E
}};

__constant__ uint256_t SECP256K1_GY = {{
    0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
    0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77
}};

// Operações aritméticas de 256 bits
__device__ __forceinline__ bool uint256_is_zero(const uint256_t* a) {
    return (a->d[0] | a->d[1] | a->d[2] | a->d[3] |
            a->d[4] | a->d[5] | a->d[6] | a->d[7]) == 0;
}

__device__ __forceinline__ int uint256_compare(const uint256_t* a, const uint256_t* b) {
    for (int i = 7; i >= 0; i--) {
        if (a->d[i] > b->d[i]) return 1;
        if (a->d[i] < b->d[i]) return -1;
    }
    return 0;
}

__device__ __forceinline__ void uint256_copy(uint256_t* dst, const uint256_t* src) {
    for (int i = 0; i < 8; i++) {
        dst->d[i] = src->d[i];
    }
}

__device__ __forceinline__ void uint256_clear(uint256_t* a) {
    for (int i = 0; i < 8; i++) a->d[i] = 0;
}

__device__ __forceinline__ void uint256_set_one(uint256_t* a) {
    a->d[0] = 1;
    for (int i = 1; i < 8; i++) a->d[i] = 0;
}

__device__ bool uint256_add(uint256_t* r, const uint256_t* a, const uint256_t* b) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t sum = (uint64_t)a->d[i] + (uint64_t)b->d[i] + carry;
        r->d[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    return carry != 0;
}

__device__ void uint256_sub(uint256_t* r, const uint256_t* a, const uint256_t* b) {
    int64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        int64_t diff = (int64_t)a->d[i] - (int64_t)b->d[i] - borrow;
        if (diff < 0) {
            r->d[i] = (uint32_t)(diff + 0x100000000LL);
            borrow = 1;
        } else {
            r->d[i] = (uint32_t)diff;
            borrow = 0;
        }
    }
}

__device__ void uint256_mod(uint256_t* r, const uint256_t* a, const uint256_t* m) {
    uint256_copy(r, a);
    while (uint256_compare(r, m) >= 0) {
        uint256_sub(r, r, m);
    }
}

__device__ void uint256_mod_add(uint256_t* r, const uint256_t* a, const uint256_t* b, const uint256_t* m) {
    bool carry = uint256_add(r, a, b);
    if (carry) {
        // Result overflowed 256 bits. Actual logical value is r + 2^256.
        // We want (r + 2^256) mod m.
        // Since m < 2^256, (r + 2^256) - m = r + (2^256 - m).
        // Let k = 2^256 - m.
        // r = r + k.
        
        // Calculate k = 0 - m (in 256-bit arithmetic 0 is 2^256)
        uint256_t zero = {{0}};
        uint256_t k;
        uint256_sub(&k, &zero, m);
        
        // Now add k to r. (This shouldn't overflow usually if m is close to 2^256)
        uint256_add(r, r, &k);
    } else {
        if (uint256_compare(r, m) >= 0) {
            uint256_sub(r, r, m);
        }
    }
}

__device__ void uint256_mod_sub(uint256_t* r, const uint256_t* a, const uint256_t* b, const uint256_t* m) {
    if (uint256_compare(a, b) >= 0) {
        uint256_sub(r, a, b);
    } else {
        uint256_t tmp;
        uint256_sub(&tmp, m, b);
        uint256_add(r, a, &tmp);
    }
}

// Multiplicação 256x256 -> 512 bits (produto completo)
// Multiplicação 256x256 -> 512 bits (produto completo)
__device__ void uint256_mul_full(uint32_t* r, const uint256_t* a, const uint256_t* b) {
    uint64_t acc = 0;
    
    #pragma unroll
    for (int k = 0; k < 16; k++) {
        uint32_t extra_carry = 0;
        
        for (int i = (k < 8 ? 0 : k - 7); i <= (k < 8 ? k : 7); i++) {
            int j = k - i;
            uint64_t prod = (uint64_t)a->d[i] * (uint64_t)b->d[j];
            uint64_t prev_acc = acc;
            acc += prod;
            if (acc < prev_acc) extra_carry++;
        }
        r[k] = (uint32_t)acc;
        acc >>= 32;
        acc |= ((uint64_t)extra_carry << 32);
    }
}

// Redução rápida mod p para secp256k1: p = 2^256 - 2^32 - 977
// Para r[0..15] (512 bits), reduz para 256 bits mod p
__device__ void secp256k1_reduce(uint256_t* r, const uint32_t* t) {
    // p = 2^256 - c where c = 2^32 + 977
    // t mod p = t_lo + t_hi * c (mod p)
    //         = t_lo + t_hi * (2^32 + 977)
    //         = t_lo + (t_hi << 32) + t_hi * 977
    
    uint64_t c_lo = 977;
    uint64_t carry = 0;
    uint32_t tmp[8]; 
    
    // Phase 1: Calculate t_lo + (t_hi << 32) + t_hi * 977
    // Store first 8 words in tmp, keep overflow in sum_final
    
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        // t_lo term: t[i]
        // t_hi * 977 term: t[i+8] * 977
        // t_hi << 32 term: t[i-1+8] -> t[i+7] (for i>0)
        
        uint64_t sum = (uint64_t)t[i] + (uint64_t)t[i + 8] * c_lo + carry;
        
        if (i > 0) {
            sum += t[i + 7];
        }
        
        tmp[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    
    // Capture the total overflow > 2^256
    // Overflow comes from:
    // 1. carry from the loop
    // 2. The last term of (t_hi << 32) which is t[15]
    uint64_t sum_final = carry + t[15];
    
    // Phase 2: Reduce the overflow
    // overflow * 2^256 = sum_final * c = sum_final * (2^32 + 977)
    // Add (sum_final * 977) and (sum_final << 32) to tmp
    
    carry = 0;
    
    // Word 0: add (sum_final * 977)_lo
    uint64_t val_977 = sum_final * c_lo;
    uint64_t s = (uint64_t)tmp[0] + (val_977 & 0xFFFFFFFFULL) + carry;
    r->d[0] = (uint32_t)s;
    carry = s >> 32;
    
    // Word 1: add (sum_final * 977)_hi + (sum_final)_lo
    s = (uint64_t)tmp[1] + (val_977 >> 32) + (sum_final & 0xFFFFFFFFULL) + carry;
    r->d[1] = (uint32_t)s;
    carry = s >> 32;
    
    // Word 2: add (sum_final)_hi
    s = (uint64_t)tmp[2] + (sum_final >> 32) + carry;
    r->d[2] = (uint32_t)s;
    carry = s >> 32;
    
    // Propagate carry for remaining words
    #pragma unroll
    for (int i = 3; i < 8; i++) {
        s = (uint64_t)tmp[i] + carry;
        r->d[i] = (uint32_t)s;
        carry = s >> 32;
    }
    
    // Phase 3: if result >= P, subtract P
    // If we have carry out, we are definitely >= 2^256 > P
    if (carry || uint256_compare(r, &SECP256K1_P) >= 0) {
        uint256_sub(r, r, &SECP256K1_P);
    }
}

// Multiplicação modular OTIMIZADA usando redução especial do secp256k1
__device__ void uint256_mod_mul(uint256_t* r, const uint256_t* a, const uint256_t* b, const uint256_t* m) {
    uint32_t t[16] = {0};
    uint256_mul_full(t, a, b);
    secp256k1_reduce(r, t);
}

// Quadrado modular (mais rápido que mul quando a == b)
__device__ void uint256_mod_sqr(uint256_t* r, const uint256_t* a) {
    uint32_t t[16] = {0};
    uint64_t acc = 0;
    
    // Termos diagonais + 2 * termos cruzados
    #pragma unroll
    for (int k = 0; k < 16; k++) {
        uint32_t extra_carry = 0;
        int start = (k < 8 ? 0 : k - 7);
        int end = k / 2;
        
        for (int i = start; i <= end; i++) {
            int j = k - i;
            uint64_t prod = (uint64_t)a->d[i] * (uint64_t)a->d[j];
            
            if (i < j) {
                // Accumulate 2 * prod
                // prod * 2 might overflow 64 bits, carry is in MSB of prod
                uint32_t msb = prod >> 63;
                uint64_t double_prod = prod << 1;
                
                extra_carry += msb;
                
                uint64_t prev = acc;
                acc += double_prod;
                if (acc < prev) extra_carry++;
            } else {
                // Accumulate prod
                uint64_t prev = acc;
                acc += prod;
                if (acc < prev) extra_carry++;
            }
        }
        t[k] = (uint32_t)acc;
        acc >>= 32;
        acc |= ((uint64_t)extra_carry << 32);
    }
    
    secp256k1_reduce(r, t);
}

// Inverso modular OTIMIZADO usando Fermat + squaring
__device__ void uint256_mod_inv(uint256_t* r, const uint256_t* a, const uint256_t* m) {
    // a^(-1) = a^(p-2) mod p
    // p-2 = 0xFFFFFFFF...FFFFFFFC2D (forma especial)
    uint256_t base, result;
    uint256_copy(&base, a);
    
    uint256_set_one(&result);
    
    // Expoente p-2 tem forma conhecida, usar square-and-multiply otimizado
    uint256_t exp;
    uint256_copy(&exp, m);
    exp.d[0] -= 2;
    
    #pragma unroll 1
    for (int i = 0; i < 8; i++) {
        #pragma unroll 1
        for (int j = 0; j < 32; j++) {
            if ((exp.d[i] >> j) & 1) {
                uint256_mod_mul(&result, &result, &base, m);
            }
            uint256_mod_sqr(&base, &base);
        }
    }
    
    uint256_copy(r, &result);
}

// Duplicar ponto na curva
__device__ void point_double(point_t* r, const point_t* p) {
    if (p->infinity || uint256_is_zero(&p->y)) {
        r->infinity = true;
        uint256_clear(&r->x);
        uint256_clear(&r->y);
        uint256_clear(&r->z);
        return;
    }

    uint256_t XX, YY, YYYY, S, M, T, X3, Y3, Z3, twoY;

    uint256_mod_mul(&XX, &p->x, &p->x, &SECP256K1_P);
    uint256_mod_mul(&YY, &p->y, &p->y, &SECP256K1_P);
    uint256_mod_mul(&YYYY, &YY, &YY, &SECP256K1_P);

    uint256_mod_mul(&S, &p->x, &YY, &SECP256K1_P);
    uint256_mod_add(&S, &S, &S, &SECP256K1_P);
    uint256_mod_add(&S, &S, &S, &SECP256K1_P);

    uint256_mod_add(&M, &XX, &XX, &SECP256K1_P);
    uint256_mod_add(&M, &M, &XX, &SECP256K1_P);

    uint256_mod_mul(&X3, &M, &M, &SECP256K1_P);
    uint256_mod_add(&T, &S, &S, &SECP256K1_P);
    uint256_mod_sub(&X3, &X3, &T, &SECP256K1_P);

    uint256_mod_sub(&T, &S, &X3, &SECP256K1_P);
    uint256_mod_mul(&Y3, &M, &T, &SECP256K1_P);
    uint256_mod_add(&T, &YYYY, &YYYY, &SECP256K1_P);
    uint256_mod_add(&T, &T, &T, &SECP256K1_P);
    uint256_mod_add(&T, &T, &T, &SECP256K1_P);
    uint256_mod_sub(&Y3, &Y3, &T, &SECP256K1_P);

    uint256_mod_add(&twoY, &p->y, &p->y, &SECP256K1_P);
    uint256_mod_mul(&Z3, &twoY, &p->z, &SECP256K1_P);

    r->x = X3;
    r->y = Y3;
    r->z = Z3;
    r->infinity = false;
}

// Adicionar dois pontos na curva
// Adicionar dois pontos na curva
__device__ void point_add(point_t* r, const point_t* p, const point_t* q) {
    if (p->infinity) {
        r->x = q->x;
        r->y = q->y;
        r->z = q->z;
        r->infinity = q->infinity;
        return;
    }
    if (q->infinity) {
        r->x = p->x;
        r->y = p->y;
        r->z = p->z;
        r->infinity = p->infinity;
        return;
    }

    uint256_t Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r2, V, tmp, tmp2, tmp3, Z3;

    uint256_mod_mul(&Z1Z1, &p->z, &p->z, &SECP256K1_P);
    uint256_mod_mul(&Z2Z2, &q->z, &q->z, &SECP256K1_P);
    uint256_mod_mul(&U1, &p->x, &Z2Z2, &SECP256K1_P);
    uint256_mod_mul(&U2, &q->x, &Z1Z1, &SECP256K1_P);

    uint256_t Z1_cubed, Z2_cubed;
    // S1 = Y1 * Z2^3
    uint256_mod_mul(&Z2_cubed, &q->z, &Z2Z2, &SECP256K1_P);
    uint256_mod_mul(&S1, &p->y, &Z2_cubed, &SECP256K1_P);
    
    // S2 = Y2 * Z1^3
    uint256_mod_mul(&Z1_cubed, &p->z, &Z1Z1, &SECP256K1_P);
    uint256_mod_mul(&S2, &q->y, &Z1_cubed, &SECP256K1_P);

    if (uint256_compare(&U1, &U2) == 0) {
        if (uint256_compare(&S1, &S2) == 0) {
            point_double(r, p);
            return;
        }
        r->infinity = true;
        uint256_clear(&r->x);
        uint256_clear(&r->y);
        uint256_clear(&r->z);
        return;
    }

    uint256_mod_sub(&H, &U2, &U1, &SECP256K1_P);
    uint256_mod_add(&tmp, &H, &H, &SECP256K1_P);
    uint256_mod_mul(&I, &tmp, &tmp, &SECP256K1_P);
    uint256_mod_mul(&J, &H, &I, &SECP256K1_P);

    uint256_mod_sub(&r2, &S2, &S1, &SECP256K1_P);
    uint256_mod_add(&r2, &r2, &r2, &SECP256K1_P);

    uint256_mod_mul(&V, &U1, &I, &SECP256K1_P);

    uint256_mod_mul(&tmp2, &r2, &r2, &SECP256K1_P);
    uint256_mod_sub(&tmp2, &tmp2, &J, &SECP256K1_P);
    uint256_mod_add(&tmp3, &V, &V, &SECP256K1_P);
    uint256_mod_sub(&tmp2, &tmp2, &tmp3, &SECP256K1_P);

    uint256_t X3, Y3;
    X3 = tmp2;

    uint256_mod_sub(&tmp, &V, &X3, &SECP256K1_P);
    uint256_mod_mul(&tmp, &r2, &tmp, &SECP256K1_P);
    uint256_mod_mul(&tmp2, &S1, &J, &SECP256K1_P);
    uint256_mod_add(&tmp2, &tmp2, &tmp2, &SECP256K1_P);
    uint256_mod_sub(&Y3, &tmp, &tmp2, &SECP256K1_P);

    uint256_mod_add(&tmp, &p->z, &q->z, &SECP256K1_P);
    uint256_mod_mul(&tmp, &tmp, &tmp, &SECP256K1_P);
    uint256_mod_sub(&tmp, &tmp, &Z1Z1, &SECP256K1_P);
    uint256_mod_sub(&tmp, &tmp, &Z2Z2, &SECP256K1_P);
    uint256_mod_mul(&Z3, &tmp, &H, &SECP256K1_P);

    r->x = X3;
    r->y = Y3;
    r->z = Z3;
    r->infinity = false;
}

// ============================================================================
// Tabela pré-computada para WINDOWED scalar multiplication
// Usa janelas de 4 bits: armazena [1*G, 2*G, ..., 15*G] para cada janela
// Total: 64 janelas (256 bits / 4) * 15 pontos = 960 pontos
// Mas para simplificar, armazenamos apenas os 256 primeiros 2^i * G
// ============================================================================

// Tabela de 2^i * G para i = 0..255 (pontos afins para economia de memória)
__constant__ uint256_t d_Gx_table[256];
__constant__ uint256_t d_Gy_table[256];

// Flag para indicar se a tabela foi inicializada no host
static bool h_G_table_initialized = false;

// Inicializar tabela no HOST e copiar para GPU (chamado uma vez no início)
void init_G_table_host() {
    if (h_G_table_initialized) return;
    
    // Calcular 2^i * G no host
    uint256_t h_Gx[256], h_Gy[256];
    
    // G inicial
    h_Gx[0] = {{0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
                0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}};
    h_Gy[0] = {{0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
                0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}};
    
    // Para os próximos pontos, usaríamos point_double no host
    // Por simplicidade, apenas copiamos G para todas as posições
    // (a otimização real requer pré-computação offline)
    for (int i = 1; i < 256; i++) {
        h_Gx[i] = h_Gx[0];
        h_Gy[i] = h_Gy[0];
    }
    
    cudaMemcpyToSymbol(d_Gx_table, h_Gx, sizeof(h_Gx));
    cudaMemcpyToSymbol(d_Gy_table, h_Gy, sizeof(h_Gy));
    
    h_G_table_initialized = true;
}

// Multiplicação escalar OTIMIZADA: k * G usando double-and-add
__device__ void scalar_mult(point_t* r, const uint256_t* k, const point_t* g) {
    r->infinity = true;
    uint256_clear(&r->x);
    uint256_clear(&r->y);
    uint256_clear(&r->z);

    point_t temp;
    temp.x = g->x;
    temp.y = g->y;
    uint256_set_one(&temp.z);
    temp.infinity = g->infinity;
    
    // Double-and-add do bit mais significativo para o menos significativo
    bool started = false;
    
    #pragma unroll 1
    for (int i = 7; i >= 0; i--) {
        #pragma unroll 1
        for (int j = 31; j >= 0; j--) {
            if (started) {
                point_double(r, r);
            }
            
            if ((k->d[i] >> j) & 1) {
                if (!started) {
                    r->x = temp.x;
                    r->y = temp.y;
                    r->z = temp.z;
                    r->infinity = temp.infinity;
                    started = true;
                } else {
                    point_t sum;
                    point_add(&sum, r, &temp);
                    *r = sum;
                }
            }
        }
    }
    
    if (!started) {
        r->infinity = true;
    }
}

// Multiplicação escalar com ponto fixo G (mais comum no BIP32)
__device__ void scalar_mult_G(point_t* r, const uint256_t* k) {
    point_t G;
    G.x = SECP256K1_GX;
    G.y = SECP256K1_GY;
    uint256_set_one(&G.z);
    G.infinity = false;
    scalar_mult(r, k, &G);
}

// Converter bytes para uint256
__device__ void bytes_to_uint256(uint256_t* r, const uint8_t* bytes) {
    for (int i = 0; i < 8; i++) {
        r->d[7 - i] = ((uint32_t)bytes[i * 4] << 24) |
                      ((uint32_t)bytes[i * 4 + 1] << 16) |
                      ((uint32_t)bytes[i * 4 + 2] << 8) |
                      ((uint32_t)bytes[i * 4 + 3]);
    }
}

// Converter uint256 para bytes
__device__ void uint256_to_bytes(uint8_t* bytes, const uint256_t* a) {
    for (int i = 0; i < 8; i++) {
        bytes[i * 4] = (a->d[7 - i] >> 24) & 0xFF;
        bytes[i * 4 + 1] = (a->d[7 - i] >> 16) & 0xFF;
        bytes[i * 4 + 2] = (a->d[7 - i] >> 8) & 0xFF;
        bytes[i * 4 + 3] = a->d[7 - i] & 0xFF;
    }
}

// Obter chave pública comprimida a partir da chave privada
__device__ void secp256k1_get_pubkey_compressed(const uint8_t* privkey, uint8_t* pubkey) {
    uint256_t k;
    bytes_to_uint256(&k, privkey);
    
    point_t G;
    G.x = SECP256K1_GX;
    G.y = SECP256K1_GY;
    uint256_set_one(&G.z);
    G.infinity = false;
    
    point_t P;
    scalar_mult(&P, &k, &G);
    
    if (P.infinity) {
        pubkey[0] = 0x02;
        for (int i = 1; i < 33; i++) pubkey[i] = 0;
        return;
    }

    uint256_t zinv, z2inv, z3inv, x_aff, y_aff;
    uint256_mod_inv(&zinv, &P.z, &SECP256K1_P);
    uint256_mod_mul(&z2inv, &zinv, &zinv, &SECP256K1_P);
    uint256_mod_mul(&z3inv, &z2inv, &zinv, &SECP256K1_P);
    uint256_mod_mul(&x_aff, &P.x, &z2inv, &SECP256K1_P);
    uint256_mod_mul(&y_aff, &P.y, &z3inv, &SECP256K1_P);
    
    pubkey[0] = (y_aff.d[0] & 1) ? 0x03 : 0x02;
    uint256_to_bytes(pubkey + 1, &x_aff);
}

// Adicionar dois escalares mod n
__device__ void secp256k1_scalar_add(const uint8_t* a, const uint8_t* b, uint8_t* result) {
    uint256_t ua, ub, ur;
    bytes_to_uint256(&ua, a);
    bytes_to_uint256(&ub, b);
    
    uint256_mod_add(&ur, &ua, &ub, &SECP256K1_N);
    
    uint256_to_bytes(result, &ur);
}

#endif // SECP256K1_CUH
