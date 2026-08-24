#!/usr/bin/env python3
"""
BIP39 Decoder & Verifier - Python Tool
Decodifica K para frase mnemônica e verifica derivações

Uso:
  python bip39_decoder.py decode -k <K> -w "word1,word2,..."
  python bip39_decoder.py info -f <arquivo.range>
  python bip39_decoder.py verify -m "frase mnemonica" -a <endereco>
"""

import argparse
import struct
import hashlib
import sys
from typing import List, Tuple, Optional

# BIP39 English wordlist (primeiras 20 palavras para exemplo - usar arquivo completo)
BIP39_WORDLIST_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"

def load_wordlist(path: Optional[str] = None) -> List[str]:
    """Carrega wordlist BIP39"""
    if path:
        with open(path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    
    # Tentar carregar de arquivo local
    import os
    local_paths = ['wordlist.txt', '../cuda-scanner/wordlist.txt', 'english.txt']
    for p in local_paths:
        if os.path.exists(p):
            with open(p, 'r') as f:
                return [line.strip() for line in f if line.strip()]
    
    # Tentar baixar
    try:
        import urllib.request
        print(f"Baixando wordlist de {BIP39_WORDLIST_URL}...")
        response = urllib.request.urlopen(BIP39_WORDLIST_URL)
        data = response.read().decode('utf-8')
        words = [line.strip() for line in data.split('\n') if line.strip()]
        # Salvar localmente
        with open('wordlist.txt', 'w') as f:
            f.write('\n'.join(words))
        return words
    except Exception as e:
        print(f"Erro ao baixar wordlist: {e}")
        sys.exit(1)

def factorials(n: int = 25) -> List[int]:
    """Calcula fatoriais de 0! até n!"""
    f = [1] * n
    for i in range(1, n):
        f[i] = f[i-1] * i
    return f

def k_to_permutation(k: int, n: int) -> List[int]:
    """Converte K (índice de permutação) para permutação usando Lehmer/Factoradic"""
    fact = factorials(n + 1)
    available = list(range(n))
    perm = []
    
    for i in range(n):
        f = fact[n - 1 - i]
        idx = k // f
        k = k % f
        perm.append(available.pop(idx))
    
    return perm

def permutation_to_k(perm: List[int]) -> int:
    """Converte permutação para K (índice de permutação)"""
    n = len(perm)
    fact = factorials(n + 1)
    available = list(range(n))
    k = 0
    
    for i in range(n):
        pos = available.index(perm[i])
        k += pos * fact[n - 1 - i]
        available.pop(pos)
    
    return k

def verify_checksum_24(indices: List[int]) -> bool:
    """Verifica checksum BIP39 para 24 palavras"""
    # 24 palavras = 264 bits = 256 bits entropia + 8 bits checksum
    entropy = bytearray(32)
    
    # Converter índices (11 bits cada) para entropia
    bits = 0
    acc = 0
    byte_idx = 0
    
    for idx in indices:
        acc = (acc << 11) | idx
        bits += 11
        
        while bits >= 8:
            bits -= 8
            entropy[byte_idx] = (acc >> bits) & 0xFF
            byte_idx += 1
            if byte_idx >= 32:
                break
    
    # Últimos 8 bits são checksum
    checksum_bits = acc & 0xFF
    
    # Calcular checksum esperado
    hash_result = hashlib.sha256(bytes(entropy)).digest()
    expected_checksum = hash_result[0]
    
    return checksum_bits == expected_checksum

def verify_checksum_12(indices: List[int]) -> bool:
    """Verifica checksum BIP39 para 12 palavras"""
    # 12 palavras = 132 bits = 128 bits entropia + 4 bits checksum
    entropy = bytearray(16)
    
    bits = 0
    acc = 0
    byte_idx = 0
    
    for idx in indices:
        acc = (acc << 11) | idx
        bits += 11
        
        while bits >= 8 and byte_idx < 16:
            bits -= 8
            entropy[byte_idx] = (acc >> bits) & 0xFF
            byte_idx += 1
    
    checksum_bits = acc & 0xF
    hash_result = hashlib.sha256(bytes(entropy)).digest()
    expected_checksum = hash_result[0] >> 4
    
    return checksum_bits == expected_checksum

def parse_words(words_str: str, wordlist: List[str]) -> List[int]:
    """Converte string de palavras para índices"""
    words = [w.strip().lower() for w in words_str.replace(',', ' ').split() if w.strip()]
    indices = []
    for w in words:
        try:
            idx = wordlist.index(w)
            indices.append(idx)
        except ValueError:
            print(f"Palavra não encontrada na wordlist: {w}")
            sys.exit(1)
    return indices

def read_range_file(path: str) -> Tuple[List[int], List[Tuple[int, int]]]:
    """Lê arquivo .range"""
    with open(path, 'rb') as f:
        # Header
        magic = struct.unpack('<I', f.read(4))[0]
        if magic != 0x42495034:
            raise ValueError(f"Magic inválido: 0x{magic:08X}")
        
        version = struct.unpack('<I', f.read(4))[0]
        if version != 2:
            raise ValueError(f"Versão não suportada: {version}")
        
        word_count = struct.unpack('<I', f.read(4))[0]
        num_ranges = struct.unpack('<I', f.read(4))[0]
        
        # Base indices
        base_indices = list(struct.unpack(f'<{word_count}H', f.read(word_count * 2)))
        
        # Ranges (u128 = 16 bytes cada)
        ranges = []
        for _ in range(num_ranges):
            start_lo, start_hi = struct.unpack('<QQ', f.read(16))
            count_lo, count_hi = struct.unpack('<QQ', f.read(16))
            start = start_lo | (start_hi << 64)
            count = count_lo | (count_hi << 64)
            ranges.append((start, count))
        
        return base_indices, ranges

def format_big_number(n: int) -> str:
    """Formata número grande com separadores"""
    s = str(n)
    result = []
    for i, c in enumerate(reversed(s)):
        if i > 0 and i % 3 == 0:
            result.append(',')
        result.append(c)
    return ''.join(reversed(result))

def cmd_decode(args, wordlist: List[str]):
    """Comando: decodificar K para frase"""
    k = args.k_value
    
    if args.range_file:
        base_indices, ranges = read_range_file(args.range_file)
    elif args.known_words:
        base_indices = parse_words(args.known_words, wordlist)
    else:
        print("Erro: forneça --range-file ou --known-words")
        sys.exit(1)
    
    n = len(base_indices)
    fact = factorials(n + 1)
    total_perms = fact[n]
    
    if k >= total_perms:
        print(f"Erro: K={k} está fora do range [0, {format_big_number(total_perms)})")
        sys.exit(1)
    
    # Converter K para permutação
    perm = k_to_permutation(k, n)
    
    # Aplicar permutação aos índices base
    final_indices = [base_indices[p] for p in perm]
    
    # Montar frase
    phrase = [wordlist[i] for i in final_indices]
    
    print("=" * 60)
    print(f"  Decodificação de K = {format_big_number(k)}")
    print("=" * 60)
    print(f"Permutação (posições): {perm}")
    print(f"Índices BIP39: {final_indices}")
    print()
    print("Frase mnemônica:")
    print(f"  {' '.join(phrase)}")
    
    # Verificar checksum
    if n == 24:
        valid = verify_checksum_24(final_indices)
        print(f"\nChecksum BIP39: {'VÁLIDO ✓' if valid else 'INVÁLIDO ✗'}")
    elif n == 12:
        valid = verify_checksum_12(final_indices)
        print(f"\nChecksum BIP39: {'VÁLIDO ✓' if valid else 'INVÁLIDO ✗'}")
    
    print("=" * 60)

def cmd_info(args, wordlist: List[str]):
    """Comando: mostrar informações do arquivo .range"""
    base_indices, ranges = read_range_file(args.range_file)
    n = len(base_indices)
    fact = factorials(n + 1)
    total_perms = fact[n]
    
    print("=" * 60)
    print(f"  Informações: {args.range_file}")
    print("=" * 60)
    print(f"Palavras: {n}")
    
    print("\nPalavras base:")
    for i, idx in enumerate(base_indices):
        print(f"  {i}: {wordlist[idx]} (idx={idx})")
    
    total_count = 0
    print(f"\nRanges ({len(ranges)}):")
    for i, (start, count) in enumerate(ranges):
        pct = (count / total_perms) * 100
        print(f"  [{i}] K: {format_big_number(start)} .. {format_big_number(start + count)}")
        print(f"      {format_big_number(count)} perms ({pct:.6f}%)")
        total_count += count
    
    print(f"\nTotal a processar: {format_big_number(total_count)} ({(total_count/total_perms)*100:.6f}%)")
    print(f"Total de permutações possíveis: {format_big_number(total_perms)}")
    print("=" * 60)

def cmd_encode(args, wordlist: List[str]):
    """Comando: converter frase para K"""
    base_indices = parse_words(args.known_words, wordlist)
    phrase_indices = parse_words(args.mnemonic, wordlist)
    
    n = len(base_indices)
    if len(phrase_indices) != n:
        print(f"Erro: frase tem {len(phrase_indices)} palavras, esperado {n}")
        sys.exit(1)
    
    # Verificar se frase usa apenas as palavras base
    base_set = set(base_indices)
    phrase_set = set(phrase_indices)
    if phrase_set != base_set:
        diff = phrase_set - base_set
        print(f"Erro: frase contém palavras que não estão na base: {diff}")
        sys.exit(1)
    
    # Encontrar permutação
    perm = []
    for idx in phrase_indices:
        pos = base_indices.index(idx)
        perm.append(pos)
    
    # Converter permutação para K
    k = permutation_to_k(perm)
    
    print("=" * 60)
    print(f"  Codificação para K")
    print("=" * 60)
    print(f"Frase: {args.mnemonic}")
    print(f"Permutação: {perm}")
    print(f"K = {format_big_number(k)}")
    print("=" * 60)

def cmd_scan_valid(args, wordlist: List[str]):
    """Comando: escanear K válidos em um range"""
    if args.range_file:
        base_indices, ranges = read_range_file(args.range_file)
        start, count = ranges[0]  # Usar primeiro range
    else:
        base_indices = parse_words(args.known_words, wordlist)
        start = args.start
        count = args.count
    
    n = len(base_indices)
    fact = factorials(n + 1)
    total_perms = fact[n]
    
    if count == 0:
        count = min(1000000, total_perms - start)  # Limitar a 1M por padrão
    
    verify_fn = verify_checksum_24 if n == 24 else verify_checksum_12
    
    print(f"Escaneando K = {format_big_number(start)} .. {format_big_number(start + count)}")
    print(f"Procurando frases com checksum válido...")
    print()
    
    valid_count = 0
    for k in range(start, start + count):
        perm = k_to_permutation(k, n)
        final_indices = [base_indices[p] for p in perm]
        
        if verify_fn(final_indices):
            valid_count += 1
            phrase = [wordlist[i] for i in final_indices]
            print(f"K={format_big_number(k)}: {' '.join(phrase)}")
            
            if args.limit and valid_count >= args.limit:
                print(f"\n(Limite de {args.limit} atingido)")
                break
        
        if (k - start) % 100000 == 0 and k > start:
            print(f"  ... {format_big_number(k - start)} testados, {valid_count} válidos", end='\r')
    
    print(f"\n\nTotal: {valid_count} frases válidas em {format_big_number(count)} testadas")

def _encode_varint(value: int) -> bytes:
    """Codifica inteiro não negativo em varint (LEB128 simples)."""
    if value < 0:
        raise ValueError("varint só suporta inteiros não negativos")
    out = bytearray()
    while True:
        to_write = value & 0x7F
        value >>= 7
        if value:
            out.append(to_write | 0x80)
        else:
            out.append(to_write)
            break
    return bytes(out)

def _decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decodifica varint a partir de data[offset:], retorna (valor, novo_offset)."""
    shift = 0
    result = 0
    pos = offset
    while True:
        if pos >= len(data):
            raise ValueError("varint incompleto")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("varint muito grande")
    return result, pos

def cmd_compress(args, wordlist: List[str]):
    """Escanear Ks válidos em um range e salvar em formato comprimido (deltas + varint)."""
    if args.range_file:
        base_indices, ranges = read_range_file(args.range_file)
        start, count = ranges[0]
    else:
        base_indices = parse_words(args.known_words, wordlist)
        start = args.start
        count = args.count

    n = len(base_indices)
    fact = factorials(n + 1)
    total_perms = fact[n]

    if count == 0:
        count = min(1_000_000, total_perms - start)

    verify_fn = verify_checksum_24 if n == 24 else verify_checksum_12

    print(f"[compress] Escaneando K = {format_big_number(start)} .. {format_big_number(start + count)}")
    print("Procurando frases com checksum válido (para compressão)...")

    valid_ks: List[int] = []
    for k in range(start, start + count):
        perm = k_to_permutation(k, n)
        final_indices = [base_indices[p] for p in perm]
        if verify_fn(final_indices):
            valid_ks.append(k)

        if (k - start) % 100000 == 0 and k > start:
            print(f"  ... {format_big_number(k - start)} testados, {len(valid_ks)} válidos", end='\r')

    print(f"\nEncontrados {len(valid_ks)} Ks válidos, iniciando compressão...")

    if not valid_ks:
        print("Nenhum K válido encontrado neste range. Nada para comprimir.")
        return

    # Ordenar e converter para deltas
    valid_ks.sort()
    first = valid_ks[0]
    deltas = [valid_ks[0]]
    for i in range(1, len(valid_ks)):
        deltas.append(valid_ks[i] - valid_ks[i - 1])

    # Codificar em varint
    encoded = bytearray()
    encoded.extend(struct.pack('<I', n))  # word_count
    encoded.extend(struct.pack('<Q', len(deltas)))  # quantidade de deltas
    for d in deltas:
        encoded.extend(_encode_varint(d))

    with open(args.output, 'wb') as f:
        f.write(b'KSVC')  # magic
        f.write(encoded)

    ratio = (len(valid_ks) * 8) / len(encoded) if encoded else 0.0
    print(f"Arquivo salvo em {args.output} ({len(encoded)} bytes)")
    print(f"Equivalente a {len(valid_ks)} Ks (8 bytes cada) -> compressão ~{ratio:.2f}x")

def cmd_decompress(args, wordlist: List[str]):
    """Ler arquivo comprimido e reconstruir Ks válidos (e opcionalmente imprimir frases)."""
    with open(args.input, 'rb') as f:
        magic = f.read(4)
        if magic != b'KSVC':
            print("Arquivo inválido (magic KSVC não encontrado)")
            sys.exit(1)
        data = f.read()

    if len(data) < 12:
        print("Arquivo comprimido muito curto")
        sys.exit(1)

    n = struct.unpack_from('<I', data, 0)[0]
    count = struct.unpack_from('<Q', data, 4)[0]
    pos = 12

    deltas: List[int] = []
    for _ in range(count):
        d, pos = _decode_varint(data, pos)
        deltas.append(d)

    # Reconstruir Ks
    ks: List[int] = []
    acc = 0
    for i, d in enumerate(deltas):
        if i == 0:
            acc = d
        else:
            acc += d
        ks.append(acc)

    print(f"Arquivo contém {len(ks)} Ks válidos (word_count={n})")

    if not args.known_words:
        print("Nenhuma --known-words fornecida, imprimindo apenas Ks.")
        for k in ks[: args.limit or 20]:
            print(f"K={format_big_number(k)}")
        return

    base_indices = parse_words(args.known_words, wordlist)
    if len(base_indices) != n:
        print(f"Aviso: word_count no arquivo={n}, mas base fornecida tem {len(base_indices)} palavras")

    print("Mostrando primeiras frases reconstruídas:")
    for k in ks[: args.limit or 20]:
        perm = k_to_permutation(k, len(base_indices))
        final_indices = [base_indices[p] for p in perm]
        phrase = [wordlist[i] for i in final_indices]
        print(f"K={format_big_number(k)}: {' '.join(phrase)}")

def main():
    parser = argparse.ArgumentParser(description='BIP39 Decoder & Verifier')
    parser.add_argument('--wordlist', '-W', help='Caminho para arquivo wordlist.txt')
    
    subparsers = parser.add_subparsers(dest='command', help='Comandos')
    
    # Comando decode
    p_decode = subparsers.add_parser('decode', help='Decodificar K para frase')
    p_decode.add_argument('-K', '--k-value', type=int, required=True, help='Valor de K')
    p_decode.add_argument('-f', '--range-file', help='Arquivo .range')
    p_decode.add_argument('-k', '--known-words', help='Palavras conhecidas (vírgula/espaço)')
    
    # Comando info
    p_info = subparsers.add_parser('info', help='Info do arquivo .range')
    p_info.add_argument('-f', '--range-file', required=True, help='Arquivo .range')
    
    # Comando encode
    p_encode = subparsers.add_parser('encode', help='Converter frase para K')
    p_encode.add_argument('-k', '--known-words', required=True, help='Palavras base')
    p_encode.add_argument('-m', '--mnemonic', required=True, help='Frase mnemônica')
    
    # Comando scan
    p_scan = subparsers.add_parser('scan', help='Escanear K válidos')
    p_scan.add_argument('-f', '--range-file', help='Arquivo .range')
    p_scan.add_argument('-k', '--known-words', help='Palavras conhecidas')
    p_scan.add_argument('--start', type=int, default=0, help='K inicial')
    p_scan.add_argument('--count', type=int, default=0, help='Quantidade (0=1M)')
    p_scan.add_argument('--limit', type=int, default=10, help='Limite de válidos a mostrar')

    # Comando compress
    p_compress = subparsers.add_parser('compress', help='Escanear Ks válidos e salvar comprimido (deltas+varint)')
    p_compress.add_argument('-f', '--range-file', help='Arquivo .range (usa primeiro range)')
    p_compress.add_argument('-k', '--known-words', help='Palavras conhecidas (se não usar range-file)')
    p_compress.add_argument('--start', type=int, default=0, help='K inicial (se não usar range-file)')
    p_compress.add_argument('--count', type=int, default=0, help='Quantidade (0=1M)')
    p_compress.add_argument('-o', '--output', required=True, help='Arquivo de saída (.kcomp)')

    # Comando decompress
    p_decompress = subparsers.add_parser('decompress', help='Reconstituir Ks válidos de arquivo comprimido')
    p_decompress.add_argument('-i', '--input', required=True, help='Arquivo comprimido (.kcomp)')
    p_decompress.add_argument('-k', '--known-words', help='Palavras base para reconstruir frases (opcional)')
    p_decompress.add_argument('--limit', type=int, default=20, help='Limite de frases/Ks a mostrar')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    wordlist = load_wordlist(args.wordlist)
    print(f"Wordlist carregada: {len(wordlist)} palavras\n")
    
    if args.command == 'decode':
        cmd_decode(args, wordlist)
    elif args.command == 'info':
        cmd_info(args, wordlist)
    elif args.command == 'encode':
        cmd_encode(args, wordlist)
    elif args.command == 'scan':
        cmd_scan_valid(args, wordlist)
    elif args.command == 'compress':
        cmd_compress(args, wordlist)
    elif args.command == 'decompress':
        cmd_decompress(args, wordlist)

if __name__ == '__main__':
    main()
