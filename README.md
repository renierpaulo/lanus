# BIP39 CUDA Scanner v2.0 - Estado da Arte

Sistema de busca de frases BIP39 utilizando GPU CUDA com **geração on-the-fly** de permutações.

## 🚀 Arquitetura v2 - "Range Only"

**Diferença principal:** Não salvamos mais frases individuais em arquivos gigantes!

- **Rust** gera um arquivo `.range` pequeno (~100 bytes) com:
  - Índices das 24 palavras base
  - Range de K (índice de permutação) a processar
- **CUDA** gera permutações **on-the-fly** usando algoritmo Lehmer/Factoradic
- **Python** para decodificação/verificação

### Vantagens:
- ✅ **Zero disco** para armazenar frases
- ✅ "Varrer tudo" é questão de **tempo de GPU**, não espaço
- ✅ Distribuição trivial entre múltiplas GPUs/máquinas
- ✅ Pause/resume salvando apenas o último K

## Estrutura do Projeto

```
trembao/
├── rust-generator/          # Gerador de arquivos .range
│   └── src/main.rs
├── cuda-scanner/            # Scanner GPU
│   └── src/
│       ├── main.cu          # Kernel principal
│       ├── sha256.cuh       # SHA256
│       ├── sha512.cuh       # SHA512 + HMAC
│       ├── ripemd160.cuh    # RIPEMD160
│       ├── secp256k1.cuh    # Curva elíptica
│       ├── base58.cuh       # Decodificação Base58
│       └── bech32.cuh       # Decodificação Bech32
├── tools/
│   └── bip39_decoder.py     # Utilitário Python
└── README.md
```

## Formato do Arquivo .range (v2)

```
Header (16 bytes):
  magic:       u32 = 0x42495034 ("BIP4")
  version:     u32 = 2
  word_count:  u32 (12 ou 24)
  num_ranges:  u32

Base Indices:
  indices:     [u16; word_count]  # Índices BIP39 das palavras fixas

Ranges:
  Para cada range:
    start:     u128 (16 bytes LE)  # K inicial
    count:     u128 (16 bytes LE)  # Quantidade de Ks
```

**Tamanho típico:** ~100 bytes (vs GBs do formato antigo!)

## Instalação e Uso

### 1. Compilar Rust Generator

```cmd
cd rust-generator
cargo build --release
```

### 2. Gerar arquivo .range

```cmd
target\release\bip39-dataset-generator.exe generate ^
  -k "grab merit chuckle can island wash floor car exit mother box festival october odor camp country trial nephew coil fabric galaxy napkin appear apple" ^
  -o ..\job.range
```

**Para dividir em múltiplas partes:**
```cmd
target\release\bip39-dataset-generator.exe generate ^
  -k "grab merit chuckle can island wash floor car exit mother box festival october odor camp country trial nephew coil fabric galaxy napkin appear apple" ^
  --splits 8 ^
  -o ..\job.range
```
Isso cria: `job_part0.range`, `job_part1.range`, etc.

### 3. Compilar CUDA Scanner

```cmd
cd cuda-scanner
build.bat
```

### 4. Preparar arquivos auxiliares

**addresses.txt** - Endereços alvo:
```
bc1qxsd68d42agvykdueutm228uzn4s2g9qp2kk7t8
1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
```

**wordlist.txt** - Baixar wordlist BIP39:
```powershell
powershell -ExecutionPolicy Bypass -File ..\download_wordlist.ps1
```

### 5. Executar busca

```cmd
build\bip39_scanner.exe ..\job.range addresses.txt wordlist.txt
```

## Comandos do Rust Generator

### `generate` - Criar arquivo .range
```cmd
bip39-dataset-generator generate ^
  -k "word1 word2 ... word24" ^
  -o output.range ^
  --start 0 ^
  --count 0 ^
  --splits 1
```

| Opção | Descrição |
|-------|-----------|
| `-k, --known-words` | 24 palavras (vírgula ou espaço) |
| `-o, --output` | Arquivo de saída (.range) |
| `--start` | K inicial (default: 0) |
| `--count` | Quantidade de Ks (0 = todos até 24!) |
| `--splits` | Dividir em N partes |

### `decode` - Decodificar K para frase
```cmd
bip39-dataset-generator decode ^
  -k "word1 word2 ... word24" ^
  -K 12345
```

### `info` - Ver informações do .range
```cmd
bip39-dataset-generator info -r job.range
```

## Utilitário Python

```bash
cd tools

# Decodificar K
python bip39_decoder.py decode -K 12345 -k "grab,merit,..."

# Info do arquivo .range
python bip39_decoder.py info -f ../job.range

# Converter frase para K
python bip39_decoder.py encode -k "grab,merit,..." -m "frase completa"

# Escanear Ks válidos (CPU, para debug)
python bip39_decoder.py scan -k "grab,merit,..." --count 100000 --limit 10
```

## Matemática por trás

### Espaço de permutações
- 24 palavras distintas → **24! ≈ 6.2 × 10²³** permutações
- ~79 bits de informação por permutação

### Algoritmo Lehmer (Factoradic)
Cada permutação é um número K entre 0 e 24!-1:

```
K = d[0]×23! + d[1]×22! + ... + d[22]×1! + d[23]×0!
```

Onde `d[i]` é a posição relativa do i-ésimo elemento entre os ainda não usados.

### Taxa de válidos
~1/256 das permutações têm checksum BIP39 válido (8 bits de checksum para 24 palavras).

## Performance

| Operação | Taxa |
|----------|------|
| Geração de permutação (GPU) | ~100M/s por GPU |
| Verificação checksum (GPU) | ~100M/s |
| PBKDF2 + derivação (GPU) | ~1-10M/s |

**Tempo para varrer tudo (24!):**
- A 10M/s: ~2 × 10¹⁵ anos 😅
- Mas se você sabe a **ordem aproximada** de algumas palavras, o espaço reduz drasticamente!

## Estratégias de Otimização

1. **Conhecer posições fixas:** Se você sabe que "grab" está na posição 0, divide por 24
2. **Conhecer grupos:** Se sabe que palavras 0-5 estão certas, divide por 6!
3. **Múltiplas GPUs:** Use `--splits` e rode cada parte em uma GPU diferente

## Notas de Segurança

⚠️ **AVISO**: Este software é destinado apenas para recuperação de carteiras próprias ou pesquisa educacional.

O uso para acessar carteiras de terceiros sem autorização é ilegal e antiético.

## Licença

MIT License
