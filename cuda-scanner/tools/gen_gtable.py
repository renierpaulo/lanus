"""Gera a tabela pre-computada de base fixa para secp256k1 (janela de 4 bits).

T[i][j] = (j+1) * 16^i * G  em coordenadas afins, i=0..63, j=0..14.
960 pontos -> 60 KB. Emite um header CUDA.
"""
from ref_bip39 import pt_mul, pt_add, GX, GY

W = 4
NWIN = 256 // W          # 64 janelas
NPT = (1 << W) - 1       # 15 pontos por janela


def words(n):
    """256 bits -> 8 x uint32 little-endian (mesmo layout do uint256_t)."""
    return [(n >> (32 * i)) & 0xFFFFFFFF for i in range(8)]


rows = []
base = (GX, GY)
for i in range(NWIN):
    acc = None
    for j in range(NPT):
        acc = pt_add(acc, base)          # acc = (j+1) * 16^i * G
        rows.append(acc)
    for _ in range(W):                   # base *= 16
        base = pt_add(base, base)

assert len(rows) == NWIN * NPT

# sanidade: conferir alguns pontos contra multiplicacao escalar direta
for (i, j) in [(0, 0), (0, 14), (1, 0), (7, 3), (63, 14)]:
    k = (j + 1) * (16 ** i)
    assert rows[i * NPT + j] == pt_mul(k), f"tabela errada em ({i},{j})"
print("tabela validada contra pt_mul()")

out = []
out.append("/* GERADO por gen_gtable.py - NAO EDITAR A MAO */")
out.append("#ifndef SECP_GTABLE_CUH")
out.append("#define SECP_GTABLE_CUH")
out.append(f"#define GT_W {W}")
out.append(f"#define GT_NWIN {NWIN}")
out.append(f"#define GT_NPT {NPT}")
out.append("// T[i][j] = (j+1) * 16^i * G, afim. Layout: x[8] entao y[8], uint32 LE.")
out.append("// Memoria global (nao __constant__): o acesso e divergente entre threads,")
out.append("// e constant memory serializa por endereco unico. Lido via __ldg -> cache RO.")
out.append(f"__device__ uint32_t d_gtable[{NWIN * NPT * 16}] = {{")
for idx, (x, y) in enumerate(rows):
    vals = words(x) + words(y)
    out.append("  " + ",".join(f"0x{v:08x}" for v in vals) + ("," if idx < len(rows) - 1 else ""))
out.append("};")
out.append("#endif")

path = "../src/secp_gtable.cuh"
open(path, "w").write("\n".join(out) + "\n")
print(f"escrito {path}  ({len(rows)} pontos, {len(rows)*64/1024:.0f} KB de dados)")
