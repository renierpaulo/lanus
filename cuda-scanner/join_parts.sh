#!/bin/bash
# Script para juntar partes de arquivos cortados (split)
# Uso: ./join_parts.sh <nome_base> <arquivo_saida>
# Exemplo: ./join_parts.sh btc1.txt addresses.txt

if [ "$#" -ne 2 ]; then
    echo "Uso: $0 <nome_base> <arquivo_saida>"
    echo "Exemplo: $0 btc1.txt addresses.txt (vai procurar por btc1.txt.part*)"
    exit 1
fi

BASE_NAME="$1"
OUTPUT_FILE="$2"

echo "[*] Procurando partes de '$BASE_NAME'..."

# Verificar se existem arquivos
COUNT=$(ls ${BASE_NAME}.part* 2>/dev/null | wc -l)

if [ "$COUNT" -eq 0 ]; then
    echo "[-] Nenhuma parte encontrada para ${BASE_NAME}.part*"
    exit 1
fi

echo "[+] Encontradas $COUNT partes. Juntando em '$OUTPUT_FILE'..."

# Juntar usando cat
cat ${BASE_NAME}.part* > "$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "[+] Sucesso! Arquivo criado: $OUTPUT_FILE"
    du -h "$OUTPUT_FILE"
else
    echo "[-] Erro ao juntar os arquivos."
    exit 1
fi
