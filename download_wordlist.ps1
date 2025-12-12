# Script PowerShell para baixar wordlist BIP39

Write-Host "============================================================"
Write-Host "  Baixando wordlist BIP39 oficial"
Write-Host "============================================================"

$url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
$output = "cuda-scanner\wordlist.txt"

try {
    Invoke-WebRequest -Uri $url -OutFile $output
    Write-Host ""
    Write-Host "Wordlist baixada com sucesso: $output"
    Write-Host "Total de palavras: $((Get-Content $output | Measure-Object -Line).Lines)"
} catch {
    Write-Host "Erro ao baixar wordlist: $_"
    Write-Host ""
    Write-Host "Baixe manualmente de:"
    Write-Host "https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt"
}

Write-Host ""
Write-Host "============================================================"
