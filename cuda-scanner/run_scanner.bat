@echo off
REM Script para executar o CUDA Scanner

echo ============================================================
echo  BIP39 CUDA Scanner
echo ============================================================

if not exist build\bip39_scanner.exe (
    echo Executavel nao encontrado! Execute build.bat primeiro.
    pause
    exit /b 1
)

if not exist wordlist.txt (
    echo AVISO: wordlist.txt nao encontrado!
    echo Execute: powershell -ExecutionPolicy Bypass -File ..\download_wordlist.ps1
    echo.
)

REM Verificar argumentos
if "%~1"=="" (
    echo Uso: run_scanner.bat ^<dataset.bin^> ^<addresses.txt^> [wordlist.txt]
    echo.
    echo Exemplo:
    echo   run_scanner.bat ..\dataset_24.bin addresses.txt wordlist.txt
    echo.
    pause
    exit /b 1
)

set DATASET=%~1
set ADDRESSES=%~2
set WORDLIST=%~3

if "%WORDLIST%"=="" set WORDLIST=wordlist.txt

echo Dataset: %DATASET%
echo Enderecos: %ADDRESSES%
echo Wordlist: %WORDLIST%
echo.

build\bip39_scanner.exe %DATASET% %ADDRESSES% %WORDLIST%

pause
