@echo off
REM Build script para Windows
REM Requer CUDA Toolkit e Visual Studio instalados

echo ============================================================
echo  BIP39 CUDA Scanner - Build Script
echo ============================================================

if not exist build mkdir build

REM Detectar arquitetura da GPU
REM RTX 5090 (Blackwell) / H100 (Hopper): sm_90
REM RTX 4090 (Ada Lovelace): sm_89
REM RTX 3090 (Ampere): sm_86

set ARCH=sm_89

echo Compilando para arquitetura %ARCH%...

nvcc -O3 -arch=%ARCH% --use_fast_math -Xptxas -O3,-v ^
    -Xcompiler "/O2 /EHsc" ^
    -o build\bip39_scanner.exe ^
    src\main.cu

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================================
    echo  Build concluido com sucesso!
    echo  Executavel: build\bip39_scanner.exe
    echo ============================================================
) else (
    echo.
    echo ============================================================
    echo  ERRO no build!
    echo ============================================================
)

pause
