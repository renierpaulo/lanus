@echo off
REM Script de exemplo para gerar dataset

echo ============================================================
echo  BIP39 Dataset Generator - Exemplo
echo ============================================================

REM Compilar em modo release
cargo build --release

if %ERRORLEVEL% NEQ 0 (
    echo Erro na compilacao!
    pause
    exit /b 1
)

echo.
echo Gerando dataset com 24 palavras conhecidas...
echo.

REM Exemplo: permutar 24 palavras conhecidas e gerar 1 milhao de validas
target\release\bip39-dataset-generator.exe ^
    -n 24 ^
    -k "grab,merit,chuckle,can,island,wash,floor,car,exit,mother,box,festival,october,odor,camp,country,trial,nephew,coil,fabric,galaxy,napkin,appear,apple" ^
    -c 1000000 ^
    -o ..\dataset_24.bin

echo.
echo ============================================================
echo  Dataset gerado: ..\dataset_24.bin
echo ============================================================

pause
