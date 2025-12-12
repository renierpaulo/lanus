# Makefile para BIP39 CUDA Scanner
# Requer CUDA Toolkit instalado

# Configuração de Arquitetura (__sm_90__ para RTX 5090/Blackwell, __sm_89__ para RTX 4090)
# Se der erro de arquitetura desconhecida, tente sm_86 ou sm_75
ARCH = sm_90

NVCC = nvcc
NVCC_FLAGS = -O3 -arch=$(ARCH) --use_fast_math -Xcompiler "/O2"

SRC_DIR = src
BUILD_DIR = build
TARGET = bip39_scanner.exe

SOURCES = $(SRC_DIR)/main.cu

.PHONY: all clean windows

all: windows

# Alvo principal para Windows
windows:
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	$(NVCC) $(NVCC_FLAGS) -o $(BUILD_DIR)\$(TARGET) $(SOURCES)

clean:
	@if exist $(BUILD_DIR) rmdir /s /q $(BUILD_DIR)
