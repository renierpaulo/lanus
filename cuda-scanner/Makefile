# Makefile para BIP39 CUDA Scanner
# Requer CUDA Toolkit instalado

NVCC = nvcc
NVCC_FLAGS = -O3 -arch=sm_75 -Xcompiler "-O3"
# Ajustar -arch conforme sua GPU:
# RTX 30xx: sm_86
# RTX 20xx: sm_75
# RTX 40xx: sm_89
# GTX 10xx: sm_61

SRC_DIR = src
BUILD_DIR = build
TARGET = bip39_scanner

SOURCES = $(SRC_DIR)/main.cu
HEADERS = $(SRC_DIR)/sha256.cuh $(SRC_DIR)/sha512.cuh $(SRC_DIR)/ripemd160.cuh \
          $(SRC_DIR)/secp256k1.cuh $(SRC_DIR)/base58.cuh $(SRC_DIR)/bech32.cuh \
          $(SRC_DIR)/bip39.cuh

.PHONY: all clean

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(SOURCES) $(HEADERS)
	$(NVCC) $(NVCC_FLAGS) -o $(BUILD_DIR)/$(TARGET) $(SOURCES)

clean:
	rm -rf $(BUILD_DIR)

# Para Windows com MSVC
windows:
	nvcc -O3 -arch=sm_75 -o build\bip39_scanner.exe src\main.cu

# Versão debug
debug:
	$(NVCC) -g -G -arch=sm_75 -o $(BUILD_DIR)/$(TARGET)_debug $(SOURCES)
