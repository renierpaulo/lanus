# Makefile para BIP39 CUDA Scanner
# Detecta automaticamente o sistema operacional para comandos básicos

NVCC = nvcc
# Ajuste a arquitetura conforme necessário (sm_89 = RTX 4090, sm_90 = H100/Blackwell)
ARCH = sm_89
NVCC_FLAGS = -O3 -arch=$(ARCH) --use_fast_math -Xcompiler "-O3"

SRC_DIR = src
BUILD_DIR = build
TARGET_NAME = bip39_scanner

# Configuração condicional de comandos
ifeq ($(OS),Windows_NT)
    # Windows
    TARGET = $(TARGET_NAME).exe
    MKDIR_CMD = if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
    # Cleaning on Windows cmd is tricky in make, simpler to assume rm exists (git bash) or use rmdir
    CLEAN_CMD = if exist $(BUILD_DIR) rmdir /s /q $(BUILD_DIR)
else
    # Linux / Unix
    TARGET = $(TARGET_NAME)
    MKDIR_CMD = mkdir -p $(BUILD_DIR)
    CLEAN_CMD = rm -rf $(BUILD_DIR)
endif

SOURCES = $(SRC_DIR)/main.cu

.PHONY: all clean

all: $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(SOURCES)
	@$(MKDIR_CMD)
	$(NVCC) $(NVCC_FLAGS) -o $@ $(SOURCES)

clean:
	@$(CLEAN_CMD)
