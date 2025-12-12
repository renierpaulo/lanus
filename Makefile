# Makefile Global para o Projeto Lanus (BIP39 CUDA Scanner)
# Detecta automaticamente a arquitetura da GPU ou usa padrão RTX 4090/5090

NVCC = nvcc

# Arquitetura Alvo: sm_89 (Ada/RTX4090), compatível com 5090. 
# Se 5090 tiver SM específico (sm_90+), ajustar aqui.
ARCH = sm_89

# Flags de Otimização Extrema
NVCC_FLAGS = -O3 -arch=$(ARCH) --use_fast_math -Xptxas -O3,-v -lineinfo

# Diretórios
SRC_DIR = cuda-scanner/src
BUILD_DIR = cuda-scanner/build
BIN_NAME = lanus_scanner

# Windows (.exe) vs Linux (sem extensão)
ifeq ($(OS),Windows_NT)
    TARGET = $(BUILD_DIR)/$(BIN_NAME).exe
    MKDIR_P = if not exist "$(subst /,\,$(BUILD_DIR))" mkdir "$(subst /,\,$(BUILD_DIR))"
    RM_RF = rmdir /s /q
else
    TARGET = $(BUILD_DIR)/$(BIN_NAME)
    MKDIR_P = mkdir -p $(BUILD_DIR)
    RM_RF = rm -rf
endif

SOURCES = $(SRC_DIR)/main.cu

# Target Principal
all: $(TARGET)

$(TARGET): $(SOURCES) ensure_dirs
	@echo "Compilando para $(ARCH)..."
	$(NVCC) $(NVCC_FLAGS) -o $(TARGET) $(SOURCES)
	@echo "Build completo: $(TARGET)"

ensure_dirs:
	$(MKDIR_P)

clean:
	$(RM_RF) "$(subst /,\,$(BUILD_DIR))"

# Atalho para rodar (assume que wordlist e targets existem)
run: $(TARGET)
	cd cuda-scanner && build/$(BIN_NAME)

# Atalho para reconstruir o btc1.txt se necessário
join_data:
ifeq ($(OS),Windows_NT)
	join_data.bat
else
	cat btc1.txt.part* > btc1.txt
endif

.PHONY: all clean run ensure_dirs join_data
