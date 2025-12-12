import os
import sys
import subprocess
import time
import platform
import math
import glob

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print("=" * 60)
    print("      BIP39 CUDA SCANNER - ORCHESTRATOR")
    print("=" * 60)

def compile_project():
    print("[*] Verificando ambiente e compilando...")
    is_windows = os.name == 'nt'
    make_cmd = ['make'] 
    
    try:
        subprocess.check_call(make_cmd)
        print("[+] Compilação bem sucedida!")
        return True
    except subprocess.CalledProcessError:
        print("[-] Erro na compilação. Tentando 'mingw32-make' se estiver no Windows...")
        if is_windows:
            try:
                subprocess.check_call(['mingw32-make'])
                print("[+] Compilação bem sucedida (mingw32-make)!")
                return True
            except:
                pass
        print("[-] Falha ao executar 'make'.")
        return False
    except FileNotFoundError:
        print("[-] Comando 'make' não encontrado.")
        return False

def get_executable_path():
    possible_names = [
        os.path.join("build", "bip39_scanner.exe"),
        os.path.join("build", "bip39_scanner"),
        os.path.join("cuda-scanner", "build", "lanus_scanner"),
        os.path.join("build", "lanus_scanner") 
    ]
    for p in possible_names:
        if os.path.exists(p):
            return p
    return os.path.join("build", "bip39_scanner.exe" if os.name == 'nt' else "bip39_scanner")

def find_address_files():
    # Procura arquivos .txt ou .bin (bloom) em diretórios próximos
    search_paths = [".", "..", "../.."]
    found_files = []
    
    for path in search_paths:
        try:
            # Pega todos txt e bin
            files = glob.glob(os.path.join(path, "*.txt")) + glob.glob(os.path.join(path, "*.bin"))
            for f in files:
                # Filtrar arquivos pequenos ou irrelevantes se quiser
                # Exemplo: Ignorar Makefiles, fontes, etc (ja filtrado por extensao)
                # Ignorar o proprio arquivo de palavras se tiver nome obvio
                if "wordlist" in f or "found" in f.lower() or "temp_words" in f:
                    continue
                found_files.append(os.path.abspath(f))
        except:
            pass
            
    # Remover duplicatas
    return sorted(list(set(found_files)))

def count_lines_fast(filename):
    # Conta linhas para estimativa (rápido para arquivos grandes no Linux, fallback python)
    print(f"[*] Contando endereços em {filename}...")
    try:
        if os.name != 'nt':
            # wc -l é muito mais rápido
            result = subprocess.check_output(['wc', '-l', filename]).decode().split()[0]
            return int(result)
        else:
            i = 0
            with open(filename, 'rb') as f:
                for i, _ in enumerate(f):
                    pass
            return i + 1
    except:
        return 0

def calculate_bloom_size(num_addresses):
    if num_addresses == 0:
        return 2048
        
    # Formula para Bloom Filter
    # m = - (n * ln(p)) / (ln(2)^2)
    # Queremos precisão extrema. p = 1e-9 (1 em 1 bilhão de falso positivo)
    
    p = 1.0e-10 # 1 em 10 bilhões
    n = num_addresses
    
    m_bits = - (n * math.log(p)) / (math.log(2)**2)
    m_bytes = m_bits / 8
    m_mb = m_bytes / (1024 * 1024)
    
    # Arredondar para cima power of 2 ou numero redondo
    suggested_mb = int(math.ceil(m_mb))
    
    # Tolerancia: dar uma folga de 20%
    suggested_mb = int(suggested_mb * 1.2)
    
    # Minimo 64MB, Maximo depende da GPU (vamos limitar a 16GB por seguranca se for absurdo)
    if suggested_mb < 64: suggested_mb = 64
    
    return suggested_mb

def main():
    clear_screen()
    print_banner()
    
    # 1. Compilação
    if not compile_project():
        input("\nPressione ENTER para sair...")
        return

    print("\n" + "-" * 60)
    print("CONFIGURAÇÃO DA BUSCA")
    print("-" * 60)

    # 2. Arquivo de Endereços (Smart Detect)
    print("\n[+] Procurando arquivos de alvo...")
    found_files = find_address_files()
    
    address_file = ""
    
    if found_files:
        print("\nArquivos encontrados:")
        for idx, f in enumerate(found_files):
            # Mostrar path relativo para ficar mais curto
            try:
                display_name = os.path.relpath(f)
            except:
                display_name = f
            size_mb = os.path.getsize(f) / (1024*1024)
            print(f"  [{idx+1}] {display_name} ({size_mb:.2f} MB)")
        
        print(f"  [{len(found_files)+1}] Digitar outro caminho manual")
        
        choice = input("\nEscolha o arquivo alvo: ").strip()
        try:
            val = int(choice)
            if 1 <= val <= len(found_files):
                address_file = found_files[val-1]
            else:
                address_file = input("Caminho manual: ").strip().strip('"')
        except:
             address_file = input("Caminho manual: ").strip().strip('"')
    else:
        address_file = input("Nenhum arquivo encontrado. Digite o caminho: ").strip().strip('"')

    if not os.path.exists(address_file):
        print(f"[-] Erro: {address_file} não encontrado.")
        return

    # Bloom Filter Auto-Calc
    print("\n[+] Calculando tamanho ideal do Bloom Filter...")
    num_addr = count_lines_fast(address_file)
    print(f"    Total de endereços estimados: {num_addr:,}")
    
    rec_bloom = calculate_bloom_size(num_addr)
    print(f"    Tamanho RECOMENDADO para precisão TOTAL (1e-10): {rec_bloom} MB")
    
    bloom_choice = input(f"Usar tamanho recomendado ({rec_bloom} MB)? [S/n]: ").strip().lower()
    if bloom_choice == 'n':
        val = input("Digite o tamanho em MB: ").strip()
        if val.isdigit():
            bloom_size = val
        else:
            bloom_size = str(rec_bloom)
    else:
        bloom_size = str(rec_bloom)

    # Palavras
    print("\n3. DEFINIÇÃO DAS PALAVRAS")
    print("Opções:")
    print("  [1] Digitar palavras manualmente")
    print("  [2] Carregar de arquivo existente")
    
    choice_words = input("Escolha [1/2]: ").strip()
    words_file = "temp_words.txt"
    
    if choice_words == '1':
        words_input = input("\nDigite as palavras (separadas por espaço): ").strip()
        with open(words_file, "w") as f:
            f.write(words_input)
    else:
        words_inp = input("Caminho do arquivo de palavras: ").strip().strip('"')
        if os.path.exists(words_inp):
            words_file = words_inp

    # GPUs
    gpus = input("\nNúmero de GPUs para usar (ENTER para todas): ").strip()
    
    # Execução
    exe_path = get_executable_path()
    cmd_args = [exe_path, "-a", address_file, "--bloom", bloom_size, "-words", words_file]
    if gpus:
        cmd_args.extend(["--gpus", gpus])

    print("\n" + "=" * 60)
    print("COMANDO GERADO:")
    print(' '.join(cmd_args))
    print("=" * 60)
    
    input("\nPressione ENTER para DECOLAR...")
    
    clear_screen()
    try:
        subprocess.call(cmd_args)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
