import os
import sys
import subprocess
import time
import platform

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print("=" * 60)
    print("      BIP39 CUDA SCANNER - ORCHESTRATOR")
    print("=" * 60)

def compile_project():
    print("[*] Verificando ambiente e compilando...")
    
    # Detectar OS
    is_windows = os.name == 'nt'
    make_cmd = ['make'] 
    
    try:
        # Tentar compilar
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
        
        print("[-] Falha ao executar 'make'. Certifique-se que o CUDA Toolkit está instalado.")
        return False
    except FileNotFoundError:
        print("[-] Comando 'make' não encontrado. Instale Build Tools ou GnuWin32.")
        return False

def get_executable_path():
    # Tenta encontrar o executável gerado
    possible_names = [
        os.path.join("build", "bip39_scanner.exe"),
        os.path.join("build", "bip39_scanner"),
        os.path.join("cuda-scanner", "build", "lanus_scanner"), # Baseado no log do usuario
        os.path.join("build", "lanus_scanner") 
    ]
    
    for p in possible_names:
        if os.path.exists(p):
            return p
            
    # Se não achou, retorna o padrão esperado do Makefile
    return os.path.join("build", "bip39_scanner.exe" if os.name == 'nt' else "bip39_scanner")

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

    # 2. Inputs do Usuário
    
    # Palavras
    print("\n1. DEFINIÇÃO DAS PALAVRAS")
    print("Opções:")
    print("  [1] Digitar palavras manualmente")
    print("  [2] Carregar de arquivo existente")
    
    choice_words = input("Escolha [1/2]: ").strip()
    words_file = "temp_words.txt"
    
    if choice_words == '1':
        words_input = input("\nDigite as palavras (separadas por espaço): ").strip()
        with open(words_file, "w") as f:
            f.write(words_input)
        print(f"[+] Palavras salvas em {words_file}")
    else:
        words_file = input("Caminho do arquivo de palavras: ").strip().strip('"')
        if not os.path.exists(words_file):
            print(f"[-] Arquivo {words_file} não encontrado.")
            return

    # Endereços Alvo
    print("\n2. ENDEREÇOS ALVO")
    address_file = input("Caminho do arquivo de endereços/bloom (ex: targets.txt): ").strip().strip('"')
    if not os.path.exists(address_file):
        print(f"[-] Arquivo {address_file} não encontrado! Criando arquivo vazio para teste...")
        with open(address_file, "w") as f:
            f.write("") # Create empty if needed or warn

    # Bloom Filter
    print("\n3. BLOOM FILTER")
    bloom_size = input("Tamanho do Bloom Filter em MB (Default: 2048): ").strip()
    if not bloom_size:
        bloom_size = "2048"

    # GPUs
    print("\n4. RECURSOS")
    gpus = input("Número de GPUs para usar (Default: todas): ").strip()
    
    # Confirmação
    exe_path = get_executable_path()
    
    cmd_args = [exe_path, "-a", address_file, "--bloom", bloom_size, "-words", words_file]
    if gpus:
        cmd_args.extend(["--gpus", gpus])

    print("\n" + "=" * 60)
    print("RESUMO DA MISSÃO")
    print(f"Executável: {exe_path}")
    print(f"Alvos:      {address_file}")
    print(f"Bloom:      {bloom_size} MB")
    print(f"Palavras:   {words_file}")
    print(f"Comando:    {' '.join(cmd_args)}")
    print("=" * 60)
    
    input("\nPressione ENTER para INICIAR A BUSCA...")
    
    # 3. Execução
    clear_screen()
    print("[*] Iniciando Scanner... (Ctrl+C para parar)\n")
    try:
        subprocess.call(cmd_args)
    except KeyboardInterrupt:
        print("\n[!] Busca interrompida pelo usuário.")
    except Exception as e:
        print(f"\n[-] Erro ao executar: {e}")

if __name__ == "__main__":
    main()
