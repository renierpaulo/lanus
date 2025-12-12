/*
 * BIP39 Range Generator v2.0 - ESTADO DA ARTE
 * 
 * Arquitetura "Range Only":
 * - Não salva frases individuais
 * - Gera arquivo de configuração pequeno com ranges de K (índice de permutação)
 * - CUDA gera permutações on-the-fly usando Lehmer/Factoradic
 * 
 * Isso permite "varrer tudo" sem usar disco para armazenar frases.
 */

use bip39::Language;
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufWriter, BufReader, Write, Read};
use std::time::Instant;

const MAGIC: u32 = 0x42495034; // "BIP4" - versão 2
const VERSION: u32 = 2;

#[derive(Parser, Debug)]
#[command(author, version, about = "BIP39 Range Generator v2.0 - Estado da Arte")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Gerar arquivo de configuração com ranges para CUDA
    Generate {
        /// Palavras conhecidas separadas por vírgula ou espaço
        #[arg(short = 'k', long, required = true)]
        known_words: String,

        /// Arquivo de saída (.range)
        #[arg(short, long, default_value = "job.range")]
        output: String,

        /// K inicial (0 = início)
        #[arg(long, default_value = "0")]
        start: u128,

        /// Quantidade de Ks a processar (0 = todos até 24!)
        #[arg(long, default_value = "0")]
        count: u128,

        /// Dividir em N partes (para múltiplas GPUs/máquinas)
        #[arg(long, default_value = "1")]
        splits: u32,
    },

    /// Decodificar K para frase mnemônica (debug/verificação)
    Decode {
        /// Arquivo .range ou especificar palavras diretamente
        #[arg(short, long)]
        range_file: Option<String>,

        /// Palavras conhecidas (se não usar range_file)
        #[arg(short = 'k', long)]
        known_words: Option<String>,

        /// Valor de K a decodificar
        #[arg(short = 'K', long)]
        k_value: u128,
    },

    /// Listar informações de um arquivo .range
    Info {
        /// Arquivo .range
        #[arg(short, long)]
        range_file: String,
    },
}

/// Fatoriais pré-calculados (0! até 24!)
fn factorials() -> [u128; 25] {
    let mut f = [1u128; 25];
    for i in 1..=24 {
        f[i] = f[i - 1] * (i as u128);
    }
    f
}

/// Converter K (índice de permutação) para permutação usando Lehmer/Factoradic
fn k_to_permutation(k: u128, n: usize) -> Vec<usize> {
    let fact = factorials();
    let mut k = k;
    let mut available: Vec<usize> = (0..n).collect();
    let mut perm = Vec::with_capacity(n);

    for i in 0..n {
        let f = fact[n - 1 - i];
        let idx = (k / f) as usize;
        k %= f;
        perm.push(available.remove(idx));
    }

    perm
}

/// Converter permutação para K (índice de permutação)
fn permutation_to_k(perm: &[usize]) -> u128 {
    let n = perm.len();
    let fact = factorials();
    let mut available: Vec<usize> = (0..n).collect();
    let mut k: u128 = 0;

    for i in 0..n {
        let pos = available.iter().position(|&x| x == perm[i]).unwrap();
        k += (pos as u128) * fact[n - 1 - i];
        available.remove(pos);
    }

    k
}

/// Verificar checksum BIP39 para 24 palavras (índices)
fn checksum_ok_24(idx: &[u16]) -> bool {
    let mut entropy = [0u8; 32];
    
    let mut acc: u64 = 0;
    for i in 0..6 {
        acc = (acc << 11) | (idx[i] as u64);
    }
    entropy[0] = (acc >> 58) as u8;
    entropy[1] = (acc >> 50) as u8;
    entropy[2] = (acc >> 42) as u8;
    entropy[3] = (acc >> 34) as u8;
    entropy[4] = (acc >> 26) as u8;
    entropy[5] = (acc >> 18) as u8;
    entropy[6] = (acc >> 10) as u8;
    entropy[7] = (acc >> 2) as u8;
    acc &= 3;
    
    for i in 6..12 {
        acc = (acc << 11) | (idx[i] as u64);
    }
    entropy[8] = (acc >> 60) as u8;
    entropy[9] = (acc >> 52) as u8;
    entropy[10] = (acc >> 44) as u8;
    entropy[11] = (acc >> 36) as u8;
    entropy[12] = (acc >> 28) as u8;
    entropy[13] = (acc >> 20) as u8;
    entropy[14] = (acc >> 12) as u8;
    entropy[15] = (acc >> 4) as u8;
    acc &= 15;
    
    for i in 12..18 {
        acc = (acc << 11) | (idx[i] as u64);
    }
    entropy[16] = (acc >> 62) as u8;
    entropy[17] = (acc >> 54) as u8;
    entropy[18] = (acc >> 46) as u8;
    entropy[19] = (acc >> 38) as u8;
    entropy[20] = (acc >> 30) as u8;
    entropy[21] = (acc >> 22) as u8;
    entropy[22] = (acc >> 14) as u8;
    entropy[23] = (acc >> 6) as u8;
    
    let mut big: u128 = (acc & 63) as u128;
    for i in 18..24 {
        big = (big << 11) | (idx[i] as u128);
    }
    entropy[24] = (big >> 64) as u8;
    entropy[25] = (big >> 56) as u8;
    entropy[26] = (big >> 48) as u8;
    entropy[27] = (big >> 40) as u8;
    entropy[28] = (big >> 32) as u8;
    entropy[29] = (big >> 24) as u8;
    entropy[30] = (big >> 16) as u8;
    entropy[31] = (big >> 8) as u8;
    
    let checksum_bits = (big & 0xFF) as u8;
    let hash = Sha256::digest(&entropy);
    
    checksum_bits == hash[0]
}

fn get_bip39_wordlist() -> Vec<String> {
    let wordlist = Language::English.word_list();
    wordlist.iter().map(|s| s.to_string()).collect()
}

fn parse_known_words(input: &str, wordlist: &[String]) -> Vec<u16> {
    input
        .split(|c| c == ',' || c == ' ')
        .filter_map(|w| {
            let word = w.trim().to_lowercase();
            if word.is_empty() {
                return None;
            }
            wordlist.iter().position(|x| x == &word).map(|i| i as u16)
        })
        .collect()
}

/// Formato do arquivo .range (v2):
/// Header:
///   magic: u32
///   version: u32
///   word_count: u32
///   num_ranges: u32
///   base_indices: [u16; word_count]
/// Ranges:
///   start: u128 (16 bytes LE)
///   count: u128 (16 bytes LE)
fn write_range_file(
    path: &str,
    base_indices: &[u16],
    ranges: &[(u128, u128)],
) -> std::io::Result<()> {
    let file = File::create(path)?;
    let mut w = BufWriter::new(file);

    // Header
    w.write_u32::<LittleEndian>(MAGIC)?;
    w.write_u32::<LittleEndian>(VERSION)?;
    w.write_u32::<LittleEndian>(base_indices.len() as u32)?;
    w.write_u32::<LittleEndian>(ranges.len() as u32)?;

    // Base indices
    for &idx in base_indices {
        w.write_u16::<LittleEndian>(idx)?;
    }

    // Ranges
    for &(start, count) in ranges {
        w.write_u128::<LittleEndian>(start)?;
        w.write_u128::<LittleEndian>(count)?;
    }

    w.flush()?;
    Ok(())
}

fn read_range_file(path: &str) -> std::io::Result<(Vec<u16>, Vec<(u128, u128)>)> {
    let file = File::open(path)?;
    let mut r = BufReader::new(file);

    let magic = r.read_u32::<LittleEndian>()?;
    if magic != MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Magic inválido",
        ));
    }

    let version = r.read_u32::<LittleEndian>()?;
    if version != VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Versão {} não suportada", version),
        ));
    }

    let word_count = r.read_u32::<LittleEndian>()? as usize;
    let num_ranges = r.read_u32::<LittleEndian>()? as usize;

    let mut base_indices = Vec::with_capacity(word_count);
    for _ in 0..word_count {
        base_indices.push(r.read_u16::<LittleEndian>()?);
    }

    let mut ranges = Vec::with_capacity(num_ranges);
    for _ in 0..num_ranges {
        let start = r.read_u128::<LittleEndian>()?;
        let count = r.read_u128::<LittleEndian>()?;
        ranges.push((start, count));
    }

    Ok((base_indices, ranges))
}

fn format_big_number(n: u128) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let wordlist = get_bip39_wordlist();
    let fact = factorials();

    match args.command {
        Commands::Generate {
            known_words,
            output,
            start,
            count,
            splits,
        } => {
            println!("============================================================");
            println!("  BIP39 Range Generator v2.0 - Estado da Arte");
            println!("============================================================");

            let base_indices = parse_known_words(&known_words, &wordlist);
            let n = base_indices.len();

            if n != 24 && n != 12 {
                eprintln!("Erro: precisa de 12 ou 24 palavras, recebeu {}", n);
                std::process::exit(1);
            }

            let total_perms = fact[n];
            let actual_count = if count == 0 { total_perms - start } else { count };
            let end = (start + actual_count).min(total_perms);

            println!("Palavras: {}", n);
            println!("Total de permutações: {}", format_big_number(total_perms));
            println!("Range: {} .. {}", format_big_number(start), format_big_number(end));
            println!("Quantidade: {}", format_big_number(actual_count));
            println!("Splits: {}", splits);
            println!("============================================================");

            // Mostrar palavras
            println!("\nPalavras base (ordem fixa):");
            for (i, &idx) in base_indices.iter().enumerate() {
                print!("{}:{} ", i, &wordlist[idx as usize]);
            }
            println!("\n");

            // Criar ranges
            let mut ranges = Vec::new();
            let per_split = actual_count / (splits as u128);
            let remainder = actual_count % (splits as u128);

            let mut current = start;
            for i in 0..splits {
                let this_count = per_split + if (i as u128) < remainder { 1 } else { 0 };
                if this_count > 0 {
                    ranges.push((current, this_count));
                    current += this_count;
                }
            }

            // Se splits > 1, criar múltiplos arquivos
            if splits == 1 {
                write_range_file(&output, &base_indices, &ranges)?;
                println!("Arquivo gerado: {}", output);
                println!("Tamanho: {} bytes", std::fs::metadata(&output)?.len());
            } else {
                for (i, &(s, c)) in ranges.iter().enumerate() {
                    let path = output.replace(".range", &format!("_part{}.range", i));
                    write_range_file(&path, &base_indices, &[(s, c)])?;
                    println!(
                        "Parte {}: {} (K {} .. {}, {} perms)",
                        i,
                        path,
                        format_big_number(s),
                        format_big_number(s + c),
                        format_big_number(c)
                    );
                }
            }

            println!("\n============================================================");
            println!("  PRONTO - Use no CUDA Scanner");
            println!("============================================================");
        }

        Commands::Decode {
            range_file,
            known_words,
            k_value,
        } => {
            let base_indices = if let Some(ref path) = range_file {
                let (indices, _) = read_range_file(path)?;
                indices
            } else if let Some(ref words) = known_words {
                parse_known_words(words, &wordlist)
            } else {
                eprintln!("Erro: forneça --range-file ou --known-words");
                std::process::exit(1);
            };

            let n = base_indices.len();
            let total_perms = fact[n];

            if k_value >= total_perms {
                eprintln!(
                    "Erro: K={} está fora do range [0, {})",
                    k_value,
                    format_big_number(total_perms)
                );
                std::process::exit(1);
            }

            // Converter K para permutação
            let perm = k_to_permutation(k_value, n);

            // Aplicar permutação aos índices base
            let final_indices: Vec<u16> = perm.iter().map(|&i| base_indices[i]).collect();

            // Montar frase
            let phrase: Vec<&str> = final_indices
                .iter()
                .map(|&i| wordlist[i as usize].as_str())
                .collect();

            println!("============================================================");
            println!("  Decodificação de K = {}", format_big_number(k_value));
            println!("============================================================");
            println!("Permutação (posições): {:?}", perm);
            println!("Índices BIP39: {:?}", final_indices);
            println!("\nFrase mnemônica:");
            println!("  {}", phrase.join(" "));

            // Verificar checksum
            if n == 24 {
                let valid = checksum_ok_24(&final_indices);
                println!("\nChecksum BIP39: {}", if valid { "VÁLIDO ✓" } else { "INVÁLIDO ✗" });
            }

            println!("============================================================");
        }

        Commands::Info { range_file } => {
            let (base_indices, ranges) = read_range_file(&range_file)?;

            println!("============================================================");
            println!("  Informações: {}", range_file);
            println!("============================================================");
            println!("Palavras: {}", base_indices.len());

            let total_perms = fact[base_indices.len()];
            let mut total_count: u128 = 0;

            println!("\nPalavras base:");
            for (i, &idx) in base_indices.iter().enumerate() {
                print!("{}:{} ", i, &wordlist[idx as usize]);
            }
            println!("\n");

            println!("Ranges ({}):", ranges.len());
            for (i, &(start, count)) in ranges.iter().enumerate() {
                println!(
                    "  [{}] K: {} .. {} ({} perms, {:.6}%)",
                    i,
                    format_big_number(start),
                    format_big_number(start + count),
                    format_big_number(count),
                    (count as f64 / total_perms as f64) * 100.0
                );
                total_count += count;
            }

            println!("\nTotal a processar: {} ({:.6}% do espaço)",
                     format_big_number(total_count),
                     (total_count as f64 / total_perms as f64) * 100.0);
            println!("============================================================");
        }
    }

    Ok(())
}
