/*
    === AES (Advanced Encryption Standard) ===
    Algoritmo de criptografia simétrica usado mundialmente para proteger dados sensíveis, 
    utilizando a mesma chave para criptografar e descriptografar informações.
*/

// Bibliotecas
use hmac::{Hmac, Mac}; // Biblioteca que gera um código de autenticação usando uma chave e um hash
use sha2::Sha256; // Biblioteca usada para transformar dados em uma "impressão digital" única de 256 bits
use std::fs::{File}; // Biblioteca para manipulação de arquivos
use std::io::{Read, Write}; // Biblioteca para leitura e escrita de arquivos 
use std::io; // Biblioteca para entrada e saída padrão
use std::env; // Biblioteca para instruções externas (terminal)
use rand::RngCore; // Biblioteca para geração de números aleatórios

type HmacSha256 = Hmac<Sha256>; // Define um apelido para implementação do algoritmo HMAC

// Tabela S-Box: Acabar com padrões
//      ??? Usada na função SubBytes para substituir cada byte do estado
//      ??? Projetada para ser não-linear e resistente a criptoanálise
const S_BOX: [u8; 256] = 
    [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];

// RCON - Constante de rodada
//      ??? Usada na expansão de chave para evitar simetria
const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];


// 1. Implementação do SubBytes
//    ??? Substitui cada byte do estado pelo valor correspondente na SBOX
fn sub_bytes(estado: &mut [u8; 16]){
    // --- Substitui o byte atual pelo valor da SBOX na posição correspondente do byte
    for i in 0..16 { 
        estado[i] = S_BOX[estado[i] as usize];
    }
}


// 2. Implementação do ShiftRows
//    ??? Desloca cada linha da matriz para a esquerda
fn shift_rows(estado: &mut[u8; 16]){
    let mut temp = [0u8; 16];
    temp.copy_from_slice(estado);

    // --- Coluna 1: Desloca 1 posição para a esquerda
    estado[1] = temp[5];
    estado[5] = temp[9];
    estado[9] = temp[13];
    estado[13] = temp[1];

    // --- Coluna 2: Desloca 2 posições para a esquerda
    estado[2] = temp[10];
    estado[6] = temp[14];
    estado[10] = temp[2];
    estado[14] = temp[6];

    // --- Coluna 3: Desloca 3 posições para a esquerda
    estado[3] = temp[15];
    estado[7] = temp[3];
    estado[11] = temp[7];
    estado[15] = temp[11];
}


// Multiplicação no Campo de Galois
//      ??? Mistura os bytes dentro de cada coluna usando aritmética GF(2^8)
//      ??? XOR (OU Exclusivo): 0x0 = 0 | 1x1 = 1 | 1x0 = 1 | 0x1 = 1
fn campo_galois(num1: u8, num2: u8) -> u8 {
    let mut resultado = 0;

    let mut copia_num1 = num1;
    let mut copia_num2 = num2;

    for _ in 0..8{
        // --- Verifica o último bit da copia do segundo número
        if (copia_num2 & 1) != 0 {
            resultado ^= copia_num1;
        } 

        let carry: u8 = copia_num1 & 0x80;

        copia_num1 <<= 1; // --- Desloca para a esquerda

        // --- Se for != 0, houve o número ultrapassou os 8 bits (carry)
        if carry != 0 {
            copia_num1 ^= 0x1B;
        }

        copia_num2 >>= 1;
    }

    resultado
}

// 3. Implementação do MixColumns
//    ??? Multiplica cada coluna por uma matriz fixa
fn mix_columns(estado: &mut[u8; 16]){
    for coluna in 0..4 {
        let i = coluna * 4;

        // --- Extração dos bytes da coluna atual
        let s0 = estado[i];
        let s1 = estado[i + 1];
        let s2 = estado [i + 2];
        let s3 = estado [i + 3];

        // --- Transformação matricial no campo GF(2^8)
        estado[i] = campo_galois(0x02, s0) ^ campo_galois(0x03, s1) ^ s2 ^ s3;

        estado[i + 1] = s0 ^ campo_galois(0x02, s1) ^ campo_galois(0x03, s2) ^ s3;

        estado[i + 2] = s0 ^ s1 ^ campo_galois(0x02, s2) ^ campo_galois(0x03, s3);

        estado[i + 3] = campo_galois(0x03, s0) ^ s1 ^ s2 ^ campo_galois(0x02, s3);
    }
}

// 4. Implementação do AddRoundKey
//    ??? Aplica XOR entre o estado e a chave da rodada
fn add_round_key(estado: &mut [u8;16], round_key: &[u8;16]) {
    for i in 0..16 {
        // --- XOR bit a bit com o byte correspondente da chave
        estado[i] ^= round_key[i];
    }
}

// 5. Implementação do Key Expansion
//    ??? Gera 15 chaves das rodadas (AES-256) - 60 palavras de 4 bytes
fn key_expansion(chave: &[u8;32]) -> [[u8; 16]; 15]{
    let mut palavras: [[u8; 4]; 60] = [[0; 4]; 60];

    // --- Copia a chave original para as primeiras 8 palavras
    for i in 0..8 {
        palavras[i][0] = chave[4 * i];
        palavras[i][1] = chave[4 * i + 1];
        palavras[i][2] = chave[4 * i + 2];
        palavras[i][3] = chave[4 * i + 3];
    }

    // --- Gera as palavras restantes
    for i in 8..60 {
        let mut temp = palavras[i - 1];

        // --- A cada 8 palavras, aplica a função de rotação e SBOX
        if i % 8 == 0 {
            // --- RotWord: rotação circular de 1 byte para esquerda
            temp = [temp[1], temp[2], temp[3], temp[0]];

            // --- SubWord: aplica SBOX em cada byte
            for j in 0..4 {
                temp[j] = S_BOX[temp[j] as usize];
            }

            // --- XOR com RCON
            temp[0] ^= RCON[i / 8];
        }

        // --- Para AES-256, a cada 8 palavras também aplica SubWord
        else if i % 8 == 4 {
            for j in 0..4 {
                temp[j] = S_BOX[temp[j] as usize];
            }
        }

        // --- Gera a nova palavra (XOR com a palavra, 8 posições atrás)
        for j in 0..4 {
            palavras[i][j] = palavras[i - 8][j] ^ temp[j];
        }
    }

    // --- Converte as palavras em chaves de rodada (cada rodada usa 4 palavras = 16 bytes)
    let mut round_keys: [[u8; 16]; 15] = [[0; 16]; 15];

    for round in 0..15 {
        for j in 0..4 {
            let indice_palavra = round * 4 + j;

            round_keys[round][j * 4] = palavras[indice_palavra][0];
            round_keys[round][j * 4 + 1] = palavras[indice_palavra][1];
            round_keys[round][j * 4 + 2] = palavras[indice_palavra][2];
            round_keys[round][j * 4 + 3] = palavras[indice_palavra][3];
        }
    }
    round_keys
}

// 6. PBKDF2
//    ??? Transforma senha simples em chave forte
fn pbkdf2(senha: &str, salt: &[u8; 16], iteracoes: u32) -> [u8; 32] {
    let mut chave_final = [0u8; 32];

    let bytes_senha = senha.as_bytes();
    let mut salt_concatenado = salt.to_vec();

    // --- Concatena o salt com o número do bloco
    salt_concatenado.extend_from_slice(&1u32.to_be_bytes());

    // --- Inicializa o motor HMAC usando SHA-256, utilizando a senha como a chave secreta
    let mut mac = HmacSha256::new_from_slice(bytes_senha).unwrap();
    // --- Passa para o HMAC o salt ja concatenado
    mac.update(&salt_concatenado);
    // --- Finaliza o cálculo e armazena o primeiro hash resultante (U1)
    let mut hash_atual_u = mac.finalize().into_bytes();
    chave_final.copy_from_slice(&hash_atual_u);

    for _ in 1..iteracoes {
        // --- Reinicia o HMAC com a senha para a nova rodada
        let mut mac = HmacSha256::new_from_slice(bytes_senha).unwrap();
        mac.update(&hash_atual_u);

        // --- Calcula o novo hash e sobrescreve 
        hash_atual_u = mac.finalize().into_bytes();
        
        // --- Operação XOR
        for j in 0..32 {
            chave_final[j] ^= hash_atual_u[j];
        }
    }

    chave_final
}

//  ================
//    CRIPTOGRAFAR     
//  ================
fn cifrar(caminho: &str){
    // --- Solicitar a senha ao usuário
    println!("Digite a senha: ");
    let mut senha = String::new();
    io::stdin().read_line(&mut senha).expect("Falha ao ler senha...");
    let senha_limpa = senha.trim();

    // --- Derivar chave
    let mut num_aleatorio = rand::rng();
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];

    num_aleatorio.fill_bytes(&mut salt);
    num_aleatorio.fill_bytes(&mut iv);

    let chave = pbkdf2(senha_limpa, &salt, 100_000);
    let round_keys = key_expansion(&chave);

    // --- Preparar Arquivo
    let mut arquivo_original = File::open(caminho).expect("Falha ao abrir arquivo...");
    let mut conteudo = Vec::new();
    arquivo_original.read_to_end(&mut conteudo).expect("Falha ao ler arquivo...");

    // --- Padding
    let comprimento = 16 - (conteudo.len() % 16);
    for _ in 0..comprimento {
        conteudo.push(comprimento as u8);
    }

    let mut texto_cifrado = Vec::new();
    let mut vetor_anterior = iv;

    // --- Processamento dos blocos (Modo CBC)
    for bloco in conteudo.chunks(16) {
        let mut estado: [u8; 16] = bloco.try_into().unwrap();

        // Aplica XOR inicial
        for i in 0..16 {
            estado[i] ^= vetor_anterior[i];
        }

        // --- CRIPTOGRAFIA
        add_round_key(&mut estado, &round_keys[0]);

        for r in 1..14{
            sub_bytes(&mut estado);
            shift_rows(&mut estado);
            mix_columns(&mut estado);
            add_round_key(&mut estado, &round_keys[r]);
        }

        sub_bytes(&mut estado);
        shift_rows(&mut estado);
        add_round_key(&mut estado, &round_keys[14]);

        texto_cifrado.extend_from_slice(&estado);
        vetor_anterior = estado;
    }   

    // --- Salvar saída
    let mut arquivo_cifrado = File::create(format!("{}.cifrado", caminho)).expect("Falha ao criar arquivo cifrado...");
    arquivo_cifrado.write_all(&salt).unwrap();
    arquivo_cifrado.write_all(&iv).unwrap();
    arquivo_cifrado.write_all(&texto_cifrado).unwrap();

    println!("Arquivo cifrado com sucesso!");
}

// Tabela S-BOX inversa
const S_BOX_INV: [u8; 256] = 
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d];

// 1. Implementação SubBytes Inversa
fn inv_sub_bytes(estado: &mut [u8; 16]) {
    for i in 0..16 {
        estado[i] = S_BOX_INV[estado[i] as usize];
    }
}

// 2. Implementação ShiftRows Inversa
fn inv_shift_rows(estado: &mut [u8; 16]) {
    let mut temp = [0u8; 16];
    temp.copy_from_slice(estado);

    // Coluna 1: Desloca 1 posição para a direita
    estado[1] = temp[13];
    estado[5] = temp[1];
    estado[9] = temp[5];
    estado[13] = temp[9];

    // Coluna 2: Desloca 2 posições para a direita
    estado[2] = temp[10];
    estado[6] = temp[14];
    estado[10] = temp[2];
    estado[14] = temp[6];

    // Coluna 3: Desloca 3 posições para a direita
    estado[3] = temp[7];
    estado[7] = temp[11];
    estado[11] = temp[15];
    estado[15] = temp[3];
}

// 3. Implementação MixColumns Inversa
fn inv_mix_columns(estado: &mut [u8; 16]){
    for coluna in 0..4 {
        let i = coluna * 4;

        let s0 = estado[i];
        let s1 = estado[i + 1];
        let s2 = estado[i + 2];
        let s3 = estado[i + 3];

        estado[i] = campo_galois(0x0E, s0) ^ campo_galois(0x0B, s1) ^ campo_galois(0x0D, s2) ^ campo_galois(0x09, s3);

        estado[i + 1] = campo_galois(0x09, s0) ^ campo_galois(0x0E, s1) ^ campo_galois(0x0B, s2) ^ campo_galois(0x0D, s3);

        estado[i + 2] = campo_galois(0x0D, s0) ^ campo_galois(0x09, s1) ^ campo_galois(0x0E, s2) ^ campo_galois(0x0B, s3);

        estado[i + 3] = campo_galois(0x0B, s0) ^ campo_galois(0x0D, s1) ^ campo_galois(0x09, s2) ^ campo_galois(0x0E, s3);
    }
}

//  ===================
//    DESCRIPTOGRAFAR     
//  ===================

fn decifrar(caminho: &str){
    // --- Solicita a senha ao usuário
    println!("Digite a senha utilizada na criptografia do arquivo: ");
    let mut senha = String::new();
    io::stdin().read_line(&mut senha).expect("Falha ao ler senha...");
    let senha_limpa = senha.trim();

    // --- Abrir arquivo cifrado
    let mut arquivo_cifrado = File::open(caminho).expect("Falha ao abrir arquivo cifrado...");
    let mut conteudo_completo = Vec::new();
    arquivo_cifrado.read_to_end(&mut conteudo_completo).expect("Falha ao ler arquivo cifrado...");

    // --- Extrair salt (16 bytes) e IV (16 bytes)
    let salt: [u8; 16] = conteudo_completo[0..16].try_into().unwrap();
    let iv: [u8; 16] = conteudo_completo[16..32].try_into().unwrap();
    let texto_cifrado = &conteudo_completo[32..];

    // --- Derivar chave
    let chave = pbkdf2(senha_limpa, &salt, 100_000);
    // --- Expandir chaves
    let round_keys = key_expansion(&chave);

    // --- Processamento dos blocos (Modo CBC Inverso)
    let mut texto_limpo = Vec::new();
    let mut vetor_anterior = iv;

    for bloco in texto_cifrado.chunks(16){
        let mut estado: [u8; 16] = bloco.try_into().unwrap();
        let bloco_cifrado_atual = estado;

        // --- DESCRIPTOGRAFIA
        add_round_key(&mut estado, &round_keys[14]);

        for r in (1..14).rev() {
            inv_shift_rows(&mut estado);
            inv_sub_bytes(&mut estado);
            add_round_key(&mut estado, &round_keys[r]);
            inv_mix_columns(&mut estado);
        }

        inv_shift_rows(&mut estado);
        inv_sub_bytes(&mut estado);
        add_round_key(&mut estado, &round_keys[0]);

        // --- XOR com o vetor anterior
        for i in 0..16 {
            estado[i] ^= vetor_anterior[i];
        }

        texto_limpo.extend_from_slice(&estado);
        vetor_anterior = bloco_cifrado_atual;
    }

    // --- Remoção do Padding
    let padding = *texto_limpo.last().unwrap() as usize;
    if padding <= 16 {
        texto_limpo.truncate(texto_limpo.len() - padding);
    }

    // --- Exibir conteúdo
    let mensagem = String::from_utf8_lossy(&texto_limpo);
    println!("\nConteúdo descriptografado:\n{}", mensagem);
}

//  ==========
//    TESTAR     
//  ==========

fn testar(){
    // --- Vetor de teste NIST
    let chave_teste = 
    [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4];
    let texto_teste = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
    let result_esperado = [0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8];

    // --- Expansão da chave e preparação do estado
    let round_keys = key_expansion(&chave_teste);
    let mut estado = texto_teste;

    // --- CRIPTOGRAFIA
    add_round_key(&mut estado, &round_keys[0]);

    for r in 1..14 {
        sub_bytes(&mut estado);
        shift_rows(&mut estado);
        mix_columns(&mut estado);
        add_round_key(&mut estado, &round_keys[r]);
    }

    sub_bytes(&mut estado);
    shift_rows(&mut estado);
    add_round_key(&mut estado, &round_keys[14]);

    // --- Verificação (Sucesso ou Falha)
    if estado == result_esperado {
        println!("SUCESSO");
    } else {
        println!("FALHA");
        println!("Esperado: {:02x?}", result_esperado);
        println!("Obtido: {:02x?}", estado);
    }
}

fn main(){
    let args: Vec<String> = env::args().collect();

    match args[1].as_str(){
        "cifrar" => cifrar(&args[2]), // cargo run cifrar mensagem.txt
        "decifrar" => decifrar(&args[2]), // cargo run decifrar mensagem.txt.cifrado
        "testar" => testar(), // cargo run testar
        _ => (),
    }
}
