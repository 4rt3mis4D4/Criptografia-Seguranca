// === BIBLIOTECAS ===
    use std::fs::File; // Biblioteca sistema de arquivos
    use std::io::{self, Read, Write};  // Biblioteca de entrada e saída de dados
    use std::env; // Biblioteca para instruções externas (terminal)
    use hmac::{Hmac, Mac}; // Biblioteca que gera um código de autenticação usando uma chave e um hash
    use sha2::Sha256; // Biblioteca usada para transformar dados em uma "impressão digital" única de 256 bits 

    type HmacSha256 = Hmac<Sha256>; // tipo auxiliar

// Tabela S-Box - Acabar com padrões:
// ??? Usada na função SubBytes para substituir cada byte do estado
// ??? Projetada para ser não-linear e resistente a criptoanálise
const S_Box: [u8; 256] = 
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

// Tabela S-Box inverso (DESCRIPTOGRAFAR)
const S_Box_Inv: [u8; 256] = 
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

// RCON - Constantes de rodada:
// ??? Usadas na expansão de chave para evitar simetrias
const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// 1. Função SubBytes 
// ??? Substitui cada byte do estado (state) pelo valor correspondente na SBOX
fn sub_bytes(state: &mut [u8; 16]){ 
    for i in 0..16 { // --- Para cada posição no array de 16 bytes
        state[i] = S_Box[state[i] as usize]; // --- Substitui o byte atual pelo valor da SBOX na posição do byte
    }
}

// 1.2 Função SubBytes Inverse (DESCRIPTOGRAFAR)
fn inv_sub_bytes(state: &mut [u8; 16]) {
    for i in 0..16 {
        state[i] = S_Box_Inv[state[i] as usize]; 
    }
}

// 2. Função ShiftRows 
// ??? Desloca cada linha da matriz para a esquerda
fn shift_rows(state: &mut[u8; 16]){
    let mut temp = [0u8; 16];
    temp.copy_from_slice(state);
    
    // Coluna 1
    // --- Desloca 1 posição para a esquerda
    state[1] = temp[5];
    state[5] = temp[9];
    state[9] = temp[13];
    state[13] = temp[1];

    // Coluna 2
    // --- Desloca 2 posições para a esquerda
    state[2] = state[10];
    state[6] = state[14];
    state[10] = temp[2];
    state[14] = temp[6];

    // Coluna 3
    // --- Desloca 3 posições para a esquerda
    state[3] = temp[15];
    state[7] = temp[3];
    state[11] = temp[7];
    state[15] = temp[11];
}

// 2.2 Função ShiftRows Inverse (DESCRIPTOGRAFAR)
// --- Desloca para a direita
fn inv_shift_rows(state: &mut [u8; 16]){
    let mut temp = [0u8; 16];
    temp.copy_from_slice(state);

    // --- Desloca 1 posição para a direita
    state[1] = temp[13];
    state[5] = temp[1];
    state[9] = temp[5];
    state[13] = temp[9];

    // --- Desloca 2 posições para a direita
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];

    // --- Desloca 3 posições para a direita
    state[3] = temp[7];
    state[7] = temp[11];
    state[11] = temp[15];
    state[15] = temp[3];
}

// 3.0 Função Multiplicação no Campo de Galois
// ??? Misturar os bytes dentro de cada coluna usando aritmética GF(2^8) 
// ??? XOR - Ou Exclusivo (0x0 = 0, 1x1 = 1, 1x0 = 1, 0x1 = 1)
fn galois_mult(a:u8, b:u8) -> u8{
    let mut result = 0; // --- Resultado
    // --- Cópias dos valores originais para modificação 
    let mut a_val = a; 
    let mut b_val = b;

    // --- Algoritmo de multiplicação no campo de Galois
    for _ in 0..8{
        // --- Verifica o último bit de b_val é 1 ou 0
        if b_val & 1 != 0 {
            result ^= a_val; // --- XOR se o bit menos significativo for 1
        }

        let carry = a_val & 0x80; // --- Verifica se vai haver carry

        a_val <<= 1; // --- Desloca para esquerda (multiplica por 2 no mundo binário)

        if carry != 0{ // --- Se for = 0, não possui carry (o número cabe nos 8 bits)
            a_val ^= 0x1B; // --- Se for != 0, XOR com polinômio redutor, houve carry (o número ultrapassou)
        }

        b_val >>= 1; // --- Desloca b para a direita (dividi por 2, descarta o ultimo bit, aguarda prox iteração)
    }
    result // --- Valor retornado
} 

// 3.1 Função MixColumns
// ??? Multiplica cada coluna por uma matriz fixa
fn mix_columns(state: &mut [u8; 16]){
    // --- Para cada coluna 0 a 3
    for col in 0..4 {
        let idx = col * 4;
        // --- Indíces dos bytes na coluna
        let s0 = state[idx];
        let s1 = state[idx + 1];
        let s2 = state[idx + 2];
        let s3 = state[idx + 3];

        // --- Aplica a transformação matricial no campo GF(2^8)
        state[idx] = galois_mult(0x02, s0) ^ galois_mult(0x03, s1) ^ s2 ^ s3;

        state[idx + 1] = s0 ^ galois_mult(0x02, s1) ^ galois_mult(0x03, s2) ^ s3;

        state[idx + 2] = s0 ^ s1 ^ galois_mult(0x02, s2) ^ galois_mult(0x03, s3);

        state[idx + 3] = galois_mult(0x03, s0) ^ s1 ^ s2 ^ galois_mult(0x02, s3);
    }
}

// 3.2 Função MixColumns Inverse (DESCRIPTOGRAFAR)
fn inv_mix_columns(state: &mut [u8; 16]){
    for col in 0..4 {
        let idx = col * 4;

        let s0 = state[idx];
        let s1 = state[idx + 1];
        let s2 = state[idx + 2];
        let s3 = state[idx + 3];

        state[idx] = galois_mult(0x0E, s0) ^ galois_mult(0x0B, s1) ^ 
                    galois_mult(0x0D, s2) ^ galois_mult(0x09, s3);

        state[idx + 1] = galois_mult(0x09, s0) ^ galois_mult(0x0E, s1) ^
                        galois_mult(0x0B, s2) ^ galois_mult(0x0D, s3);

        state[idx + 2] = galois_mult(0x0D, s0) ^ galois_mult(0x09, s1) ^ 
                        galois_mult(0x0E, s2) ^ galois_mult(0x0B, s3);

        state[idx + 3] = galois_mult(0x0B, s0) ^ galois_mult(0x0D, s1) ^ 
                        galois_mult(0x09, s2) ^ galois_mult(0x0E, s3);
    }
}

// 4. Função AddRoundKey
// ??? Aplica XOR entre o estado e a chave da rodada
fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]){
    // --- Para cada byte do estado (16 bytes)
    for i in 0..16 {
        // --- XOR bit a bit com o byte correspondente da chave
        state[i] ^= round_key[i];
    }
}

// 5. Expansão da Chave
// ??? Gera as 15 chaves das rodadas (AES-256) - 60 palavras de 4 bytes
fn key_expansion(key: &[u8; 32]) -> [[u8; 16]; 15]{
    // --- Vetor para armazenar todas as palavras
    let mut palavras: [[u8; 4]; 60] = [[0; 4]; 60];

    // --- Copia a chave original para as primeiras 8 palavras
    for i in 0..8 {
        palavras[i][0] = key[4 * i];
        palavras[i][1] = key[4 * i + 1];
        palavras[i][2] = key[4 * i + 2];
        palavras[i][3] = key[4 * i + 3];
    }

    // --- Gera as palavras restantes (8 até 59)
    for i in 8..60 {
        let mut temp = palavras[i - 1]; // --- Palavra anterior
        
        // --- A cada 8 palavras, aplica a função de rotação e SBOX
        if i % 8 == 0{
            // --- RotWord: rotação circular de 1 byte para esquerda
            temp = [temp[1], temp[2], temp[3], temp[0]];
            // --- SubWord: aplica SBOX em cada byte
            for j in 0..4 {
                temp[j] = S_Box[temp[j] as usize];
            }
            // --- XOR com a constante RCON
            temp[0] ^= RCON[i / 8];
        }

        // --- Para AES-256, a cada 8 palavras também aplica SubWord
        else if i % 8 == 4 {
            for j in 0..4 {
                temp[j] = S_Box[temp[j] as usize];
            }
        }

        // --- Gera a nova palavra: XOR com a palavra 8 posições atrás
        for j in 0..4 {
            palavras[i][j] = palavras[i - 8][j] ^ temp[j];
        }
    }

    // --- Converte as palavras em chaves de rodada (cada rodada usa 4 palavras = 16 bytes)
    let mut round_keys: [[u8; 16]; 15] = [[0; 16]; 15];

    for round in 0..15 {
        for j in 0..4 {
            let palavra_idx = round * 4 + j;
            round_keys[round][j * 4] = palavras[palavra_idx][0];
            round_keys[round][j * 4 + 1] = palavras[palavra_idx][1];
            round_keys[round][j * 4 + 2] = palavras[palavra_idx][2];
            round_keys[round][j * 4 + 3] = palavras[palavra_idx][3];
        }
    }
    round_keys
}

// === PBKDF2 ===
// ??? Transforma senha simples em chave forte
fn pbkdf2(pass: &str, salt: &[u8; 16], iter: u32) -> [u8; 32]{
    let mut result = [0u8; 32]; // Armazena resultado final

    let pass_bytes = pass.as_bytes(); // Converte string em bytes
    let mut salt_concat = salt.to_vec(); // Cria um vetor mutável
    salt_concat.extend_from_slice(&1u32.to_be_bytes()); // Concatena o salt com o número do bloco

    // --- Inicializa o motor HMAC usando SHA-256, utilizando a senha como a chave secreta
    let mut mac = HmacSha256::new_from_slice(pass_bytes).unwrap();
    // ---Passa para o HMAC o salt ja concatenado
    mac.update(&salt_concat);
    // --- Finaliza o cálculo e armazena o primeiro hash resultante (U1)
    let mut u = mac.finalize().into_bytes();
    result.copy_from_slice(&u); // Copia o valor

    for _ in 1..iter { // Roda até o número de iteração
        // --- Reinicia o HMAC com a senha para a nova rodada.
        let mut mac = HmacSha256::new_from_slice(pass_bytes).unwrap();
        mac.update(&u); 
        u = mac.finalize().into_bytes(); // Calcula o novo hash e sobrescreve u
        for j in 0..32 {
            result[j] ^= u[j]; // Operação XOR
        }
    }
    result 
}

// === CRIPTOGRAFAR ===
// Modo de operação CBC (Cipher Black Chaining)
// ??? Cada bloco de texto simples passa por uma operação XOR com o bloco cifrado anterior antes de ser criptografado
fn cifrar(caminho: &str){
    print!("Digite a senha: "); // Solicitação de senha
    io::stdout().flush().unwrap();

    let mut senha = String::new(); // Salva senha
    io::stdin().read_line(&mut senha).unwrap();

    let salt = [0xAFu8; 16]; // Valor fixo para salt (PBKDF2)
    let iv = [0x12u8; 16]; // Valor fixo IV (CBC)

    // Gera chave de 256 bits a partir da senha
    let chave = pbkdf2(senha.trim(), &salt, 100_000);
    let rkeys = key_expansion(&chave); // Expansão da chave

    let mut f_in = File::open(caminho).unwrap(); // Abre o arquivo "mensagem.txt"
    let mut f_out = File::create(format!("{}.cifrado", caminho)).unwrap(); // Novo arquivo criptografado
    
    // Escreva o Salt e o IV no ínicio do arquivo (quais valores serão usados?)
    f_out.write_all(&salt).unwrap();
    f_out.write_all(&iv).unwrap();

    let mut buffer = [0u8; 16]; // Bloco de 16 bytes
    let mut iv_corr = iv; // Atualizado a cada bloco

    // Lê o arquivo em pedaços de 16 bytes
    while let Ok(n) = f_in.read(&mut buffer){
        if n == 0 { 
            break;
        }

        for i in 0..16 {
            buffer[i] ^= iv_corr[i]; // Realiza o XOR
        }

        // Processo de Criptografia
        add_round_key(&mut buffer, &rkeys[0]);

        // 13 Rodadas
        for i in 1..14{
            sub_bytes(&mut buffer);
            shift_rows(&mut buffer);
            mix_columns(&mut buffer);
            add_round_key(&mut buffer, &rkeys[i]);
        }

        // Rodada Final (14)
        sub_bytes(&mut buffer);
        shift_rows(&mut buffer);
        add_round_key(&mut buffer, &rkeys[14]);
        
        iv_corr = buffer; // Salva resultado para ser usado no prox bloco
        f_out.write_all(&buffer).unwrap(); // Grava os 16 byres cifrados do arq de saída
    }
    println!("Cifrado com sucesso!");
}

fn decifrar(caminho: &str){
    print!("Senha: "); // Solicita a senha para o usuário
    io::stdout().flush().unwrap();

    let mut senha = String::new(); // Salva senha
    io::stdin().read_line(&mut senha).unwrap();

    let mut f_in = File::open(caminho).unwrap(); // Abre arquivo passado

    let mut salt = [0u8; 16]; // Valor fixo para salt (PBKDF2)
    let mut iv = [0u8; 16]; // Valor fixo IV (CBC)

    // Lê os primeiros 16 bytes do arquivo para o Salt e os próximo 16 bytes para o IV
    // (Para gerar a mesma chave)
    f_in.read_exact(&mut salt).unwrap(); 
    f_in.read_exact(&mut iv).unwrap();

    // Gera chave de 256 bits a partir da senha
    let chave = pbkdf2(senha.trim(), &salt, 100_000);
    let rkeys = key_expansion(&chave); // Gera as mesmas 15 subchaves

    // Cria o arquivo de saída
    let mut f_out = File::create(caminho.replace(".cifrado", ".decifrado")).unwrap();

    let mut buffer = [0u8; 16];
    let mut iv_corr = iv;
    
    // Lê o arquivo em pedaços de 16 bytes
    while let Ok(n) = f_in.read(&mut buffer){
        if n == 0{
            break;
        }
        let next_iv = buffer; // Será utilizado para o próximo bloco

        // Começa de trás pra frente (aplica rodada 14)
        add_round_key(&mut buffer, &rkeys[14]);

        // Descriptogração 
        // Rodada 13 até 1
        for i in (1..14).rev(){
            inv_sub_bytes(&mut buffer);
            inv_shift_rows(&mut buffer);
            add_round_key(&mut buffer, &rkeys[i]);
            inv_mix_columns(&mut buffer);
        }

        // Rodada Final
        inv_sub_bytes(&mut buffer);
        inv_shift_rows(&mut buffer);
        add_round_key(&mut buffer, &rkeys[0]);

        for i in 0..16{
            buffer[i] ^= iv_corr[i]; // XOR
        }
        iv_corr = next_iv; // Para o próx bloco

        f_out.write_all(&buffer).unwrap(); // Grava os 16 bytes recuperados
    }
    println!("Decifrado!");
}

fn testar(){
    let chave = [0u8; 32]; // Define uma chave nula de 256bits 
    let mut bloco = [0u8; 16]; // Define um texto nulo de 16 bytes

    // Bloco resultante de zeros
    let esperado = [
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 
        0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87 
    ];

    let rkeys = key_expansion(&chave); // Expande a chave

    add_round_key(&mut bloco, &rkeys[0]); // Aplica XOR inicial

    // Ciptografar

    // 13 Rodadas
    for i in 1..14{
        sub_bytes(&mut bloco);
        shift_rows(&mut bloco);
        mix_columns(&mut bloco);
        add_round_key(&mut bloco, &rkeys[i]);
    }

    // Rodada final 14
    sub_bytes(&mut bloco);
    shift_rows(&mut bloco);
    add_round_key(&mut bloco, &rkeys[14]);

    println!("Resultado obtido: {:02x?}", bloco); // Exibe o resultado da função

    // Verifica se a implementação deu certo
    if bloco == esperado{
        println!("Esperado: {:02x?}", esperado);
        println!("STATUS: SUCESSO.");
    } else {
        println!("STATUS: FALHA");
        println!("Esperado: {:02x?}", esperado);
    }
}

// === MAIN ===
fn main(){
    let args: Vec<String> = env::args().collect(); // Captura de argumentos

    match args[1].as_str(){
        "cifrar" => cifrar(&args[2]), // cargo run cifrar mensagem.txt
        "decifrar" => decifrar(&args[2]), // cargo run decifrar mensagem.txt.cifrado
        "testar" => testar(), // cargo run testar
        _ => (),
    }
}
