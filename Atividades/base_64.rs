/* 
    === Base64 ===
    Algoritmo de codificar que converte dados binários em uma representação textual usando
    um conjunto limitado de caracteres (A-Z, a-z, 0-9, + e /).
*/

// Bibliotecas
use std::io;

// 1. Declarar contante do conjunto de 64 caracteres para representar dados
const BASE64_CHARS : &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// 2. Dividir os dados de entrada em blocos de 3 Bytes
fn dividir_dados (entrada: &str) -> Vec<Vec<String>> {
    entrada.as_bytes() // --- Obtém os bytes da String
        .chunks(3) // --- Divide em blocos de 3 bytes
        .map(|bloco|{
            bloco.iter()
                .map(|byte| format!("{:08b}", byte)) // --- Converte em binário
                .collect()
        })
        .collect()
}

// 3. Quebrar em grupos de 6 bits
fn quebrar_grupos (bloco_3b: &Vec<String>) -> Vec<String> {
    // --- Concatenação
    let mut sequencia = bloco_3b.concat();

    // 5. Lidar com Padding (=)
    while sequencia.len() % 6 != 0 {
        sequencia.push('0');
    }

    // --- Quebra o bloco concatenado em grupos de 6 bits
    sequencia.as_bytes()
        .chunks(6)
        .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
        .collect()
}

// 4. Mapear para Caracteres da Base64
fn mapeamento_base64 (binario_6b: &Vec<String>, quant_bytes: usize) -> String {
    let mut resultado = String::new(); // Armazena resultado do mapeamento
    let caracter_base64: Vec<char> = BASE64_CHARS.chars().collect(); // Converte a String em um vetor de caracteres

    for bin in binario_6b {
        // --- Converte binário para decimal
        let decimal = u8::from_str_radix(bin, 2).expect("Falha ao converter para decimal...");

        // --- Mapeia para seu respectivo caractere da Base64
        resultado.push(caracter_base64[decimal as usize]);
    }

    // 5. Aplica Padding (=) de acordo com a quantidade de bytes 
    match quant_bytes {
        1 => resultado.push_str("=="),
        2 => resultado.push_str("="),
        _ => {}
    }
    
    resultado 
}

fn codificar (entrada: &str) -> String {
    let blocos_3b = dividir_dados(entrada); // (2) Dividir os dados de entrada em blocos de 3 Bytes

    let mut resultado = String::new();

    for (i, bloco_3b) in blocos_3b.iter().enumerate(){
        let grupos_6b = quebrar_grupos(bloco_3b); // (3) Quebrar em Grupos de 6 Bits + (5) Lidar com Padding
        let codificado = mapeamento_base64(&grupos_6b, bloco_3b.len()); // (4) Mapear para Caracteres Base64 + (5) Lidar com Padding

        resultado.push_str(&codificado);
    }

    resultado
}

// 6. Decodificar
fn decodificar (entrada_codificada: &str) -> String{
    // 3. Remover os bits extras adicionados para alinhamento.
    let entrada_sem_padding = entrada_codificada.trim_matches('=');

    // 1. Substituir os caracteres Base64 pelos seus valores de 6 bits.
    let mut bits_concatenados = String::new();
    for c in entrada_sem_padding.chars() {
        if let Some(pos) = BASE64_CHARS.find(c) {
            bits_concatenados.push_str(&format!("{:06b}", pos));
        }
    }

    // 2. Juntar os bits em blocos de 8 para formar os bytes originais.
    let bytes: Vec<u8> = bits_concatenados
        .as_bytes()
        .chunks(8)
        .filter(|chunk| chunk.len() == 8)
        .map(|chunk| {
            let string_temp = String::from_utf8(chunk.to_vec()).unwrap();
            u8::from_str_radix(&string_temp, 2).expect("Falha ao converter para binário")
        })
        .collect();
    
    String::from_utf8(bytes).expect("Falha ao converter para string")
}

fn main(){
    println!("Digite o texto para codificar: ");
    let mut texto = String::new();
    io::stdin().read_line(&mut texto).expect("Falha ao ler e salvar texto...");
    let texto_limpo = texto.trim();

    println!("\n=== INICIANDO BASE64 ===");
    println!("Texto: {}", texto_limpo);

    let resultado_codificado = codificar(texto_limpo);
    println!("Codificado: {}", resultado_codificado);

    let resultado_decodificado = decodificar(&resultado_codificado);
    println!("Decodificado: {}", resultado_decodificado);

    println!("\nFim do Programa...");
    /*
    let texto = "Ma";
    let blocos_3b = dividir_dados(texto);

    for (i, bloco_3b) in blocos_3b.iter().enumerate(){
        let grupos_6b = quebrar_grupos(bloco_3b);
        let codificado = mapeamento_base64(&grupos_6b, bloco_3b.len());

        println!("Bloco {}: {:?}", i+1, bloco_3b);
        println!("Grupos de 6bits: {:?}", grupos_6b);
        println!("Codificado Base64: {}", codificado);
    }
    */
}
