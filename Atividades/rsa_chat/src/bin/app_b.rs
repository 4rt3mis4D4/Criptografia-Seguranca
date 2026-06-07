// Aplicação B
// Conecta em: 127.0.0.1:8080

#[path ="../rsa.rs"]
mod rsa;

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::thread;

fn main() {
    println!("=== APLICAÇÃO B — Chat RSA Seguro ===\n");

    // Geração de par de chaves RSA de B
    let (my_key_pub, my_key_priv) = rsa::gerar_chave(71, 73, 13);
    println!("[B] Par de chaves RSA gerado.");
    println!("[B] Chave pública: (n={}, e={})", my_key_pub.n, my_key_pub.e);

    // Conecta à aplicação A
    let mut stream = TcpStream::connect("127.0.0.1:8080")
        .expect("[B] Falha ao conectar com A em 127.0.0.1:8080. Certifique-se de que A está rodando.");
    println!("[B] Conectado à Aplicação A!\n");

    // Troca de chave públicas
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut linha_recebida = String::new();
    reader
        .read_line(&mut linha_recebida)
        .expect("[B] Falha ao receber chave pública de A");

    let partes: Vec<u128> = linha_recebida
        .trim_end_matches(|c| c == '\r' || c == '\n')
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().parse().expect("[B] Formato de chave inválido."))
        .collect();

    let key_pub_a = rsa::ChavePublica {
        n: partes[0],
        e: partes[1],
    };
    println!("[B] Chave pública de A recebida: (n={}, e={}).", key_pub_a.n, key_pub_a.e);

    let linha_chave = format!("{},{}\n", my_key_pub.n, my_key_pub.e);
    stream
        .write_all(linha_chave.as_bytes())
        .expect("[B] Falha ao enviar chave pública para A.");
    stream.flush().expect("[B] Falha ao fazer flush da chave.");

    println!("Chat Iniciado! Digite suas mensagens abaixo.");
    println!("Ctrl+C para encerrar.");

    // Thread de recepção
    let stream_leitura = stream.try_clone().unwrap();
    thread::spawn(move || {
        let mut leitor = BufReader::new(stream_leitura);
        loop {
             let mut linha = String::new();
             match  leitor.read_line(&mut linha) {
                Ok(0) => {
                    println!("\n[Sistema] A encerrou a conexão.");
                    break;
                }
                Ok(_) => {
                    let decifrada: String = linha
                    .trim()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        let c = s.parse::<u128>().unwrap_or(0);
                        rsa::decifrar(c, &my_key_priv) as u8 as char
                    })
                    .collect();
                println!("[A] >>> {}", decifrada);
                }
                 Err(e) => {
                    eprintln!("[B] Erro ao receber mensagem: {}", e);
                    break;
                 }
             }
        }
    });

    // Loop principal de envio
    let stdin = io::stdin();
    for linha_resultado in stdin.lock().lines() {
        let mensagem = match linha_resultado {
            Ok(l) => l,
            Err(_) => break,
        };

        if mensagem.trim().is_empty() {
            continue;
        }

        let cifrada: String = mensagem
            .chars()
            .map(|ch| format!("{},", rsa::cifrar(ch as u128, &key_pub_a)))
            .collect();

        let pacote = format!("{}\n", cifrada);
        if let Err(e) = stream.write_all(pacote.as_bytes()) {
            eprintln!("[B] Falha ao enviar mensagem: {}", e);
            break;
        }
        stream.flush().ok();

        println!("[B] <<< {} (enviado cifrado)", mensagem);
    }

    println!("[B] Encerrando.");
}
