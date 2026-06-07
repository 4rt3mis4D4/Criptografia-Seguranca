// Aplicação A 
// Porta: 127.0.0.1:8080

#[path ="../rsa.rs"]
mod rsa;

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;

fn main(){
    println!("=== APLICAÇÃO A — Chat RSA Seguro ===\n");

    // Geração do par de chaves
    let (my_key_pub, my_key_priv) = rsa::gerar_chave(61,53, 17);
    println!("[A] Par de chaves gerados:");
    println!("[A] Chave pública: (n={}, e={})", my_key_pub.n, my_key_pub.e);

    // Aguarda conexão de B
    let listener = TcpListener::bind("127.0.0.1:8080").expect("[A] Falha ao abrir a porta 8080.");
    println!("[A] Aguardando conexão de B na porta 8080...\n");

    let (mut stream, endereco) = listener
        .accept()
        .expect("[A] Falha ao aceitar conexão.");
    println!("[A] Conexão estabelecida com {}!\n", endereco);

    // Troca de chaves públicas
    let linha_chave = format!("{},{}\n", my_key_pub.n, my_key_pub.e);
    stream
        .write_all(linha_chave.as_bytes())
        .expect("[A] Falha ao enviar chave pública.");
    stream.flush().expect("[A] Falha ao fazer flush da chave.");
    println!("[A] Chave pública enviada para B.");

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut linha_recebida = String::new();
    reader
        .read_line(&mut linha_recebida)
        .expect("[A] Falha ao receber chave pública de B.");

    let partes: Vec<u128> = linha_recebida
        .trim_end_matches(|c| c == '\r' || c == '\n')
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().parse().expect("[A] Formato de chave inválido"))
        .collect();

    let key_pub_b = rsa::ChavePublica {
        n: partes[0],
        e: partes[1],
    };
    println!("[A] Chave pública de B recebida: (n={}, e={}).", key_pub_b.n, key_pub_b.e);
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
                    println!("\n[Sistema] B encerrou a conexão.");
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
                    println!("[B] >>> {}", decifrada);
                }
                Err(e) => {
                    eprintln!("[A] Erro ao receber mensagem: {}", e);
                    break;
                }
            }
        }
    });

    // Loop de envio
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
            .map(|ch| format!("{},", rsa::cifrar(ch as u128, &key_pub_b)))
            .collect();

        let pacote = format!("{}\n", cifrada);
        if let Err(e) = stream.write_all(pacote.as_bytes()) {
            eprintln!("[A] Falha ao enviar mensagem: {}", e);
            break;
        }
        stream.flush().ok();
        
        println!("[A] <<< {} (enviado cifrado)", mensagem);
    }

    println!("[A] Encerrando.")
}
