# 🔐 Sistema de Criptografia em Rust

Este diretório implementa um fluxo completo de criptografia segura utilizando três pilares fundamentais: **PBKDF2**, **AES-256** e **modo CBC**. Juntos, eles transformam uma senha simples em uma proteção robusta.

---

## 🧩 Componentes

### 🔑 PBKDF2 (Derivação de Chave)
Transforma senhas fracas em **chaves criptográficas fortes**.

- Usa **Salt aleatório**
- Executa **100.000 iterações (HMAC-SHA256)**
- Gera uma **chave de 256 bits**
- Protege contra **força bruta** e *rainbow tables*

---

### 🔒 AES-256 (Criptografia)
Responsável por cifrar os dados.

- Criptografia simétrica por blocos
- **14 rodadas internas**
- Etapas principais:
  - AddRoundKey (XOR)
  - SubBytes (S-BOX)
  - ShiftRows (transposição)
  - MixColumns (Galois)

---

### 🔗 Modo CBC (Encadeamento)
Evita padrões na criptografia.

- Usa **IV aleatório (16 bytes)**
- Aplica **XOR antes da cifragem**
- Encadeia blocos cifrados
- Suporte a **padding (preenchimento)**

---

## ⚙️ Fluxo de Execução

```text
Senha → PBKDF2 → Chave 256 bits
       ↓
     IV (CBC)
       ↓
     AES-256
       ↓
Arquivo Final = Salt + IV + Dados Cifrados
```

---
# Constantes AES - S-Box e RCON

## S_BOX

**Declaração:**
```rust
const S_BOX: [u8; 256] = [0x63, 0x7c, /* ... */, 0x16];
```

**Funcionalidade:**
- Tabela de substituição utilizada na função `SubBytes` do algoritmo AES.
- Cada byte do estado é substituído por seu correspondente nesta tabela.
- Projetada para ser não-linear e resistente a ataques de criptoanálise, eliminando padrões estatísticos nos dados.

---

## RCON

**Declaração:**
```rust
const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
```

**Funcionalidade:**
- Constantes de rodada utilizadas no processo de expansão de chave do AES. 
- Evitam simetria entre as rodadas, garantindo que cada rodada da chave expandida seja única e aumentando a segurança contra ataques relacionados à chave.

---

## S_BOX_INV

**Declaração:**
```rust
const S_BOX_INV: [u8; 256] = [0x52, 0x09, /* ... */, 0x7d];
```

**Funcionalidade:**
- Tabela inversa da S_BOX, utilizada na função `InvSubBytes` durante o processo de decifração do AES. 
- Reconstrói o estado original revertendo a substituição não-linear aplicada na cifragem.

---

# Funções AES-256: Cifragem


## 🔐 Função `sub_bytes` 

### 📌 Código

```rust
fn sub_bytes(estado: &mut [u8; 16]){
    for i in 0..16 { 
        estado[i] = S_BOX[estado[i] as usize];
    }
}
````

## 🧠 Explicação

* **`estado: &mut [u8; 16]`** → array de 16 bytes que pode ser modificado diretamente.
* **`for i in 0..16`** → percorre todos os 16 bytes.
* **`estado[i] as usize`** → usa o valor do byte como índice.
* **`S_BOX[...]`** → busca o valor correspondente na tabela.
* **Atribuição** → substitui o byte original pelo valor da S-Box.

---
## 🔐 Função `shift_rows` 

### 📌 Código

```rust
fn shift_rows(estado: &mut[u8; 16]){
    let mut temp = [0u8; 16];
    temp.copy_from_slice(estado);

    estado[1] = temp[5];
    estado[5] = temp[9];
    estado[9] = temp[13];
    estado[13] = temp[1];

    estado[2] = temp[10];
    estado[6] = temp[14];
    estado[10] = temp[2];
    estado[14] = temp[6];

    estado[3] = temp[15];
    estado[7] = temp[3];
    estado[11] = temp[7];
    estado[15] = temp[11];
}
````

## 🧠 Explicação

* **`estado: &mut [u8; 16]`** → array de 16 bytes que será modificado.
* **`temp.copy_from_slice`** → cria uma cópia do estado original.
* **Primeiro bloco** → desloca a 2ª linha 1 posição à esquerda.
* **Segundo bloco** → desloca a 3ª linha 2 posições à esquerda.
* **Terceiro bloco** → desloca a 4ª linha 3 posições à esquerda.

---

## 🔐 Função `campo_galois` 

### 📌 Código

```rust
fn campo_galois(num1: u8, num2: u8) -> u8 {
    let mut resultado = 0;

    let mut copia_num1 = num1;
    let mut copia_num2 = num2;

    for _ in 0..8{
        if (copia_num2 & 1) != 0 {
            resultado ^= copia_num1;
        } 

        let carry: u8 = copia_num1 & 0x80;

        copia_num1 <<= 1;

        if carry != 0 {
            copia_num1 ^= 0x1B;
        }

        copia_num2 >>= 1;
    }

    resultado
}
````

## 🧠 Explicação

* **Parâmetros (`num1`, `num2`)** → bytes a serem multiplicados.
* **Loop `0..8`** → percorre os bits do segundo número.
* **`& 1`** → verifica o bit menos significativo.
* **`resultado ^= copia_num1`** → aplica XOR quando necessário.
* **`carry`** → verifica overflow (bit mais alto).
* **`<<= 1`** → desloca bits à esquerda (multiplicação).
* **`^= 0x1B`** → redução no campo GF(2^8).
* **Retorno** → resultado da multiplicação no campo de Galois.

---

## 🔐 Função `mix_columns` 

### 📌 Código

```rust
fn mix_columns(estado: &mut[u8; 16]){
    for coluna in 0..4 {
        let i = coluna * 4;

        let s0 = estado[i];
        let s1 = estado[i + 1];
        let s2 = estado [i + 2];
        let s3 = estado [i + 3];

        estado[i] = campo_galois(0x02, s0) ^ campo_galois(0x03, s1) ^ s2 ^ s3;

        estado[i + 1] = s0 ^ campo_galois(0x02, s1) ^ campo_galois(0x03, s2) ^ s3;

        estado[i + 2] = s0 ^ s1 ^ campo_galois(0x02, s2) ^ campo_galois(0x03, s3);

        estado[i + 3] = campo_galois(0x03, s0) ^ s1 ^ s2 ^ campo_galois(0x02, s3);
    }
}
````

## 🧠 Explicação

* **Loop `0..4`** → percorre as 4 colunas.
* **`i = coluna * 4`** → calcula início da coluna.
* **`s0..s3`** → extrai bytes da coluna.
* **`campo_galois`** → realiza multiplicações no GF(2^8).
* **XOR (`^`)** → combina os resultados.
* **Atribuição** → substitui a coluna por uma versão misturada.

---

## 🔐 Função `add_round_key` 

### 📌 Código

```rust
fn add_round_key(estado: &mut [u8;16], round_key: &[u8;16]) {
    for i in 0..16 {
        estado[i] ^= round_key[i];
    }
}
````

## 🧠 Explicação

* **`estado`** → dados a serem modificados.
* **`round_key`** → chave da rodada.
* **Loop `0..16`** → percorre todos os bytes.
* **`^=` (XOR)** → combina estado com a chave.
* **Resultado** → mistura dos dados com a chave.

---

## 🔐 Função `key_expansion` 

### 📌 Código

```rust
fn key_expansion(chave: &[u8;32]) -> [[u8; 16]; 15]{
    let mut palavras: [[u8; 4]; 60] = [[0; 4]; 60];

    for i in 0..8 {
        palavras[i][0] = chave[4 * i];
        palavras[i][1] = chave[4 * i + 1];
        palavras[i][2] = chave[4 * i + 2];
        palavras[i][3] = chave[4 * i + 3];
    }

    for i in 8..60 {
        let mut temp = palavras[i - 1];

        if i % 8 == 0 {
            temp = [temp[1], temp[2], temp[3], temp[0]];

            for j in 0..4 {
                temp[j] = S_BOX[temp[j] as usize];
            }

            temp[0] ^= RCON[i / 8];
        }

        else if i % 8 == 4 {
            for j in 0..4 {
                temp[j] = S_BOX[temp[j] as usize];
            }
        }

        for j in 0..4 {
            palavras[i][j] = palavras[i - 8][j] ^ temp[j];
        }
    }

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
````

## 🧠 Explicação

* **`chave: &[u8;32]`** → chave inicial de 256 bits.
* **`palavras[60]`** → armazena palavras de 4 bytes.
* **Primeiro loop** → copia chave original.
* **Segundo loop** → gera novas palavras.
* **`i % 8 == 0`** → aplica rotação + S-Box + RCON.
* **`i % 8 == 4`** → aplica apenas S-Box.
* **XOR** → combina palavras anteriores.
* **Conversão final** → agrupa em 15 round keys de 16 bytes.
* **Retorno** → todas as chaves das rodadas.

---

# Funções AES-256: Decifragem

## 🔐 Função `inv_sub_bytes` 

### 📌 Código

```rust
fn inv_sub_bytes(estado: &mut [u8; 16]) {
    for i in 0..16 {
        estado[i] = S_BOX_INV[estado[i] as usize];
    }
}
````

## 🧠 Explicação

* **`estado: &mut [u8; 16]`** → array de 16 bytes que será modificado.
* **`for i in 0..16`** → percorre todos os bytes.
* **`estado[i] as usize`** → usa o valor como índice.
* **`S_BOX_INV[...]`** → busca o valor na S-Box inversa.
* **Atribuição** → restaura o byte original.

---

## 🔐 Função `inv_shift_rows` 

### 📌 Código

```rust
fn inv_shift_rows(estado: &mut [u8; 16]) {
    let mut temp = [0u8; 16];
    temp.copy_from_slice(estado);

    estado[1] = temp[13];
    estado[5] = temp[1];
    estado[9] = temp[5];
    estado[13] = temp[9];

    estado[2] = temp[10];
    estado[6] = temp[14];
    estado[10] = temp[2];
    estado[14] = temp[6];

    estado[3] = temp[7];
    estado[7] = temp[11];
    estado[11] = temp[15];
    estado[15] = temp[3];
}
````

## 🧠 Explicação

* **`estado: &mut [u8; 16]`** → array que será alterado.
* **`temp.copy_from_slice`** → cópia do estado original.
* **Primeiro bloco** → desloca a 2ª linha 1 posição à direita.
* **Segundo bloco** → desloca a 3ª linha 2 posições à direita.
* **Terceiro bloco** → desloca a 4ª linha 3 posições à direita.

---

## 🔐 Função `inv_mix_columns` 

### 📌 Código

```rust
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
````

## 🧠 Explicação

* **Loop `0..4`** → percorre as colunas.
* **`i = coluna * 4`** → posição inicial da coluna.
* **`s0..s3`** → bytes da coluna.
* **`campo_galois`** → multiplicação no GF(2^8).
* **XOR (`^`)** → combina resultados.
* **Atribuição** → reverte a mistura das colunas.

---
# 🛡️ Função `cifrar` 

### 🧾 Código

```rust
fn cifrar(caminho: &str){
    println!("Digite a senha: ");
    let mut senha = String::new();
    io::stdin().read_line(&mut senha).expect("Falha ao ler senha...");
    let senha_limpa = senha.trim();

    let mut num_aleatorio = rand::rng();
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];

    num_aleatorio.fill_bytes(&mut salt);
    num_aleatorio.fill_bytes(&mut iv);

    let chave = pbkdf2(senha_limpa, &salt, 100_000);
    let round_keys = key_expansion(&chave);

    let mut arquivo_original = File::open(caminho).expect("Falha ao abrir arquivo...");
    let mut conteudo = Vec::new();
    arquivo_original.read_to_end(&mut conteudo).expect("Falha ao ler arquivo...");

    let comprimento = 16 - (conteudo.len() % 16);
    for _ in 0..comprimento {
        conteudo.push(comprimento as u8);
    }

    let mut texto_cifrado = Vec::new();
    let mut vetor_anterior = iv;

    for bloco in conteudo.chunks(16) {
        let mut estado: [u8; 16] = bloco.try_into().unwrap();

        for i in 0..16 {
            estado[i] ^= vetor_anterior[i];
        }

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

    let mut arquivo_cifrado = File::create(format!("{}.cifrado", caminho)).expect("Falha...");
    arquivo_cifrado.write_all(&salt).unwrap();
    arquivo_cifrado.write_all(&iv).unwrap();
    arquivo_cifrado.write_all(&texto_cifrado).unwrap();

    println!("Arquivo cifrado com sucesso!");
}
````

## 📘 Explicação

* **Entrada da senha** → usuário digita a senha.
* **`salt` e `iv`** → valores aleatórios para segurança.
* **`pbkdf2`** → gera uma chave forte a partir da senha.
* **Leitura do arquivo** → carrega conteúdo em memória.
* **Padding** → ajusta tamanho para múltiplos de 16 bytes.
* **CBC (`vetor_anterior`)** → encadeia os blocos com XOR.
* **Rodadas AES** → aplica SubBytes, ShiftRows, MixColumns e AddRoundKey.
* **Armazenamento** → salva `salt + iv + dados cifrados`.

---

# 🛡️ Função `pbkdf2` 

### 🧾 Código

```rust
fn pbkdf2(senha: &str, salt: &[u8; 16], iteracoes: u32) -> [u8; 32] {
    let mut chave_final = [0u8; 32];

    let bytes_senha = senha.as_bytes();
    let mut salt_concatenado = salt.to_vec();
    salt_concatenado.extend_from_slice(&1u32.to_be_bytes());

    let mut mac = HmacSha256::new_from_slice(bytes_senha).unwrap();
    mac.update(&salt_concatenado);
    let mut hash_atual_u = mac.finalize().into_bytes();
    chave_final.copy_from_slice(&hash_atual_u);

    for _ in 1..iteracoes {
        let mut mac = HmacSha256::new_from_slice(bytes_senha).unwrap();
        mac.update(&hash_atual_u);

        hash_atual_u = mac.finalize().into_bytes();
        
        for j in 0..32 {
            chave_final[j] ^= hash_atual_u[j];
        }
    }

    chave_final
}
````

## 📘 Explicação

* **`senha` + `salt`** → base para gerar chave segura.
* **HMAC-SHA256** → função criptográfica usada.
* **Primeiro hash (U1)** → inicializa a chave.
* **Loop de iterações** → reforça segurança contra ataques.
* **XOR acumulado** → combina todos os hashes.
* **Retorno** → chave final de 256 bits.

---

# 🛡️ Função `decifrar` 

### 🧾 Código

```rust
fn decifrar(caminho: &str){
    println!("Digite a senha utilizada na criptografia do arquivo: ");
    let mut senha = String::new();
    io::stdin().read_line(&mut senha).expect("Falha...");
    let senha_limpa = senha.trim();

    let mut arquivo_cifrado = File::open(caminho).expect("Falha...");
    let mut conteudo_completo = Vec::new();
    arquivo_cifrado.read_to_end(&mut conteudo_completo).expect("Falha...");

    let salt: [u8; 16] = conteudo_completo[0..16].try_into().unwrap();
    let iv: [u8; 16] = conteudo_completo[16..32].try_into().unwrap();
    let texto_cifrado = &conteudo_completo[32..];

    let chave = pbkdf2(senha_limpa, &salt, 100_000);
    let round_keys = key_expansion(&chave);

    let mut texto_limpo = Vec::new();
    let mut vetor_anterior = iv;

    for bloco in texto_cifrado.chunks(16){
        let mut estado: [u8; 16] = bloco.try_into().unwrap();
        let bloco_cifrado_atual = estado;

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

        for i in 0..16 {
            estado[i] ^= vetor_anterior[i];
        }

        texto_limpo.extend_from_slice(&estado);
        vetor_anterior = bloco_cifrado_atual;
    }

    let padding = *texto_limpo.last().unwrap() as usize;
    if padding <= 16 {
        texto_limpo.truncate(texto_limpo.len() - padding);
    }

    let mensagem = String::from_utf8_lossy(&texto_limpo);
    println!("\nConteúdo descriptografado:\n{}", mensagem);
}
````

## 📘 Explicação

* **Entrada da senha** → usuário fornece senha.
* **Extração (`salt` e `iv`)** → recupera dados iniciais.
* **`pbkdf2`** → recria a mesma chave.
* **CBC inverso** → usa bloco anterior para XOR.
* **Rodadas inversas AES** → desfaz criptografia.
* **Remoção de padding** → restaura tamanho original.
* **Saída** → exibe conteúdo descriptografado.

---

## 🛡️ Modo CBC (Cipher Block Chaining)

### 🧾 Código

```rust
estado[i] ^= vetor_anterior[i];
vetor_anterior = estado;
````

## 📘 Explicação

* **CBC** → cada bloco depende do anterior.
* **XOR inicial** → mistura com IV ou bloco anterior.
* **Encadeamento** → saída atual vira entrada do próximo.
* **Segurança** → evita padrões iguais no texto cifrado.
* **No decifrar** → usa bloco cifrado anterior para reverter.

---

# 🔄 Fluxo Completo (AES + PBKDF2 + CBC)

### 1. 🗝️ Fluxo `pbkdf2` (Geração da Chave)

Transforma uma senha simples em uma chave segura.

* **Entrada:** 🔤 Senha + 🧂 Salt + 🔄 Iterações  
* **Processo:**
    1. Usa **HMAC-SHA256** para gerar um hash inicial.
    2. Repete o processo várias vezes (ex: 100.000).
    3. Aplica **XOR (⊕)** acumulando os resultados.
* **Saída:** 🔑 Chave de 32 bytes (AES-256)

---

### 2. 🔒 Fluxo `cifrar` (Criptografia)

Transforma texto legível em dados protegidos.

* **Passo A:** 🛠️ Preparação
    * Gera 🎲 **IV** e 🧂 **Salt**
    * Aplica 🧱 **Padding** (múltiplos de 16 bytes)

* **Passo B:** 🔗 CBC (Encadeamento)
    * Cada bloco faz **XOR (⊕)** com o anterior (ou IV)

* **Passo C:** ⚙️ Rodadas AES
    1. 🔄 SubBytes
    2. 🪜 ShiftRows
    3. 🧪 MixColumns
    4. 🔑 AddRoundKey

* **Saída:**
```
[ SALT | IV | DADOS CIFRADOS ]
```

---

### 3. 🔓 Fluxo `decifrar` (Descriptografia)

Recupera o texto original.

* **Passo A:** 🔍 Leitura
    * Separa 🧂 Salt, 🎲 IV e dados

* **Passo B:** 🔑 Recriar chave
    * Usa `pbkdf2` com mesma senha

* **Passo C:** ⏪ AES Inverso + CBC
    1. InvShiftRows
    2. InvSubBytes
    3. AddRoundKey
    4. InvMixColumns
    * Depois aplica XOR com bloco anterior

* **Passo D:** 🧹 Remover Padding

* **Saída:** 📜 Texto original

---

### 🧩 Resumo Visual

```

CIFRAR:
Senha → PBKDF2 → AES + CBC → Arquivo

DECIFRAR:
Arquivo → PBKDF2 → AES inverso + CBC → Texto

```

---

### 🥪 Estrutura do Arquivo Final

* 🍞 **Salt** → gera a chave  
* 🧀 **IV** → inicia o CBC  
* 🥩 **Dados cifrados** → conteúdo protegido  

---
