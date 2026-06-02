// Implementação Algoritmo RSA - Gabriela Pedroso

// ESTRUTURA DAS CHAVES
// -- Chave Pública (n,e): CIFRAR mensagens ou verificar assinaturas
pub struct ChavePublica {
    pub n: u128,
    pub e: u128,
}
// -- Chave Privada (n,d): DECIFRAR mensagens ou criar assinaturas
pub struct ChavePrivada {
    pub n: u128,
    pub d: u128,
}

// FUNÇÕES AUXILIARES
// -- Algoritmo de Euclides para encontrar o MDC
fn mdc(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let temp = b;
        b = a % b;
        a = temp;
    }
    a
}
// -- Exponenciação Modular Rápida
fn exp_modular(mut base: u128, mut exp: u128, n: u128) -> u128 {
    let mut res = 1;
    base %= n;
    while exp > 0 {
        if exp % 2 == 1 {
            res = (res * base) % n;
        }
        base = (base * base) % n;
        exp /= 2;
    }
    res
}
// Inverso Modular usando Euclides Estendido para encontrar "d"
fn inverso_modular(e: u128, phi: u128) -> Option<u128> {
    let (mut a, mut b) = (e as i128, phi as i128);
    let (mut x0, mut x1) = (0,1);
    let m = b;
    if b == 1 {
        return None;
    }
    while a > 1 {
        let q = a / b;
        let mut t = b;
        b = a % b;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if x1 < 0 {
        x1 += m;
    }
    Some(x1 as u128)
}

// GERAÇÃO DAS CHAVES
pub fn gerar_chave (p: u128, q: u128, e: u128) -> (ChavePublica, ChavePrivada){
    // 2. Calcular n = p x q
    let n = p * q;

    // 3. Calcular φ(n) = (p−1)(q−1)
    let phi = (p - 1) * (q - 1);

    // 4. 1 < e < φ(n) e gcd(e, φ(n)) = 1
    assert_eq!(mdc(e, phi), 1, "O expoente não atende: 1 < e < φ(n) e gcd(e, φ(n)) = 1");

    // 5. Calcular o expoente privado d: d x e ≡ 1 (mod φ(n))
    let d = inverso_modular(e, phi).expect("Erro ao calcular inverso modular");

    (ChavePublica { n, e }, ChavePrivada { n, d})
}

// CIFRAGEM: C = M^e mod n 
fn cifrar(mensagem: u128, pub_key: &ChavePublica) -> u128 {
    assert!(mensagem < pub_key.n, "Mensagem deve ser menor que 'n'");
    exp_modular(mensagem, pub_key.e, pub_key.n)
}

// DECIFRAR: M = C^d mod n
fn decifrar(cifrado: u128, priv_key: &ChavePrivada) -> u128 {
    exp_modular(cifrado, priv_key.d, priv_key.n)
}

// MAIN
fn main() {
    let p = 11; 
    let q = 17;
    let e = 7;
    let m = 88;

    let (pub_key, priv_key) = gerar_chave(p, q, e);

    println!("Chave Pública: (n = {}, e = {})", pub_key.n, pub_key.e);
    println!("Chave Privada: (n = {}, e = {})", priv_key.n, priv_key.d);

    let c = cifrar(m, &pub_key);
    println!("Mensagem Cifrada: {}", c);

    let m = decifrar(c, &priv_key);
    println!("Mensagem Decifrada: {}", m);
}
