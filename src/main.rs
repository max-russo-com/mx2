use std::io::{self, Write};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use rand::seq::SliceRandom;
use sha2::{Sha256, Digest};
use serde_json::json;

type Result<T> = std::result::Result<T, String>;

// ====== Derivazione chiave Argon2id (come nella MAX App) ======

fn a2_key_from_passcodes(p1: &str, p2: &str, salt: &[u8]) -> [u8; 32] {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).expect("argon2 params");
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut pwd = Vec::with_capacity(p1.len() + p2.len() + 8);
    pwd.extend_from_slice(b"P1"); pwd.push(0); pwd.extend_from_slice(p1.as_bytes()); pwd.push(0);
    pwd.extend_from_slice(b"P2"); pwd.push(0); pwd.extend_from_slice(p2.as_bytes());

    let mut out = [0u8; 32];
    a2.hash_password_into(&pwd, salt, &mut out).expect("argon2");
    out
}

// === SHA-256 hex (come in Swift: sha256Hex) ===
fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

// === Deriva i due passcode interni da UNA sola password (stessa logica Swift) ===
fn derive_two_passcodes_from_pwd(pwd: &str) -> (String, String) {
    let hex = sha256_hex(pwd);
    let (first8, _) = hex.split_at(8.min(hex.len()));
    let last8 = &hex[hex.len().saturating_sub(8)..];

    let p1 = format!("{pwd}•1{first8}");
    let p2 = format!("{pwd}•2{last8}");
    (p1, p2)
}

// ====== MX2: cifratura / decifratura compatibili con lib.rs ======

/// CIFRATURA MX2 (2 passcode derivati) — formato identico a MAX App:
/// MX2:pc:v1|xchacha20poly1305|salt_b64|nonce_b64|tag_b64|ct_b64
fn encrypt_phrase(plain: &str, p1: &str, p2: &str) -> Result<String> {
    let mut salt  = [0u8; 16];
    let mut nonce = [0u8; 24];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let key = a2_key_from_passcodes(p1, p2, &salt);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let aad = b"MAX|MX2|pc|v1";

    let ct_tag = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain.as_bytes(), aad })
        .map_err(|_| "aead-encrypt-failed".to_string())?;

    // separa ciphertext e tag (ultimi 16 byte)
    let (ct, tag) = ct_tag.split_at(ct_tag.len().saturating_sub(16));

    Ok(format!(
        "MX2:pc:v1|xchacha20poly1305|{}|{}|{}|{}",
        STANDARD.encode(&salt),
        STANDARD.encode(&nonce),
        STANDARD.encode(tag),
        STANDARD.encode(ct),
    ))
}

/// DECIFRATURA MX2 (2 passcode derivati) — stessa logica del core
fn decrypt_phrase(packet: &str, p1: &str, p2: &str) -> Result<String> {
    if packet.to_ascii_uppercase().starts_with("MX2:") {
        let parts: Vec<&str> = packet.split('|').collect();
        if parts.len() == 6 && parts[0].to_ascii_uppercase().starts_with("MX2:PC:V1") {
            let salt  = STANDARD
                .decode(parts[2])
                .map_err(|e| format!("base64 salt error: {e}"))?;
            let nonce = STANDARD
                .decode(parts[3])
                .map_err(|e| format!("base64 nonce error: {e}"))?;
            let tag   = STANDARD
                .decode(parts[4])
                .map_err(|e| format!("base64 tag error: {e}"))?;
            let ct    = STANDARD
                .decode(parts[5])
                .map_err(|e| format!("base64 ct error: {e}"))?;

            if salt.len() != 16 || nonce.len() != 24 || tag.len() != 16 {
                return Err("bad-sizes".into());
            }

            let key = a2_key_from_passcodes(p1, p2, &salt);
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
            let aad = b"MAX|MX2|pc|v1";

            let mut ct_tag = Vec::with_capacity(ct.len() + tag.len());
            ct_tag.extend_from_slice(&ct);
            ct_tag.extend_from_slice(&tag);

            let pt = cipher
                .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct_tag, aad })
                .map_err(|_| "aead-decrypt-failed".to_string())?;

            return String::from_utf8(pt).map_err(|e| format!("utf8 error: {e}"));
        }
        return Err("bad-packet".into());
    }
    Err("not-an-MX2-packet".into())
}

// ====== Frasi random (simile a generateRandomPhrase di Swift) ======

fn generate_random_phrase(len: usize) -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS:  &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{};:,.?/|~^";

    let mut rng = OsRng;
    let mut out = Vec::with_capacity(len);

    let all: Vec<u8> = [LETTERS, DIGITS, SYMBOLS].concat();

    // riempi con caratteri casuali
    for _ in 0..len {
        out.push(all[(rng.next_u32() as usize) % all.len()]);
    }

    // forza almeno 3 numeri e 3 simboli
    for _ in 0..3 {
        let pos = (rng.next_u32() as usize) % len;
        out[pos] = DIGITS[(rng.next_u32() as usize) % DIGITS.len()];
    }
    for _ in 0..3 {
        let pos = (rng.next_u32() as usize) % len;
        out[pos] = SYMBOLS[(rng.next_u32() as usize) % SYMBOLS.len()];
    }

    // shuffle finale
    out.shuffle(&mut rng);

    String::from_utf8(out).unwrap()
}

// ====== Password: policy minima (come nell’app) ======

fn password_stats(s: &str) -> (usize, usize, usize, usize, usize) {
    let mut up = 0;
    let mut lo = 0;
    let mut di = 0;
    let mut sy = 0;
    for ch in s.chars() {
        if ch.is_ascii_uppercase() { up += 1; }
        else if ch.is_ascii_lowercase() { lo += 1; }
        else if ch.is_ascii_digit() { di += 1; }
        else { sy += 1; }
    }
    (s.chars().count(), up, lo, di, sy)
}

/// Stessa regola spiegata all’utente: ≥14, 1 maiuscola, 1 minuscola, 3 numeri, 3 simboli
fn meets_minimum_policy(p: &str) -> bool {
    let (len, up, lo, di, sy) = password_stats(p);
    len >= 14 && up >= 1 && lo >= 1 && di >= 3 && sy >= 3
}

// ====== Plain text per backup (JSON come nell’app) ======

fn build_recovery_plain(phrase1: &str, phrase2: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let payload = json!({
        "type": "MAXREC",
        "v": 2,
        "ts": ts,
        "p1": phrase1,
        "p2": phrase2,
    });
    payload.to_string()
}

fn parse_recovery_plain(s: &str) -> Option<(String, String)> {
    // Prova JSON
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(s) {
        if val.get("type")?.as_str()? == "MAXREC" {
            let p1 = val.get("p1")?.as_str()?.to_string();
            let p2 = val.get("p2")?.as_str()?.to_string();
            if !p1.is_empty() && !p2.is_empty() {
                return Some((p1, p2));
            }
        }
    }

    // Fallback stile testo
    if let Some(start) = s.find("P1:\n") {
        if let Some(mid) = s[start+4..].find("P2:\n") {
            let p1 = &s[start+4 .. start+4+mid];
            let rest = &s[start+4+mid+4 ..];
            let p2 = rest.lines().take_while(|line| !line.starts_with("TS:")).collect::<Vec<_>>().join("\n");
            if !p1.trim().is_empty() && !p2.trim().is_empty() {
                return Some((p1.trim().to_string(), p2.trim().to_string()));
            }
        }
    }

    None
}

// ====== I/O di base ======

fn read_line(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| format!("io error: {e}"))?;
    let mut s = String::new();
    io::stdin()
        .read_line(&mut s)
        .map_err(|e| format!("io error: {e}"))?;
    Ok(s.trim_end().to_string())
}

// ====== MAIN ======

fn main() {
    println!("=== MAX MX2 Open Demo (UNA sola password, compatibile con MAX App) ===\n");
    println!("Questo tool usa la stessa MX2 dell’app (Argon2id + XChaCha20-Poly1305, header MX2:pc:v1).");
    println!("Dietro le quinte ci sono DUE passcode, ma qui inserisci UNA sola password.\n");
    println!("Scegli cosa vuoi fare:");
    println!("  1) Genera due frasi nuove e crea il backup cifrato");
    println!("  2) Decifra un backup MX2 ed estrai le due frasi\n");

    let choice = loop {
        let s = read_line("Digita 1 o 2 e premi Invio: ").unwrap_or_default();
        match s.trim() {
            "1" | "2" => break s.trim().to_string(),
            _ => {
                println!("Per favore digita solo 1 oppure 2.\n");
            }
        }
    };

    // 1) Chiedi UNA sola password, con la stessa policy dell’app
    let password = loop {
        let p = read_line("Password (>=14 caratteri, 1 minuscola, 1 MAIUSCOLA, 3 numeri, 3 simboli): ")
            .unwrap_or_default();
        if !meets_minimum_policy(&p) {
            println!("❌ Password troppo debole o non conforme ai requisiti.\n");
            continue;
        }
        println!("✔️ Password accettata.\n");
        break p;
    };

    let (pass1, pass2) = derive_two_passcodes_from_pwd(&password);

    if choice == "1" {
        // ===== Modalità 1: genera frasi e cifra =====
        println!("Generazione di 2 frasi casuali da 80 caratteri…");

        let phrase1 = generate_random_phrase(80);
        let phrase2 = generate_random_phrase(80);

        println!("\nFrase 1:\n{}\n", phrase1);
        println!("Frase 2:\n{}\n", phrase2);

        let plain = build_recovery_plain(&phrase1, &phrase2);

        match encrypt_phrase(&plain, &pass1, &pass2) {
            Ok(cipher) => {
                println!("=== BACKUP MX2 DA SALVARE / IMPORTARE NELL’APP ===\n");
                println!("{cipher}\n");
                println!("Puoi copiare questo testo e:");
                println!("- salvarlo in un file di testo sicuro;");
                println!("- generare un QR (come fa l’app) e stamparlo;");
                println!("- incollarlo nella MAX App per verificare che venga decifrato.\n");
            }
            Err(e) => {
                eprintln!("Errore in cifratura: {e}");
            }
        }
    } else {
        // ===== Modalità 2: decifra un backup esistente =====
        println!("Incolla qui sotto il testo cifrato (riga MX2:pc:v1|...):\n");
        let cipher = read_line("Cipher MX2: ").unwrap_or_default();

        match decrypt_phrase(&cipher, &pass1, &pass2) {
            Ok(plain) => {
                println!("\nTesto decifrato (plain):\n{}\n", plain);
                if let Some((p1, p2)) = parse_recovery_plain(&plain) {
                    println!("=== FRASI ESTRATTE DAL BACKUP ===\n");
                    println!("Frase 1:\n{}\n", p1);
                    println!("Frase 2:\n{}\n", p2);
                } else {
                    println!("Non sono riuscito a estrarre p1/p2 dal testo (formato inatteso).");
                }
            }
            Err(e) => {
                eprintln!("Errore in decifratura: {e}");
            }
        }
    }
}
