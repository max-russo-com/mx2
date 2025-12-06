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

// ====== Argon2id key derivation (same as in the MAX App) ======

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

// === SHA-256 hex (same as Swift: sha256Hex) ===
fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

// === Derive two internal passcodes from ONE password (same logic as Swift) ===
fn derive_two_passcodes_from_pwd(pwd: &str) -> (String, String) {
    let hex = sha256_hex(pwd);
    let (first8, _) = hex.split_at(8.min(hex.len()));
    let last8 = &hex[hex.len().saturating_sub(8)..];

    let p1 = format!("{pwd}•1{first8}");
    let p2 = format!("{pwd}•2{last8}");
    (p1, p2)
}

// ====== MX2: encrypt / decrypt compatible with lib.rs ======

/// MX2 ENCRYPTION (2 derived passcodes) — format identical to the MAX App:
/// MX2:pc:v1|xchacha20poly1305|salt_b64|nonce_b64|tag_b64|ct_b64
fn encrypt_phrase(plain: &str, p1: &str, p2: &str) -> Result<String> {
    let mut salt  = [0u8; 16]; // 16-byte salt, as recommended baseline in the SPEC (16–32 bytes allowed)
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

    // split ciphertext and tag (last 16 bytes)
    let (ct, tag) = ct_tag.split_at(ct_tag.len().saturating_sub(16));

    Ok(format!(
        "MX2:pc:v1|xchacha20poly1305|{}|{}|{}|{}",
        STANDARD.encode(&salt),
        STANDARD.encode(&nonce),
        STANDARD.encode(tag),
        STANDARD.encode(ct),
    ))
}

/// MX2 DECRYPTION (2 derived passcodes) — same logic as the core
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

// ====== Random phrases (similar to generateRandomPhrase in Swift) ======

fn generate_random_phrase(len: usize) -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS:  &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{};:,.?/|~^";

    let mut rng = OsRng;
    let mut out = Vec::with_capacity(len);

    let all: Vec<u8> = [LETTERS, DIGITS, SYMBOLS].concat();

    // fill with random characters
    for _ in 0..len {
        out.push(all[(rng.next_u32() as usize) % all.len()]);
    }

    // force at least 3 digits and 3 symbols
    for _ in 0..3 {
        let pos = (rng.next_u32() as usize) % len;
        out[pos] = DIGITS[(rng.next_u32() as usize) % DIGITS.len()];
    }
    for _ in 0..3 {
        let pos = (rng.next_u32() as usize) % len;
        out[pos] = SYMBOLS[(rng.next_u32() as usize) % SYMBOLS.len()];
    }

    // final shuffle
    out.shuffle(&mut rng);

    String::from_utf8(out).unwrap()
}

// ====== Password: minimum policy (same as the app) ======

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

/// Same rule shown to the user: ≥14 chars, 1 uppercase, 1 lowercase, 3 digits, 3 symbols
fn meets_minimum_policy(p: &str) -> bool {
    let (len, up, lo, di, sy) = password_stats(p);
    len >= 14 && up >= 1 && lo >= 1 && di >= 3 && sy >= 3
}

// ====== Plain text for backup (JSON, same as the app) ======

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
    // Try JSON
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(s) {
        if val.get("type")?.as_str()? == "MAXREC" {
            let p1 = val.get("p1")?.as_str()?.to_string();
            let p2 = val.get("p2")?.as_str()?.to_string();
            if !p1.is_empty() && !p2.is_empty() {
                return Some((p1, p2));
            }
        }
    }

    // Fallback: plain text style
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

// ====== Basic I/O ======

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
    println!("=== MAX MX2 Open Demo (ONE password, compatible with the MAX App) ===\n");
    println!("This tool uses the same MX2 container as the MAX App (Argon2id + XChaCha20-Poly1305, header MX2:pc:v1).");
    println!("Behind the scenes there are TWO internal passcodes, but here you type only ONE password.\n");
    println!("Choose what you want to do:");
    println!("  1) Generate two new phrases and create an encrypted backup");
    println!("  2) Decrypt an MX2 backup and extract the two phrases\n");

    let choice = loop {
        let s = read_line("Type 1 or 2 and press Enter: ").unwrap_or_default();
        match s.trim() {
            "1" | "2" => break s.trim().to_string(),
            _ => {
                println!("Please type only 1 or 2.\n");
            }
        }
    };

    // 1) Ask for ONE password, with the same policy as the app
    let password = loop {
        let p = read_line("Password (>=14 chars, 1 lowercase, 1 UPPERCASE, 3 digits, 3 symbols): ")
            .unwrap_or_default();
        if !meets_minimum_policy(&p) {
            println!("❌ Password too weak or not compliant with the requirements.\n");
            continue;
        }
        println!("✔️ Password accepted.\n");
        break p;
    };

    let (pass1, pass2) = derive_two_passcodes_from_pwd(&password);

    if choice == "1" {
        // ===== Mode 1: generate phrases and encrypt =====
        println!("Generating 2 random phrases of 80 characters…");

        let phrase1 = generate_random_phrase(80);
        let phrase2 = generate_random_phrase(80);

        println!("\nPhrase 1:\n{}\n", phrase1);
        println!("Phrase 2:\n{}\n", phrase2);

        let plain = build_recovery_plain(&phrase1, &phrase2);

        match encrypt_phrase(&plain, &pass1, &pass2) {
            Ok(cipher) => {
                println!("=== MX2 BACKUP TO SAVE / IMPORT INTO THE APP ===\n");
                println!("{cipher}\n");
                println!("You can copy this text and:");
                println!("- save it to a secure text file;");
                println!("- generate a QR code (like the app does) and print it;");
                println!("- paste it into the MAX App to verify that it decrypts.\n");
            }
            Err(e) => {
                eprintln!("Encryption error: {e}");
            }
        }
    } else {
        // ===== Mode 2: decrypt an existing backup =====
        println!("Paste the encrypted text below (line starting with MX2:pc:v1|...):\n");
        let cipher = read_line("MX2 cipher: ").unwrap_or_default();

        match decrypt_phrase(&cipher, &pass1, &pass2) {
            Ok(plain) => {
                println!("\nDecrypted plain text:\n{}\n", plain);
                if let Some((p1, p2)) = parse_recovery_plain(&plain) {
                    println!("=== PHRASES EXTRACTED FROM BACKUP ===\n");
                    println!("Phrase 1:\n{}\n", p1);
                    println!("Phrase 2:\n{}\n", p2);
                } else {
                    println!("Could not extract p1/p2 from the text (unexpected format).");
                }
            }
            Err(e) => {
                eprintln!("Decryption error: {e}");
            }
        }
    }
}
