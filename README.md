# MX² — MAX to eXcryption Container

![Rust](https://img.shields.io/badge/Rust-1.74+-orange)
![XChaCha20-Poly1305](https://img.shields.io/badge/XChaCha20--Poly1305-AEAD-blue)
![Argon2id](https://img.shields.io/badge/Argon2id-Password%20Hardening-green)
![License](https://img.shields.io/badge/License-MIT-yellow)


**MX² (MAX to eXcryption)** is an open, verifiable, password-protected container format.  
It is used inside the MAX ecosystem to store **two long, high-entropy secret phrases** securely and reproducibly.

These two phrases (`p1`, `p2`) allow the MAX App to deterministically reconstruct:

- **MAX-ID** (mathematical identity)  
- **SPHINCS+** private key (PQC Login)  
- **FrodoKEM** keypair (PQC Chat)  
- **MAX Lock** encryption keys  
- **MAX Signature** keys  
- All deterministic MAX modules  

MX² is the **cryptographic foundation** of the MAX identity system.
