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


## ✨ What MX² does

MX² transforms **one user password** into a secure cryptographic container.  
It performs the following steps:

1. Derives **two internal passcodes** from the password (via SHA-256).  
2. Hardens the password using **Argon2id** (64 MiB, 3 iterations).  
3. Encrypts the data using **XChaCha20-Poly1305 (AEAD)**.  
4. Produces a portable ASCII-safe string:

```text
MX2:pc:v1|xchacha20poly1305|salt_b64|nonce_b64|tag_b64|ct_b64
```

Example internal JSON payload:

{"type":"MAXREC","v":2,"ts":1730000000,"p1":"…","p2":"…"}

Full specification:  
👉 [SPEC_MX2_v1.md](./SPEC_MX2_v1.md)


## 🔧 High-level design

The MX² container is constructed through the following steps:

````
password
  ↓
SHA-256 hex
  ↓
derive two passcodes
  ↓
Argon2id + salt  →  key32
  ↓
XChaCha20-Poly1305 (AEAD)
  ↓
salt + nonce + authenticated ciphertext
  ↓
MX2:pc:v1 container
````

MX² guarantees:

- Determinism  
- Portability  
- Auditability  
- Modern cryptographic primitives  
- Independence from the internal MAX-ID logic
