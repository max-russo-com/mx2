# MX² — MAX 2 eXcryption Container

![Rust](https://img.shields.io/badge/Rust-1.74+-orange)
![XChaCha20-Poly1305](https://img.shields.io/badge/XChaCha20--Poly1305-AEAD-blue)
![Argon2id](https://img.shields.io/badge/Argon2id-Password%20Hardening-green)
![License](https://img.shields.io/badge/License-MIT-yellow)


**MX² (MAX 2 eXcryption)** is an open, verifiable, password-protected container format.  

It stores two long, high-entropy secret phrases securely, reproducibly, and in a portable ASCII-safe structure.

The goal is to provide a deterministic format and key-derivation logic that works identically across platforms, while keeping encryption randomized and aligned with modern AEAD best practices (Argon2id + XChaCha20-Poly1305).

> **Why “MX²”?**  
> The name refers to a “second layer” (²) built on top of standard cryptographic primitives, where *M* and *X* indicate a minimal, extensible container format.  
> The meaning is intentionally lightweight: MX² is simply a compact name for a portable encryption container.

## ⭐ Features

• Portable ASCII-safe container

• Deterministic format and key-derivation logic

• Based exclusively on standard, well-studied cryptography

• Zero cloud dependency

• Suitable for QR encoding

• Fully auditable by researchers

• Reproducible across platforms

## ✨ What MX² does

MX² uses a user password to **encrypt and protect** a JSON payload containing
two long, high-entropy secret phrases (`p1`, `p2`).  
The password **does not generate** these phrases — it only derives the key
used to protect them.

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
              [ Secret Phrases ]
                  p1 , p2
                    │
                    ▼
              JSON payload (MAXREC)
                    │
                    │  (encrypted by key32)
                    │
                    ▼

password ───► SHA-256 ───► internal passcodes ───► Argon2id ───► key32
                                                                     │
                                                                     ▼
                                                        XChaCha20-Poly1305
                                                                     │
                                                                     ▼
                                                          MX2:pc:v1 container
````

MX² guarantees:

•	Reproducible format and key-derivation logic

•	Portability across platforms and implementations

•	Auditability of parameters and on-disk representation

•	Use of modern, well-studied cryptographic primitives

•	Independence from the internal MAX-ID logic

#### Determinism vs randomness

MX² is deterministic in its *format* and key-derivation logic: given the same password, parameters and JSON payload, an implementation will always derive the same key material and produce a structurally equivalent container.

The encryption itself is randomized: each container uses a fresh random salt and XChaCha20-Poly1305 nonce, so two containers created from the same input will have different ciphertexts and tags. This is intentional and follows standard AEAD best practices.


## 📁 Repository contents

- src/main.rs — command-line demo tool

- SPEC_MX2_v1.md — technical specification for MX²

- Cargo.toml — Rust crate definition

- LICENSE — MIT license

- .gitignore — Rust standard ignores

## 🧪 CLI Demo (Rust)

This repository includes a small command-line tool that demonstrates how MX² works.

You can build and run it with:

````
git clone https://github.com/max-russo-com/mx2.git
cd mx2
cargo run
````

After running the tool, you will see a menu:

• Option 1: generate two new secret phrases and create an encrypted MX² backup

• Option 2: decrypt an existing MX² backup and recover the stored phrases

The demo enforces the same password policy as the MAX App:

- at least 14 characters

- at least 1 lowercase

- at least 1 uppercase

- at least 3 digits

- at least 3 symbols


## 🔐 Security Notes

MX² uses modern, well-studied cryptographic primitives.

**Password Hardening — Argon2id**

memory: 64 MiB

iterations: 3

lanes: 1

output: 32 bytes

**AEAD Encryption — XChaCha20-Poly1305**

nonce: 24 bytes

tag: 16 bytes

AAD: "MAX|MX2|pc|v1"

**Randomness**

Salt: 16 bytes

Nonce: 24 bytes

RNG: OsRng

**Security properties**

Fully authenticated encryption

Stateless format

No server involved

No key material leaves the device

MX² is a secure building block, not a standalone key manager.


## 📱 Compatibility with the MAX App

The MAX App uses MX² to store and recover two secret phrases locally.

This repository implements the exact same container format:

SHA-256 → internal passcodes

Argon2id parameters

XChaCha20-Poly1305 AEAD

Header MX2:pc:v1

JSON MAXREC payload

This allows full independent verification.

### 🔄 Cross-Compatibility Tests (Desktop ↔ MAX App)

This repository allows researchers to perform a **full interoperability test**
between the open MX² implementation (this Rust code) and the MAX App.

You can verify mathematically that the MAX App uses the exact same MX² format:

- SHA-256 for deriving internal passcodes  
- Argon2id (64 MiB, 3 iterations, 1 lane)  
- XChaCha20-Poly1305 (AEAD, 24-byte nonce, 16-byte tag)  
- JSON MAXREC payload  
- `MX2:pc:v1` header  

#### 📲 Download the MAX App (TestFlight)

You can install the MAX App Beta here:

👉 **https://testflight.apple.com/join/pc6PdFz5**



#### ✔️ Test 1 — Encrypt on desktop → decrypt in MAX App  
Create an MX² container with this Rust tool (`cargo run`)  
and import it inside the MAX App.  
The MAX App will correctly decrypt the payload.

#### ✔️ Test 2 — Encrypt in MAX App → decrypt on desktop  
Create an MX² backup inside the MAX App.  
Then use this repository to decrypt it on your computer.  
The Rust implementation will correctly recover the JSON payload.

These two tests provide **cryptographic transparency**:
anyone can confirm that the MAX App truly implements MX² exactly as specified,
without requiring access to any internal deterministic logic of MAX-ID.

This level of interoperability is intentional:  
MX² is designed to be **open, verifiable and reproducible** across platforms.

## 🔍 Independent verification

Researchers can:

inspect the MX² format

verify Argon2id parameters

reproduce MX² containers

decrypt MAXREC payloads

confirm the MAX App uses this exact container

write compatible implementations

This provides transparency without revealing proprietary MAX-ID logic.


## 🖥 Supported Platforms

macOS

Linux

Windows (WSL recommended)


## 📚 Cryptography Standards & References

MX² relies exclusively on standard, verifiable cryptographic primitives.

**Argon2id (Password Hardening)**
https://datatracker.ietf.org/doc/draft-irtf-cfrg-argon2/

https://github.com/P-H-C/phc-winner-argon2

**XChaCha20-Poly1305 (AEAD Encryption)**
https://datatracker.ietf.org/doc/rfc8439/

https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/

https://cr.yp.to/chacha.html

**Poly1305 MAC**
https://cr.yp.to/mac/poly1305-20050329.pdf

**SHA-256 (Hash Function)**
https://csrc.nist.gov/publications/detail/fips/180/4/final

**AEAD — Authenticated Encryption with Associated Data**
https://datatracker.ietf.org/doc/rfc5116/

**Base64 Encoding**
https://datatracker.ietf.org/doc/rfc4648/

All cryptographic components used by MX² are open, standardized, and independently verifiable.

## 🔗 Use inside the MAX ecosystem (optional context)

MX² was originally designed as the local container for two long-term, high-entropy secret phrases used in a broader deterministic identity system (the MAX App).

These two phrases (`p1`, `p2`) allow the MAX App to reproducibly derive:

- **MAX-ID** (mathematical identity)  
- **SPHINCS+** private key (PQC Login)  
- **FrodoKEM** keypair (PQC Chat)  
- **MAX Lock** encryption keys  
- **MAX Signature** keys  
- All deterministic MAX modules in the architecture

This context is optional: MX² is a **standalone, general-purpose container format**.  
The deterministic MAX-ID derivation logic is proprietary and **not part of this repository**.  
MX² remains fully open, auditable, and independently verifiable.


## 📄 License

This project is released under the MIT License.
See the LICENSE file for details.

## Author

Massimo Russo
https://www.max-russo.com
