MX² — MAX to eXcryption Container



MX² (MAX to eXcryption) is an open, verifiable, password-protected container format.
It is used inside the MAX ecosystem to store two long, high-entropy secret phrases securely and reproducibly.

These two phrases (p1, p2) allow the MAX App to deterministically reconstruct:

MAX-ID (mathematical identity)

SPHINCS+ keypair (PQC Login)

FrodoKEM keypair (PQC Chat)

MX² Lock encryption keys

MAX Signature keys

All deterministic MAX modules

MX² is the cryptographic foundation of the MAX identity system.

✨ What MX² does

MX² takes one user password and transforms it into a secure container:

Derives two internal passcodes (via SHA-256).

Hardens the password using Argon2id (64 MiB, 3 iterations).

Encrypts the data using XChaCha20-Poly1305 (AEAD).

Produces a portable ASCII-safe container:

MX2:pc:v1|xchacha20poly1305|salt_b64|nonce_b64|tag_b64|ct_b64

The internal payload is typically a JSON structure:

{"type":"MAXREC","v":2,"ts":1730000000,"p1":"…","p2":"…"}

Full specification: SPEC_MX2_v1.md

🔧 High-level design

Flow overview:

password
→ SHA-256 hex
→ derive two passcodes
→ Argon2id + salt → key32
→ XChaCha20-Poly1305 (AEAD)
→ salt + nonce + authenticated ciphertext
→ MX2:pc:v1 container

MX² is:

Deterministic

Portable

Auditable

Standard

Independent

📁 Repository contents

src/main.rs — CLI tool

SPEC_MX2_v1.md — formal specification

Cargo.toml — Rust config

LICENSE — MIT

.gitignore — Rust ignores

🧪 CLI Demo

Build & run:

git clone https://github.com/max-russo-com/mx2.git

cd mx2
cargo run

The demo tool allows you to:

generate new phrases and create an MX² backup

decrypt an MX² backup and extract p1/p2

Password policy (same as MAX App):

14+ chars

≥1 lowercase

≥1 uppercase

≥3 digits

≥3 symbols

🔐 Security Notes

MX² uses modern, widely-accepted cryptographic primitives.

Password Hardening (Argon2id):

memory: 64 MiB

iterations: 3

lanes: 1

output: 32 bytes

AEAD Encryption (XChaCha20-Poly1305):

nonce: 24 bytes

tag: 16 bytes

AAD: "MAX|MX2|pc|v1"

Randomness:

Salt: 16 bytes

Nonce: 24 bytes

RNG: OsRng

Safety:

Fully authenticated encryption

Stateless format

No server involved

MX² is a secure building block, not a key manager.

📱 Compatibility with the MAX App

The MAX App uses MX² for its identity backup.

This repository implements the exact same format:

SHA-256 → passcodes

Argon2id parameters

XChaCha20-Poly1305

Header MX2:pc:v1

JSON MAXREC payload

It enables independent verification.

🔍 Independent verification

Researchers can:

inspect the MX² format

verify Argon2id parameters

reproduce MX² containers

decrypt MAXREC payloads

compare outputs with the MAX App

This provides transparency without exposing proprietary deterministic logic.

📄 License

This project is released under the MIT License.

Author

Massimo Russo
https://www.max-russo.com

MAX Ecosystem: PQC Login, PQC Chat, MAX Lock, MAX Signature, MAX Prime, MX², MAX OS.



📚 Cryptography Standards & References

MX² relies exclusively on modern, well-studied, publicly documented cryptographic primitives.
Official specifications and references:

Argon2id (Password Hardening)
https://datatracker.ietf.org/doc/draft-irtf-cfrg-argon2/

https://github.com/P-H-C/phc-winner-argon2

XChaCha20-Poly1305 (AEAD Encryption)
https://datatracker.ietf.org/doc/rfc8439/

https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/

https://cr.yp.to/chacha.html

Poly1305 MAC
https://cr.yp.to/mac/poly1305-20050329.pdf

SHA-256 (Hash Function)
https://csrc.nist.gov/publications/detail/fips/180/4/final

AEAD — Authenticated Encryption with Associated Data
https://datatracker.ietf.org/doc/rfc5116/

Base64 Encoding
https://datatracker.ietf.org/doc/rfc4648/

All cryptographic components used by MX² are open, standardized, and independently verifiable.
