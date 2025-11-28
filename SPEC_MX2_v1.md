MX² Specification — Version 1 (MX2:PC:V1)

Status: Draft
Version: 1.0
Author: Massimo Russo
Last update: 2025-12
License: To be defined

## 1. Introduction

MX² (“MAX to eXcryption”) is a deterministic cryptographic container
designed to protect high-entropy secrets and make them portable across devices,
QR codes, backups and recovery flows.

It is the foundation layer (“Level 2”) of the MAX ecosystem and is used for:

storing the internal secret that regenerates MAX-ID

deriving deterministic SPHINCS+ keypairs (Login)

deriving deterministic FrodoKEM keypairs (Chat)

encrypting local user data (Lock)

providing a verifiable structure for external auditors

The MX² container is built on strong, well-studied primitives:

Argon2id — memory-hard key derivation

XChaCha20-Poly1305 — AEAD symmetric encryption

SHA-256 — integrity and versioning


## 2. Design goals

Determinism — same input → same output

Portability — works as string, file, QR

Transparency — all fields are inspectable

Security — modern, audit-ready primitives

Minimalism — no unnecessary metadata

Independence — reveals nothing about MAX-ID logic


## 3. Format overview

An MX² container has the following structure (Version 1):

MX2:PC:V1|salt_b64|nonce_b64|tag_b64|ciphertext_b64


Fields are separated by the ASCII | character.


## 4. Field definitions
**4.1 Header**

Literal: MX2:PC:V1

Meaning:

MX2 → format family

PC → Portable Container

V1 → version 1

**4.2 salt_b64**

Base64-encoded salt for Argon2id

Length: 16–32 bytes (recommended: 16)

MUST be unique per container

**4.3 nonce_b64**

Base64-encoded

24 bytes (XChaCha20)

MUST NOT repeat for the same key

**4.4 tag_b64**

Base64-encoded

16 bytes authentication tag

**4.5 ciphertext_b64**

Base64-encoded ciphertext

Contains encrypted JSON

## 5. Internal encrypted payload

The decrypted payload MUST be JSON.
Recommended schema:

{
  "version": 1,
  "phrases": "…",
  "meta": {
    "created_at": 1737811200,
    "device": "iPhone15,3",
    "format": "MX2:PC:V1"
  }
}


Notes:

phrases contains the high-entropy secret

meta is optional

Version SHOULD be included for future migrations

## 6. Cryptographic process
**6.1 Deriving the key**
key = Argon2id(phrases, salt, memory=64MiB, iterations=3, parallelism=1)

**6.2 Encryption**
ciphertext, tag = XChaCha20-Poly1305(key, nonce, plaintext)

**6.3 Assembly**
header | salt_b64 | nonce_b64 | tag_b64 | ciphertext_b64

## 7. Determinism

MX² is deterministic when:

phrases are identical

salt is constant

version V1 is unchanged

In the MAX App:

MX² for identity regeneration → deterministic

MX² for Chat messaging → non-deterministic (uses FrodoKEM)

## 8. Security considerations

MX² does NOT contain private keys

MX² reveals nothing about MAX-ID

MX² MUST be treated as secret

JSON MUST NOT contain derivable keys

Rotate MX² if passphrases change

Uses only proven primitives (Argon2id + XChaCha20-Poly1305)

## 9. Compatibility
Current version

MX2:PC:V1

Future versions (planned)

MX2:PC:V2 — extended metadata

MX2:PC:V3 — binary compact version

MX2:EX:V1 — extended eXcryption container

## 10. Test vector (example only)
'''
MX2:PC:V1|2sQ3QzF1zN0=|AAECAwQFBgcICQoLDA0ODxAREhM=|W7Rzuu9J6t5WZg==|p9S0P9uzp8DLiGsQmZq1zknHnNn0ZIqQ2xFZ2w==
'''

This is not a real encrypted payload.

## 11. Reference implementations

Rust implementation (coming soon)

Swift implementation (inside MAX App)

Python validator (planned)

## 12. Changelog

v1.0 — Draft

Initial public specification

Defines MX2:PC:V1

Includes internal JSON schema

Provides deterministic model

End of SPEC.
