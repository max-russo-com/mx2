# MX² Specification — Version 1 (MX2:PC:V1)

Status: **Draft (Non-Normative Core)**
Version: **1.0**
Author: **Massimo Russo**
Last update: **2025-12**
License: **MIT**

## 1. Introduction

MX² (“MAX 2 eXcryption”) is a **portable, password-protected container format** for encrypting long-term, high-entropy secret phrases.

MX² is:
- **open**
- **verifiable**
- **ASCII-safe**
- **fully reproducible**
- **based exclusively on standardized cryptography**

The format is intentionally minimal and suitable for:
- file storage
- text encoding
- QR encoding
- cross-platform interoperability

This document defines:
the **MX2:PC:V1** container format
the internal JSON record **(MAXREC)**
the password-based encryption mechanism
the normative requirements for compliant implementations.


## 1.1 Security Model (High-Level Overview)

MX² uses a simple but powerful **three-layer trust model**:
```
        [1] Password (user secret)
                     │
                     ▼
        [2] MX² Container (encrypted vault)
                     │
                     ▼
        [3] Secret Phrases p1, p2 (root secrets)
```


