# Incident Report  

**Date:** 2026‑10‑06  

---  

## Summary  
The memory image shows RWX‑injected code regions in several legitimate processes, indicating a system‑wide hooking technique [F6][F7][F8][F9][F10][F11].  
A large collection of low‑strength RSA keys (1024‑bit, 1536‑bit, and 2048‑bit with small exponents) was recovered, all scoring ≤ 40/100 [F28][F37][F53].  
Multiple cryptographic primitives (ECC P‑256, AES, RSA, AES‑GCM, ECC secp256k1, 3DES, DES, ChaCha20/Salsa20) were identified with confidence ranging from 40 % to 99.8 % [F19][F20][F21][F22][F23][F25][F26][F27].  
No high‑severity credential artifacts were observed [F1][F2].  

---  

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| ECC P‑256 | 99.8% | implementation constants | [F19] |
| AES | 98.8% | implementation constants | [F20] |
| RSA | 98.2% | implementation constants | [F21] |
| AES‑GCM | 95.5% | API/string references only | [F22] |
| ECC secp256k1 | 92.8% | implementation constants | [F23] |
| generic | 83.2% | API/string references only | [F24] |
| 3DES | 75.0% | API/string references only | [F25] |
| DES | 60.0% | implementation constants | [F26] |
| ChaCha20/Salsa20 | 40.0% | implementation constants | [F27] |

### RSA Keys  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bit | 65537 | 35 | modulus size | [F28] |
| 1024 bit | 65537 | 35 | modulus size | [F29] |
| 1024 bit | 65537 | 35 | modulus size | [F30] |
| 1024 bit | 65537 | 35 | modulus size | [F31] |
| 1024 bit | 65537 | 35 | modulus size | [F32] |
| 1024 bit | 65537 | 35 | modulus size | [F33] |
| 1024 bit | 65537 | 35 | modulus size | [F34] |
| 1024 bit | 65537 | 35 | modulus size | [F35] |
| 1024 bit | 65537 | 35 | modulus size | [F36] |
| 2048 bit | 3 | 40 | small exponent | [F37] |
| 1024 bit | 65537 | 35 | modulus size | [F38] |
| 1536 bit | 65537 | 35 | modulus size | [F39] |
| 1024 bit | 65537 | 35 | modulus size | [F40] |
| 1024 bit | 65537 | 35 | modulus size | [F41] |
| 1024 bit | 65537 | 35 | modulus size | [F42] |
| 1024 bit | 65537 | 35 | modulus size | [F43] |
| 1024 bit | 65537 | 35 | modulus size | [F44] |
| 1024 bit | 65537 | 35 | modulus size | [F45] |
| 1024 bit | 65537 | 35 | modulus size | [F46] |
| 2048 bit | 3 | 40 | small exponent | [F47] |
| 1024 bit | 65537 | 35 | modulus size | [F48] |
| 1024 bit | 65537 | 35 | modulus size | [F49] |
| 1024 bit | 65537 | 35 | modulus size | [F50] |
| 1024 bit | 65537 | 35 | modulus size | [F51] |
| 1024 bit | 65537 | 35 | modulus size | [F52] |
| 1536 bit | 3 | 10 | modulus size; small exponent | [F53] |
| 1024 bit | 65537 | 35 | modulus size | [F54] |
| 1024 bit | 65537 | 35 | modulus size | [F55] |
| 1024 bit | 65537 | 35 | modulus size | [F56] |

---  

## Credentials  
No high‑confidence credential artifacts (passwords, tokens, or hashes) were extracted from the memory image [F1][F2].  

---  

## Processes and Network  

- The host was running **42 processes** at the time of capture [F1].  
- **65 network connections** were observed in the memory snapshot [F3].  
- **7 injected‑code entries** were recorded in the summary view [F4].  
- **13 USB device records** were present [F5].  

### Suspicious RWX‑Injected Regions  

| Process (PID) | Observation |
|---------------|-------------|
| `svchost.exe` (776) | One RWX region (0xde0000) containing code identical to that found in four other processes – indicative of a system‑wide hook [F6] |
| `svchost.exe` (1052) | One RWX region (0x610000) with

## Validation notes (automatic)
Rule-based risk score: 30/100. This report failed these checks, treat the points below as unverified:
- no risk score stated