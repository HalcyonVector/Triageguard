# Incident Report  

**Date:** 2026‑10‑13  
**Analyst:** Malware Triage Team  

---  

## Summary  
Memory analysis of the `wannacry.elf` sample shows active **WannaCry ransomware** execution with several **high‑severity injected processes** (ATT&CK T1055 – Process Injection) and evidence of a **Tor client** used for command‑and‑control (ATT&CK T1090.003) [F7][F8][F9][F89].  
Cryptographic artefacts are severely weakened: a **critical 512‑bit RSA private key** (0‑bit security) and dozens of legacy 1024‑bit RSA keys, plus two 2048‑bit keys that use a non‑standard exponent e = 3 [F71][F29][F30][F31][F32][F33][F34][F35][F36][F37][F38][F39][F40][F41][F42][F43][F44][F45][F46][F47][F48][F49][F50][F51][F52][F53][F54][F55][F56][F57][F58][F59][F60][F61][F62].  

The rule‑based risk score of **95 / 100** (Compromise 91, Crypto Exposure 95) is retained because the findings fully justify a near‑maximum rating [F71][F7][F8][F9][F89].  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA | 99.2% | implementation constants | [F71] |
| Tor (onion routing) | 85.0% | API/string references only | [F89] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | Critical – modulus factorable, 0‑bit security | [F71] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F29] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F30] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F31] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F32] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F33] |
| 2048 bits | 3 | 88 | Non‑compliant exponent (FIPS 186‑5) | [F34] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F35] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F36] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F37] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F38] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F39] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F40] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F41] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F42] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F43] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F44] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F45] |
| 1536 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F46] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F47] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F48] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F49] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F50] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F51] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F52] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F53] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F54] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F55] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F56] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F57] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F58] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F59] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F60] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F61] |
| 2048 bits | 3 | 88 | Non‑compliant exponent (FIPS 186‑5) | [F62] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F63] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F64] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F65] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F66] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F67] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F68] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F69] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F70] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F72] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F73] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F74] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F75] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F76] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F77] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F78] |
| 1024 bits | 65537 | 62 | Legacy size, disallowed (≤80‑bit security) | [F79] |

---  

## Credentials  
No credential artefacts (password hashes, clear‑text credentials, or tokens) were recovered from the memory image [F71].  

---  

## Processes and Network  

| PID | Process | Observation | ATT&CK Technique | Finding |
|-----|---------|-------------|------------------|---------|
| 1760 | **EMET_Agent.exe** | Contains a RWX memory region with unique executable code, indicating code injection. | T1055 (Process Injection) | [F7] |
| 2392 | **svchost.exe** | Three RWX regions; two start with zero bytes, one holds unique code – another injection indicator. | T1055 | [F8] |
| 2288 | **SearchFilterHo** | One RWX region with unique code, consistent with injection. | T1055 | [F9] |
| 816 | **@WanaDecryptor** | Command line includes the word “Decrypt”, suggesting ransomware decryption activity. | – | [F11] |
| 1252 | **@WanaDecryptor** | Same decryption‑related command line, lower severity. | – | [F12] |
| 832 | **explorer.exe** | RWX region that starts with zero bytes (low‑severity anomaly). | – | [F6] |
| 3812 | **ed01ebfbc9eb5b** | Executable runs from a user‑writable desktop folder, a persistence technique. | – | [F10] |
| – | **Tor client artefacts** | 6 055 onion relay keys found, confirming Tor usage for C2. | T1090.003 (Use of Tor