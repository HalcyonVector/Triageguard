# Incident Report  

## Summary  
The analyzed memory image contains a large number of weak RSA keys, including a **critical 512‑bit RSA key** with zero security strength, and dozens of 1024‑bit keys that are deprecated and non‑compliant. Several system processes (csrss.exe, winlogon.exe, lsass.exe, soffice.bin) exhibit RWX‑injected memory regions, indicating possible code injection activity. No clear credential artifacts were recovered.  

## Cryptography  

**Identified Algorithms**

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA | 99.5% | implementation constants | [F110] |
| RSA | 99.5% | implementation constants | [F30] |
| RSA | 99.5% | implementation constants | [F31] |
| RSA | 99.5% | implementation constants | [F32] |
| RSA | 99.5% | implementation constants | [F33] |
| RSA | 99.5% | implementation constants | [F34] |
| RSA | 99.5% | implementation constants | [F35] |
| RSA | 99.5% | implementation constants | [F36] |
| RSA | 99.5% | implementation constants | [F37] |
| RSA | 99.5% | implementation constants | [F38] |
| RSA | 99.5% | implementation constants | [F39] |
| RSA | 99.5% | implementation constants | [F40] |
| RSA | 99.5% | implementation constants | [F41] |
| RSA | 99.5% | implementation constants | [F42] |
| RSA | 99.5% | implementation constants | [F43] |
| RSA | 99.5% | implementation constants | [F44] |
| RSA | 99.5% | implementation constants | [F45] |
| RSA | 99.5% | implementation constants | [F46] |
| RSA | 99.5% | implementation constants | [F47] |
| RSA | 99.5% | implementation constants | [F48] |
| RSA | 99.5% | implementation constants | [F49] |
| RSA | 99.5% | implementation constants | [F50] |
| RSA | 99.5% | implementation constants | [F51] |
| RSA | 99.5% | implementation constants | [F52] |
| RSA | 99.5% | implementation constants | [F53] |
| RSA | 99.5% | implementation constants | [F54] |
| RSA | 99.5% | implementation constants | [F55] |
| RSA | 99.5% | implementation constants | [F56] |
| RSA | 99.5% | implementation constants | [F57] |
| RSA | 99.5% | implementation constants | [F58] |
| RSA | 99.5% | implementation constants | [F59] |
| RSA | 99.5% | implementation constants | [F60] |
| RSA | 99.5% | implementation constants | [F61] |
| RSA | 99.5% | implementation constants | [F62] |
| RSA | 99.5% | implementation constants | [F63] |
| RSA | 99.5% | implementation constants | [F64] |
| RSA | 99.5% | implementation constants | [F65] |
| RSA | 99.5% | implementation constants | [F66] |
| RSA | 99.5% | implementation constants | [F67] |
| RSA | 99.5% | implementation constants | [F68] |
| RSA | 99.5% | implementation constants | [F69] |
| RSA | 99.5% | implementation constants | [F70] |

**RSA Key Details**

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | modulus size factorable (critical) | [F110] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F30] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F31] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F32] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F33] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F34] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F35] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F36] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F37] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F38] |
| 2048 bits | 3 | 88 | small exponent (non‑compliant) | [F39] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F40] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F41] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F42] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F43] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F44] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F45] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F46] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F47] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F48] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F49] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F50] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F51] |
| 2048 bits | 3 | 88 | small exponent (non‑compliant) | [F52] |
| 2048 bits | 3 | 88 | small exponent (non‑compliant) | [F53] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F54] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F55] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F56] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F57] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F58] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F59] |
| 1536 bits | 65537 | 62 | legacy size, disallowed | [F60] |
| 2048 bits | 3 | 88 | small exponent (non‑compliant) | [F61] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F62] |
| 1024 bits | 3 | 62 | legacy size, small exponent | [F63] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F64] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F65] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F66] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F67] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F68] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F69] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F70] |

## Credentials  
No credential artifacts (passwords, hashes, tokens) were extracted from the memory image.  

## Processes and Network  
- **csrss.exe (PID 924)** – contains one RWX‑injected heap segment; data appears to be heap rather than executable code. [F6]  
- **winlogon.exe (PID 948)** – ten RWX‑injected regions; two heap segments and eight regions start with zero bytes, suggesting placeholder or obfuscated code. [F7]  
- **lsass.exe (PID 1004)** – one RWX‑injected region that starts with zero bytes, no visible code. [F8]  
- **soffice.bin (PID 3088)** – one RWX‑injected region containing runtime call thunks and a C++ bridge vtable, indicative of dynamic code generation. [F9]  

No network connections or sockets were reported in the findings.  

## Risk Score  

| Component | Score | Justification |
|-----------|-------|---------------|


## Validation notes (automatic)
Rule-based risk score: 42/100. This report failed these checks, treat the points below as unverified:
- no risk score stated