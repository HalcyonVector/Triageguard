# Incident Report  

**Date:** 2026‑10‑17  

---  

## Summary  
Memory forensics revealed **four high‑severity processes** with RWX‑memory injections (ATT&CK T1055) and **two critical RSA‑512 keys** that provide essentially no security. The combination of active code‑injection and broken cryptographic material indicates a strong attacker foothold and severe crypto exposure.  

---  

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA‑512 | 99.0% | implementation constants | [F37] |
| RSA‑512 | 99.0% | implementation constants | [F48] |
| RSA‑1024 | 99.0% | implementation constants | [F33] |
| RSA‑1024 | 99.0% | implementation constants | [F34] |
| RSA‑1024 | 99.0% | implementation constants | [F35] |
| RSA‑1024 | 99.0% | implementation constants | [F36] |
| RSA‑1024 | 99.0% | implementation constants | [F40] |
| RSA‑1024 | 99.0% | implementation constants | [F41] |
| RSA‑1024 | 99.0% | implementation constants | [F43] |
| RSA‑1024 | 99.0% | implementation constants | [F44] |
| RSA‑1024 | 99.0% | implementation constants | [F45] |
| RSA‑1024 | 99.0% | implementation constants | [F46] |
| RSA‑1024 | 99.0% | implementation constants | [F47] |
| RSA‑1024 | 99.0% | implementation constants | [F49] |
| RSA‑1024 | 99.0% | implementation constants | [F50] |
| RSA‑1536 | 99.0% | implementation constants | [F39] |
| RSA‑2048 | 99.0% | implementation constants | [F38] |
| RSA‑2048 | 99.0% | implementation constants | [F42] |
| RSA‑2048 | 99.0% | implementation constants | [F51] |
| RSA‑2048 | 99.0% | implementation constants | [F53] |
| RSA‑2048 | 99.0% | implementation constants | [F54] |
| RSA‑2048 | 99.0% | implementation constants | [F55] |
| RSA‑2048 | 99.0% | implementation constants | [F56] |
| RSA‑2048 | 99.0% | implementation constants | [F59] |
| RSA‑4096 | 99.0% | implementation constants | [F52] |
| RSA‑4096 | 99.0% | implementation constants | [F57] |
| RSA‑4096 | 99.0% | implementation constants | [F58] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | 0‑bit security – publicly factorable | [F37] |
| 512 bits | 65537 | 0 | 0‑bit security – publicly factorable | [F48] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F33] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F34] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F35] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F36] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F40] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F41] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F43] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F44] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F45] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F46] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F47] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F49] |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | [F50] |
| 1536 bits | 65537 | 62 | 80‑bit security, legacy only | [F39] |
| 2048 bits | 3 | 88 | Non‑compliant small exponent (FIPS 186‑5) | [F38] |
| 2048 bits | 3 | 88 | Non‑compliant small exponent (FIPS 186‑5) | [F42] |
| 2048 bits | 3 | 88 | Non‑compliant small exponent (FIPS 186‑5) | [F51] |
| 2048 bits | 3 | 88 | Non‑compliant small exponent (FIPS 186‑5) | [F53] |
| 2048 bits | 3 | 88 | Non‑compliant small exponent (FIPS 186‑5) | [F54] |
| 2048 bits | 3 | 88 | Non‑compliant small exponent (FIPS 186‑5) | [F55] |
| 2048 bits | 43147 | 88 | Non‑compliant exponent (FIPS 186‑5) | [F56] |
| 2048 bits | 3 | 88 | Non‑compliant small exponent (FIPS 186‑5) | [F59] |
| 4096 bits | 3 | 100 | Non‑compliant small exponent (FIPS 186‑5) | [F52] |
| 4096 bits | 3 | 100 | Non‑compliant small exponent (FIPS 186‑5) | [F57] |
| 4096 bits | 3 | 100 | Non‑compliant small exponent (FIPS 186‑5) | [F58] |

---  

## Credentials  
No credential artifacts (passwords, tokens, certificates) were reported in the findings.  

---  

## Processes and Network  

| PID | Process | Observation | ATT&CK Technique |
|-----|---------|-------------|-------------------|
| 2128 | SearchApp.exe | Two RWX‑injected regions; one region shares identical code with three other processes – system‑wide hook | T1055 (Process Injection) [F6] |
| 7068 | RuntimeBroker. | One RWX‑injected region with unique executable code | T1055 (Process Injection) [F7] |
| 7484 | smartscreen.ex | Five RWX‑injected regions; three share identical code across processes, two contain unique code – coordinated hooking | T1055 (Process Injection) [F8] |
| 5912 | WWAHost.exe | Two RWX‑injected regions; one shared across processes, one unique | T1055 (Process Injection) [F10] |
| 7780 | OneDrive.exe | One RWX region that starts with zero bytes; no executable code observed (low severity) | – [F9] |
| 4628 | ChromeSetup.ex | Executed from a user‑writable folder (`C:\Users\alex\Downloads\ChromeSetup.exe`) – potential persistence vector (low severity) | – [F11] |

No network‑traffic artifacts were present in the supplied findings.  

---  

## Risk Score  

| Component | Score |
|-----------|-------|
| **Overall** | 90 |
| **Compromise** | 