# Incident Report  

**Date:** 2026‑10‑15  

---  

## Summary  
Memory forensics uncovered **process‑injection** activity in three high‑severity processes and a **critical 512‑bit RSA key** that provides essentially no security. The combination of active code injection (ATT&CK T1055) and numerous weak/legacy RSA keys indicates that an attacker has both execution foothold and the ability to compromise cryptographic confidentiality.  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA | 99.9% | implementation constants | [F59] |
| RSA | 99.9% | implementation constants | [F34] |
| RSA | 99.9% | implementation constants | [F35] |
| RSA | 99.9% | implementation constants | [F36] |
| RSA | 99.9% | implementation constants | [F37] |
| RSA | 99.9% | implementation constants | [F38] |
| RSA | 99.9% | implementation constants | [F39] |
| RSA | 99.9% | implementation constants | [F40] |
| RSA | 99.9% | implementation constants | [F41] |
| RSA | 99.9% | implementation constants | [F42] |
| RSA | 99.9% | implementation constants | [F43] |
| RSA | 99.9% | implementation constants | [F44] |
| RSA | 99.9% | implementation constants | [F45] |
| RSA | 99.9% | implementation constants | [F46] |
| RSA | 99.9% | implementation constants | [F47] |
| RSA | 99.9% | implementation constants | [F48] |
| RSA | 99.9% | implementation constants | [F49] |
| RSA | 99.9% | implementation constants | [F50] |
| RSA | 99.9% | implementation constants | [F51] |
| RSA | 99.9% | implementation constants | [F52] |
| RSA | 99.9% | implementation constants | [F53] |
| RSA | 99.9% | implementation constants | [F54] |
| RSA | 99.9% | implementation constants | [F55] |
| RSA | 99.9% | implementation constants | [F56] |
| RSA | 99.9% | implementation constants | [F57] |
| RSA | 99.9% | implementation constants | [F58] |
| RSA | 99.9% | implementation constants | [F60] |
| RSA | 99.9% | implementation constants | [F61] |
| RSA | 99.9% | implementation constants | [F62] |
| RSA | 99.9% | implementation constants | [F63] |
| RSA | 99.9% | implementation constants | [F64] |
| RSA | 99.9% | implementation constants | [F65] |
| RSA | 99.9% | implementation constants | [F66] |
| RSA | 99.9% | implementation constants | [F67] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | modulus ≤ 512 bits – publicly factorable (critical) | [F59] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F34] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F35] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F36] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F37] |
| 2048 bits | 65537 | 88 | acceptable exponent but **shared modulus** | [F38] |
| 2048 bits | 65537 | 88 | shared modulus | [F39] |
| 2048 bits | 65537 | 88 | shared modulus | [F40] |
| 1536 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F41] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F42] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F43] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F44] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F45] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F46] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F47] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F48] |
| 2048 bits | 6702873 | 88 | shared modulus, non‑standard exponent | [F49] |
| 2048 bits | 83529 | 88 | shared modulus, non‑standard exponent | [F50] |
| 2048 bits | 7266387 | 88 | shared modulus, non‑standard exponent | [F51] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F52] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F53] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F54] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F55] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F56] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F57] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F58] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F60] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F61] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F62] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F63] |
| 4096 bits | 3 | 100 | strong size but non‑compliant small exponent (FIPS 186‑5) | [F64] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F65] |
| 1024 bits | 65537 | 62 | legacy size (≤ 80‑bit security) | [F66] |
| 1024 bits | 3 | 62 | legacy size + small exponent | [F67] |

---  

## Credentials  
N/A  

---  

## Processes and Network  

| PID | Process | Severity | Observation | ATT&CK Technique |
|-----|---------|----------|-------------|-------------------|
| 3724 | spoolsv.exe | **critical** | Four RWX regions; one contains unique executable code, three contain PE headers → likely injected DLL/EXE | T1055 (Process Injection) [F8] |
| 1292 | Microsoft.Acti | **high** | Five RWX regions, each with unique executable code → strong indication of code injection | T1055 (Process Injection) [F6] |
| 400 | ServerManager. | **high** | Three RWX regions with unique executable code → process injection evidence | T1055 (Process Injection) [F10] |

---  

## Risk Score  

- **Overall risk:** **96** (rule‑based score) – justified by the presence of critical process injection ([F8]) and a completely broken RSA‑512 key ([F59]) which together drive a very high compromise likelihood and a severe crypto exposure component.  
- **Compromise score:** **95** – high because multiple processes show active code injection (critical and high findings) indicating attacker control ([F8], [F6], [F10]).  
- **Crypto exposure score:** **55** – elevated due to the existence of a critical 512‑bit RSA key (strength 0) and a large population of legacy/weak RSA keys (strength ≤ 62) that reduce overall cryptographic security ([F59], [F34]‑[F67]).  

---  

## Recommendations  

- **Terminate and investigate injected processes** – immediately stop `spoolsv.exe`, `Microsoft.Acti`, and `ServerManager.` and perform a full forensic dump to identify the payloads ([F8], [F6], [F10]).  
- **Remove or replace all