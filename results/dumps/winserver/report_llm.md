# Incident Report  

## Summary  
The memory image contains a **critical** process‑injection artifact in `spoolsv.exe` (PID 3724) with four RWX regions, three of which hold PE headers consistent with injected DLL/EXE modules (ATT&CK T1055)【F8】. No high‑severity credential or network artifacts were reported, but the image holds a large set of **low‑severity RSA keys**, many of which are 1024‑bit or use non‑standard exponents (e = 3), indicating weak cryptographic material【F34】【F37】.  

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA‑1024 | 99.0% | implementation constants | 【F34】 |
| RSA‑1536 | 99.0% | implementation constants | 【F41】 |
| RSA‑2047 | 99.0% | implementation constants | 【F71】 |
| RSA‑2048 | 99.0% | implementation constants | 【F37】 |
| RSA‑4096 | 99.0% | implementation constants | 【F64】 |

### RSA Keys Detail  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F34】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F35】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F36】 |
| 2048 | 3 | 88 | 112‑bit security, non‑compliant exponent (FIPS 186‑5) – small exponent | 【F37】 |
| 2048 | 65537 | 88 | 112‑bit security, acceptable – shared modulus | 【F38】 |
| 2048 | 65537 | 88 | 112‑bit security, acceptable – shared modulus | 【F39】 |
| 2048 | 65537 | 88 | 112‑bit security, acceptable – shared modulus | 【F40】 |
| 1536 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F41】 |
| 2048 | 3 | 88 | 112‑bit security, non‑compliant exponent (FIPS 186‑5) – small exponent | 【F42】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F43】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F44】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F45】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F46】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F47】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F48】 |
| 2048 | 6702873 | 88 | 112‑bit security, acceptable – shared modulus | 【F49】 |
| 2048 | 83529 | 88 | 112‑bit security, acceptable – shared modulus | 【F50】 |
| 2048 | 7266387 | 88 | 112‑bit security, acceptable – shared modulus | 【F51】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F52】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F53】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F54】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F55】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F56】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F57】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F58】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F60】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F61】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F62】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F63】 |
| 4096 | 3 | 100 | 128‑bit security, non‑compliant exponent (FIPS 186‑5) – small exponent | 【F64】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F65】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F66】 |
| 1024 | 3 | 62 | 80‑bit security, disallowed (legacy use only) – small exponent | 【F67】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F68】 |
| 2048 | 3 | 88 | 112‑bit security, non‑compliant exponent (FIPS 186‑5) – small exponent | 【F69】 |
| 2048 | 3 | 88 | 112‑bit security, non‑compliant exponent (FIPS 186‑5) – small exponent | 【F70】 |
| 2047 | 3 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size, small exponent | 【F71】 |
| 2048 | 50557 | 88 | 112‑bit security, non‑compliant exponent (FIPS 186‑5) – small exponent | 【F72】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F73】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F74】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F75】 |
| 1024 | 65537 | 62 | 80‑bit security, disallowed (legacy use only) – modulus size | 【F76】 |

## Credentials  
No credential artifacts were reported in the findings.  

## Processes and Network  
- `spoolsv.exe` (PID 3724) shows four RWX memory regions, three containing PE headers, indicating injected malicious code (ATT&CK T1055)【F8】.  
- Additional processes (`Microsoft.Acti`, `svchost.exe`, `explorer.exe`, `ServerManager.`) have low‑severity RWX regions but no evidence of malicious payloads【F6】【F7】【F9】【F10】.  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|---------------|
| **Overall** | **96** | Rule‑based baseline; supported by critical injection (F8) and numerous weak RSA keys (F34)【F8】【F34】 |
| **Compromise** | **95** | Critical process injection in `spoolsv.exe` demonstrates active compromise【F8】 |
| **Crypto Exposure** | **20** | Presence of many low‑strength RSA‑1024 keys and small‑exponent keys (e = 3) lowers crypto posture【F34】【F37】 |

## Recommendations  

- **Isolate and terminate the injected `spoolsv.exe` process**; investigate its parent chain and any persisted artifacts【F8】.  
- **Conduct a full system scan** for additional code‑injection artifacts in other processes (e.g., `Microsoft.Acti`, `svchost.exe`)【F6】【F7】【F9】【F10】.  
- **Replace all RSA‑1024 keys** with RSA‑2048 or stronger keys; re‑issue certificates and update any services that rely on them【F34】.  
- **Re‑key services using small exponent (e = 3) keys** (e.g., RSA‑2048 e = 3) to use the standard exponent 65537 and comply with FIPS 186‑5【F37】【F42】【F64】.  
- **Implement strict key‑generation policies** that enforce minimum key sizes (≥2048 bits) and approved exponents; audit existing key stores for legacy keys【F34】【F41】【F71】.  
- **Enable DEP and enforce ASLR** on the host to reduce the success of future RWX injection attempts【F8】.  
- **Monitor for further ATT&CK T1055 activity** using endpoint detection and response (EDR) solutions, focusing on RWX memory allocations and PE header anomalies【F8】.  

---  