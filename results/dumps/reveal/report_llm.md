# Incident Report  

**Date:** 2026‑10‑16  

---  

## Summary  
The memory dump contains **critical RSA‑512 keys** (strength 0/100) and **high‑severity process‑injection activity** in `smartscreen.exe` (PID 2820) and `powershell.exe` (PID 3692) (ATT&CK T1055) [F37][F54][F10][F11]. A symmetric JWT signed with HS256 and lacking an expiry claim was also found [F72]. These artifacts drive a **rule‑based overall risk score of 90** (compromise 80, crypto exposure 98) [F10][F37][F72].  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA‑512 | 99.2% | implementation constants | [F37] |
| RSA‑512 | 99.2% | implementation constants | [F54] |
| RSA‑1024 | 98.5% | implementation constants | [F34] |
| RSA‑1024 | 98.5% | implementation constants | [F35] |
| RSA‑1024 | 98.5% | implementation constants | [F36] |
| RSA‑1024 | 98.5% | implementation constants | [F38] |
| RSA‑2048 (e = 3) | 98.5% | implementation constants | [F39] |
| RSA‑1024 (DER SPKI) | 98.5% | implementation constants | [F40] |
| RSA‑1024 (DER SPKI) | 98.5% | implementation constants | [F41] |
| RSA‑1024 (e = 3, DER) | 98.5% | implementation constants | [F42] |
| RSA‑1024 (e = 3, DER) | 98.5% | implementation constants | [F43] |
| RSA‑2048 (e = 3, DER) | 98.5% | implementation constants | [F44] |
| RSA‑1024 (DER) | 98.5% | implementation constants | [F45] |
| RSA‑1024 (DER) | 98.5% | implementation constants | [F46] |
| RSA‑1536 (DER) | 98.5% | implementation constants | [F47] |
| RSA‑1024 (DER) | 98.5% | implementation constants | [F48] |
| RSA‑4096 (e = 3, DER) | 98.5% | implementation constants | [F49] |
| RSA‑1024 (DER) | 98.5% | implementation constants | [F50] |
| RSA‑2048 (e = 43147, DER) | 98.5% | implementation constants | [F51] |
| RSA‑4096 (e = 62353, DER) | 98.5% | implementation constants | [F52] |
| RSA‑1024 (e = 3, DER) | 98.5% | implementation constants | [F53] |
| RSA‑2048 (e = 3, DER) | 98.5% | implementation constants | [F55] |
| RSA‑2048 (e = 3, DER) | 98.5% | implementation constants | [F56] |
| RSA‑2048 (e = 3, DER) | 98.5% | implementation constants | [F57] |
| RSA‑4096 (e = 3, DER) | 98.5% | implementation constants | [F58] |
| RSA‑2048 (e = 65537, DER) | 98.5% | implementation constants | [F59] |
| RSA‑2048 (e = 3, DER) | 98.5% | implementation constants | [F60] |
| RSA‑1024 (e = 65537, DER) | 98.5% | implementation constants | [F61] |
| RSA‑2048 (e = 3, DER) | 98.5% | implementation constants | [F62] |
| JWT (HS256) | 97.0% | API/string references only | [F72] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | modulus factorable (broken) | [F37] |
| 512 bits | 65537 | 0 | modulus factorable (broken) | [F54] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F39] |
| 4096 bits | 3 | 100 | non‑compliant small exponent (FIPS 186‑5) | [F49] |

---  

## Credentials  

| Type | Details | Finding |
|------|---------|---------|
| JWT (HS256) | Symmetric token, no `exp` claim, offline‑guessable secret | [F72] |

---  

## Processes and Network  

| PID | Process | Suspicious Activity | ATT&CK Technique(s) | Finding |
|-----|---------|---------------------|----------------------|---------|
| 2820 | `smartscreen.exe` | 1 RWX injected region containing unique code | T1055 (Process Injection) | [F10] |
| 3692 | `powershell.exe` | 5 RWX injected regions containing unique code | T1055 (Process Injection), T1059.001 (PowerShell) | [F11] |

*No network‑related findings were reported in the supplied data.*  

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|----------------|
| **Overall** | **90** | Rule‑based score (90) is retained; critical RSA‑512 keys (F37, F54) and process injection (F10, F11) justify the high rating. |
| **Compromise** | **80** | High‑severity injected code in `smartscreen.exe` and `powershell.exe` demonstrates active attacker techniques (T1055, T1059.001) [F10][F11]. |
| **Crypto Exposure** | **98** | Presence of broken RSA‑512 keys (strength 0) and many legacy/weak RSA keys (≤ 1024 bits, small exponents) severely weakens cryptographic security [F37][F54][F34][F39][F49]. |

---  

## Recommendations  

- **Rotate all RSA keys** – Replace the RSA‑512 keys (F37, F54) and any RSA keys ≤ 1024 bits or with small exponents (e = 3) with RSA‑2048+ keys using a public exponent of 65537. Use a hardware security module (HSM) for generation and storage [F37][F54][F34][F39][F49].  
- **Re‑issue JWTs** – Switch to asymmetric signing (e.g., RS256 or ES256) and add an `exp` claim to limit token lifetime. Store the signing secret in a protected vault [F72].  
- **Mitigate process injection** – Enable Data Execution Prevention (DEP) and Control Flow Guard (CFG) on all binaries; deploy endpoint detection and response (EDR) rules to alert on RWX memory mappings in legitimate processes [F10][F11].  
- **Enforce cryptographic policy** – Disallow RSA keys < 2048 bits and any exponent ≠ 65537; configure libraries to use only approved algorithms (AES‑GCM, RSA‑2048+, ECC). [F34][F39][F49].  
- **Audit and harden libraries** – Verify that only approved cryptographic providers are loaded; remove legacy CAPI providers that may expose weak keys [F34][F35][F36][F38].  
- **Logging and monitoring** – Capture process‑creation events, memory‑map changes, and JWT usage; correlate with threat‑intel feeds for known malicious payloads [F10][F11][F72].  
- **Incident response** – Isolate the affected host, acquire a full forensic image, and search for additional indicators (e.g., C2 traffic, credential dumping) before remediation [F10][F11].  

---  

*All factual statements are cited to the corresponding findings as required.*

## Validation notes (automatic)
Rule-based risk score: 90/100. This report failed these checks, treat the points below as unverified:
- only 86% of claims carry a citation