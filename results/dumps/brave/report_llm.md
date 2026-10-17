# Incident Report  

## Summary  
The memory image contains a high‑severity PowerShell process (PID 5096) with five RWX‑injected memory regions, indicating in‑memory code injection and script execution (ATT&CK T1055, T1059.001) [F10]. Additional processes show injected or anomalous RWX memory (MsMpEng.exe, SearchApp.exe, smartscreen.ex, OneDrive.exe) [F6][F7][F8][F9]. Credential artifacts are present in clear text: a symmetric HS256 JWT, an AWS access key ID, and a bearer token [F76][F77][F78]. Cryptographic analysis reveals numerous weak RSA keys (mostly 1024‑bit with legacy exponent 65537 and several 2048‑bit keys using the non‑compliant exponent 3), resulting in low‑strength keys that violate modern security policies [F38‑F71].  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA (various key sizes) | 99.2% | implementation constants | [F38] |
| HS256 (JWT) | 98.5% | API/string references only | [F76] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bits | 65537 | 62 | legacy size (≤1024 bits) | [F38] |
| 1024 bits | 65537 | 62 | legacy size | [F39] |
| 1024 bits | 65537 | 62 | legacy size | [F40] |
| 1024 bits | 65537 | 62 | legacy size | [F41] |
| 1024 bits | 65537 | 62 | legacy size | [F42] |
| 1024 bits | 65537 | 62 | legacy size | [F43] |
| 1023 bits | 65537 | 62 | legacy size | [F44] |
| 1024 bits | 65537 | 62 | legacy size | [F45] |
| 2048 bits | 3 | 88 | non‑compliant exponent (e = 3) | [F46] |
| 1024 bits | 65537 | 62 | legacy size | [F47] |
| 1024 bits | 65537 | 62 | legacy size | [F48] |
| 1024 bits | 65537 | 62 | legacy size | [F49] |
| 1024 bits | 65537 | 62 | legacy size | [F50] |
| 1536 bits | 65537 | 62 | legacy size | [F51] |
| 1024 bits | 65537 | 62 | legacy size | [F52] |
| 2048 bits | 3 | 88 | non‑compliant exponent | [F53] |
| 2048 bits | 3 | 88 | non‑compliant exponent | [F54] |
| 1024 bits | 65537 | 62 | legacy size | [F55] |
| 1024 bits | 65537 | 62 | legacy size | [F56] |
| 1024 bits | 65537 | 62 | legacy size | [F57] |
| 1024 bits | 65537 | 62 | legacy size | [F58] |
| 1024 bits | 65537 | 62 | legacy size | [F59] |
| 1024 bits | 65537 | 62 | legacy size | [F60] |
| 4096 bits | 3 | 100 | non‑compliant exponent | [F61] |
| 4096 bits | 3 | 100 | non‑compliant exponent | [F62] |
| 4096 bits | 3 | 100 | non‑compliant exponent | [F63] |
| 2048 bits | 3 | 88 | non‑compliant exponent | [F64] |
| 4096 bits | 62353 | 100 | non‑compliant exponent | [F65] |
| 2048 bits | 3 | 88 | non‑compliant exponent | [F66] |
| 2048 bits | 43147 | 88 | non‑compliant exponent | [F67] |
| 2048 bits | 3 | 88 | non‑compliant exponent | [F68] |
| 2048 bits | 50557 | 88 | non‑compliant exponent | [F69] |
| 2048 bits | 3 | 88 | non‑compliant exponent | [F70] |
| 1024 bits | 65537 | 62 | legacy size | [F71] |

## Credentials  

| Type | Value (truncated) | ATT&CK Technique(s) | Finding |
|------|-------------------|---------------------|---------|
| JWT (HS256) | `eyJhbG...8Sus` | T1528, T1552 | [F76] |
| AWS Access Key ID | `AKIAIW...H53A` | T1552 | [F77] |
| Bearer token | `585d36...ca1d` | T1528, T1552 | [F78] |

## Processes and Network  

- **PowerShell (PID 5096)** – 5 RWX‑injected regions containing unique executable code, indicating malicious code injection (high severity) [F10].  
- **MsMpEng.exe (PID 1156)** – 7 RWX regions associated with expected JIT activity; low severity [F6].  
- **SearchApp.exe (PID 5104)** – 2 RWX‑injected regions with unique code (low severity) [F7].  
- **smartscreen.ex (PID 6716)** – 2 RWX‑injected regions with unique code (low severity) [F8].  
- **OneDrive.exe (PID 6988)** – 1 RWX region starting with zero bytes and no code at the base (low severity) [F9].  

No explicit network connections were identified in the provided findings.  

## Risk Score  

- **Overall Risk:** **89** – derived from the rule‑based score (compromise 80, crypto exposure 93) [F10][F38].  
- **Compromise (80):** Supported by the high‑severity injected PowerShell process and the presence of multiple other injected processes [F10][F6][F7][F8][F9].  
- **Crypto Exposure (93):** Driven by the large number of weak RSA keys (strength ≤ 62) and the presence of a symmetric HS256 JWT whose security depends on a secret that can be guessed offline [F38][F76].  

## Recommendations  

- **Terminate and isolate the injected PowerShell process**; capture a full memory dump for deeper malware analysis [F10].  
- **Rotate all exposed credentials:**  
  - Replace the HS256 JWT secret with an asymmetric signing algorithm (e.g., RS256) and enforce short token lifetimes [F76].  
  - Revoke the AWS access key ID and generate a new one with MFA and least‑privilege permissions [F77].  
  - Revoke the bearer token and issue a new token with higher entropy [F78].  
- **Replace all weak RSA keys:**  
  - Decommission every RSA‑1024 key and migrate to RSA‑2048 or larger with a compliant exponent 65537 – see findings [F38‑F45][F47‑F52][F55‑F60][F71].  
  - Re‑issue keys that currently use the non‑compliant exponent 3 (or other small exponents) with a standard exponent 65537 – see findings [F46][F53][F54][F64][F66][F67][F68][F69][F70].  
  - Update applications to use approved CNG providers that enforce FIPS‑compliant parameters [F46][F53][F54][F64][F65][F66][F67][F68][F69][F70][F61‑F63].  
- **Run a comprehensive memory integrity scan** to locate any additional injected code or hidden artifacts not captured in the current extraction [F10][F6][F7][F8][F9].  
- **Harden endpoint protection:** enable DEP, CFG, and restrict RWX memory allocations to trusted binaries only [F10].  
- **Audit network egress controls** to prevent exfiltration of discovered credentials and keys [F76][F77][F78].  
- **Establish a key management policy** that disallows legacy key sizes (≤1024 bits) and non‑standard exponents, with regular rotation and automated compliance checks [F38‑F71].  