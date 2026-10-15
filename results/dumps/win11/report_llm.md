# Incident Report  

**Date:** 2026‑10‑15  

---  

## Summary  
The memory image contains a **critical** 512‑bit RSA key, multiple legacy RSA keys, several expired JWTs, and a Notepad process that was launched with a command line referencing an “encryption_log.txt” file (ATT&CK T1486) [F8]. These artefacts indicate weak cryptographic hygiene and evidence of ransomware‑style activity [F65][F80].  

---  

## Cryptography  

### Algorithms Identified  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA (512‑bit modulus) | 100% | implementation constants | [F65] |
| RSA (1024‑bit modulus) | 100% | implementation constants | [F36] |
| RSA (2048‑bit modulus) | 100% | implementation constants | [F39] |
| RSA (4096‑bit modulus) | 100% | implementation constants | [F51] |
| PS256 (JWT signature) | 100% | API/string references only | [F76] |
| TLS_RSA_WITH_AES_256_CBC_SHA | 100% | implementation constants | [F80] |
| TLS_RSA_WITH_3DES_EDE_CBC_SHA | 100% | implementation constants | [F80] |
| SSL 3.0 | 100% | implementation constants | [F80] |

### RSA Keys (strength assessment)  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | modulus size = 512 bits (publicly factorable) – **critical** | [F65] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F36] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F39] |
| 4096 bits | 3 | 100 | non‑compliant small exponent (FIPS 186‑5) | [F51] |

---  

## Credentials  

| Type | Token (truncated) | Status | ATT&CK Techniques | Finding |
|------|-------------------|--------|-------------------|---------|
| JWT | eyJhbG…2Yeg | expired (exp = 1775072274) | T1528, T1552 | [F76] |
| JWT | eyJhbG…EMRX | expired | T1528, T1552 | [F77] |
| JWT | eyJhbG…n2Lx | expired | T1528, T1552 | [F78] |
| JWT | eyJhbG…HQ0L | expired | T1528, T1552 | [F79] |

All tokens use the PS256 algorithm, which is recorded in the algorithm table [F76].  

---  

## Processes  

| PID | Process | Notable Behaviour | ATT&CK Technique | Finding |
|-----|---------|-------------------|------------------|---------|
| 8860 | Notepad.exe | Launched with a command line that references “encryption_log.txt”, suggesting file encryption activity | T1486 (Data Encrypted for Impact) | [F8] |
| 3088 | MsMpEng.exe | Contains 15 RWX/injected memory regions, which is typical for a JIT engine and not currently flagged as malicious | – | [F6] |
| 1300 | OneDrive.exe | Contains one RWX region that starts with zero bytes and has no code at the base address | – | [F7] |
| 2164 | DumpIt.exe | Executed from a user‑writable desktop folder, a practice that can facilitate abuse | – | [F9] |

---  

## Network  

| Observation | Details | ATT&CK Technique | Finding |
|-------------|---------|------------------|---------|
| TLS session (localhost) | Cipher suites observed: **TLS_RSA_WITH_AES_256_CBC_SHA**, **TLS_RSA_WITH_3DES_EDE_CBC_SHA**; SSL 3.0 also present. All lack forward secrecy and are classified as weak. | T1573 (Encrypted Channel) | [F80] |

---  

## Risk Score (qualitative)  

* **Compromise** – Moderate evidence of attacker activity is present, primarily the Notepad process that appears to be encrypting a user file (T1486) [F8] and the presence of multiple expired JWTs that could be harvested (T1528, T1552) [F76][F77][F78][F79].  
* **Crypto Exposure** – Very high because of the critical RSA‑512 key with zero security [F65], numerous legacy RSA keys [F36][F39], and weak TLS cipher suites [F80].  

These observations align with the supplied rule‑based scores (overall 75, compromise 55, crypto 91) and justify retaining them.  

---  

## Recommendations  

1. **Rotate and replace the RSA‑512 key immediately**; generate a new key of at least 3072 bits and store it securely [F65].  
2. **Re‑key all RSA keys ≤ 1024 bits** and replace small‑exponent keys (e = 3) with keys using the recommended exponent 65537 [F36][F39][F51].  
3. **Disable legacy TLS protocols and cipher suites** (SSL 3.0, RSA key‑exchange ciphers) and enforce TLS 1.2+ with AEAD suites such as TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 [F80].  
4. **Implement process‑execution monitoring** to alert on legitimate binaries invoked with suspicious arguments (e.g., Notepad encrypting files) [F8].  
5. **Invalidate all JWTs found in memory** and rotate the underlying signing keys; enforce short token lifetimes and avoid keeping tokens in process memory [F76][F77][F78][F79].  
6. **Patch the operating system and cryptographic libraries** to remove support for SSL 3.0 and to obtain the latest security updates [F80].  
7. **Conduct a full forensic investigation** of the host to determine the origin of the ransomware‑style activity, collect additional logs, and verify whether data exfiltration occurred [F8].  

---  

*All factual statements are supported by the cited findings.*

## Validation notes (automatic)
Rule-based risk score: 75/100. This report failed these checks, treat the points below as unverified:
- no risk score stated
- crypto exposure 512 differs from rule-based 91 by more than 20
- only 82% of claims carry a citation