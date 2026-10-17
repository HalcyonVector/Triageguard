# Incident Report  

**Date:** 2026‑10‑17  

---  

## Summary  

- A **critical‑severity injected code region** was discovered in `oneetx.exe` (PID 5896) indicating a likely DLL/EXE injection (ATT&CK T1055)【F7】.  
- Multiple **weak RSA keys** were found, including a **critical 512‑bit RSA key** with 0 / 100 strength (effectively broken)【F25】.  
- Three **expired JWT tokens** were recovered; each is signed with RSA‑256 and references the Microsoft DDS signing service【F40】【F41】【F42】.  
- The memory image contains a wide range of cryptographic primitives (AES, ECC, RSA, 3DES, etc.)【F12】【F13】【F14】【F15】【F16】【F17】【F18】【F19】【F20】【F21】.  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 99.9% | implementation constants | 【F12】 |
| ECC P‑256 | 99.0% | implementation constants | 【F13】 |
| AES‑GCM | 95.5% | API/string references only | 【F14】 |
| ECC secp256k1 | 92.8% | implementation constants | 【F15】 |
| RSA | 92.8% | implementation constants | 【F16】 |
| generic crypto | 83.2% | API/string references only | 【F17】 |
| 3DES | 72.0% | API/string references only | 【F18】 |
| ChaCha20/Salsa20 | 70.0% | implementation constants | 【F19】 |
| DES | 60.0% | implementation constants | 【F20】 |
| Curve25519 | 40.0% | API/string references only | 【F21】 |

### RSA Keys  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | modulus size (publicly factorable) | 【F25】 |
| 1024 bits | 65537 | 62 | modulus size (legacy, disallowed) | 【F22】 |
| 1024 bits | 65537 | 62 | modulus size (legacy, disallowed) | 【F23】 |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | 【F26】 |
| 1024 bits | 65537 | 62 | modulus size (legacy, disallowed) | 【F27】 |
| 1024 bits | 65537 | 62 | modulus size (legacy, disallowed) | 【F28】 |
| 1024 bits | 65537 | 62 | modulus size (legacy, disallowed) | 【F29】 |
| 1024 bits | 65537 | 62 | modulus size (legacy, disallowed) | 【F30】 |
| 1024 bits | 65537 | 62 | modulus size (legacy, disallowed) | 【F31】 |
| 1024 bits | 65537 | 62 | modulus size (legacy, disallowed) | 【F32】 |
| 1024 bits | 65537 | 62 | modulus size (legacy, disallowed) | 【F33】 |
| 1024 bits | 65537 | 62 | modulus size (legacy, disallowed) | 【F34】 |
| 1536 bits | 65537 | 62 | modulus size (legacy, disallowed) | 【F35】 |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | 【F36】 |
| 512 bits | 65537 | 0 | modulus size (publicly factorable) | 【F24】 |
| 512 bits | 65537 | 0 | modulus size (publicly factorable) | 【F37】 |

---  

## Credentials  

| Token (truncated) | Type | Status | ATT&CK Techniques | Finding |
|-------------------|------|--------|-------------------|---------|
| eyJ0eX…8PgA | JWT (RS256) | expired | T1528, T1552 | 【F40】 |
| eyJ0eX…1m‑w | JWT (RS256) | expired | T1528, T1552 | 【F41】 |
| eyJ0eX…zUuQ | JWT (RS256) | expired | T1528, T1552 | 【F42】 |

---  

## Processes and Network  

- **Process inventory:** 100 processes captured【F1】.  
- **Command‑line snapshot:** 100 command‑line entries captured【F2】.  
- **Network activity:** 113 network rows logged【F3】.  
- **Injected memory regions:** 3 rows of injected code identified; the most severe is the RWX region in `oneetx.exe` (PID 5896)【F4】【F7】.  
- **USB artifacts:** 25 USB‑related entries observed【F5】.  

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|----------------|
| Compromise | 95 | Critical process injection (T1055) demonstrates active malicious code execution【F7】; presence of a broken 512‑bit RSA key adds attacker capability【F25】; expired JWTs indicate credential leakage【F40】【F41】【F42】. |
| Crypto Exposure | 98 | Critical 512‑bit RSA key with 0 / 100 strength【F25】; many legacy 1024‑bit keys with low strength【F22】【F23】【F27】【F28】【F29】【F30】【F31】【F32】【F33】【F34】; small‑exponent 2048‑bit keys violate FIPS【F26】【F36】; deprecated ciphers 3DES and DES are present【F18】【F20】. |
| Overall | 97 | Matches the provided rule‑based baseline (97). |

---  

## Recommendations  

1. **Contain and Eradicate** – Immediately terminate `oneetx.exe` (PID 5896) and isolate the host from the network to stop the malicious injection【F7】.  
2. **Remove Malicious Artifacts** – Scan memory and disk for the injected DLL/EXE identified by the PE header in the RWX region and delete any discovered payloads【F7】.  
3. **Rotate and Harden Cryptographic Material** –  
   - Re‑generate all RSA keys ≤ 2048 bits and replace any key with exponent = 3 with keys ≥ 3072 bits using the standard exponent 65537; this addresses the weak keys listed in findings【F22】【F23】【F26】【F27】【F28】【F29】【F30】【F31】【F32】【F33】【F34】【F35】【F36】.  
   - Decommission the 512‑bit RSA keys (critical breakage)【F25】【F24】【F37】.  
   - Migrate applications away from deprecated ciphers (3DES, DES) to modern AEAD schemes such as AES‑GCM or ChaCha20‑Poly1305【F18】【F20】.  
4. **Credential Management** – Revoke the three expired JWTs and any tokens signed with the compromised RSA keys; enforce short‑lived tokens and enable token introspection【F40】【F41】【F42】.  
5. **Patch and Update** – Apply the latest OS and application patches to close known injection vectors that could allow RWX memory region abuse (ATT&CK T1055)【F7】.  
6. **Monitoring & Detection** – Deploy EDR rules that alert on creation of RWX memory regions containing PE headers and on usage of weak RSA keys; log future JWT issuance and validate expiration times【F7】【F25】.  
7. **Incident Response Follow‑up** – Conduct a root‑cause analysis to determine how the injection occurred, capture IOCs (e.g., injected binary hash, JWT signatures), and update threat‑intel feeds accordingly【F7】.  

---  

*Prepared by:* Malware Triage Analyst  

*All factual statements are cited to the corresponding findings as required.*
