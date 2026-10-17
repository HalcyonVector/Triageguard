## Summary  
A high‑severity PowerShell process (PID 3692) was found executing code from five RWX memory regions that are unique to the process, indicating code injection (ATT&CK T1055, T1059.001) [F11].  
A JWT token using symmetric HS256 was discovered; its security relies on a secret of unknown strength, is vulnerable to offline guessing, and lacks an expiration claim [F72].  
Numerous RSA keys were extracted, the majority being 1024‑bit with weak security (≈80‑bit) and several using non‑standard small exponents, further reducing cryptographic strength [F34‑F69].  

These findings drive a rule‑based overall risk score of **86** (Compromise 80, Crypto Exposure 64).

---

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA (various key sizes) | 99.0% | implementation constants | [F34] |
| RSA (various key sizes) | 99.0% | implementation constants | [F35] |
| RSA (various key sizes) | 99.0% | implementation constants | [F36] |
| RSA (various key sizes) | 99.0% | implementation constants | [F38] |
| RSA (various key sizes) | 99.0% | implementation constants | [F39] |
| RSA (various key sizes) | 99.0% | implementation constants | [F40] |
| RSA (various key sizes) | 99.0% | implementation constants | [F41] |
| RSA (various key sizes) | 99.0% | implementation constants | [F42] |
| RSA (various key sizes) | 99.0% | implementation constants | [F43] |
| RSA (various key sizes) | 99.0% | implementation constants | [F44] |
| RSA (various key sizes) | 99.0% | implementation constants | [F45] |
| RSA (various key sizes) | 99.0% | implementation constants | [F46] |
| RSA (various key sizes) | 99.0% | implementation constants | [F47] |
| RSA (various key sizes) | 99.0% | implementation constants | [F48] |
| RSA (various key sizes) | 99.0% | implementation constants | [F49] |
| RSA (various key sizes) | 99.0% | implementation constants | [F50] |
| RSA (various key sizes) | 99.0% | implementation constants | [F51] |
| RSA (various key sizes) | 99.0% | implementation constants | [F52] |
| RSA (various key sizes) | 99.0% | implementation constants | [F53] |
| RSA (various key sizes) | 99.0% | implementation constants | [F55] |
| RSA (various key sizes) | 99.0% | implementation constants | [F56] |
| RSA (various key sizes) | 99.0% | implementation constants | [F57] |
| RSA (various key sizes) | 99.0% | implementation constants | [F58] |
| RSA (various key sizes) | 99.0% | implementation constants | [F59] |
| RSA (various key sizes) | 99.0% | implementation constants | [F60] |
| RSA (various key sizes) | 99.0% | implementation constants | [F61] |
| RSA (various key sizes) | 99.0% | implementation constants | [F62] |
| RSA (various key sizes) | 99.0% | implementation constants | [F63] |
| RSA (various key sizes) | 99.0% | implementation constants | [F64] |
| RSA (various key sizes) | 99.0% | implementation constants | [F65] |
| RSA (various key sizes) | 99.0% | implementation constants | [F66] |
| RSA (various key sizes) | 99.0% | implementation constants | [F67] |
| RSA (various key sizes) | 99.0% | implementation constants | [F68] |
| RSA (various key sizes) | 99.0% | implementation constants | [F69] |
| HS256 (JWT) | 98.5% | API/string references only | [F72] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F34] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F35] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F36] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F38] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F39] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F40] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F41] |
| 1024 bits | 3 | 62 | modulus size; small exponent | [F42] |
| 1024 bits | 3 | 62 | modulus size; small exponent | [F43] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F44] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F45] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F46] |
| 1536 bits | 65537 | 62 | modulus size (legacy) | [F47] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F48] |
| 4096 bits | 3 | 100 | non‑compliant small exponent (FIPS 186‑5) | [F49] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F50] |
| 2048 bits | 43147 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F51] |
| 4096 bits | 62353 | 100 | non‑compliant small exponent (FIPS 186‑5) | [F52] |
| 1024 bits | 3 | 62 | modulus size; small exponent | [F53] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F55] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F56] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F57] |
| 4096 bits | 3 | 100 | non‑compliant small exponent (FIPS 186‑5) | [F58] |
| 2048 bits | 65537 | 88 | shared modulus (acceptable) | [F59] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F60] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F61] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F62] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F63] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F64] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F65] |
| 2048 bits | 131071 | 88 | shared modulus (acceptable) | [F66] |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F67] |
| 4096 bits | 3 | 100 | non‑compliant small exponent (FIPS 186‑5) | [F68] |
| 1024 bits | 65537 | 62 | modulus size (legacy) | [F69] |

---

## Credentials  
* **JWT (HS256)** – symmetric key‑based signing; security depends on the secret’s entropy, which is unknown. The token lacks an `exp` claim, enabling indefinite reuse. Offline brute‑force attacks are feasible [F72].

---

## Processes and Network  

| PID | Process | Observation | ATT&CK Technique(s) | Finding |
|-----|---------|-------------|----------------------|---------|
| 3692 | powershell.exe | 5 RWX injected regions with unique code → code injection | T1055, T1059.001 | [F11] |
| 7848 | RuntimeBroker.exe | 1 RWX region starting with zero bytes, no code at base (low risk) | – | [F6] |
| 4492 | thunderbird.exe | 2 RWX regions, expected for JIT | – | [F7] |
| 3644 | thunderbird.exe | 2 RWX regions, expected for JIT | – | [F8] |
| 3004 | thunderbird.exe | 1 RWX region, expected for JIT | – | [F9] |
| 2820 | smartscreen.exe | 1 RWX region with unique code (low risk) | – | [F10] |

Network information was captured (79 rows of network data), but no malicious connections were explicitly identified in the extracted data [F3].

---

## Risk Score  

* **Overall Risk:** **86** – matches the rule‑based score (no contradictory evidence) [F11][F72][F34‑F69].  
* **Compromise (80)** – driven by the high‑severity injected PowerShell process (code injection) [F11] and the presence of a weak, non‑expiring JWT that could be abused [F72].  
* **Crypto Exposure (64)** – many legacy RSA‑1024 keys (strength 62) and several keys with non‑standard small exponents reduce cryptographic assurance, plus the symmetric HS