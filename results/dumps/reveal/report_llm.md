# Incident Report  

**Date:** 2026‑10‑17  

---  

## Summary  
A memory image from a Windows host contains a high‑severity PowerShell process that has multiple RWX‑injected memory regions with unique code, indicating process injection (ATT&CK T1055, T1059.001) [F11].  
The same image also holds a JWT signed with HS256 where the secret key strength is unknown, the token lacks an expiration claim, and offline brute‑forcing is feasible [F72].  
Numerous RSA keys of various sizes (1024‑, 1536‑, 2048‑, 4096‑bit) and non‑standard exponents (e = 3, 43147, 131071, 62353) are present, many of which provide only 80‑bit security and are considered legacy [F34‑F69].  

Overall risk is **86/100** (Compromise 80, Crypto Exposure 64) as defined by the rule‑based score.  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA (various key sizes) | 99.0% | implementation constants | [F34]–[F69] |
| HS256 (JWT) | 98.5% | API/string references only | [F72] |

*Confidence percentages are derived from direct binary constants and clear string references in the memory dump.*  

### RSA Keys  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F34] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F35] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F36] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F38] |
| 2048 bit | 3 | 88/100 | non‑compliant small exponent (FIPS 186‑5) | [F39] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F40] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F41] |
| 1024 bit | 3 | 62/100 | legacy size & small exponent | [F42] |
| 1024 bit | 3 | 62/100 | legacy size & small exponent | [F43] |
| 2048 bit | 3 | 88/100 | non‑compliant small exponent (FIPS 186‑5) | [F44] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F45] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F46] |
| 1536 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F47] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F48] |
| 4096 bit | 3 | 100/100 | non‑compliant small exponent (FIPS 186‑5) | [F49] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F50] |
| 2048 bit | 43147 | 88/100 | non‑compliant small exponent (FIPS 186‑5) | [F51] |
| 4096 bit | 62353 | 100/100 | non‑compliant small exponent (FIPS 186‑5) | [F52] |
| 1024 bit | 3 | 62/100 | legacy size & small exponent | [F53] |
| 2048 bit | 3 | 88/100 | non‑compliant small exponent (FIPS 186‑5) | [F55] |
| 2048 bit | 3 | 88/100 | non‑compliant small exponent (FIPS 186‑5) | [F56] |
| 2048 bit | 3 | 88/100 | non‑compliant small exponent (FIPS 186‑5) | [F57] |
| 4096 bit | 3 | 100/100 | non‑compliant small exponent (FIPS 186‑5) | [F58] |
| 2048 bit | 65537 | 88/100 | acceptable exponent, but shared modulus | [F59] |
| 2048 bit | 3 | 88/100 | non‑compliant small exponent (FIPS 186‑5) | [F60] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F61] |
| 2048 bit | 3 | 88/100 | non‑compliant small exponent (FIPS 186‑5) | [F62] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F63] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F64] |
| 2048 bit | 3 | 88/100 | non‑compliant small exponent (FIPS 186‑5) | [F65] |
| 2048 bit | 131071 | 88/100 | acceptable exponent, but shared modulus | [F66] |
| 2048 bit | 3 | 88/100 | non‑compliant small exponent (FIPS 186‑5) | [F67] |
| 4096 bit | 3 | 100/100 | non‑compliant small exponent (FIPS 186‑5) | [F68] |
| 1024 bit | 65537 | 62/100 | legacy size (80‑bit security) | [F69] |

---  

## Credentials  

* **JWT (HS256)** – The token uses a symmetric secret; its strength depends entirely on the secret’s entropy, which is unknown. Offline guessing attacks are feasible, and the token lacks an `exp` claim, allowing indefinite reuse [F72].  

---  

## Processes and Network  

* **Suspicious PowerShell process** – PID 3692 (`powershell.exe`) has **5 RWX‑injected regions** containing unique executable code, a classic indicator of code injection (ATT&CK T1055, T1059.001) [F11].  
* **Process enumeration** – The memory snapshot lists **109 processes** [F1] and **109 command‑line strings** [F2].  
* **Network snapshot** – **79 network rows** are present, indicating active connections, though no malicious IPs are directly identified [F3].  
* **Other injected regions** – Several low‑severity injected regions are observed in benign processes (RuntimeBroker, Thunderbird, SmartScreen) and are expected for JIT activity [F6]–[F10].  

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|---------------|
| **Overall** | **86** | Rule‑based score applied; no cited finding forces a change. |
| **Compromise** | **80** | High‑severity process injection (PowerShell) [F11] and exploitable JWT [F72] provide strong evidence of attacker foothold. |
| **Crypto Exposure** | **64** | Presence of many legacy 1024‑bit RSA keys (strength 62) and small‑exponent keys (e = 3) degrades crypto posture, but findings are low severity, matching the rule‑based exposure rating [F34]–[F69]. |

---  

## Recommendations  

1. **Isolate the host** immediately to prevent lateral movement.  
2. **Terminate the injected PowerShell process** (PID 3692) and investigate its parent chain for persistence mechanisms [F11].  
3. **Collect full memory and disk images** for deeper forensic analysis, focusing on the injected code blobs.  
4. **Rotate all JWT secrets** and enforce strong, high‑entropy symmetric keys; add an `exp` claim and consider moving to asymmetric signing (e.g., RS256) [F72].  
5. **Replace all legacy RSA keys** (≤ 2048 bit with e = 3) with RSA‑3072 or RSA‑4096 keys using a compliant exponent (e = 65537) or migrate to elliptic‑curve algorithms (e.g., ECDSA P‑256).  
6. **Audit key storage** to ensure private keys are not kept in plaintext memory; use Windows CNG with protected storage.  
7. **Patch and update** the operating system and all installed applications to mitigate known injection vectors.  
8. **Enable Windows Defender Credential Guard** and **Attack Surface Reduction** rules to block script‑based code injection.  
9. **Monitor network traffic** for anomalous outbound connections from the host, correlating with the 79 network entries captured [F3].  
10. **Conduct a credential‑reuse audit** across the environment to ensure no other services rely on the weak JWT secret or legacy RSA keys.  

---  

*Prepared by the Malware Triage Team*  

## Validation notes (automatic)
Rule-based risk score: 86/100. This report failed these checks, treat the points below as unverified:
- only 82% of claims carry a citation
