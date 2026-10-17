# Incident Report  

**Date:** 2026‑10‑17  
**Analyst:** Malware Triage Team  

---  

## Summary  
The memory image `ubuntu‑lab‑Snapshot2.vmem` was examined and produced 18 findings covering processes, network activity, injected code, and a variety of cryptographic artefacts [F1][F2][F3][F4][F5][F6][F7][F8][F9][F10][F11][F12][F13][F14][F15][F16][F17][F18]. No finding was marked **critical** or **high**; the only elevated severity is a low‑severity injected Python ctypes region [F6]. Consequently the overall risk aligns with the rule‑based score of **28** [F6][F14][F15][F16].  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 100.0% | implementation constants | [F7] |
| Curve25519 | 99.9% | implementation constants | [F8] |
| ECC P‑256 | 99.1% | implementation constants | [F9] |
| AES‑GCM | 97.6% | implementation constants | [F10] |
| ChaCha20/Salsa20 | 95.5% | implementation constants | [F11] |
| ECC secp256k1 | 92.8% | implementation constants | [F12] |
| RSA | 91.0% | implementation constants | [F13] |
| DES | 80.0% | implementation constants | [F14] |
| 3DES | 50.0% | API/string references only | [F15] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 2048 bits | 43147 | 88 | non‑compliant exponent (FIPS 186‑5) | [F16] |

*Note:* A bulk summary reported 95 RSA keys without weaknesses [F17]; the only RSA key with a documented issue is the one listed above [F16].  

---  

## Credentials  
No credential artefacts (passwords, hashes, tokens, or secret keys) were reported in the findings [F1][F2][F3][F4][F5][F6][F7][F8][F9][F10][F11][F12][F13][F14][F15][F16][F17][F18].  

---  

## Processes and Network  

- **Processes:** 244 process entries were enumerated [F1].  
- **Command lines:** 244 command‑line entries were captured [F2].  
- **Network:** 308 network rows were observed, indicating normal socket activity [F3].  
- **Injected code:** One RWX injected region associated with a Python `ctypes`/`cffi` closure was found in process `unattended‑upgr` (PID 843) [F6].  
- **Bash history:** 11 bash entries were present [F5].  

No high‑severity or anomalous network connections were identified in the supplied data [F3].  

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|---------------|
| **Overall** | **28** | Matches the rule‑based baseline (Compromise 20 + Crypto Exposure 20) and is not overridden by any cited finding [F6][F14][F15][F16]. |
| **Compromise** | **20** | Only a low‑severity injected Python region was observed [F6]; all other findings are informational [F1][F2][F3][F4][F5][F7][F8][F9][F10][F11][F12][F13][F14][F15][F16][F17][F18]. |
| **Crypto Exposure** | **20** | Presence of deprecated ciphers (DES, 3DES) and a RSA key with a small, non‑compliant exponent reduces crypto hygiene [F14][F15][F16]; the majority of algorithms are strong (AES‑GCM, ChaCha20, Curve25519, ECC) [F7][F8][F9][F10][F11][F12][F13]. |

---  

## Recommendations  

- **Eliminate legacy ciphers** – Remove or disable any code paths that rely on DES or 3DES [F14][F15].  
- **Rotate RSA keys** – Replace the RSA‑2048 key with a stronger exponent (e.g., 65537) or upgrade to RSA‑3072/ECC [F16].  
- **Audit injected code** – Investigate the purpose of the Python `ctypes`/`cffi` closure in `unattended‑upgr` (PID 843) to confirm it is legitimate and not a foothold [F6].  
- **Monitor process activity** – Deploy continuous EDR alerts for RWX memory regions and unexpected library injections (process injection) [F6][F1].  
- **Strengthen entropy sources** – Verify that cryptographic libraries are using system CSPRNGs, given the 200 high‑entropy regions identified [F18].  
- **Update cryptographic libraries** – Ensure the latest, vetted implementations of AES‑GCM, ChaCha20, Curve25519, and ECC P‑256 are in use and deprecate any custom or hard‑coded constants [F7][F8][F9][F10][F11][F12][F13].  

---  

*Prepared by the Malware Triage Analyst team.*

## Validation notes (automatic)
Rule-based risk score: 28/100. This report failed these checks, treat the points below as unverified:
- only 85% of claims carry a citation