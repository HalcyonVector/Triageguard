# Incident Report  

**Date:** 2026‑10‑17  

---  

## Summary  
The memory image contains five processes that invoke the Python `cryptography` library and include the word “encrypt” on their command lines, matching ATT&CK technique **T1486 – Data Encrypted for Impact** [F7]. A high‑severity RSA‑2048 key with exponent e = 3 was found in the `legacy_rsa` process, which is non‑compliant with FIPS 186‑5 and vulnerable to Hastad broadcast attacks [F27]. Two additional RSA keys with small exponents were identified, and private keys for `keysvc` and `legacy_rsa` were recovered from residual prime data, allowing decryption of any data encrypted with those keys [F21][F26][F28]. Symmetric keys for AES‑256 were also extracted from `updater` and `keysvc` [F29][F30]. Deprecated ciphers DES and 3DES appear in the memory image [F18][F20].  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 100.0% | implementation constants | [F12] |
| Curve25519 | 99.7% | implementation constants | [F13] |
| ECC P‑256 | 99.1% | implementation constants | [F14] |
| AES‑GCM | 97.6% | implementation constants | [F15] |
| ChaCha20/Salsa20 | 95.5% | implementation constants | [F16] |
| ECC secp256k1 | 92.8% | implementation constants | [F17] |
| DES | 80.0% | implementation constants | [F18] |
| RSA | 70.0% | implementation constants | [F19] |
| 3DES | 50.0% | API/string references only | [F20] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 2048 bits | 3 | 88 | small exponent (vulnerable to Hastad attacks) | [F27] |
| 2048 bits | 43 147 | 88 | small exponent (non‑compliant) | [F21] |

---  

## Credentials  
No plaintext credentials, tokens, or password hashes were recovered from the memory image [F4].  

---  

## Processes and Network  

* The snapshot lists **252 processes** [F1].  
* **252 command‑line strings** were captured [F2].  
* **299 network entries** (sockets, connections) were observed [F3].  
* One RWX injected region (libffi closure trampolines) was found in PID 931, which is typical for Python ctypes/cffi usage [F6].  
* Bash history contains **15 entries** [F5].  

### Encryption‑Related Processes  

| PID | Process | Observation | ATT&CK |
|-----|---------|-------------|--------|
| 1275 | `updater` | Command line includes “encrypt” and imports `cryptography.hazmat.primitives` | T1486 [F7] |
| 1276 | `syncd` | Same pattern as above | T1486 [F8] |
| 1277 | `keysvc` | Same pattern as above | T1486 [F9] |
| 1278 | `legacy_rsa` | Same pattern as above | T1486 [F10] |
| 1279 | `python3` (generic) | Same pattern as above | T1486 [F11] |

### Key Recovery  

* Private RSA‑2048 key of `keysvc` (PID 1277) was reconstructed from a residual prime, enabling decryption of data encrypted with that key [F26].  
* Private RSA‑2048 key of `legacy_rsa` (PID 1278) was similarly reconstructed [F28].  
* AES‑256 key of `updater` (PID 1275) was extracted from its expanded key schedule [F29].  
* Two copies of the AES‑256 key of `keysvc` (PID 1277) were extracted [F30].  

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|---------------|
| **Overall** | 67 | The supplied rule‑based score is 67 (Compromise 55, Crypto Exposure 55) [F1]. |
| **Compromise** | 55 | Multiple processes are performing encryption with suspicious command lines and match ATT&CK T1486, indicating possible ransomware activity [F7][F8][F9][F10][F11]. |
| **Crypto Exposure** | 55 | Presence of RSA keys with small exponents, recovered private keys, and deprecated ciphers (DES, 3DES) increase the likelihood of successful decryption by an adversary [F27][F21][F18][F20]. |

---  

## Recommendations  

1. **Regenerate RSA keys** with a compliant exponent (e = 65537) and replace the vulnerable keys [F27][F21].  
2. **Securely erase residual key material** by zero‑ing memory after use and employing `mlock`/`munlock` to prevent key leakage [F26][F28][F29][F30].  
3. **Disable DES and 3DES** in all libraries and configurations; enforce modern ciphers such as AES‑GCM or ChaCha20 [F18][F20].  
4. **Deploy endpoint detection** that flags processes loading `cryptography` modules with “encrypt” in the command line and correlates with ATT&CK T1486 [F7][F8][F9][F10][F11].  
5. **Review network activity** for the 299 observed connections and block any outbound traffic from the suspicious processes [F3].  
6. **Patch cryptographic libraries** to the latest versions and enable FIPS‑mode where required [F12][F13][F14][F15][F16][F17].  
7. **Audit injected code regions** even when they appear legitimate (e.g., PID 931) to ensure no malicious payloads are present [F6].  

---  

*Prepared by the Malware Triage Analyst*  

## Validation notes (automatic)
Rule-based risk score: 67/100. This report failed these checks, treat the points below as unverified:
- only 88% of claims carry a citation