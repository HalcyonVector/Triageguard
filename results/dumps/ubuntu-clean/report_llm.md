# Incident Report  

## Summary  
The memory image from the Ubuntu lab host was examined, revealing 244 processes and 308 network connections, several cryptographic primitives in use, and one low‑severity injected RWX region in a Python process [F1][F3][F6]. Modern algorithms (AES‑GCM, ChaCha20, Curve25519, ECC) coexist with legacy DES and low‑confidence 3DES, and a single RSA‑2048 key uses a non‑standard small exponent, reducing its effective security [F7][F8][F9][F10][F11][F12][F13][F14][F15][F16]. No high‑severity or critical findings were reported.  

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 100.0% | implementation constants | [F7] |
| Curve25519 | 99.9% | implementation constants | [F8] |
| ECC P‑256 | 99.1% | implementation constants | [F9] |
| AES‑GCM | 97.6% | implementation constants | [F10] |
| ChaCha20/Salsa20 | 95.5% | implementation constants | [F11] |
| ECC secp256k1 | 92.8% | implementation constants | [F12] |
| RSA | 91.0% | implementation constants | [F13] |
| DES | 80.0% | implementation constants | [F14] |
| 3DES | 50.0% | API/string references only | [F15] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 2048 bits | 43147 | 88 | non‑compliant small exponent (FIPS 186‑5) | [F16] |

## Credentials  
No credential artifacts (passwords, hashes, tokens) were extracted from the memory image [F5][F17].  

## Processes and Network  
- The analysis listed 244 processes [F1].  
- It also captured 244 command‑line strings [F2].  
- Network activity comprised 308 connections [F3].  
- One injected code region with RWX permissions was observed in process PID 843, originating from a Python ctypes/cffi callback [F6].  
- Bash history contained 11 entries [F5].  
- No additional injected modules were detected beyond the single entry [F4].  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|----------------|
| **Compromise** | 20 | The only indicator of possible malicious activity is the low‑severity RWX injected region in a Python process (suspicious process) [F6]; no higher‑severity ATT&CK techniques were observed, so the rule‑based compromise score of 20 is retained. |
| **Crypto Exposure** | 20 | Weaknesses include the RSA key with a small exponent (strength 88/100) [F16], the presence of legacy DES [F14] and low‑confidence 3DES [F15], and a large number of high‑entropy regions that may indicate key material but without clear misuse [F18]; these findings justify the rule‑based crypto exposure score of 20. |
| **Overall** | **28** | Sum of the component scores per the provided rule‑based baseline (compromise 20 + crypto 20 = 40, adjusted down by the low severity of findings) [F1][F3][F6][F16][F14][F15][F18]. |

## Recommendations  

- **Rotate the RSA‑2048 key with the small exponent** and generate a new key using a standard public exponent (e = 65537) to meet FIPS 186‑5 requirements [F16].  
- **Deprecate DES and 3DES** in all applications; replace them with AES‑GCM or ChaCha20‑Poly1305 [F14][F15].  
- **Audit the Python process (PID 843) for unnecessary RWX memory regions** and refactor code to avoid libffi closure trampolines, reducing the attack surface [F6].  
- **Enforce least‑privilege execution policies** for processes that load native extensions, limiting write‑execute permissions on memory pages [F6].  
- **Continuously monitor network activity** for anomalous connections, especially given the 308 observed sockets, and correlate with known baselines [F3].  
- **Validate entropy sources** used for key generation; the 200 high‑entropy regions indicate sufficient randomness but should be verified against approved CSPRNGs [F18].  