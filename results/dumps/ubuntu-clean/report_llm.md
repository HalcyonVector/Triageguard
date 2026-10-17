# Incident Report  

**Date:** 2026‑10‑17  

---  

## Summary  
A memory image (`ubuntu‑lab‑Snapshot2.vmem`) was analyzed and the forensic pipeline surfaced several cryptographic primitives, a low‑severity injected Python process, and one RSA‑2048 key with a non‑standard exponent [F7][F6][F16]. No high‑ or critical‑severity findings or ATT&CK technique identifiers were observed. The baseline risk score of **28** (Compromise 20 / Crypto Exposure 20) is applied [F1].  

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
| 2048 bits | 43147 | 88/100 | Small, non‑compliant exponent (FIPS 186‑5) | [F16] |

---  

## Credentials  
No credential artifacts were reported in the findings [F1].  

---  

## Processes and Network  

- The image contains **244** process entries [F1].  
- It also contains **244** command‑line entries [F2].  
- **308** network connection rows were captured [F3].  
- One injected code region was detected (RWX by design) [F4].  
- Bash history includes **11** entries [F5].  
- A low‑severity suspicious injected Python process (PID 843, `unattended‑upgr`) was observed [F6].  

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|---------------|
| **Overall** | **28** | Matches the rule‑based baseline (Compromise 20 + Crypto Exposure 20) [F1]. |
| **Compromise** | **20** | No ATT&CK technique IDs or high‑severity malicious activity were found; the only anomalous process is low severity [F6]. |
| **Crypto Exposure** | **20** | Legacy ciphers (DES, 3DES) and a RSA key with a small exponent are present, but all findings are informational or low severity [F14][F15][F16]. |

---  

## Recommendations  

- **Disable legacy ciphers** – Remove DES and 3DES from all services and replace them with modern AEAD algorithms such as AES‑GCM or ChaCha20‑Poly1305 [F14][F15].  
- **Rotate the RSA key** – Generate a new RSA‑2048 (or larger) key using the standard exponent 65537 to achieve FIPS 186‑5 compliance [F16].  
- **Validate modern algorithm usage** – Ensure that AES‑GCM, Curve25519, ECC P‑256, and secp256k1 are employed with appropriate key lengths and secure modes [F7][F8][F9][F10][F11][F12][F13].  
- **Monitor the injected Python process** – Although classified as low severity, continuously watch PID 843 (`unattended‑upgr`) for any escalation or persistence attempts [F6].  
- **Review network connections** – Examine the 308 captured sockets for unexpected outbound traffic or unusual ports [F3].  
- **Leverage high‑entropy regions** – The image contains 200 high‑entropy regions (~19 MB); ensure cryptographic libraries are seeded from these sources [F18].  
- **Establish regular forensic baselines** – Perform periodic memory captures and compare cryptographic footprints to detect the introduction of weak algorithms or rogue keys [F7][F13].  

---  

*All factual statements are cited to the corresponding finding IDs as required.*
