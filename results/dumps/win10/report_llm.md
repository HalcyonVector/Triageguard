# Incident Report  

## Summary  
Memory analysis of host **DESKTOP‑SDN1RPT** identified two critical‑severity processes with injected executable code, indicating process injection (ATT&CK T1055) and, for PowerShell, script execution (ATT&CK T1059.001) [F6][F8].  A large collection of legacy RSA keys (1024‑bit, 2048‑bit with small exponent, and a 512‑bit key) was found, all scoring low on strength and violating modern cryptographic standards [F25][F26][F27][F28][F29][F30][F31][F32][F33][F34][F35][F36][F37][F38][F39][F40].  Network capture shows outbound TLS connections to several CDN hosts without weak cipher usage [F48].  The rule‑based overall risk score of **96** (Compromise 95, Crypto Exposure 20) is consistent with the evidence [F6][F8][F25][F37][F48].

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 99.9% | implementation constants | [F16] |
| ECC P‑256 | 99.0% | implementation constants | [F17] |
| AES‑GCM | 95.5% | API/string references only | [F18] |
| ECC secp256k1 | 92.8% | implementation constants | [F19] |
| RSA | 92.8% | implementation constants | [F20] |
| generic crypto | 83.2% | API/string references only | [F21] |
| DES | 60.0% | implementation constants | [F22] |
| 3DES | 60.0% | API/string references only | [F23] |
| Curve25519 | 40.0% | API/string references only | [F24] |

### RSA Key Inventory  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F25] |
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F26] |
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F27] |
| 2048 bit | 3 | 88 | small exponent (non‑compliant) | [F28] |
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F29] |
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F30] |
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F31] |
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F32] |
| 1536 bit | 65537 | 62 | modulus size (legacy) | [F33] |
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F34] |
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F35] |
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F36] |
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F38] |
| 1024 bit | 65537 | 62 | modulus size (legacy) | [F39] |
| 2048 bit | 3 | 88 | small exponent (non‑compliant) | [F40] |
| 512 bit  | 65537 | 0  | modulus size (broken) | [F37] |

## Credentials  
No credential artifacts (passwords, hashes, tokens) were reported in the extracted findings [F1].

## Processes and Network  

* **Suspicious processes** – `spoolsv.exe` (PID 2188) contains one RWX region with a PE header, indicating a likely injected DLL/EXE [F6].  
* `powershell.exe` (PID 3316) contains five RWX regions, two of which hold PE headers and two with unique executable code, confirming injection and script execution [F8].  

* **Network activity** – 115 network rows were logged, summarised as 50 TLS conversations to CDN hosts such as `64.media.tumblr.com` and `a.thumbs.redditmedia.com`; no weak TLS ciphers were observed [F3][F48].

## Risk Score  

| Component | Score | Justification |
|-----------|-------|----------------|
| **Compromise** | **95** | Critical process‑injection findings (spoolsv.exe and powershell.exe) drive a high compromise likelihood [F6][F8]. |
| **Crypto Exposure** | **20** | Presence of many legacy RSA keys (1024‑bit, 512‑bit, small exponent) lowers cryptographic posture, matching the baseline exposure rating [F25][F26][F27][F28][F29][F30][F31][F32][F33][F34][F35][F36][F37][F38][F39][F40]. |
| **Overall** | **96** | Sum of the two component scores as defined by the rule‑based model [F6][F8][F25][F37][F48]. |

The scores align with the provided rule‑based values; no contradictory evidence was found to adjust them.

## Recommendations  

* **Terminate and investigate injected processes** – stop `spoolsv.exe` and `powershell.exe`, capture full memory dumps for deeper analysis of the injected payloads [F6][F8].  
* **Apply system hardening** – install all OS and application patches, enable Windows Defender Credential Guard, and enforce policies that prevent RWX memory allocations for untrusted binaries [F6][F8].  
* **Replace all legacy RSA keys** – generate new RSA‑3072 or ECC (P‑256) keys, retire every 1024‑bit and 512‑bit key, and avoid small public exponents (e = 3) [F25][F26][F27][F28][F29][F30][F31][F32][F33][F34][F35][F36][F37][F38][F39][F40].  
* **Deprecate weak symmetric algorithms** – discontinue use of DES and 3DES; migrate any remaining services to AES‑GCM or AES‑CBC with proper key management [F22][F23].  
* **Validate TLS configurations** – ensure all outbound TLS connections use strong cipher suites (e.g., TLS 1.3, AES‑GCM) and that server certificates are properly validated [F48].  
* **Deploy EDR for code‑injection detection** – use endpoint detection and response tools that alert on RWX memory regions and unexpected PE headers in process address spaces [F6][F8].  
* **Review high‑entropy memory regions** – examine the 200 high‑entropy regions identified in the host memory for possible leakage of cryptographic material [F42].  

Implementing these actions will mitigate the immediate compromise vectors and reduce the long‑term cryptographic risk.