# Incident Report  

**Date:** 2026‑10‑06  

---  

## Summary  
Memory analysis of the compromised host revealed multiple processes with RWX‑injected memory regions that share identical code, indicating a system‑wide hooking mechanism (e.g., code injection into `svchost.exe`, `explorer.exe`, `wmpnetwk.exe`, `notepad.exe`, and a shell launched by `vmtoolsd.exe`) [F6] [F7] [F8] [F9] [F10] [F11].  
Cryptographic artefacts include a range of algorithms (ECC, AES, RSA, etc.) and a large number of low‑strength RSA keys (mostly 1024‑bit, some with small exponents) [F19]‑[F27] [F28]‑[F53] [F57].  
No high‑severity credentials or network connections were flagged, but the presence of many injected regions and weak RSA keys raises the overall risk [F1] [F3] [F4] [F5].  

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| ECC P‑256 | 99.8% | implementation constants | [F19] |
| AES | 98.8% | implementation constants | [F20] |
| RSA | 98.2% | implementation constants | [F21] |
| AES‑GCM | 95.5% | API/string references only | [F22] |
| ECC secp256k1 | 92.8% | implementation constants | [F23] |
| generic crypto | 83.2% | API/string references only | [F24] |
| 3DES | 75.0% | API/string references only | [F25] |
| DES | 60.0% | implementation constants | [F26] |
| ChaCha20/Salsa20 | 40.0% | implementation constants | [F27] |

### RSA Keys  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bits | 65537 | 35 | weak modulus size | [F28] |
| 1024 bits | 65537 | 35 | weak modulus size | [F29] |
| 1024 bits | 65537 | 35 | weak modulus size | [F30] |
| 1024 bits | 65537 | 35 | weak modulus size | [F31] |
| 1024 bits | 65537 | 35 | weak modulus size | [F32] |
| 1024 bits | 65537 | 35 | weak modulus size | [F33] |
| 1024 bits | 65537 | 35 | weak modulus size | [F34] |
| 1024 bits | 65537 | 35 | weak modulus size | [F35] |
| 1024 bits | 65537 | 35 | weak modulus size | [F36] |
| 2048 bits | 3 | 40 | small exponent | [F37] |
| 1024 bits | 65537 | 35 | weak modulus size | [F38] |
| 1536 bits | 65537 | 35 | weak modulus size | [F39] |
| 1024 bits | 65537 | 35 | weak modulus size | [F40] |
| 1024 bits | 65537 | 35 | weak modulus size | [F41] |
| 1024 bits | 65537 | 35 | weak modulus size | [F42] |
| 1024 bits | 65537 | 35 | weak modulus size | [F43] |
| 1024 bits | 65537 | 35 | weak modulus size | [F44] |
| 1024 bits | 65537 | 35 | weak modulus size | [F45] |
| 1024 bits | 65537 | 35 | weak modulus size | [F46] |
| 2048 bits | 3 | 40 | small exponent | [F47] |
| 1024 bits | 65537 | 35 | weak modulus size | [F48] |
| 1024 bits | 65537 | 35 | weak modulus size | [F49] |
| 1024 bits | 65537 | 35 | weak modulus size | [F50] |
| 1024 bits | 65537 | 35 | weak modulus size | [F51] |
| 1024 bits | 65537 | 35 | weak modulus size | [F52] |
| 1536 bits | 3 | 10 | weak modulus & small exponent | [F53] |
| 1024 bits | 65537 | 35 | weak modulus size | [F54] |
| 1024 bits | 65537 | 35 | weak modulus size | [F55] |
| 1024 bits | 65537 | 35 | weak modulus size | [F56] |

## Credentials  
No credential artefacts (passwords, hashes, tokens) were reported in the findings [F1] [F2].  

## Processes and Network  

| Category | Detail |
|----------|--------|
| Processes | 42 processes enumerated [F1] |
| Command lines | 42 command‑line strings captured [F2] |
| Network connections | 65 network entries observed [F3] |
| Injected regions summary | 7 injected memory regions identified [F4] |
| USB devices | 13 USB device records logged [F5] |

## Risk Score  
**Score:** **30** (rule‑based baseline) [F1] [F3] [F4] [F5] [F6]‑[F11] [F19]‑[F27] [F28]‑[F53] [F57].  

*Justification:* All findings are rated **low** or **medium** severity; no critical/high‑severity items were present [F6]‑[F11] [F28]‑[F53]. The presence of multiple RWX‑injected regions and a large set of weak RSA keys increases the attack surface but does not, by itself, justify raising the score above the baseline [F19]‑[F27] [F57].  

## Recommendations  

1. **Memory‑forensic deep dive** – Investigate the identical injected code across processes (`svchost.exe`, `explorer.exe`, etc.) to determine the payload and its persistence mechanism [F6] [F7] [F8] [F9] [F10] [F11].  
2. **Terminate and remediate** – Isolate the host, terminate suspicious processes, and remove the injected modules; consider full system re‑image [F6]‑[F11].  
3. **Patch and harden** – Apply all Windows patches; disable unnecessary services that could be leveraged for code injection [F6]‑[F11].  
4. **Key management** – Replace all low‑strength RSA keys (1024‑bit, small exponent) with keys ≥ 3072 bits and a standard exponent 65537, or migrate to elliptic‑curve keys [F28]‑[F53].  
5. **Audit cryptographic usage** – Verify that deprecated algorithms (DES, 3DES, ChaCha20/Salsa20 with low confidence) are not used in production code [F25]‑[F27].  
6. **Network monitoring** – Correlate the 65 network entries with threat intelligence feeds; block any suspicious outbound traffic [F3].  
7. **USB device control** – Review the 13 USB device logs for unauthorized peripherals; enforce strict device‑control policies [F5].  
8. **Continuous monitoring** – Deploy an EDR solution capable of detecting RWX memory allocations and code‑injection patterns to prevent recurrence [F4] [F6]‑[F11].  

---  

*Prepared by:* Malware Triage Analyst  
*All factual statements are cited to the corresponding finding IDs.*