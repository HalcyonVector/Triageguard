# Incident Report  

## Summary  
The memory image contains a large number of weak RSA keys, including a **critical RSA‑512 key** that provides effectively no security [F110]. Numerous additional RSA‑1024, RSA‑2048 (with a non‑standard exponent 3), and RSA‑1536 keys are present, all flagged as low‑severity but collectively representing a serious cryptographic exposure. Several system processes (csrss.exe, winlogon.exe, lsass.exe, soffice.bin) show injected RWX memory regions, indicating possible code‑injection activity, though each is rated low severity [F6][F7][F8][F9]. No explicit credential or network artifacts were reported.  

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA‑512 | 100% | implementation constants | [F110] |
| RSA‑1024 | 100% | implementation constants | [F30][F31][F32][F33][F34][F35][F36][F37][F38][F40][F41][F42][F43][F44][F45][F46][F47][F48][F49][F50][F51][F54][F55][F56][F57][F58][F59][F62][F64][F65][F66][F67][F68][F69][F70] |
| RSA‑2048 (e = 3) | 100% | implementation constants | [F39][F52][F53][F61][F61] |
| RSA‑1536 | 100% | implementation constants | [F60] |

*Confidence reflects the certainty that the algorithm was identified in the memory image (derived from direct API/string references).  

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | broken (publicly factorable) | [F110] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F30] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F31] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F32] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F33] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F34] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F35] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F36] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F37] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F38] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F40] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F41] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F42] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F43] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F44] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F45] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F46] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F47] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F48] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F49] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F50] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F51] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F54] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F55] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F56] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F57] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F58] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F59] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F62] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F64] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F65] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F66] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F67] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F68] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F69] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F70] |
| 2048 bits | 3 | 88 | non‑compliant exponent (FIPS 186‑5) | [F39] |
| 2048 bits | 3 | 88 | non‑compliant exponent (FIPS 186‑5) | [F52] |
| 2048 bits | 3 | 88 | non‑compliant exponent (FIPS 186‑5) | [F53] |
| 2048 bits | 3 | 88 | non‑compliant exponent (FIPS 186‑5) | [F61] |
| 1536 bits | 65537 | 62 | legacy size, disallowed | [F60] |

## Credentials  
No credential artifacts were reported in the findings.  

## Processes and Network  
- **csrss.exe (PID 924)** – one RWX injected heap region detected [F6].  
- **winlogon.exe (PID 948)** – multiple RWX injected heap regions and zero‑filled regions [F7].  
- **lsass.exe (PID 1004)** – one RWX injected zero‑filled region [F8].  
- **soffice.bin (PID 3088)** – one RWX region containing runtime call thunks and a C++ bridge vtable [F9].  

No network connections or listeners were identified in the supplied findings.  

## Risk Score  

- **Overall Risk Score:** **42** (rule‑based value) – no finding provides a clear, cited justification to adjust the overall score.  
- **Compromise (20/100):** The injected RWX regions in critical system processes suggest possible code‑injection activity, but each finding is low severity; therefore the compromise component remains at the rule‑based 20, justified by the low‑severity process findings [F6][F7][F8][F9].  
- **Crypto Exposure (55/100):** The presence of a critical RSA‑512 key (strength 0) and dozens of legacy RSA‑1024 keys (strength 62) significantly degrades cryptographic posture. This aligns with the rule‑based crypto exposure of 55, supported by the extensive RSA findings [F110][F30‑F70].  

## Recommendations  

- **Immediate key rotation** for the RSA‑512 key and any RSA‑1024 keys used in production; replace with RSA‑3072 or ECC P‑256+ keys [F110][F30‑F70].  
- **Enforce minimum RSA key size** of 2048 bits with a public exponent of 65537; reject keys with exponent 3 [F39][F52][F53][F61].  
- **Deprecate legacy cryptographic libraries** that generate RSA‑1024 keys; update applications to use modern APIs (e.g., CNG, OpenSSL ≥ 1.1.1) [F30‑F70].  
- **Investigate the injected RWX regions** in csrss.exe, winlogon.exe, lsass.exe, and soffice.bin for possible malware payloads; consider memory forensics to extract shellcode and correlate with known ATT&CK techniques such as *Process Injection* (T1055) [F6][F7][F8][F9].  
- **Implement runtime integrity controls** (e.g., Windows Defender Application Control, Code Integrity) to prevent unauthorized memory modifications.  
- **Conduct a full credential dump** and network traffic capture to verify whether the weak keys have been used to encrypt or sign malicious communications.  

---  
