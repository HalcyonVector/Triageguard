# Incident Report  

**Date:** 2026‑10‑06  
**Analyst:** Malware Triage Team  

---  

## Summary  
The memory image of *DESKTOP‑SDN1RPT* shows two critical injected processes—`spoolsv.exe` (PID 2188) and `powershell.exe` (PID 3316)—both containing RWX regions with PE headers, indicating malicious DLL/EXE injection [F6][F8]. A 512‑bit RSA key with exponent 65537 is present and is publicly factorable, representing a critical cryptographic weakness [F37]. Numerous additional low‑strength RSA keys (1024‑bit, 1536‑bit, and 2048‑bit with small exponent) are also found, suggesting the host was used for weak or illicit cryptographic operations [F25][F28][F33]. Cryptographic primitives such as ECC P‑256, AES, AES‑GCM, RSA, secp256k1, 3DES, DES, and Curve25519 are detected throughout the memory image [F16][F17][F18][F19][F20][F22][F23][F24]. Network captures reveal TLS connections to several media‑hosting domains, but no strong TLS configuration is reported [F48].  

---  

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| ECC P‑256 | 99.3% | implementation constants | [F16] |
| AES | 98.8% | implementation constants | [F17] |
| AES‑GCM | 95.5% | API/string references only | [F18] |
| RSA | 94.0% | implementation constants | [F19] |
| ECC secp256k1 | 92.8% | implementation constants | [F20] |
| generic crypto | 83.2% | API/string references only | [F21] |
| 3DES | 75.0% | API/string references only | [F22] |
| DES | 60.0% | implementation constants | [F23] |
| Curve25519 | 40.0% | API/string references only | [F24] |

### RSA Keys  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | modulus size (publicly factorable) | [F37] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F25] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F26] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F27] |
| 2048 bits | 3 | 40 | small exponent | [F28] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F29] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F30] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F31] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F32] |
| 1536 bits | 65537 | 35 | modulus size (weak) | [F33] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F34] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F35] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F36] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F38] |
| 1024 bits | 65537 | 35 | modulus size (weak) | [F39] |
| 2048 bits | 3 | 40 | small exponent | [F40] |

---  

## Credentials  
No credential artifacts (passwords, hashes, tokens) were extracted from the memory image [F1][F2].  

---  

## Processes  

- `spoolsv.exe` (PID 2188) contains a RWX injected region with a PE header, indicating a likely malicious DLL/EXE injection [F6].  
- `powershell.exe` (PID 3316) has five RWX injected regions, two of which contain PE headers and two with unique executable code, strongly suggesting malicious code injection [F8].  
- `MsMpEng.exe` (PID 2404) shows an RWX region identified as a known JIT process; this behavior is expected and not flagged as malicious [F7].  
- The full process list comprises 95 entries [F1].  

---  

## Network  

- The memory image records 115 network rows, representing 50 distinct conversations [F3].  
- TLS Server Name Indication (SNI) values include `64.media.tumblr.com`, `66.media.tumblr.com`, `78.media.tumblr.com`, `a.thumbs.redditmedia.com`, and `a125375509.cdn.optimizely.com`, indicating outbound HTTPS traffic to content‑delivery networks [F48].  
- The analysis notes “weak TLS []”, suggesting that strong TLS configurations were not observed [F48].  

---  

## Risk Score  

The provided rule‑based risk score is **85**. This baseline already accounts for the critical injected processes and the broken RSA‑512 key, and no cited finding justifies a different value, so the score is retained.  

---  

## Recommendations  

- **Isolate the host** from the network to stop further lateral movement or data exfiltration [F6][F8].  
- **Terminate and remove** the injected `spoolsv.exe` and `powershell.exe` instances; capture a full memory dump for deeper analysis [F6][F8].  
- **Re‑image the system** after confirming removal of all malicious artifacts, as the presence of numerous weak RSA keys indicates possible illicit cryptographic activity [F25][F28][F33].  
- **Update and harden TLS configurations** on all outbound connections; enforce TLS 1.2/1.3 with strong cipher suites to mitigate potential downgrade attacks [F48].  
- **Conduct a full forensic investigation** of the filesystem and registry to locate persistence mechanisms (e.g., scheduled tasks, startup entries) that may have loaded the malicious modules [F4][F5].  
- **Monitor network traffic** for additional connections to the listed SNI domains and any unknown external IPs; consider blocking unnecessary outbound traffic [F48].  
- **Review and rotate any credentials** that may have been used on the compromised host, even though none were found in memory, to eliminate the risk of credential reuse [F1][F2].  

---  

*End of Report*  