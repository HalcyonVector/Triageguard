**Incident Report** – *Memory image: DESKTOP‑SDN1RPT.mem*  

---  

## Summary  
The analysis identified two **critical** malicious processes injecting executable code into privileged system binaries: `spoolsv.exe` (PID 2188) and `powershell.exe` (PID 3316) [F6][F8]. A **critical** RSA‑512 key (modulus 512‑bit) was also found, which is trivially factorable [F37]. Numerous low‑strength RSA keys (1024‑bit and 2048‑bit with small exponents) are present, indicating weak cryptographic practices [F25][F28][F40]. Network traffic shows TLS connections to several CDN hosts but no weak TLS ciphers were flagged [F48].  

---  

## Cryptography  

| Algorithm | Confidence | Finding(s) | Strength / Issues |
|-----------|------------|------------|-------------------|
| ECC P‑256 | 99.3 % | [F16] | No known weakness |
| AES (CBC) | 98.8 % | [F17] | No issue reported |
| AES‑GCM | 95.5 % | [F18] | No issue reported |
| RSA (generic) | 94.0 % | [F19] | Includes weak keys (see RSA inventory) |
| ECC secp256k1 | 92.8 % | [F20] | No issue reported |
| 3DES | 75.0 % | [F22] | Deprecated algorithm |
| DES | 60.0 % | [F23] | Deprecated algorithm |
| Curve25519 | 40.0 % | [F24] | Low detection confidence |

### RSA key inventory  

- **RSA‑512** (e = 65537) – strength 0 / 100; modulus is publicly factorable [F37].  
- **RSA‑1024** (e = 65537) – 12 keys each scoring 35 / 100 due to insufficient modulus size [F25][F26][F27][F29][F30][F31][F32][F34][F35][F36][F38][F39].  
- **RSA‑2048** (e = 3) – 2 keys scoring 40 / 100 because of a small exponent [F28][F40].  
- Overall RSA summary reports 151 keys without detected weaknesses and 6 corrupt key‑like structures [F41].

### Entropy observations  

High‑entropy regions (potential cryptographic material) total 200 across the image (≈864 KB) [F42]; additional localized high‑entropy blocks are present in the dumped binaries [F43][F45][F46][F47].  

---  

## Credentials  

No credential artifacts (passwords, hashes, tokens) were identified in the supplied findings [F1][F2].  

---  

## Processes and Network  

- The system hosts **95 processes** and **95 command‑line strings** [F1][F2].  
- **Critical injected processes**:  
  - `spoolsv.exe` (PID 2188) contains a RWX memory region with a PE header, indicating a likely injected DLL/EXE [F6].  
  - `powershell.exe` (PID 3316) shows five RWX regions, two with unique executable code and one with a PE header, strongly suggesting malicious injection [F8].  
- A low‑severity RWX region in `MsMpEng.exe` (PID 2404) is attributed to expected JIT activity [F7].  
- The memory image records **7 injected regions** in total [F4].  
- Static dumps of the suspicious regions exhibit varying entropy (e.g., 5.368 for the spoolsv region) but no known crypto imports or YARA matches [F9][F11][F13][F14][F15].  
- Network summary: **115 connections** captured, with **50 distinct conversations**; TLS Server Name Indication (SNI) values include several media CDN hosts (e.g., `64.media.tumblr.com`) and no weak TLS ciphers were flagged [F3][F48].  

---  

## Risk Score (0‑100)  

The rule‑based risk score is **85**; this value already reflects the presence of the critical findings (process injection and broken RSA‑512 key) [F6][F8][F37]. No cited evidence justifies a deviation, so the final risk score remains **85**.  

---  

## Recommendations  

- **Containment** – Immediately isolate the host from the network to stop further exfiltration or lateral movement [F6][F8].  
- **Process remediation** –  
  - Terminate the injected `spoolsv.exe` and `powershell.exe` instances [F6][F8];  
  - Replace the binaries with trusted copies from a clean source [F6][F8];  
  - Perform a full memory dump of the injected RWX regions for deeper malware analysis [F9][F11][F13][F14][F15].  
- **Key management** –  
  - Revoke the RSA‑512 key and all RSA‑1024 keys; generate new RSA‑3072 or RSA‑4096 keys with strong exponents (e ≥ 65537) [F37][F25][F28][F40];  
  - Update all services to use modern algorithms (AES‑GCM, ECC P‑256) and disable deprecated ciphers (3DES, DES) [F22][F23].  
- **Credential hygiene** – Deploy credential‑dump detection tools and enforce strict credential protection policies, even though no credentials were observed in this dump [F1][F2].  
- **Network monitoring** –  
  - Inspect the recorded TLS connections for anomalous data exfiltration to the listed CDNs [F48];  
  - Enforce TLS 1.3 with strong cipher suites across the environment.  
- **System hardening** –  
  - Enable Windows Defender Exploit Guard and configure Controlled Folder Access to block unauthorized code injection [F7];  
  - Regularly audit for RWX memory regions in privileged processes [F4].  
- **Forensic follow‑up** –  
  - Correlate the high‑entropy regions with potential cryptographic keys or payloads [F42][F45][F46][F47];  
  - Conduct static and dynamic analysis of the injected PE files to identify command‑and‑control infrastructure [F9][F11][F13][F14][F15].  

---  

*Prepared by: Malware Triage Analyst*  

## Validation notes (automatic)
Rule-based risk score: 85/100. This report failed these checks, treat the points below as unverified:
- only 88% of claims carry a citation