# Incident Report  

**Date:** 2026‑10‑17  
**Analyst:** Malware Triage Team  

---  

## Summary  
The memory image of *DESKTOP‑SDN1RPT* shows clear evidence of compromise:  

* `spoolsv.exe` (PID 2188) contains a RWX‑memory region with a PE header, indicating a injected DLL/EXE and matching ATT&CK **T1055** (Process Injection)【F6】.  
* `powershell.exe` (PID 3316) has five RWX‑memory regions, one of which also contains a PE header; the activity maps to ATT&CK **T1055** and **T1059.001** (PowerShell)【F8】.  
* Numerous weak RSA keys (1024‑bit, 1536‑bit, 2048‑bit with exponent 3, and a 512‑bit broken key) are present in memory, exposing cryptographic material【F25】‑【F40】【F37】.  

These observations justify the supplied rule‑based overall risk score of **96** (Compromise 95, Crypto Exposure 20).  

---  

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 99.9% | implementation constants | 【F16】 |
| ECC P‑256 | 99.0% | implementation constants | 【F17】 |
| AES‑GCM | 95.5% | API/string references only | 【F18】 |
| ECC secp256k1 | 92.8% | implementation constants | 【F19】 |
| RSA | 92.8% | implementation constants | 【F20】 |
| generic crypto | 83.2% | API/string references only | 【F21】 |
| DES | 60.0% | implementation constants | 【F22】 |
| 3DES | 60.0% | API/string references only | 【F23】 |
| Curve25519 | 40.0% | API/string references only | 【F24】 |

### RSA Key Weaknesses  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F25】 |
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F26】 |
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F27】 |
| 2048 bit | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | 【F28】 |
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F29】 |
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F30】 |
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F31】 |
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F32】 |
| 1536 bit | 65537 | 62 | weak size (80‑bit security) | 【F33】 |
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F34】 |
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F35】 |
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F36】 |
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F38】 |
| 1024 bit | 65537 | 62 | weak size (80‑bit security) | 【F39】 |
| 2048 bit | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | 【F40】 |
| 512 bit | 65537 | 0 | broken (0‑bit security) | 【F37】 |

---  

## Credentials  
The findings do not contain any credential artifacts such as passwords, NTLM hashes, or bearer tokens【F1】.  

---  

## Processes and Network  

| Category | Detail | Finding |
|----------|--------|---------|
| Suspicious process | `spoolsv.exe` (PID 2188) has one RWX region (0x1840000) that contains a PE header, indicating injected code【F6】. |
| Suspicious process | `powershell.exe` (PID 3316) has five RWX regions, including one with a PE header; the activity is linked to ATT&CK **T1055** and **T1059.001**【F8】. |
| Expected JIT activity | `MsMpEng.exe` (PID 2404) shows a known JIT RWX region, classified as low severity【F7】. |
| Process inventory | 95 processes were enumerated in the memory image【F1】. |
| Command‑line inventory | 95 command‑line strings were captured【F2】. |
| Network summary | 115 network rows were logged, representing 50 TLS conversations with SNI hosts such as `*.tumblr.com`, `redditmedia.com`, and `optimizely.com`; no weak TLS ciphers were reported【F3】【F48】. |
| USB devices | 32 USB device entries were observed【F5】. |
| Injected memory overview | A total of 7 injected memory rows were identified across the image【F4】. |

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|---------------|
| **Compromise** | **95** | Supported by two **critical** injection findings in `spoolsv.exe` and `powershell.exe` (F6, F8). |
| **Crypto Exposure** | **20** | Driven by the presence of many weak RSA keys (F25‑F40, F37) despite a majority of keys being clean (F41). |
| **Overall** | **96** | The overall score follows the rule‑based value supplied, which aligns with the evidence above. |

---  

## Recommendations  

* **Terminate malicious processes** – Immediately stop `spoolsv.exe` (PID 2188) and `powershell.exe` (PID 3316) to halt the injected payloads【F6】【F8】.  
* **Isolate the host** – Disconnect the workstation from the network to prevent lateral movement【F6】【F8】.  
* **Dump and analyse injected regions** – Extract the RWX memory regions (addresses listed in F6 and F8) for static analysis and IOC extraction【F6】【F8】.  
* **Patch the operating system** – Apply the latest Windows security updates to address known injection vulnerabilities【F6】.  
* **Disable unnecessary services** – If the Print Spooler is not required, disable it to remove the `spoolsv.exe` attack surface【F6】.  
* **Regenerate RSA keys** – Replace all 1024‑bit, 1536‑bit, and 2048‑bit keys with RSA ≥ 3072‑bit keys using a standard exponent (65537) to eliminate the weak keys identified (F25‑F40, F37).  
* **Remove legacy algorithms** – Reconfigure applications to disable DES and 3DES, which were detected (F22, F23).  
* **Enforce strong cryptography** – Prefer AES‑GCM (high confidence) and ECC P‑256 for new implementations; avoid low‑confidence AES usage (F44).  
* **Enable EDR and PowerShell logging** – Deploy endpoint detection and response with alerts for RWX allocations and enable PowerShell script‑block logging to detect future abuse (related to F8).  
* **Review TLS configurations** – Verify that only TLS 1.2/1.3 with strong cipher suites are allowed, even though no weak ciphers were observed (F48).  
* **Credential hygiene** – Although no credentials were found, rotate any service‑account passwords that may have been used by the injected code and store secrets in a protected vault【F1】.  

---  

*All statements are directly supported by the cited findings.*