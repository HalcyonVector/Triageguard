# Incident Report  

## Summary  
A memory image from a Windows workstation shows multiple signs of malicious activity.  
- A high‑severity injected code region was found in **RuntimeBroker.exe** (PID 7068) with a RWX memory page containing unique executable code, matching ATT&CK technique **T1055 – Process Injection**【F7】.  
- Numerous low‑severity processes also contain RWX injected regions (SearchApp.exe, smartscreen.ex, OneDrive.exe, WWAHost.exe)【F6】【F8】【F9】【F10】, and a Chrome installer is executing from a user‑writable folder【F11】.  
- Crypto analysis reveals the presence of a single AES implementation (100 % confidence)【F23】 and a large set of weak RSA keys, many 1024‑bit with 80‑bit security and several keys using non‑standard small exponents (e = 3)【F33‑F63】.  
- The system hosts 127 processes, 127 command‑line entries, and 86 network connections【F1】【F2】【F3】.  

These artifacts indicate a compromised host with active code injection and extensive use of legacy, non‑compliant cryptographic material.

---

## Cryptography  

### Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 100.0% | implementation constants | F23 |

### RSA Keys  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F33 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F34 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F35 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F36 |
| 2048 bit | 3 | 88 | small exponent (non‑compliant) | F38 |
| 1536 bit | 65537 | 62 | modulus size (legacy, disallowed) | F39 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F40 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F41 |
| 2048 bit | 3 | 88 | small exponent (non‑compliant) | F42 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F43 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F44 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F45 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F46 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F47 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F49 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F50 |
| 2048 bit | 3 | 88 | small exponent (non‑compliant) | F51 |
| 4096 bit | 3 | 100 | small exponent (non‑compliant) | F52 |
| 2048 bit | 3 | 88 | small exponent (non‑compliant) | F53 |
| 2048 bit | 3 | 88 | small exponent (non‑compliant) | F54 |
| 2048 bit | 3 | 88 | small exponent (non‑compliant) | F55 |
| 2048 bit | 43147 | 88 | non‑standard exponent (non‑compliant) | F56 |
| 4096 bit | 3 | 100 | small exponent (non‑compliant) | F57 |
| 4096 bit | 3 | 100 | small exponent (non‑compliant) | F58 |
| 2048 bit | 3 | 88 | small exponent (non‑compliant) | F59 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F60 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F61 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F62 |
| 1024 bit | 65537 | 62 | modulus size (legacy, disallowed) | F63 |

---

## Credentials  
No credential artifacts (passwords, hashes, tokens) were extracted from the memory image.  

---

## Processes and Network  

- **Process inventory:** 127 processes observed【F1】.  
- **Command‑line snapshot:** 127 distinct command‑line strings captured【F2】.  
- **Network activity:** 86 network rows (connections, sockets) present【F3】.  

### Suspicious Processes  

| PID | Process | Issue | ATT&CK Technique | Finding |
|-----|---------|-------|------------------|---------|
| 7068 | RuntimeBroker. | RWX injected region with unique code | T1055 – Process Injection | F7 |
| 2128 | SearchApp.exe | RWX region; code shared across 3 processes (system‑wide hook) | T1055 | F6 |
| 7484 | smartscreen.ex | Multiple RWX regions; some unique code | T1055 | F8 |
| 7780 | OneDrive.exe | RWX region starting with zero bytes (potential placeholder) | T1055 | F9 |
| 5912 | WWAHost.exe | RWX region; shared code hook | T1055 | F10 |
| 4628 | ChromeSetup.ex | Executable run from user‑writable Downloads folder | – | F11 |

---

## Risk Score  

- **Overall risk score:** **82** (rule‑based)【Rule‑based risk score】.  
- **Compromise component:** **80** – justified by the high‑severity injected RuntimeBroker process (F7) and multiple additional injected regions (F6‑F10) indicating active exploitation【F7】【F6】【F8】【F9】【F10】.  
- **Crypto exposure component:** **20** – driven by the abundance of weak RSA keys (strength 62–88, many 1024‑bit, small exponents)【F33‑F63】 and the presence of only a single AES implementation (F23). No evidence suggests the score should be adjusted beyond the rule‑based values.

---

## Recommendations  

- **Terminate and investigate the injected RuntimeBroker process** (PID 7068) and any other processes with RWX memory pages (SearchApp.exe, smartscreen.ex, OneDrive.exe, WWAHost.exe)【F7】【F6】【F8】【F9】【F10】.  
- **Conduct a full malware scan** and collect forensic images of the affected processes to identify the payload and its persistence mechanisms.  
- **Enforce DEP and ASLR** system‑wide; block execution from writable directories to prevent user‑downloaded binaries like ChromeSetup.exe from running【F11】.  
- **Replace all RSA‑1024 keys** with RSA‑2048 or RSA‑3072 keys using the standard exponent 65537; deprecate any keys with exponent 3 or other non‑standard values【F33‑F63】.  
- **Re‑issue certificates or tokens** that rely on the weak RSA keys to eliminate legacy cryptographic exposure.  
- **Audit application code** for hard‑coded cryptographic constants; ensure only approved algorithms (e.g., AES with secure key sizes) are used【F23】.  
- **Monitor network connections** for anomalous outbound traffic from the compromised host (86 rows observed)【F3】 and apply host‑based intrusion detection rules for process‑injection patterns.  
- **Update all software** to the latest patches, especially components that may be targeted for code injection (e.g., RuntimeBroker, SearchApp, smartscreen).  

Implementing these actions will mitigate the immediate compromise, reduce the attack surface, and bring the cryptographic posture into compliance with modern security standards.

## Validation notes (automatic)
Rule-based risk score: 82/100. This report failed these checks, treat the points below as unverified:
- only 86% of claims carry a citation