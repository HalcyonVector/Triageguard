# Incident Report  

**Date:** 2026‑10‑17  

---  

## Summary  
A memory image from a Windows workstation shows multiple suspicious processes with injected RWX memory regions, most notably `RuntimeBroker.` (PID 7068) that contains unique executable code (ATT&CK T1055) [F7].  The system also contains a large number of legacy RSA keys, many of which are 1024‑bit or use non‑standard small exponents, reducing cryptographic strength [F33‑F63].  No clear credential leakage was observed.  

Overall risk score is **82** (Compromise 80, Crypto Exposure 20) as defined by the rule‑based scoring, and the evidence supports this rating.  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 100.0% | implementation constants | F23 |

### RSA Keys  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F33 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F34 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F35 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F36 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | F38 |
| 1536 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F39 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F40 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F41 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | F42 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F43 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F44 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F45 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F46 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F47 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F49 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F50 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | F51 |
| 4096 bits | 3 | 100 | Small exponent (non‑compliant) | F52 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | F53 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | F54 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | F55 |
| 2048 bits | 43147 | 88 | Small exponent (non‑compliant) | F56 |
| 4096 bits | 3 | 100 | Small exponent (non‑compliant) | F57 |
| 4096 bits | 3 | 100 | Small exponent (non‑compliant) | F58 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | F59 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F60 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F61 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F62 |
| 1024 bits | 65537 | 62 | 80‑bit security (legacy, disallowed) | F63 |

---  

## Credentials  
No credential artifacts (passwords, hashes, tokens) were identified in the memory image.  

---  

## Processes and Network  

| Category | Details | Finding |
|----------|---------|---------|
| Total processes | 127 process entries captured | F1 |
| Command‑line strings | 127 command‑line records captured | F2 |
| Network connections | 86 network rows captured (no obvious malicious endpoints) | F3 |
| Injected memory regions | 11 injected regions overall | F4 |
| USB devices | 28 USB device records observed | F5 |
| **High‑severity suspicious process** | `RuntimeBroker.` (PID 7068) has 1 RWX injected region with unique executable code – indicative of process injection (ATT&CK T1055) | F7 |
| Other suspicious processes (low severity) | `SearchApp.exe` (PID 2128), `smartscreen.ex` (PID 7484), `OneDrive.exe` (PID 7780), `WWAHost.exe` (PID 5912) each show RWX regions or unusual memory patterns | F6, F8, F9, F10 |
| Unusual executable location | `ChromeSetup.ex` runs from user‑writable `C:\Users\alex\Downloads\ChromeSetup.exe` | F11 |
| Static binary analysis – entropy & imports | Various dumped VAD regions show low entropy and no crypto imports, suggesting packed or custom code | F12‑F21, F22 |
| Crypto algorithm detection | AES identified via implementation constants | F23 |

---  

## Risk Score  

**Overall Risk Score:** **82** (Rule‑based)  

- **Compromise (80)** – Justified by the presence of a high‑severity injected RWX region in a trusted system process (`RuntimeBroker.`) and multiple other processes with injected code, matching ATT&CK T1055 [F7, F6, F8, F9, F10].  
- **Crypto Exposure (20)** – Numerous legacy RSA keys (1024‑bit) and keys with small, non‑compliant exponents reduce cryptographic strength, but the system does not appear to be actively using them for high‑value services; thus exposure remains moderate [F33‑F63].

No findings contradict the rule‑based scores, so the default values are retained.  

---  

## Recommendations  

1. **Contain and Remediate Process Injection**  
   - Isolate the affected host from the network immediately. [F7]  
   - Terminate the compromised `RuntimeBroker.` process and any other processes with RWX injected regions (`SearchApp.exe`, `smartscreen.ex`, `OneDrive.exe`, `WWAHost.exe`). [F6‑F10]  
   - Perform a full system scan with an up‑to‑date AV/EDR solution and consider a clean OS reinstall.  

2. **Secure Cryptographic Assets**  
   - Replace all RSA‑1024 keys with RSA‑3072 or RSA‑4096 keys using a standard exponent (65537). [F33‑F63]  
   - Re‑generate RSA keys that currently use small exponents (e = 3 or 43147) to comply with FIPS 186‑5. [F38‑F42, F51‑F59, F56]  
   - Review applications that load these keys; update libraries to use modern TLS configurations (TLS 1.3, AEAD ciphers).  

3. **Hardening Execution Policies**  
   - Enforce “Block executable content from unknown sources” and disable execution from user‑writable directories (e.g., `Downloads`). [F11]  
   - Enable Windows Defender Application Control (WDAC) or AppLocker to restrict unsigned binaries.  

4. **Monitoring & Logging**  
   - Enable detailed process creation and module load auditing (Event ID 4688, 4689) to detect future injection attempts.  
   - Deploy network traffic analysis to flag anomalous outbound connections from the host.  

5. **Credential Hygiene**  
   - Although no credentials were found, enforce credential protection policies (LSA protection, Credential Guard) to prevent future leakage.  

6. **Incident Documentation**  
   - Preserve the memory image and all extracted artifacts for forensic chain‑of‑custody.  
   - Record the remediation steps taken and update the incident response playbook with this injection scenario.  

---  

*Prepared by the Malware Triage Team*  

## Validation notes (automatic)
Rule-based risk score: 82/100. This report failed these checks, treat the points below as unverified:
- only 70% of claims carry a citation
