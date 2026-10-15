# Incident Report  

**Date:** 2026‑10‑15  

---  

## Summary  
- The host **DESKTOP‑SDN1RPT** shows two critical code‑injection events: `spoolsv.exe` (PID 2188) has an RWX memory region that starts with a PE header, indicating a likely injected DLL/EXE and mapping to ATT&CK **T1055** [F6].  
- `powershell.exe` (PID 3316) contains five RWX regions, two of which hold unique executable code and one with a PE header, also matching ATT&CK **T1055** and **T1059.001** [F8].  
- A **critical** 512‑bit RSA key (e = 65537) was recovered; its modulus is publicly factorable, giving it 0‑bit security and a “broken” status [F37].  

These artifacts demonstrate an active attacker who has injected malicious code into trusted system processes and is using extremely weak cryptographic material.  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 99.9% | implementation constants | [F16] |
| ECC P‑256 | 99.0% | implementation constants | [F17] |
| AES‑GCM | 95.5% | API/string references only | [F18] |
| ECC secp256k1 | 92.8% | implementation constants | [F19] |
| RSA | 92.8% | implementation constants | [F20] |
| generic | 83.2% | API/string references only | [F21] |
| DES | 60.0% | implementation constants | [F22] |
| 3DES | 60.0% | API/string references only | [F23] |
| Curve25519 | 40.0% | API/string references only | [F24] |

### RSA Key Strength  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | modulus size broken (publicly factorable) | [F37] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F25] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F26] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F27] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F28] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F29] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F30] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F31] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F32] |
| 1536 bits | 65537 | 62 | legacy size, disallowed | [F33] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F34] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F35] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F36] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F38] |
| 1024 bits | 65537 | 62 | legacy size, disallowed | [F39] |
| 2048 bits | 3 | 88 | non‑compliant exponent (FIPS 186‑5) | [F28] |
| 2048 bits | 3 | 88 | non‑compliant exponent (FIPS 186‑5) | [F40] |

---  

## Credentials  
- The supplied findings do not contain any credential‑related entries [F1].  

---  

## Processes and Network  

| Category | Observation | Finding |
|----------|-------------|---------|
| Suspicious process – `spoolsv.exe` | One RWX region with a PE header, indicating injected code (ATT&CK T1055) | [F6] |
| Suspicious process – `powershell.exe` | Five RWX regions; two contain unique code and one contains a PE header (ATT&CK T1055, T1059.001) | [F8] |
| Network traffic | 50 TLS conversations observed; SNI list includes several media CDNs; no weak TLS versions reported | [F48] |

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|---------------|
| **Compromise** | **95** (rule‑based) | Supported by the two critical injection findings (F6, F8) that demonstrate an active foothold [F6][F8]. |
| **Crypto Exposure** | **70** (adjusted) | The critical 512‑bit RSA key (F37) reduces the crypto‑exposure rating from the baseline 55 to 70 because it provides 0‑bit security [F37]. |
| **Overall** | **96** (rule‑based) | The overall risk remains at the provided rule‑based value; the component adjustment does not change the aggregate score [F6][F8][F37]. |

---  

## Recommendations  

1. **Isolate the host** – Immediately place the machine on a quarantine network and stop the malicious `spoolsv.exe` and `powershell.exe` processes [F6][F8].  
2. **Capture fresh forensic images** – Obtain a new memory dump and a full disk image for deeper analysis of the injected payloads [F6][F8].  
3. **Remove injected code** – Use trusted utilities (e.g., Sysinternals Process Explorer, Autoruns) to locate and delete the DLL/EXE files referenced by the RWX regions [F6][F8].  
4. **Regenerate cryptographic keys** – Discard the 512‑bit RSA key and all legacy 1024‑bit keys; replace them with RSA ≥ 3072 bits or modern ECC (P‑256/P‑384) keys [F37][F25][F28].  
5. **Enforce strong crypto policies** – Disable DES and 3DES, require TLS 1.2 or higher with strong cipher suites, and audit for low‑confidence algorithm usage (DES, 3DES, Curve25519) [F22][F23][F24].  
6. **Apply system patches** – Install the latest Windows updates and enable mitigations such as Control Flow Guard and Data Execution Prevention to hinder future code‑injection attempts [F6][F8].  
7. **Monitor for lateral movement** – Correlate additional network logs with the observed TLS SNI list to detect any further malicious communications [F48].  
8. **Review credential protection** – Although no credentials were found, verify that LSASS and DPAPI are protected (e.g., enable Credential Guard) to prevent future credential dumping [F1].  

---  

*Prepared by the Malware Triage Team.*  

## Validation notes (automatic)
Rule-based risk score: 96/100. This report failed these checks, treat the points below as unverified:
- strength for F28 stated as 62 but computed 88
- only 88% of claims carry a citation