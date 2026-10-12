# Incident Report  

**Date:** 2026‑10‑12  

---  

## Summary  
Memory analysis uncovered three processes with RWX‑injected memory regions, a hallmark of process injection (ATT&CK T1055) [F8][F6][F10].  A critically weak RSA‑512 key (strength 0/100) was also extracted [F59].  In addition, numerous legacy RSA keys (1024‑2048 bits) with small exponents or shared moduli were found [F34][F37][F38][F64].  The combination of active code injection and severely compromised cryptographic material indicates a high‑severity breach [F8][F59].  

---  

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA‑512 | 99.2% | implementation constants | [F59] |
| RSA‑1024 | 98.7% | implementation constants | [F34] |
| RSA‑1536 | 97.5% | implementation constants | [F41] |
| RSA‑2047 | 96.3% | implementation constants | [F71] |
| RSA‑2048 | 98.0% | implementation constants | [F37] |
| RSA‑4096 | 99.5% | implementation constants | [F64] |

*Confidence values are derived from deterministic parsing of the DER/CAPI blobs present in the memory image [F59].*  

### RSA Key Details (Critical)  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | modulus size broken (publicly factorable) | [F59] |

---  

## Credentials  
*The pipeline did not return any credential‑type findings.*  

---  

## Processes and Network  

| PID | Process | Injection Details | ATT&CK Technique | Finding |
|-----|---------|-------------------|------------------|---------|
| 3724 | spoolsv.exe | 4 RWX regions; 1 executable private memory with unique code, 3 PE‑header regions (likely injected DLL/EXE) | T1055 – Process Injection | [F8] |
| 1292 | Microsoft.Acti | 5 RWX regions; all contain executable private memory with unique code | T1055 – Process Injection | [F6] |
| 400 | ServerManager. | 3 RWX regions; all contain executable private memory with unique code | T1055 – Process Injection | [F10] |
| 1236 | svchost.exe (low) | 1 RWX region starting with zero bytes, no code at base | – | [F7] |
| 3472 | explorer.exe (low) | 2 RWX regions starting with zero bytes, no code at base | – | [F9] |

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|----------------|
| **Overall** | **97** | Rule‑based overall score supplied (97) is consistent with the evidence of compromise and weak crypto [F8][F59][F6][F10]. |
| **Compromise** | **95** | Multiple critical/high‑severity injected processes demonstrate active attacker control [F8][F6][F10]. |
| **Crypto Exposure** | **95** | Presence of a broken RSA‑512 key (strength 0) and many legacy keys with small exponents or shared moduli dramatically reduce cryptographic security [F59][F34][F37][F38][F64]. |

No cited finding contradicts the rule‑based values, so the scores remain unchanged.  

---  

## Recommendations  

* **Containment** – Immediately terminate the injected processes (spoolsv.exe, Microsoft.Acti, ServerManager.) and isolate the host from the network [F8][F6][F10].  
* **Forensic Capture** – Perform a full live memory dump for deeper analysis of the injected PE files [F8][F6][F10].  
* **Root‑Cause Investigation** – Analyze the PE headers found in the RWX regions to identify the payload and its origin [F8][F6][F10].  
* **Cryptographic Remediation** – Revoke and replace the RSA‑512 key (strength 0) [F59]; replace all RSA ≤1024‑bit keys and any keys using non‑standard exponents (e = 3) with RSA‑2048 or larger keys using the standard exponent 65537 [F34][F37][F64].  
* **Key‑Management Policy** – Enforce generation policies that disallow shared moduli and small exponents; require a minimum key size of 2048 bits [F34][F37][F38][F64].  
* **System Hardening** – Apply the latest OS and service patches (especially for the print spooler) [F8]; enable Windows Defender Credential Guard and Attack Surface Reduction rules that block unsigned code injection [F8][F6][F10].  
* **Monitoring & Detection** – Deploy EDR alerts for RWX memory allocations and PE‑header detections in privileged processes [F8][F6][F10]; monitor outbound network traffic for anomalous connections from the compromised host.  
* **Credential Review** – Although no credentials were found, force a password reset for privileged accounts that may have been used on the host, as credential dumping is a common post‑infection step.  

---  

*Prepared by:* Malware Triage Analyst  
*Classification:* Confidential – Internal Use Only  

## Validation notes (automatic)
Rule-based risk score: 97/100. This report failed these checks, treat the points below as unverified:
- only 73% of claims carry a citation