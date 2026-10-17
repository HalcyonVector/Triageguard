# Incident Report  

**Date:** 2026‑10‑17  
**Analyst:** Malware Triage Team  

---  

## Summary  
The memory image contains evidence of a potentially malicious encryption activity launched from a legitimate Notepad.exe process (PID 8860) that referenced an “encrypt” command line and is mapped to ATT&CK technique **T1486 – Data Encrypted for Impact**【F8】.  
Four expired JWTs signed with **PS256** were discovered in memory, each flagged with credential‑access techniques **T1528** and **T1552**【F76】【F77】【F78】【F79】.  
Network capture shows a single TLS conversation using deprecated protocols (SSL 3.0) and weak cipher suites **TLS_RSA_WITH_AES_256_CBC_SHA** and **TLS_RSA_WITH_3DES_EDE_CBC_SHA**【F80】.  
A large number of RSA keys are present, many of which are 1024‑bit or use non‑standard small exponents (e = 3), indicating weak cryptographic material【F36】【F37】【F38】【F39】【F40】【F41】【F42】【F43】【F44】【F45】【F46】【F47】【F48】【F49】【F50】【F51】【F52】【F53】【F54】【F55】【F56】【F57】【F58】.  

Using the supplied rule‑based scores, the overall **Risk Score** is **74** (Compromise 55, Crypto Exposure 84). The findings justify these values; no single artifact forces a deviation from the baseline.  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| PS256 (JWT signature) | 98% | API/string references only | 【F76】 |
| TLS_RSA_WITH_AES_256_CBC_SHA | 95% | implementation constants | 【F80】 |
| TLS_RSA_WITH_3DES_EDE_CBC_SHA | 95% | implementation constants | 【F80】 |
| SSL 3.0 | 90% | implementation constants | 【F80】 |

### RSA Keys  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F36】 |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F37】 |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F38】 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | 【F39】 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | 【F40】 |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F41】 |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F42】 |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F43】 |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F44】 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | 【F45】 |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F46】 |
| 2048 bits | 65537 | 88 | Shared modulus (acceptable exponent) | 【F47】 |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F48】 |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F49】 |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F50】 |
| 4096 bits | 3 | 100 | Small exponent (non‑compliant) | 【F51】 |
| 4096 bits | 40409 | 100 | Small exponent (non‑compliant) | 【F52】 |
| 2048 bits | 50557 | 88 | Small exponent (non‑compliant) | 【F53】 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | 【F54】 |
| 2048 bits | 65671 | 88 | Shared modulus (acceptable) | 【F55】 |
| 1024 bits | 65537 | 62 | 80‑bit security, legacy only | 【F56】 |
| 4096 bits | 3 | 100 | Small exponent (non‑compliant) | 【F57】 |
| 2048 bits | 3 | 88 | Small exponent (non‑compliant) | 【F58】 |

---  

## Credentials  

| Token ID | Algorithm | Expiration (epoch) | Status | Finding |
|----------|-----------|--------------------|--------|---------|
| eyJhbG…2Yeg | PS256 | 1775072274 (future) – **expired** at analysis time | Expired JWT | 【F76】 |
| eyJhbG…EMRX | PS256 | 1775072274 – **expired** | Expired JWT | 【F77】 |
| eyJhbG…n2Lx | PS256 | 1775072274 – **expired** | Expired JWT | 【F78】 |
| eyJhbG…HQ0L | PS256 | 1775072274 – **expired** | Expired JWT | 【F79】 |

All tokens are signed with **PS256** and reference the same key identifier (`kid: 3B4CE43603FB6F5D0897547CCE2414F7E6A9DE90`)【F76】. Their expiration timestamps indicate they are no longer valid, but their presence suggests credential material was resident in memory.  

---  

## Processes and Network  

* **Suspicious Process** – `Notepad.exe` (PID 8860) launched with a command line that includes an encryption log file path, mapped to ATT&CK **T1486** (Data Encrypted for Impact)【F8】.  
* **Low‑severity anomalies** – `MsMpEng.exe` (PID 3088) shows 15 RWX injected regions, typical for a JIT process【F6】; `OneDrive.exe` (PID 1300) has one zero‑filled RWX region【F7】; `DumpIt.exe` (PID 2164) runs from a user‑writable desktop folder【F9】.  
* **Network** – One TLS conversation (127.0.0.1 ↔ 127.0.0.1:443) using SSL 3.0 and the weak cipher suites listed above, flagged with ATT&CK **T1573 – Encrypted Channel**【F80】. No external C2 endpoints were observed.  

---  

## Risk Score  

| Component | Score | Justification |
|-----------|-------|---------------|
| **Overall** | **74** | Matches the rule‑based baseline; findings do not provide a clear, cited reason to adjust the score. |
| **Compromise** | **55** | Presence of a ransomware‑style encryption command (F8) and credential artifacts (expired JWTs, F76‑F79) indicate moderate attacker foothold, but no active exfiltration or persistence beyond low‑severity anomalies. |
| **Crypto Exposure** | **84** | Numerous legacy RSA keys (1024‑bit, small exponents) and deprecated TLS configurations (SSL 3.0, RSA key‑exchange ciphers) create a high cryptographic risk, consistent with the supplied exposure rating. |

---  

## Recommendations  

1. **Isolate the suspicious Notepad process** and collect its full memory dump for deeper static analysis; terminate if confirmed malicious【F8】.  
2. **Re‑key all RSA material**: replace 1024‑bit keys and any keys with exponent = 3 with at least 2048‑bit keys using the standard exponent = 65537. Decommission shared‑modulus keys (e.g., F47, F55)【F36‑F58】.  
3. **Disable SSL 3.0 and weak RSA cipher suites** on all services; enforce TLS 1.2/1.3 with forward‑secrecy suites (ECDHE‑AES‑GCM, etc.)【F80】.  
4. **Invalidate and rotate all JWTs**; enforce short lifetimes, proper revocation, and consider using RS256 (RSA‑PKCS1‑v1_5) or ES256 (ECDSA) with strong key management【F76‑F79】.  
5. **Audit the low‑severity processes** (MsMpEng, OneDrive, DumpIt) for signs of code injection or abuse of writable directories; apply least‑privilege policies and enable Windows Defender Application Control (WDAC)