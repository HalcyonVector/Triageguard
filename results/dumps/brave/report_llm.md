# Incident Report  

**Date:** 2026‑10‑17  

---  

## Summary  
The memory image shows a **high‑severity PowerShell process** (PID 5096) with **five RWX‑injected memory regions** containing unique executable code, indicating process injection (ATT&CK T1055, T1059.001) [F10]. In addition, three clear‑text credentials were recovered: a JWT signed with HS256 [F76], an AWS access‑key ID [F77], and a Bearer token [F78]. The image also contains **numerous legacy RSA keys** (1024‑, 1023‑, 1536‑, 2048‑, 4096‑bit) many of which use a small exponent (e = 3) [F38]‑[F71]. These artifacts together point to an active compromise with significant cryptographic exposure.  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA‑1024 | 99.0% | implementation constants | [F38] |
| RSA‑1023 | 99.0% | implementation constants | [F44] |
| RSA‑1536 | 99.0% | implementation constants | [F51] |
| RSA‑2048 | 99.0% | implementation constants | [F46] |
| RSA‑4096 | 99.0% | implementation constants | [F61] |
| HS256 (JWT) | 99.0% | API/string references only | [F76] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bits | 65537 | 62/100 | weak modulus size (≤1024 bits) | [F38] |
| 1023 bits | 65537 | 62/100 | non‑standard size (≤1024 bits) | [F44] |
| 1536 bits | 65537 | 62/100 | weak modulus size (≤2048 bits) | [F51] |
| 2048 bits | 3 | 88/100 | small exponent (non‑compliant) | [F46] |
| 4096 bits | 3 | 100/100 | small exponent (non‑compliant) | [F61] |
| 4096 bits | 62353 | 100/100 | non‑standard exponent (non‑FIPS) | [F65] |

---  

## Credentials  

| Type | Value (truncated) | ATT&CK Technique(s) | Finding |
|------|-------------------|----------------------|---------|
| JWT (HS256) | `eyJhbG…8Sus` (expired) | T1528, T1552 | [F76] |
| AWS Access Key ID | `AKIAIW…H53A` | T1552 | [F77] |
| Bearer token | `585d36…ca1d` | T1528, T1552 | [F78] |

All three tokens are present in clear text in the captured memory and can be used for authentication or lateral movement [F76] [F77] [F78].  

---  

## Processes and Network  

| PID | Process | Observation | ATT&CK Technique(s) | Severity | Finding |
|-----|---------|-------------|----------------------|----------|---------|
| 5096 | `powershell.exe` | 5 RWX‑injected regions with unique code | T1055, T1059.001 | **High** | [F10] |
| 1156 | `MsMpEng.exe` | 7 RWX regions (expected JIT) | T1055 (expected) | Low | [F6] |
| 5104 | `SearchApp.exe` | 2 RWX regions with unique code | T1055 | Low | [F7] |
| 6716 | `smartscreen.ex` | 2 RWX regions with unique code | T1055 | Low | [F8] |
| 6988 | `OneDrive.exe` | 1 RWX region starts with zero bytes, no code | T1055 (suspicious) | Low | [F9] |

No network sockets or outbound connections were reported in the findings.  

---  

## Risk Score  

| Component | Score (0‑100) |
|-----------|---------------|
| Overall | 89 |
| Compromise | 80 |
| Crypto Exposure | 93 |

(The scores are taken directly from the rule‑based risk score supplied in the prompt.)  

---  

## Recommendations  

* **Terminate the injected PowerShell process** (PID 5096) and isolate the host from the network [F10].  
* **Revoke and rotate** the exposed JWT, AWS access key, and Bearer token; enforce MFA and short‑lived tokens for future use [F76] [F77] [F78].  
* **Replace all legacy RSA keys** (≤2048 bits or with exponent 3) with RSA‑3072 or ECC keys using a public exponent of 65537; regenerate keys that currently use e = 3 or other non‑standard exponents [F38]‑[F71].  
* **Upgrade TLS** to version 1.3 across all services and deprecate CAPI blobs that embed weak RSA parameters [F38]‑[F71].  
* **Enforce code‑integrity policies** (e.g., Windows Defender Application Control) to block RWX memory allocations for non‑trusted binaries [F10].  
* **Enable PowerShell Constrained Language Mode** and activate script‑block logging to detect future abuse [F10].  
* **Deploy EDR alerts** for RWX memory regions in `powershell.exe` and for the use of the leaked AWS key or Bearer token in cloud logs [F10] [F77] [F78].  
* **Apply the latest Windows updates** to the affected components (MsMpEng, SearchApp, SmartScreen, OneDrive) to reduce the attack surface [F6] [F7] [F8] [F9].  

---  

*Prepared by the Malware Triage Team*  
