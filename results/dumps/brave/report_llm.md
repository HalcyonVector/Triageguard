# Incident Report  

**Date:** 2026‑10‑16  
**Analyst:** Malware Triage Team  

---  

## Summary  
Memory analysis uncovered three high‑severity processes that contain injected RWX code, indicating active process‑injection attacks (ATT&CK T1055) and, for PowerShell, command‑line abuse (ATT&CK T1059.001) [F7][F8][F10].  
Clear‑text credential artefacts were also found: a symmetric JWT (HS256), an AWS access‑key ID, and a bearer token, all of which are searchable in memory and usable for offline attacks [F76][F77][F78].  
A large set of legacy RSA keys (1024‑bit and 1023‑bit) and several 2048‑/4096‑bit keys with non‑standard exponents (e = 3) were extracted, exposing weak cryptography [F38‑F67].  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA (various key sizes) | 99.2% | implementation constants | [F38] |
| HMAC‑SHA‑256 (HS256) | 98.5% | API/string references only | [F76] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F38] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F39] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F40] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F41] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F42] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F43] |
| 1023 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F44] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F45] |
| 2048 bits | 3 | 88/100 | non‑compliant exponent (e = 3) | [F46] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F47] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F48] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F49] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F50] |
| 1536 bits | 65537 | 62/100 | weak size (≤2048 bits) | [F51] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F52] |
| 2048 bits | 3 | 88/100 | non‑compliant exponent (e = 3) | [F53] |
| 2048 bits | 3 | 88/100 | non‑compliant exponent (e = 3) | [F54] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F55] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F56] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F57] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F58] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F59] |
| 1024 bits | 65537 | 62/100 | weak size (≤1024 bits) | [F60] |
| 4096 bits | 3 | 100/100 | non‑compliant exponent (e = 3) | [F61] |
| 4096 bits | 3 | 100/100 | non‑compliant exponent (e = 3) | [F62] |
| 4096 bits | 3 | 100/100 | non‑compliant exponent (e = 3) | [F63] |
| 2048 bits | 3 | 88/100 | non‑compliant exponent (e = 3) | [F64] |
| 4096 bits | 62353 | 100/100 | non‑standard exponent | [F65] |
| 2048 bits | 3 | 88/100 | non‑compliant exponent (e = 3) | [F66] |
| 2048 bits | 43147 | 88/100 | non‑standard exponent | [F67] |

---  

## Credentials  

| Type | Value (truncated) | ATT&CK Technique(s) | Finding |
|------|-------------------|---------------------|---------|
| JWT (HS256) | `eyJhbG...8Sus` | T1528, T1552 | [F76] |
| AWS Access Key ID | `AKIAIW...H53A` | T1552 | [F77] |
| Bearer token | `585d36...ca1d` | T1528, T1552 | [F78] |

All three artefacts appear in clear‑text memory, making them trivially reusable by an attacker [F76][F77][F78].  

---  

## Processes and Network  

| PID | Process | Suspicious Behaviour | ATT&CK Technique(s) | Finding |
|-----|---------|----------------------|---------------------|---------|
| 5104 | SearchApp.exe | 2 RWX injected regions with unique code | T1055 | [F7] |
| 6716 | smartscreen.exe | 2 RWX injected regions with unique code | T1055 | [F8] |
| 5096 | powershell.exe | 5 RWX injected regions; command‑line usage | T1055, T1059.001 | [F10] |
| 1156 | MsMpEng.exe | 7 RWX regions but identified as known JIT process (expected) | – | [F6] |
| 6988 | OneDrive.exe | 1 RWX region starting with zero bytes, no code at base | – | [F9] |

The high‑severity injected processes (F7, F8, F10) demonstrate active malicious code execution on the host.  

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|---------------|
| Overall | 89 (rule‑based) | The supplied rule‑based score aligns with the observed high‑severity injections and weak cryptography [F7][F8][F10][F38] |
| Compromise | 80 | High‑severity injected processes provide clear evidence of compromise [F7][F8][F10] |
| Crypto Exposure | 93 | Numerous legacy RSA keys (strength ≤ 62) and non‑standard exponents increase exposure [F38][F46][F61] |

No cited finding forces a deviation from the provided scores, so the rule‑based values are retained.  

---  

## Recommendations  

- **Terminate injected processes** (SearchApp.exe, smartscreen.exe, powershell.exe) and isolate the host from the network [F7]  
- **Perform a full memory dump** and run a secondary forensic scan for additional code‑cave injections [F10]  
- **Revoke and rotate** the exposed JWT, AWS access key, and bearer token; store new secrets in a dedicated secret‑management system [F76]  
- **Replace all RSA‑1024/1023 keys** with RSA‑2048 or larger keys using the standard exponent e = 65537 [F38]  
- **Regenerate any 2048‑/4096‑bit keys** that currently use exponent e = 3 or other non‑standard values, conforming to FIPS‑186‑5 [F46]  
- **Apply the latest Windows patches** for Search, SmartScreen, and PowerShell to mitigate known injection vectors [F8]  
- **Deploy EDR alerts** for creation of RWX memory regions in trusted processes [F9]  
- **Enable logging** for credential access (AWS IAM, JWT generation) and set up alerts for anomalous token usage [F77]  
- **Enforce a policy** prohibiting storage of secrets in plaintext memory or files [F76]  
- **Conduct developer training** on secure key management and the risks of legacy cryptography [F38]  

---  

*Prepared by the Malware Triage Team.*

## Validation notes (automatic)
Rule-based risk score: 89/100. This report failed these checks, treat the points below as unverified:
- only 85% of claims carry a citation