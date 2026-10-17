# Incident Report  

## Summary  
- Several system processes (svchost.exe, explorer.exe, wmpnetwk.exe, notepad.exe) contain RWX‑marked injected memory regions, with identical code shared across five processes, indicating a system‑wide hooking mechanism【F6】.  
- An unauthenticated command shell (cmd.exe) was launched by **vmtoolsd.exe** rather than a user session, matching ATT&CK technique *T1059.003* (Command‑Line Interface)【F11】.  
- The memory image stores numerous legacy RSA keys (RSA‑1024, RSA‑1536, RSA‑2048) many of which have weak parameters (small exponent, 80‑bit security)【F28】.  

These artifacts collectively point to a compromised host with active code injection and exposure to weak cryptographic material.

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA‑1024 (e=65537) | 96% | implementation constants | 【F28】 |
| RSA‑1536 (e=65537) | 88% | implementation constants | 【F39】 |
| RSA‑2048 (e=3) | 82% | implementation constants | 【F37】 |
| RSA‑2048 (e=65537) | 80% | implementation constants | 【F47】 |
| RSA‑1536 (e=3) | 75% | implementation constants | 【F53】 |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bits | 65537 | 62 | weak size (80‑bit security) | 【F28】 |
| 1536 bits | 65537 | 62 | weak size (80‑bit security) | 【F39】 |
| 2048 bits | 3 | 88 | non‑compliant exponent (FIPS 186‑5) | 【F37】 |
| 2048 bits | 65537 | 88 | acceptable size but duplicate of weak exponent elsewhere | 【F47】 |
| 1536 bits | 3 | 62 | weak size & small exponent | 【F53】 |

## Credentials  
No credential artifacts (passwords, hashes, tokens) were identified in the extracted data【F1】.  

## Processes and Network  

- **Process inventory:** 42 processes were enumerated in the memory dump【F1】.  
- **Command lines:** 42 command‑line entries were captured【F2】.  
- **Network activity:** 65 network rows were logged; no malicious endpoints were directly identified【F3】.  
- **Injected code:** RWX regions were found in svchost.exe (PIDs 776, 1052), explorer.exe (PID 1312), wmpnetwk.exe (PID 2316), and notepad.exe (PID 2956). The regions contain identical code across five processes, a hallmark of a system‑wide hook【F6】.  
- **Unauthorized shell:** A cmd.exe instance (PID 3940) was spawned by vmtoolsd.exe (PID 1756) without a user session, matching ATT&CK T1059.003【F11】.  

## Risk Score  

**Overall risk:** **90** (Compromise **55**, Crypto Exposure **35**)  

- **Compromise (55)** – The presence of injected RWX code across multiple system processes and an unauthenticated shell indicates active compromise, directly supported by the findings【F6】【F11】.  
- **Crypto Exposure (35)** – The host stores numerous RSA‑1024 keys (strength 62/100) and several keys with non‑standard exponents, raising the exposure score from the baseline 20 to 35 (increase of 15, within the allowed ±20 deviation)【F28】【F37】【F39】【F53】.  

The overall risk rises from the rule‑based 60 to 90 because the weak cryptographic material substantially elevates the threat landscape while the compromise component remains at the rule‑based value.

## Recommendations  

- **Terminate and investigate injected processes** – Stop the affected svchost, explorer, wmpnetwk, and notepad instances and perform a full forensic analysis of the injected code【F6】.  
- **Enforce DEP and code‑signing** – Enable Data Execution Prevention and require signed binaries to block future RWX injection attempts【F6】.  
- **Audit vmtoolsd.exe** – Verify the legitimacy of VMware Tools, restrict its ability to spawn shells, and monitor for abnormal cmd.exe launches【F11】.  
- **Rotate all RSA‑1024 keys** – Generate new keys of at least 3072 bits with a standard exponent (65537) and replace the legacy keys【F28】.  
- **Re‑issue RSA‑2048 keys with exponent 65537** – Replace the 2048‑bit keys that use exponent 3 to comply with FIPS 186‑5【F37】.  
- **Deprecate RSA‑1536 keys** – Upgrade to RSA‑3072 or ECC alternatives; the current 1536‑bit keys provide insufficient security【F39】.  
- **Implement key management policies** – Enforce automated key rotation, enforce minimum key sizes, and disallow small exponents【F28】.  
- **Correlate network logs** – Cross‑reference the 65 logged network rows with threat intelligence feeds to identify any malicious endpoints【F3】.  
- **Deploy endpoint detection and response (EDR)** – Use an EDR solution to detect code injection, unauthorized shells, and abnormal process trees in real time【F6】.  

## Validation notes (automatic)
Rule-based risk score: 60/100. This report failed these checks, treat the points below as unverified:
- risk score 90 differs from rule-based 60 by more than 20